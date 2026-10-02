"""Tailscale Collector。

2 種類のイベントを生成する。

* Configuration audit log (``GET /api/v2/tailnet/{tailnet}/logging/configuration``)
  を前回終端から overlap 付きで取得し、1 エントリ = 1 イベントにする。
* device 一覧 (``GET /api/v2/tailnet/{tailnet}/devices``) を取得し、前回 state
  との差分から ``device_added`` / ``device_removed`` / ``device_changed`` を作る。

認証は OAuth client (client credentials) を優先し、無ければ API access
token を使う。secret は環境変数等から実行時に読み、ログ・raw に残さない。

外部仕様は docs/implementation-notes.md を参照。フィールド名は公式ドキュメント
に基づくが、未知のフィールドはすべて payload に残す。
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, cast
from urllib.parse import urlencode

from tem_pad.checks import CheckResult
from tem_pad.collectors.base import CollectorContext, CollectOutput
from tem_pad.config import Config, TailscaleConfig
from tem_pad.httputil import HttpError, form_encode, request
from tem_pad.models import KIND_UNKNOWN, Event, format_timestamp, parse_timestamp
from tem_pad.sanitize import sanitize, sanitize_dict
from tem_pad.secrets import SecretError

SOURCE = "tailscale"

# target.type の値からイベント種別へのざっくりした対応
_TARGET_KIND = (
    (("NODE", "DEVICE", "MACHINE"), "audit_device"),
    (("USER",), "audit_user"),
    (("POLICY", "ACL", "HUJSON"), "audit_policy"),
    (("KEY", "AUTHKEY", "AUTH_KEY", "CREDENTIAL", "OAUTH", "API"), "audit_key"),
    (("TAILNET", "DNS", "SETTING"), "audit_tailnet"),
)

# device 差分で比較するフィールド。接続状態などの揮発的な値は除外する
_DEVICE_FIELDS = (
    "name",
    "hostname",
    "os",
    "user",
    "tags",
    "authorized",
    "addresses",
    "keyExpiryDisabled",
    "isExternal",
    "isEphemeral",
    "blocksIncomingConnections",
    "tailnetLockKey",
    "machineKey",
    "nodeKey",
    "expires",
    "clientVersion",
    "advertisedRoutes",
    "enabledRoutes",
    "sshEnabled",
)

_AUDIT_KNOWN_KEYS = frozenset(
    {"eventGroupID", "origin", "actor", "target", "action", "old", "new", "eventTime", "deferredAt"}
)


class TailscaleAuthError(RuntimeError):
    """認証情報が不足または無効。"""


def as_str_dict(value: Any) -> dict[str, Any]:  # noqa: ANN401
    """JSON 由来の dict をキー str の dict にする。dict でなければ空。"""
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in cast("dict[Any, Any]", value).items()}


def _extract_list(data: Any, key: str) -> list[dict[str, Any]]:  # noqa: ANN401
    inner = as_str_dict(data).get(key) if isinstance(data, dict) else data
    if not isinstance(inner, list):
        return []
    return [as_str_dict(item) for item in cast("list[Any]", inner) if isinstance(item, dict)]


class TailscaleClient:
    """Tailscale API の最小クライアント。"""

    def __init__(self, config: Config) -> None:
        """Args: config: 全体設定。"""
        self.cfg = config.tailscale
        self._auth_header: str | None = None

    def _authorization(self) -> str:
        if self._auth_header is not None:
            return self._auth_header
        client_id = self.cfg.oauth_client_id.resolve()
        client_secret = self.cfg.oauth_client_secret.resolve()
        if client_id and client_secret:
            token = self._exchange_oauth(client_id, client_secret)
            self._auth_header = f"Bearer {token}"
            return self._auth_header
        api_key = self.cfg.api_key.resolve()
        if api_key:
            # API access token は Basic 認証のユーザー名として渡す
            encoded = base64.b64encode(f"{api_key}:".encode()).decode("ascii")
            self._auth_header = f"Basic {encoded}"
            return self._auth_header
        raise TailscaleAuthError(
            "Tailscale の認証情報がありません。"
            f" OAuth client ({self.cfg.oauth_client_id.describe()} /"
            f" {self.cfg.oauth_client_secret.describe()}) か"
            f" API key ({self.cfg.api_key.describe()}) を設定してください"
        )

    def _exchange_oauth(self, client_id: str, client_secret: str) -> str:
        fields = {"client_id": client_id, "client_secret": client_secret}
        if self.cfg.oauth_scopes:
            fields["scope"] = " ".join(self.cfg.oauth_scopes)
        try:
            resp = request(
                f"{self.cfg.api_base_url}/api/v2/oauth/token",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=form_encode(fields),
                timeout=self.cfg.timeout_seconds,
            )
        except HttpError as exc:
            # 本文に secret は含まれないが念のためステータスだけ伝える
            raise TailscaleAuthError(
                f"OAuth token の取得に失敗しました (HTTP {exc.status})"
            ) from exc
        token = as_str_dict(resp.json()).get("access_token")
        if not isinstance(token, str) or not token:
            raise TailscaleAuthError("OAuth token レスポンスに access_token がありません")
        return token

    def get_json(self, path: str, params: dict[str, str] | None = None) -> Any:  # noqa: ANN401
        """認証付き GET。"""
        url = f"{self.cfg.api_base_url}{path}"
        if params:
            url += "?" + urlencode(params)
        resp = request(
            url,
            headers={"Authorization": self._authorization(), "Accept": "application/json"},
            timeout=self.cfg.timeout_seconds,
        )
        return resp.json()

    def configuration_audit_logs(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        """設定監査ログを取得する。"""
        data = self.get_json(
            f"/api/v2/tailnet/{self.cfg.tailnet}/logging/configuration",
            {"start": format_timestamp(start), "end": format_timestamp(end)},
        )
        return _extract_list(data, "logs")

    def devices(self) -> list[dict[str, Any]]:
        """device 一覧を取得する (fields=all)。"""
        data = self.get_json(f"/api/v2/tailnet/{self.cfg.tailnet}/devices", {"fields": "all"})
        return _extract_list(data, "devices")


# ---------------------------------------------------------------------------
# 正規化
# ---------------------------------------------------------------------------


def audit_kind(entry: dict[str, Any]) -> str:
    """監査ログエントリから kind を決める。"""
    target = as_str_dict(entry.get("target"))
    target_type = str(target.get("type") or "").upper()
    if not target_type:
        return KIND_UNKNOWN if not entry.get("action") else "audit_other"
    for needles, kind in _TARGET_KIND:
        if any(needle in target_type for needle in needles):
            return kind
    return "audit_other"


def audit_event_id(entry: dict[str, Any]) -> str:
    """エントリに一意 ID が無いため内容のハッシュを使う。"""
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
    return "audit:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _entry_time(entry: dict[str, Any], fallback: datetime) -> datetime:
    for key in ("eventTime", "timestamp", "time"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            try:
                return parse_timestamp(value)
            except ValueError:
                continue
    return fallback


def normalize_audit_entry(entry: dict[str, Any], host: str, fallback_time: datetime) -> Event:
    """監査ログ 1 エントリを Event にする。未知フィールドは payload に残す。

    ``old`` / ``new`` / 未知フィールドには任意の値が入り得るため、保存前に
    secret らしいキーの削除と既知 secret 形式の伏せ字化を行う。
    """
    entry = sanitize_dict(entry)
    actor = as_str_dict(entry.get("actor"))
    target = as_str_dict(entry.get("target"))
    actor_name = actor.get("loginName") or actor.get("displayName") or actor.get("id")
    payload: dict[str, Any] = {
        "event_group_id": entry.get("eventGroupID"),
        "origin": entry.get("origin"),
        "actor_id": actor.get("id"),
        "actor_type": actor.get("type"),
        "actor_display_name": actor.get("displayName"),
        "target_id": target.get("id"),
        "target_name": target.get("name"),
        "target_type": target.get("type"),
        "target_property": target.get("property"),
        "old": entry.get("old"),
        "new": entry.get("new"),
        "deferred_at": entry.get("deferredAt"),
    }
    extra = {k: v for k, v in entry.items() if k not in _AUDIT_KNOWN_KEYS}
    if extra:
        payload["extra"] = extra
    return Event(
        timestamp=_entry_time(entry, fallback_time),
        source=SOURCE,
        kind=audit_kind(entry),
        host=host,
        actor=str(actor_name) if actor_name else None,
        action=str(entry["action"]) if entry.get("action") else None,
        decision=None,
        event_id=audit_event_id(entry),
        payload=payload,
    )


def device_snapshot(devices: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """差分比較用に device 一覧を nodeId キーの dict に縮約する。"""
    snapshot: dict[str, dict[str, Any]] = {}
    for device in devices:
        key = device.get("nodeId") or device.get("id")
        if not key:
            continue
        snapshot[str(key)] = {
            field: device.get(field) for field in _DEVICE_FIELDS if field in device
        }
    return snapshot


def diff_devices(
    previous: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    *,
    host: str,
    now: datetime,
) -> list[Event]:
    """前回と今回のスナップショットから device イベントを作る。"""
    events: list[Event] = []
    for node_id, device in current.items():
        if node_id not in previous:
            events.append(_device_event("device_added", node_id, device, host, now, changes=None))
            continue
        before = previous[node_id]
        changes: dict[str, dict[str, Any]] = {}
        for field in _DEVICE_FIELDS:
            old = before.get(field)
            new = device.get(field)
            if _normalize_value(old) != _normalize_value(new):
                changes[field] = {"old": old, "new": new}
        if changes:
            events.append(
                _device_event("device_changed", node_id, device, host, now, changes=changes)
            )
    for node_id, device in previous.items():
        if node_id not in current:
            events.append(_device_event("device_removed", node_id, device, host, now, changes=None))
    return events


def _normalize_value(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, list):
        return sorted(str(item) for item in cast("list[Any]", value))
    return value


def device_event_id(kind: str, node_id: str, content: dict[str, Any]) -> str:
    """device 差分イベントの決定的な ID。

    同じスナップショット差分から同じ ID が出るので、state 保存前にプロセスが
    落ちて同じ差分を再計算しても重複排除できる。
    """
    canonical = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"device:{node_id}:{kind}:{digest}"


def _device_event(
    kind: str,
    node_id: str,
    device: dict[str, Any],
    host: str,
    now: datetime,
    *,
    changes: dict[str, dict[str, Any]] | None,
) -> Event:
    device = sanitize_dict(device)
    payload: dict[str, Any] = {
        "node_id": node_id,
        "device_name": device.get("name"),
        "hostname": device.get("hostname"),
        "os": device.get("os"),
        "user": device.get("user"),
        "tags": device.get("tags"),
        "authorized": device.get("authorized"),
        "addresses": device.get("addresses"),
        "is_external": device.get("isExternal"),
        "is_ephemeral": device.get("isEphemeral"),
    }
    if changes is not None:
        payload["changes"] = sanitize_dict(changes)
    return Event(
        timestamp=now,
        source=SOURCE,
        kind=kind,
        host=host,
        actor=str(device.get("user")) if device.get("user") else None,
        action=kind.split("_", 1)[1],
        decision=None,
        event_id=device_event_id(kind, node_id, changes if changes is not None else device),
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class TailscaleCollector:
    """Tailscale の監査ログと device 差分を収集する。"""

    name = SOURCE

    def enabled(self, config: Config) -> bool:
        """設定上有効か。"""
        return config.tailscale.enabled

    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput:
        """監査ログと device 差分を取得する。"""
        cfg = ctx.config.tailscale
        host = ctx.config.general.host
        client = TailscaleClient(ctx.config)
        warnings: list[str] = []
        events: list[Event] = []
        new_state = dict(state)

        # --- Configuration audit log ---
        start = _audit_window_start(state, ctx.now, cfg)
        entries = [
            sanitize_dict(entry) for entry in client.configuration_audit_logs(start, ctx.now)
        ]
        if not ctx.dry_run:
            ctx.raw.write_json(
                SOURCE,
                "audit",
                {
                    "start": format_timestamp(start),
                    "end": format_timestamp(ctx.now),
                    "logs": entries,
                },
            )
        for entry in entries:
            try:
                events.append(normalize_audit_entry(entry, host, ctx.now))
            except Exception as exc:  # noqa: BLE001
                # 1 件の異常で全体を止めず unknown として残す
                warnings.append(f"audit entry を正規化できませんでした: {type(exc).__name__}")
                events.append(
                    Event(
                        timestamp=ctx.now,
                        source=SOURCE,
                        kind=KIND_UNKNOWN,
                        host=host,
                        event_id=audit_event_id(entry),
                        payload={"raw": sanitize(entry)},
                    )
                )
        new_state["audit_cursor"] = format_timestamp(ctx.now)

        # --- Devices ---
        if _devices_due(state, ctx.now, cfg.devices_interval_seconds):
            devices = [sanitize_dict(device) for device in client.devices()]
            if not ctx.dry_run:
                ctx.raw.write_json(SOURCE, "devices", {"devices": devices})
            current = device_snapshot(devices)
            previous_raw = state.get("devices")
            if isinstance(previous_raw, dict):
                previous = {
                    str(k): as_str_dict(v)
                    for k, v in cast("dict[Any, Any]", previous_raw).items()
                    if isinstance(v, dict)
                }
                events.extend(diff_devices(previous, current, host=host, now=ctx.now))
            else:
                warnings.append(
                    f"device 一覧の初回取得 ({len(current)} 台) を基準として保存しました"
                )
            new_state["devices"] = current
            new_state["devices_fetched_at"] = format_timestamp(ctx.now)

        return CollectOutput(events=events, state=new_state, warnings=warnings)


def _audit_window_start(state: dict[str, Any], now: datetime, cfg: TailscaleConfig) -> datetime:
    cursor = state.get("audit_cursor")
    start = now - timedelta(hours=cfg.audit_initial_lookback_hours)
    if isinstance(cursor, str) and cursor:
        with contextlib.suppress(ValueError):
            start = parse_timestamp(cursor) - timedelta(seconds=cfg.audit_overlap_seconds)
    earliest = now - timedelta(hours=cfg.audit_max_window_hours)
    return max(start, earliest)


def _devices_due(state: dict[str, Any], now: datetime, interval: int) -> bool:
    fetched = state.get("devices_fetched_at")
    if not isinstance(fetched, str) or not fetched:
        return True
    try:
        last = parse_timestamp(fetched)
    except ValueError:
        return True
    return (now - last).total_seconds() >= interval


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def doctor_checks(config: Config) -> list[CheckResult]:
    """Tailscale 関連の診断。credential の値は表示しない。"""
    cfg = config.tailscale
    if not cfg.enabled:
        return [CheckResult.skip("Tailscale", "設定で無効")]
    results: list[CheckResult] = []
    try:
        has_oauth = bool(cfg.oauth_client_id.resolve() and cfg.oauth_client_secret.resolve())
        has_key = bool(cfg.api_key.resolve())
    except SecretError as exc:
        return [
            CheckResult.ng(
                "Tailscale credentials", str(exc), "secret の取得元設定を確認してください"
            )
        ]
    if has_oauth:
        results.append(
            CheckResult.ok(
                "Tailscale credentials", f"OAuth client ({cfg.oauth_client_id.describe()})"
            )
        )
    elif has_key:
        results.append(
            CheckResult.warn(
                "Tailscale credentials",
                f"API key ({cfg.api_key.describe()}) を使用。長期運用には OAuth client を推奨",
                "OAuth client を作成し TAILSCALE_OAUTH_CLIENT_ID/SECRET を設定してください",
            )
        )
    else:
        results.append(
            CheckResult.ng(
                "Tailscale credentials",
                "OAuth client も API key も見つかりません",
                "TAILSCALE_OAUTH_CLIENT_ID と TAILSCALE_OAUTH_CLIENT_SECRET を設定してください"
                " (docs/setup.md)",
            )
        )
        results.append(CheckResult.skip("Tailscale API reachable", "認証情報がないため未確認"))
        return results
    try:
        devices = TailscaleClient(config).devices()
    except (TailscaleAuthError, HttpError, SecretError, ValueError) as exc:
        results.append(
            CheckResult.ng(
                "Tailscale API reachable",
                str(exc),
                "credential の scope (devices:core:read, logs:configuration:read) と"
                " tailnet 設定を確認してください",
            )
        )
        return results
    results.append(CheckResult.ok("Tailscale API reachable", f"devices={len(devices)}"))
    return results
