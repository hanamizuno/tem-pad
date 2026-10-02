"""Proton Pass Collector (Token for Agents の監査ログ)。

``pass-cli agent list --output json`` で Agent を列挙し、Agent ごとに
``pass-cli agent monitor <name> --limit N --output json`` で監査記録を取る。
利用者アカウントでログインしたセッションが必要 (Agent 自身のセッションでは
他 Agent のログは見えない)。

secret (パスワードやトークンなど) は監査記録に含まれない想定だが、
念のため疑わしいキーは保存前に取り除く。item / vault / reason は
``redact_mode`` でハッシュ化または削除できる。

JSON のフィールド名は CLI のバージョンで変わり得るため、候補キーを
順に探す寛容なパーサにしている (docs/implementation-notes.md)。
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, cast

from tem_pad.checks import CheckResult
from tem_pad.collectors.base import CollectorContext, CollectOutput
from tem_pad.config import Config, ProtonPassConfig
from tem_pad.models import KIND_UNKNOWN, Event, parse_timestamp
from tem_pad.procutil import CommandError, run_command, which
from tem_pad.sanitize import sanitize

SOURCE = "proton-pass"

_AGENT_NAME_KEYS = ("name", "agent_name", "agentName", "title", "label")
_AGENT_ID_KEYS = ("id", "pat_id", "patId", "personal_access_token_id", "agent_id", "token_id")
_RECORD_ID_KEYS = ("record_id", "recordId", "id", "event_id", "eventId", "log_id")
_ACTION_KEYS = ("action", "event", "event_type", "eventType", "operation", "type")
_VAULT_KEYS = ("vault", "vault_name", "vaultName", "share_name", "shareName")
_VAULT_ID_KEYS = ("vault_id", "vaultId", "share_id", "shareId")
_ITEM_KEYS = ("item", "item_title", "itemTitle", "item_name", "itemName", "title")
_ITEM_ID_KEYS = ("item_id", "itemId", "object_id", "objectId")
_REASON_KEYS = ("reason", "agent_reason", "agentReason")
_TIME_KEYS = (
    "timestamp",
    "time",
    "created_at",
    "createdAt",
    "create_time",
    "createTime",
    "date",
    "event_time",
    "eventTime",
)
_CONSUMED_KEYS = frozenset(
    _RECORD_ID_KEYS
    + _ACTION_KEYS
    + _VAULT_KEYS
    + _VAULT_ID_KEYS
    + _ITEM_KEYS
    + _ITEM_ID_KEYS
    + _REASON_KEYS
    + _TIME_KEYS
)

# 変更系の操作はダッシュボードで強調したいので kind を分ける
_WRITE_ACTIONS = ("create", "update", "trash", "untrash", "move", "delete", "write", "edit")

# epoch がこの値より大きければミリ秒とみなす
_EPOCH_MILLIS_THRESHOLD = 1e11


def as_str_dict(value: Any) -> dict[str, Any]:  # noqa: ANN401
    """JSON 由来の dict をキー str の dict にする。dict でなければ空。"""
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in cast("dict[Any, Any]", value).items()}


def first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:  # noqa: ANN401
    """候補キーのうち最初に値が入っているものを返す。"""
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def strip_secret_keys(data: Any) -> Any:  # noqa: ANN401
    """共通 sanitizer で secret らしいキーを削除し、既知の secret 形式を伏せ字にする。"""
    return sanitize(data)


def parse_json_output(text: str) -> Any:  # noqa: ANN401
    """CLI の JSON 出力を解釈する。先頭に人間向けの行が混ざっていても JSON 部分を拾う。"""
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    # 警告行などが前にある場合に備え、最初の [ または { から再試行する
    for opener in ("[", "{"):
        index = stripped.find(opener)
        if index >= 0:
            try:
                return json.loads(stripped[index:])
            except json.JSONDecodeError:
                continue
    raise ValueError("pass-cli の出力を JSON として解釈できません")


def _unwrap_list(data: Any, keys: tuple[str, ...]) -> list[Any]:  # noqa: ANN401
    """配列そのもの、または dict 内の候補キー配下の配列を取り出す。"""
    if isinstance(data, list):
        return list(cast("list[Any]", data))
    if isinstance(data, dict):
        record = as_str_dict(data)
        for key in keys:
            value = record.get(key)
            if isinstance(value, list):
                return list(cast("list[Any]", value))
        return [record]
    return []


def parse_agents(data: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    """``agent list --output json`` の出力から Agent の一覧を取り出す。"""
    items = _unwrap_list(data, ("agents", "items", "data", "tokens", "personal_access_tokens"))
    agents: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            record = as_str_dict(item)
            name = first(record, _AGENT_NAME_KEYS)
            if name is None:
                continue
            agents.append(
                {
                    "name": str(name),
                    "id": _opt(first(record, _AGENT_ID_KEYS)),
                    "raw": strip_secret_keys(record),
                }
            )
        elif isinstance(item, str) and item:
            agents.append({"name": item, "id": None, "raw": {}})
    return agents


def parse_monitor_records(data: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    """``agent monitor --output json`` の出力から記録の一覧を取り出す。"""
    items = _unwrap_list(data, ("records", "logs", "events", "items", "data", "entries"))
    return [as_str_dict(item) for item in items if isinstance(item, dict)]


def _opt(value: Any) -> str | None:  # noqa: ANN401
    return None if value in (None, "") else str(value)


def record_timestamp(record: dict[str, Any], fallback: datetime) -> datetime:
    """記録の時刻。epoch 秒/ミリ秒と ISO 文字列の両方を受け付ける。"""
    value = first(record, _TIME_KEYS)
    if isinstance(value, bool):
        return fallback
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > _EPOCH_MILLIS_THRESHOLD:
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str) and value:
        if value.isdigit():
            return record_timestamp({"timestamp": int(value)}, fallback)
        try:
            return parse_timestamp(value)
        except ValueError:
            return fallback
    return fallback


def redact(value: str | None, mode: str) -> str | None:
    """redact_mode に応じて値を加工する。"""
    if value is None or mode == "plain":
        return value
    if mode == "drop":
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def record_event_id(agent: str, record: dict[str, Any]) -> str:
    """記録 ID があればそれを、なければ内容のハッシュを使う。"""
    record_id = first(record, _RECORD_ID_KEYS)
    if record_id is not None:
        return f"{agent}:{record_id}"
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    return f"{agent}:sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:32]}"


def normalize_record(
    agent: dict[str, Any],
    record: dict[str, Any],
    *,
    host: str,
    now: datetime,
    cfg: ProtonPassConfig,
) -> Event:
    """監査記録 1 件を Event にする。"""
    clean = as_str_dict(strip_secret_keys(record))
    action = _opt(first(clean, _ACTION_KEYS))
    lowered = (action or "").lower()
    if not action:
        kind = KIND_UNKNOWN
    elif any(word in lowered for word in _WRITE_ACTIONS):
        kind = "agent_write"
    else:
        kind = "agent_read"

    extra = {k: v for k, v in clean.items() if k not in _CONSUMED_KEYS}
    payload: dict[str, Any] = {
        "agent": agent["name"],
        "agent_id": agent.get("id"),
        "record_id": _opt(first(clean, _RECORD_ID_KEYS)),
        "vault": redact(_opt(first(clean, _VAULT_KEYS)), cfg.redact_mode),
        "vault_id": redact(_opt(first(clean, _VAULT_ID_KEYS)), cfg.redact_mode),
        "item": redact(_opt(first(clean, _ITEM_KEYS)), cfg.redact_mode),
        "item_id": redact(_opt(first(clean, _ITEM_ID_KEYS)), cfg.redact_mode),
        "reason": redact(_opt(first(clean, _REASON_KEYS)), cfg.redact_mode),
        "reason_missing": first(clean, _REASON_KEYS) in (None, ""),
    }
    if extra:
        payload["extra"] = extra
    return Event(
        timestamp=record_timestamp(clean, now),
        source=SOURCE,
        kind=kind,
        host=host,
        actor=str(agent["name"]),
        action=action,
        decision=None,
        event_id=record_event_id(str(agent["name"]), record),
        payload=payload,
    )


class ProtonPassCollector:
    """Proton Pass Agent の監査ログを収集する。"""

    name = SOURCE

    def enabled(self, config: Config) -> bool:
        """設定上有効か。"""
        return config.proton_pass.enabled

    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput:
        """Agent を列挙し、それぞれの監査記録を取得する。"""
        cfg = ctx.config.proton_pass
        host = ctx.config.general.host
        warnings: list[str] = []
        events: list[Event] = []
        env = {"PASS_LOG_LEVEL": "error"}

        list_result = run_command(
            [cfg.cli_path, "agent", "list", "--output", "json"],
            timeout=cfg.timeout_seconds,
            env=env,
        )
        agents = parse_agents(parse_json_output(list_result.stdout))
        if cfg.agents:
            agents = [agent for agent in agents if agent["name"] in cfg.agents]
        if not ctx.dry_run:
            ctx.raw.write_json(SOURCE, "agents", [agent["raw"] for agent in agents])

        previous = as_str_dict(state.get("agents"))
        per_agent: dict[str, Any] = {}
        for agent in agents:
            name = str(agent["name"])
            try:
                monitor = run_command(
                    [
                        cfg.cli_path,
                        "agent",
                        "monitor",
                        name,
                        "--limit",
                        str(cfg.monitor_limit),
                        "--output",
                        "json",
                    ],
                    timeout=cfg.timeout_seconds,
                    env=env,
                )
                records = parse_monitor_records(parse_json_output(monitor.stdout))
            except (CommandError, ValueError) as exc:
                warnings.append(f"agent {name!r} の monitor に失敗: {exc}")
                per_agent[name] = previous.get(name, {})
                continue
            if not ctx.dry_run:
                ctx.raw.write_json(SOURCE, f"monitor-{name}", strip_secret_keys(records))
            limit_reached = len(records) >= cfg.monitor_limit
            if limit_reached:
                # 直近 N 件しか取れないので、前回の実行から N 件を超える記録があると取りこぼす
                warnings.append(
                    f"agent {name!r} の monitor が monitor_limit ({cfg.monitor_limit}) 件に"
                    "達しました。取りこぼしの可能性があるため monitor_limit を増やすか"
                    "実行間隔を短くしてください"
                )
            latest_id: str | None = None
            for record in records:
                try:
                    event = normalize_record(agent, record, host=host, now=ctx.now, cfg=cfg)
                except Exception as exc:  # noqa: BLE001
                    # 1 件の異常で全体を止めない
                    warnings.append(
                        f"agent {name!r} の記録を正規化できませんでした: {type(exc).__name__}"
                    )
                    continue
                events.append(event)
                if latest_id is None:
                    latest_id = event.payload.get("record_id")
            per_agent[name] = {
                "id": agent.get("id"),
                "last_record_id": latest_id,
                "records_seen": len(records),
                "limit_reached": limit_reached,
            }
        new_state = dict(state)
        new_state["agents"] = per_agent
        return CollectOutput(events=events, state=new_state, warnings=warnings)


def doctor_checks(config: Config) -> list[CheckResult]:
    """Proton Pass CLI の存在とログイン状態を確認する。"""
    cfg = config.proton_pass
    if not cfg.enabled:
        return [CheckResult.skip("Proton Pass", "設定で無効")]
    results: list[CheckResult] = []
    path = which(cfg.cli_path)
    if path is None:
        results.append(
            CheckResult.ng(
                "Proton Pass CLI installed",
                f"{cfg.cli_path} が見つかりません",
                "pass-cli をインストールするか proton_pass.cli_path を設定してください",
            )
        )
        results.append(CheckResult.skip("Proton Pass authenticated", "CLI がないため未確認"))
        return results
    results.append(CheckResult.ok("Proton Pass CLI installed", path))
    try:
        info = run_command(
            [cfg.cli_path, "info"], timeout=cfg.timeout_seconds, env={"PASS_LOG_LEVEL": "error"}
        )
    except CommandError as exc:
        results.append(
            CheckResult.ng(
                "Proton Pass authenticated",
                str(exc),
                "利用者アカウントで pass-cli login を実行してください"
                " (Agent の監査ログ閲覧には利用者セッションが必要)",
            )
        )
        return results
    if "Personal Access Token" in info.stdout:
        results.append(
            CheckResult.warn(
                "Proton Pass authenticated",
                "PAT/Agent セッションでログイン中",
                "他 Agent の監査ログを見るには利用者アカウントのセッションが必要です",
            )
        )
    else:
        results.append(CheckResult.ok("Proton Pass authenticated", "user session"))
    return results
