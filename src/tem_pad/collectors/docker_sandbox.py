"""Docker Sandboxes Collector。

2 方式を扱う。

* **native**: Docker AI Governance の native audit JSONL
  (``~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit/*.jsonl``) が
  ある場合。Collector は何もせず、Grafana Alloy が直接 tail する
  (deploy/alloy/config.alloy)。完成した ``.jsonl`` のみ読み ``.tmp`` は
  読まない。
* **policy-log**: ``sbx policy log --json`` の出力から正規化する fallback。
  native audit は有償の AI Governance プランと組織ポリシーが前提で、
  個人アカウントでは生成されないため、個人環境では通常こちらになる。

``sbx policy log`` は sandbox・host・判定の組ごとの集計 (件数と最終時刻)
であり、接続ごとの記録ではない。そのため前回スナップショットとの差分で
イベントを作り、count の増分を payload に載せる。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from tem_pad.checks import CheckResult
from tem_pad.collectors.base import CollectorContext, CollectOutput
from tem_pad.config import Config, DockerSandboxConfig
from tem_pad.models import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_UNKNOWN,
    Event,
    normalize_decision,
    parse_timestamp,
)
from tem_pad.procutil import CommandError, run_command, which
from tem_pad.sanitize import sanitize

SOURCE = "docker-sandbox"

_SANDBOX_KEYS = ("sandbox", "sandbox_name", "sandboxName", "name")
_TYPE_KEYS = ("type", "policy_type", "policyType", "kind")
_HOST_KEYS = ("host", "hostname", "domain", "resource", "destination", "target")
_PROXY_KEYS = ("proxy", "path", "egress", "egress_path")
_RULE_KEYS = ("rule", "rule_name", "ruleName", "matched_rule", "policy")
_REASON_KEYS = ("reason", "deny_reason", "denyReason", "detail")
_LAST_SEEN_KEYS = ("last_seen", "lastSeen", "last_seen_at", "timestamp", "time", "updated_at")
_COUNT_KEYS = ("count", "hits", "requests", "total")
_DECISION_KEYS = ("decision", "action", "verdict", "status", "result")
_CONSUMED_KEYS = frozenset(
    k.lower()
    for k in _SANDBOX_KEYS
    + _TYPE_KEYS
    + _HOST_KEYS
    + _PROXY_KEYS
    + _RULE_KEYS
    + _REASON_KEYS
    + _LAST_SEEN_KEYS
    + _COUNT_KEYS
    + _DECISION_KEYS
)

# epoch がこの値より大きければミリ秒とみなす
_EPOCH_MILLIS_THRESHOLD = 1e11


def default_native_audit_dir() -> Path:
    """OS 既定の native audit ディレクトリ。"""
    if sys.platform == "darwin":
        return Path("~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit").expanduser()
    if sys.platform.startswith("linux"):
        base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
        return Path(base).expanduser() / "sandboxes" / "sandboxes" / "auditkit"
    local = Path(os.environ.get("LOCALAPPDATA", "~")).expanduser()
    return local / "DockerSandboxes" / "sandboxes" / "logs" / "auditkit"


def native_audit_dir(cfg: DockerSandboxConfig) -> Path:
    """設定または OS 既定の native audit ディレクトリ。"""
    return cfg.native_audit_dir or default_native_audit_dir()


def native_audit_available(cfg: DockerSandboxConfig) -> bool:
    """完成済み ``.jsonl`` が 1 つ以上あれば native audit が有効とみなす。"""
    directory = native_audit_dir(cfg)
    if not directory.is_dir():
        return False
    return any(directory.glob("*.jsonl"))


def effective_mode(cfg: DockerSandboxConfig) -> str:
    """auto を解決した実効モード。"""
    if cfg.mode == "auto":
        return "native" if native_audit_available(cfg) else "policy-log"
    return cfg.mode


def as_str_dict(value: Any) -> dict[str, Any]:  # noqa: ANN401
    """JSON 由来の dict をキー str の dict にする。dict でなければ空。"""
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in cast("dict[Any, Any]", value).items()}


def first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:  # noqa: ANN401
    """候補キーのうち最初に値が入っているものを返す (大文字小文字を無視)。"""
    lowered = {str(k).lower(): v for k, v in record.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return value
    return None


def _implied_decision(text: str) -> str | None:
    lowered = text.lower()
    if "block" in lowered or "den" in lowered:
        return DECISION_DENY
    if "allow" in lowered:
        return DECISION_ALLOW
    return None


def parse_policy_log(data: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    """``sbx policy log --json`` の出力を (decision 付きの) 行リストにする。

    配列そのもの、``{"blocked": [...], "allowed": [...]}`` 形式、
    ``{"entries": [...]}`` 形式のいずれにも対応する。
    """
    if isinstance(data, list):
        return [as_str_dict(item) for item in cast("list[Any]", data) if isinstance(item, dict)]
    rows: list[dict[str, Any]] = []
    for key, value in as_str_dict(data).items():
        if not isinstance(value, list):
            continue
        implied = _implied_decision(key)
        for item in cast("list[Any]", value):
            if not isinstance(item, dict):
                continue
            row = as_str_dict(item)
            if implied and first(row, _DECISION_KEYS) is None:
                row["decision"] = implied
            rows.append(row)
    return rows


def row_decision(row: dict[str, Any]) -> str:
    """行の allow/deny を決める。明示の decision、bool フラグ、rule 名の順に見る。"""
    raw = first(row, _DECISION_KEYS)
    if isinstance(raw, bool):
        return DECISION_ALLOW if raw else DECISION_DENY
    normalized = normalize_decision(str(raw)) if raw is not None else None
    if normalized in (DECISION_ALLOW, DECISION_DENY):
        return normalized
    flags = (("blocked", DECISION_DENY), ("denied", DECISION_DENY), ("allowed", DECISION_ALLOW))
    for key, when_true in flags:
        value = row.get(key)
        if isinstance(value, bool):
            other = DECISION_ALLOW if when_true == DECISION_DENY else DECISION_DENY
            return when_true if value else other
    return _implied_decision(str(first(row, _RULE_KEYS) or "")) or DECISION_UNKNOWN


def row_key(row: dict[str, Any]) -> str:
    """集計行の識別キー (sandbox / type / host / proxy / rule / decision)。"""
    parts = [
        str(first(row, _SANDBOX_KEYS) or ""),
        str(first(row, _TYPE_KEYS) or "network"),
        str(first(row, _HOST_KEYS) or ""),
        str(first(row, _PROXY_KEYS) or ""),
        str(first(row, _RULE_KEYS) or ""),
        row_decision(row),
    ]
    return "|".join(parts)


def _int(value: Any) -> int | None:  # noqa: ANN401
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (float, str)):
        try:
            return int(float(value))
        except ValueError:
            return None
    return None


def row_timestamp(row: dict[str, Any], fallback: datetime) -> datetime:
    """last_seen を時刻にする。解釈できなければ取得時刻。"""
    value = first(row, _LAST_SEEN_KEYS)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > _EPOCH_MILLIS_THRESHOLD:
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str) and value:
        try:
            return parse_timestamp(value)
        except ValueError:
            return fallback
    return fallback


def normalize_row(
    row: dict[str, Any],
    *,
    previous_count: int | None,
    host: str,
    now: datetime,
) -> Event:
    """集計行を Event にする。"""
    decision = row_decision(row)
    sandbox = first(row, _SANDBOX_KEYS)
    remote = first(row, _HOST_KEYS)
    count = _int(first(row, _COUNT_KEYS))
    delta = None
    if count is not None:
        delta = count - previous_count if previous_count is not None else count
    extra = {k: v for k, v in row.items() if k.lower() not in _CONSUMED_KEYS}
    remote_str = str(remote) if remote is not None else None
    domain = remote_str
    if remote_str and remote_str.count(":") == 1:
        domain = remote_str.rsplit(":", 1)[0]
    sandbox_str = str(sandbox) if sandbox is not None else None
    payload: dict[str, Any] = {
        "sandbox": sandbox_str,
        "agent": _guess_agent(sandbox_str) if sandbox_str else None,
        "policy_type": str(first(row, _TYPE_KEYS) or "network"),
        "remote_host": remote_str,
        "domain": domain,
        "proxy": first(row, _PROXY_KEYS),
        "rule": first(row, _RULE_KEYS),
        "reason": first(row, _REASON_KEYS),
        "count": count,
        "count_delta": delta,
        "last_seen": first(row, _LAST_SEEN_KEYS),
        "collection_mode": "policy-log",
    }
    if extra:
        payload["extra"] = extra
    canonical = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
    return Event(
        timestamp=row_timestamp(row, now),
        source=SOURCE,
        kind="network_egress",
        host=host,
        actor=sandbox_str,
        action="connect",
        decision=decision,
        event_id="policy-log:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32],
        payload=payload,
    )


def _guess_agent(sandbox: str) -> str | None:
    """sandbox 名の先頭要素を Agent 名の推定値として返す (claude-repo なら claude)。"""
    head = sandbox.split("-", 1)[0].strip()
    return head or None


class DockerSandboxCollector:
    """Docker Sandboxes のネットワークアクセスを収集する。"""

    name = SOURCE

    def enabled(self, config: Config) -> bool:
        """設定上有効か。"""
        return config.docker_sandbox.enabled and config.docker_sandbox.mode != "disabled"

    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput:
        """実効モードに応じて policy log を収集する。native なら何もしない。"""
        cfg = ctx.config.docker_sandbox
        mode = effective_mode(cfg)
        if mode == "native":
            return CollectOutput(
                events=[],
                state=None,
                skipped=True,
                skip_reason=f"native audit JSONL を Alloy が直接読みます ({native_audit_dir(cfg)})",
            )
        result = run_command(
            [cfg.sbx_path, "policy", "log", "--json", "--limit", str(cfg.policy_log_limit)],
            timeout=cfg.timeout_seconds,
        )
        data: Any = []
        try:
            if result.stdout.strip():
                data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("sbx policy log --json の出力を JSON として解釈できません") from exc
        data = sanitize(data)
        if not ctx.dry_run:
            ctx.raw.write_json(SOURCE, "policy-log", data)
        rows = parse_policy_log(data)

        previous = as_str_dict(state.get("rows"))
        current: dict[str, Any] = {}
        events: list[Event] = []
        warnings: list[str] = []
        host = ctx.config.general.host
        for row in rows:
            key = row_key(row)
            count = _int(first(row, _COUNT_KEYS))
            last_seen = first(row, _LAST_SEEN_KEYS)
            current[key] = {"count": count, "last_seen": last_seen}
            before = as_str_dict(previous.get(key))
            previous_count: int | None = None
            if before:
                if before.get("count") == count and before.get("last_seen") == last_seen:
                    continue
                previous_count = _int(before.get("count"))
            try:
                events.append(
                    normalize_row(row, previous_count=previous_count, host=host, now=ctx.now)
                )
            except Exception as exc:  # noqa: BLE001
                # 1 行の異常で全体を止めない
                warnings.append(f"policy log 行を正規化できませんでした: {type(exc).__name__}")
        new_state = dict(state)
        new_state["rows"] = current
        new_state["mode"] = mode
        return CollectOutput(events=events, state=new_state, warnings=warnings)


def doctor_checks(config: Config) -> list[CheckResult]:
    """sbx CLI と audit モードの確認。"""
    cfg = config.docker_sandbox
    if not cfg.enabled or cfg.mode == "disabled":
        return [CheckResult.skip("Docker Sandbox", "設定で無効")]
    results: list[CheckResult] = []
    mode = effective_mode(cfg)
    directory = native_audit_dir(cfg)
    if mode == "native":
        results.append(CheckResult.ok("Docker Sandbox audit mode", f"native ({directory})"))
        results.append(CheckResult.skip("Docker / sbx CLI available", "native モードでは不要"))
        return results
    if cfg.mode == "native":
        results.append(
            CheckResult.ng(
                "Docker Sandbox audit mode",
                f"mode=native ですが {directory} に .jsonl がありません",
                "AI Governance の Local disk 配信を有効にするか"
                " mode を auto/policy-log にしてください",
            )
        )
    else:
        results.append(
            CheckResult.ok(
                "Docker Sandbox audit mode", f"policy-log (native audit JSONL なし: {directory})"
            )
        )
    path = which(cfg.sbx_path)
    if path is None:
        results.append(
            CheckResult.ng(
                "Docker / sbx CLI available",
                f"{cfg.sbx_path} が見つかりません",
                "Docker Sandboxes (sbx) をインストールするか"
                " docker_sandbox.sbx_path を設定してください",
            )
        )
        return results
    try:
        run_command(
            [cfg.sbx_path, "policy", "log", "--json", "--limit", "1"], timeout=cfg.timeout_seconds
        )
    except CommandError as exc:
        results.append(
            CheckResult.ng(
                "Docker / sbx CLI available",
                str(exc),
                "sbx ls で認証状態を確認し、必要なら sbx login を実行してください",
            )
        )
        return results
    results.append(CheckResult.ok("Docker / sbx CLI available", path))
    return results
