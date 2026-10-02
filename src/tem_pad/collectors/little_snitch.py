"""Little Snitch Collector。

``littlesnitch log-traffic --begin-date ... --end-date ...`` の CSV 出力を
poll 方式で取得し、1 行 = 1 イベントにする。Little Snitch の CLI は
多くの操作で root を要求するため、既定では ``sudo -n`` 経由で呼ぶ。
sudoers には ``littlesnitch log-traffic *`` だけを許可する
(docs/setup.md)。tem-pad 自体は root で動かさない。

CSV のカラム名は Little Snitch 5/6 で公開されているもの (date, direction,
uid, ipAddress, remoteHostname, protocol, port, connectCount, denyCount,
byteCountIn, byteCountOut, connectingExecutable, parentAppExecutable) を
基準にし、ヘッダ行から動的に読むので順序変更や追加カラムには耐える。
"""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from tem_pad.checks import CheckResult
from tem_pad.collectors.base import CollectorContext, CollectOutput
from tem_pad.config import Config, LittleSnitchConfig
from tem_pad.models import DECISION_ALLOW, DECISION_DENY, Event, parse_timestamp
from tem_pad.procutil import CommandError, run_command, which
from tem_pad.sanitize import redact_text

SOURCE = "little-snitch"

# 集計中の直近区間を避けるため、終端は現在時刻より少し前にする
SETTLE_SECONDS = 90

_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}

# ヘッダ名の候補。小文字に揃えて比較する
_COLUMNS: dict[str, tuple[str, ...]] = {
    "date": ("date", "timestamp", "time", "start"),
    "direction": ("direction",),
    "uid": ("uid", "userid"),
    "remote_ip": ("ipaddress", "remoteip", "remoteaddress", "ip"),
    "remote_host": ("remotehostname", "hostname", "remotehost", "host"),
    "protocol": ("protocol", "proto"),
    "port": ("port", "remoteport"),
    "connect_count": ("connectcount", "connections", "allowcount"),
    "deny_count": ("denycount", "denied"),
    "bytes_in": ("bytecountin", "bytesin", "bytesreceived", "rxbytes"),
    "bytes_out": ("bytecountout", "bytesout", "bytessent", "txbytes"),
    "executable": ("connectingexecutable", "executable", "process", "path"),
    "parent_app": ("parentappexecutable", "parentapp", "parent"),
}


def build_command(cfg: LittleSnitchConfig, begin: datetime, end: datetime) -> list[str]:
    """log-traffic コマンドを組み立てる。日時はローカル時刻で渡す。"""
    command: list[str] = []
    if cfg.use_sudo:
        command.extend(["sudo", "-n"])
    command.extend(
        [
            cfg.cli_path,
            "log-traffic",
            "--begin-date",
            _local_string(begin),
            "--end-date",
            _local_string(end),
        ]
    )
    return command


def _local_string(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def parse_csv(text: str) -> list[dict[str, str]]:
    """CSV をヘッダ名付きの行 dict にする。空出力は空リスト。"""
    stripped = text.strip()
    if not stripped:
        return []
    reader = csv.DictReader(io.StringIO(stripped))
    return [
        {str(k).strip(): (v or "").strip() for k, v in row.items() if k is not None}
        for row in reader
    ]


def _column(row: dict[str, str], key: str) -> str | None:
    lowered = {name.lower(): value for name, value in row.items()}
    for candidate in _COLUMNS[key]:
        if candidate in lowered and lowered[candidate] != "":
            return lowered[candidate]
    return None


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def row_event_id(row: dict[str, str]) -> str:
    """行全体のハッシュ。overlap で同じ行を再取得しても重複排除できる。"""
    canonical = "\x1f".join(f"{k}={row[k]}" for k in sorted(row))
    return "ls:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def normalize_row(row: dict[str, str], *, host: str, fallback: datetime) -> Event:
    """CSV 1 行を Event にする。"""
    date_raw = _column(row, "date")
    timestamp = fallback
    if date_raw:
        try:
            timestamp = parse_timestamp(date_raw)
        except ValueError:
            timestamp = fallback
    executable = _column(row, "executable")
    process_name = Path(executable).name if executable else None
    connect_count = _int_or_none(_column(row, "connect_count"))
    deny_count = _int_or_none(_column(row, "deny_count"))
    if deny_count and deny_count > 0:
        decision = DECISION_DENY
        kind = "connection_denied"
    else:
        decision = DECISION_ALLOW
        kind = "connection"
    protocol_raw = _column(row, "protocol")
    protocol_name = _PROTOCOLS.get(
        protocol_raw or "", protocol_raw.lower() if protocol_raw else None
    )
    direction = (_column(row, "direction") or "").lower() or None

    known = {name for names in _COLUMNS.values() for name in names}
    extra = {k: v for k, v in row.items() if k.lower() not in known and v != ""}
    payload: dict[str, Any] = {
        "direction": direction,
        "uid": _int_or_none(_column(row, "uid")),
        "remote_ip": _column(row, "remote_ip"),
        "remote_host": _column(row, "remote_host"),
        "protocol": protocol_name,
        "protocol_number": _int_or_none(protocol_raw),
        "port": _int_or_none(_column(row, "port")),
        "connect_count": connect_count,
        "deny_count": deny_count,
        "bytes_in": _int_or_none(_column(row, "bytes_in")),
        "bytes_out": _int_or_none(_column(row, "bytes_out")),
        "executable": executable,
        "process": process_name,
        "parent_app": _column(row, "parent_app"),
    }
    if extra:
        payload["extra"] = extra
    return Event(
        timestamp=timestamp,
        source=SOURCE,
        kind=kind,
        host=host,
        actor=process_name,
        action="connect" if direction != "in" else "accept",
        decision=decision,
        event_id=row_event_id(row),
        payload=payload,
    )


def window(
    state: dict[str, Any], now: datetime, cfg: LittleSnitchConfig
) -> tuple[datetime, datetime]:
    """今回取得する区間 (begin, end) を決める。"""
    end = now - timedelta(seconds=SETTLE_SECONDS)
    cursor = state.get("cursor")
    begin: datetime | None = None
    if isinstance(cursor, str) and cursor:
        try:
            begin = parse_timestamp(cursor) - timedelta(seconds=cfg.overlap_seconds)
        except ValueError:
            begin = None
    if begin is None:
        begin = end - timedelta(minutes=cfg.initial_lookback_minutes)
    # 長期停止後に巨大な区間を取らないよう 24 時間で打ち切る
    begin = max(begin, end - timedelta(hours=24))
    return begin, end


class LittleSnitchCollector:
    """Little Snitch の通信履歴を poll 方式で収集する。"""

    name = SOURCE

    def enabled(self, config: Config) -> bool:
        """設定上有効か。"""
        return config.little_snitch.enabled

    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput:
        """前回終端から現在 (少し手前) までの通信履歴を取得する。"""
        cfg = ctx.config.little_snitch
        begin, end = window(state, ctx.now, cfg)
        if end <= begin:
            return CollectOutput(
                events=[],
                state=None,
                skipped=True,
                skip_reason="取得区間がまだありません",
            )
        command = build_command(cfg, begin, end)
        result = run_command(command, timeout=cfg.timeout_seconds)
        csv_text = redact_text(result.stdout)
        if not ctx.dry_run:
            ctx.raw.write_text(SOURCE, "log-traffic", csv_text, ext="csv")
        rows = parse_csv(csv_text)
        events: list[Event] = []
        warnings: list[str] = []
        for row in rows:
            try:
                events.append(normalize_row(row, host=ctx.config.general.host, fallback=end))
            except Exception as exc:  # noqa: BLE001  (1 行の異常で全体を止めない)
                warnings.append(f"CSV 行を正規化できませんでした: {type(exc).__name__}")
        new_state = dict(state)
        new_state["cursor"] = end.astimezone(UTC).isoformat()
        return CollectOutput(events=events, state=new_state, warnings=warnings)


def doctor_checks(config: Config) -> list[CheckResult]:
    """Little Snitch CLI と権限の確認。"""
    cfg = config.little_snitch
    if not cfg.enabled:
        return [CheckResult.skip("Little Snitch", "設定で無効")]
    results: list[CheckResult] = []
    path = which(cfg.cli_path)
    if path is None:
        results.append(
            CheckResult.ng(
                "Little Snitch CLI installed",
                f"{cfg.cli_path} が見つかりません",
                "Little Snitch 6 をインストールし、little_snitch.cli_path を確認してください",
            )
        )
        results.append(CheckResult.skip("Little Snitch access available", "CLI がないため未確認"))
        return results
    results.append(CheckResult.ok("Little Snitch CLI installed", path))
    now = datetime.now(tz=UTC)
    command = build_command(cfg, now - timedelta(minutes=1), now)
    try:
        run_command(command, timeout=cfg.timeout_seconds)
    except CommandError as exc:
        hint = "Little Snitch の設定で「ターミナルからのアクセスを許可」を有効にしてください"
        if cfg.use_sudo:
            hint = (
                "sudoers に littlesnitch log-traffic の NOPASSWD 許可を追加してください"
                " (docs/setup.md)。加えて Little Snitch 側で CLI アクセスを許可する必要があります"
            )
        results.append(CheckResult.ng("Little Snitch access available", str(exc), hint))
        return results
    results.append(CheckResult.ok("Little Snitch access available", "log-traffic OK"))
    return results
