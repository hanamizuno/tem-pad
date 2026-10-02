"""Little Snitch Collector のテスト (CLI はスタブ化)。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import load_fixture

from tem_pad.collectors.base import CollectorContext, run_collector
from tem_pad.collectors.little_snitch import (
    SETTLE_SECONDS,
    LittleSnitchCollector,
    build_command,
    normalize_row,
    parse_csv,
    window,
)
from tem_pad.config import Config, LittleSnitchConfig
from tem_pad.procutil import CommandError, CommandResult


def test_parse_csv_and_normalize(now: datetime):
    rows = parse_csv(load_fixture("little_snitch", "log_traffic.csv"))
    assert len(rows) == 4
    events = [normalize_row(row, host="mac-studio", fallback=now) for row in rows]

    allowed = events[0]
    assert allowed.kind == "connection"
    assert allowed.decision == "allow"
    assert allowed.actor == "com.docker.backend"
    assert allowed.payload["remote_host"] == "api.anthropic.com"
    assert allowed.payload["protocol"] == "tcp"
    assert allowed.payload["port"] == 443
    assert allowed.payload["bytes_in"] == 12000
    assert allowed.payload["parent_app"].endswith("Docker Desktop")
    assert allowed.timestamp == datetime(2026, 9, 6, 8, 0, tzinfo=UTC)

    denied = events[1]
    assert denied.kind == "connection_denied"
    assert denied.decision == "deny"
    assert denied.payload["deny_count"] == 2

    inbound = events[2]
    assert inbound.action == "accept"
    assert inbound.payload["protocol"] == "udp"
    assert inbound.payload["remote_host"] is None

    broken = events[3]
    assert broken.timestamp == now
    assert broken.actor is None

    assert len({e.event_id for e in events}) == 4


def test_parse_csv_empty():
    assert parse_csv("") == []
    assert parse_csv("\n\n") == []


def test_parse_csv_unknown_columns():
    text = "date,foo,remoteHostname\n2026-09-06T08:00:00Z,bar,x.example\n"
    event = normalize_row(parse_csv(text)[0], host="h", fallback=datetime.now(tz=UTC))
    assert event.payload["remote_host"] == "x.example"
    assert event.payload["extra"] == {"foo": "bar"}


def test_build_command_with_and_without_sudo():
    begin = datetime(2026, 9, 6, 8, 0, tzinfo=UTC)
    end = begin + timedelta(minutes=1)
    cfg = LittleSnitchConfig(use_sudo=True, cli_path="/x/littlesnitch")
    command = build_command(cfg, begin, end)
    assert command[:2] == ["sudo", "-n"]
    assert command[2:4] == ["/x/littlesnitch", "log-traffic"]
    assert "--begin-date" in command
    assert "--end-date" in command
    cfg.use_sudo = False
    assert build_command(cfg, begin, end)[0] == "/x/littlesnitch"


def test_window_initial_and_incremental(now: datetime):
    cfg = LittleSnitchConfig(overlap_seconds=60, initial_lookback_minutes=30)
    begin, end = window({}, now, cfg)
    assert end == now - timedelta(seconds=SETTLE_SECONDS)
    assert begin == end - timedelta(minutes=30)
    cursor = (now - timedelta(minutes=5)).isoformat()
    begin, end = window({"cursor": cursor}, now, cfg)
    assert begin == now - timedelta(minutes=6)
    # 壊れた cursor は初回扱い
    begin, _ = window({"cursor": "garbage"}, now, cfg)
    assert begin == end - timedelta(minutes=30)
    # 長期停止後は 24 時間で打ち切り
    old = (now - timedelta(days=10)).isoformat()
    begin, end = window({"cursor": old}, now, cfg)
    assert begin == end - timedelta(hours=24)


def test_collector_end_to_end(
    ctx: CollectorContext, config: Config, monkeypatch: pytest.MonkeyPatch
):
    csv_text = load_fixture("little_snitch", "log_traffic.csv")
    calls: list[list[str]] = []

    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        calls.append(list(command))
        return CommandResult(stdout=csv_text, stderr="", returncode=0)

    monkeypatch.setattr("tem_pad.collectors.little_snitch.run_command", fake)
    result = run_collector(LittleSnitchCollector(), ctx)
    assert result.ok
    assert result.written == 4
    assert calls[0][0] == config.little_snitch.cli_path  # use_sudo=False (conftest)
    state = ctx.states.load("little-snitch")
    assert "cursor" in state
    raw = list((config.raw_dir / "little-snitch").glob("*.csv"))
    assert len(raw) == 1

    # overlap 再取得は重複として捨てられる
    ctx.now = ctx.now + timedelta(minutes=1)
    second = run_collector(LittleSnitchCollector(), ctx)
    assert second.written == 0
    assert second.duplicates == 4


def test_collector_permission_error(ctx: CollectorContext, monkeypatch: pytest.MonkeyPatch):
    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        raise CommandError(command, "sudo: a password is required", returncode=1)

    monkeypatch.setattr("tem_pad.collectors.little_snitch.run_command", fake)
    result = run_collector(LittleSnitchCollector(), ctx)
    assert not result.ok
    assert "password is required" in (result.error or "")
    assert not (ctx.config.events_dir / "little-snitch.jsonl").exists()


def test_disabled_collector_is_skipped(ctx: CollectorContext, config: Config, tmp_path: Path):
    config.little_snitch.enabled = False
    result = run_collector(LittleSnitchCollector(), ctx)
    assert result.skipped
