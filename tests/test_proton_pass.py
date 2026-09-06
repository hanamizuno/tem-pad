"""Proton Pass Collector のテスト (pass-cli はスタブ化)。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.conftest import load_fixture

from tem_pad.collectors.base import CollectorContext, run_collector
from tem_pad.collectors.proton_pass import (
    ProtonPassCollector,
    normalize_record,
    parse_agents,
    parse_json_output,
    parse_monitor_records,
    redact,
    strip_secret_keys,
)
from tem_pad.config import Config, ProtonPassConfig
from tem_pad.procutil import CommandError, CommandResult


def test_parse_agents_variants():
    data = load_fixture("proton_pass", "agent_list.json")
    agents = parse_agents(data)
    assert [a["name"] for a in agents] == ["claude-dev", "codex-ci"]
    assert agents[0]["id"] == "pat_abc123"
    assert parse_agents({"agents": data}) == agents
    assert parse_agents(["plain-name"])[0]["name"] == "plain-name"
    assert parse_agents(None) == []
    assert parse_agents([{"no": "name"}]) == []


def test_parse_json_output_tolerates_noise():
    assert parse_json_output("warning: update available\n[1, 2]") == [1, 2]
    assert parse_json_output("") is None
    with pytest.raises(ValueError, match="JSON"):
        parse_json_output("nothing here")


def test_strip_secret_keys_recursive():
    data = {"item": "x", "Password": "p", "nested": [{"token": "t", "ok": 1}]}
    assert strip_secret_keys(data) == {"item": "x", "nested": [{"ok": 1}]}


def test_redact_modes():
    assert redact("vault", "plain") == "vault"
    assert redact("vault", "drop") is None
    hashed = redact("vault", "hash")
    assert hashed is not None
    assert hashed.startswith("sha256:")
    assert redact(None, "hash") is None


def test_normalize_records(now: datetime):
    cfg = ProtonPassConfig()
    agent = {"name": "claude-dev", "id": "pat_abc123"}
    records = parse_monitor_records(load_fixture("proton_pass", "agent_monitor.json"))
    events = [normalize_record(agent, r, host="h", now=now, cfg=cfg) for r in records]

    read = events[0]
    assert read.kind == "agent_read"
    assert read.actor == "claude-dev"
    assert read.action == "ItemRead"
    assert read.payload["vault"] == "agents-tem-pad"
    assert read.payload["vault_id"] == "share_xyz"
    assert read.payload["item_id"] == "item_xyz"
    assert read.timestamp == datetime.fromtimestamp(1788000000, tz=UTC)
    assert read.event_id == "claude-dev:record_001"

    write = events[1]
    assert write.kind == "agent_write"
    assert write.payload["reason_missing"] is True
    assert write.timestamp == datetime(2026, 9, 6, 8, 30, tzinfo=UTC)

    leaky = events[2]
    assert "password" not in json.dumps(leaky.to_dict()).lower()
    assert "MUST-NOT-BE-STORED" not in leaky.to_json()
    assert leaky.timestamp == datetime.fromtimestamp(1788000100, tz=UTC)  # ミリ秒を秒へ

    weird = events[3]
    assert weird.kind == "unknown"
    assert weird.timestamp == now
    assert weird.event_id is not None
    assert weird.event_id.startswith("claude-dev:sha256:")


def test_normalize_hash_mode(now: datetime):
    cfg = ProtonPassConfig(redact_mode="hash")
    record = {"record_id": "r", "action": "ItemRead", "vault": "V", "item": "I", "reason": "R"}
    event = normalize_record({"name": "a", "id": None}, record, host="h", now=now, cfg=cfg)
    for key in ("vault", "item", "reason"):
        assert str(event.payload[key]).startswith("sha256:")
    assert "V" not in event.to_json().replace("sha256", "")


def _stub_run_command(responses: dict[str, str], failures: set[str] | None = None):
    calls: list[list[str]] = []

    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        calls.append(list(command))
        key = " ".join(command[1:3])
        if failures and command[3] in failures if len(command) > 3 else False:
            raise CommandError(command, "boom", returncode=1)
        stdout = responses.get(key)
        if stdout is None:
            raise CommandError(command, "unexpected command")
        return CommandResult(stdout=stdout, stderr="", returncode=0)

    return fake, calls


def test_collector_end_to_end(
    ctx: CollectorContext, config: Config, monkeypatch: pytest.MonkeyPatch
):
    agents = json.dumps(load_fixture("proton_pass", "agent_list.json"))
    monitor = json.dumps(load_fixture("proton_pass", "agent_monitor.json"))
    fake, calls = _stub_run_command({"agent list": agents, "agent monitor": monitor})
    monkeypatch.setattr("tem_pad.collectors.proton_pass.run_command", fake)

    result = run_collector(ProtonPassCollector(), ctx)
    assert result.ok
    assert result.fetched == 8  # 2 agents x 4 records
    assert result.written == 8
    assert calls[1][:4] == [config.proton_pass.cli_path, "agent", "monitor", "claude-dev"]
    assert "--limit" in calls[1]
    for cmd in calls:
        joined = " ".join(cmd)
        assert "PROTON_PASS_PERSONAL_ACCESS_TOKEN" not in joined

    # raw に secret が漏れていない
    raw_dir = config.raw_dir / "proton-pass"
    assert not any("MUST-NOT-BE-STORED" in p.read_text() for p in raw_dir.iterdir())

    # 2 回目は全件重複
    second = run_collector(ProtonPassCollector(), ctx)
    assert second.written == 0
    assert second.duplicates == 8
    state = ctx.states.load("proton-pass")
    assert state["agents"]["claude-dev"]["last_record_id"] == "record_001"


def test_collector_agent_filter_and_partial_failure(
    ctx: CollectorContext, config: Config, monkeypatch: pytest.MonkeyPatch
):
    config.proton_pass.agents = ["codex-ci"]
    agents = json.dumps(load_fixture("proton_pass", "agent_list.json"))
    fake, calls = _stub_run_command({"agent list": agents}, failures={"codex-ci"})
    monkeypatch.setattr("tem_pad.collectors.proton_pass.run_command", fake)
    result = run_collector(ProtonPassCollector(), ctx)
    assert result.ok  # monitor の失敗は warning に留める
    assert result.written == 0
    assert any("codex-ci" in w for w in result.warnings)
    assert len(calls) == 2


def test_collector_list_failure(ctx: CollectorContext, monkeypatch: pytest.MonkeyPatch):
    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        raise CommandError(command, "not logged in", returncode=1)

    monkeypatch.setattr("tem_pad.collectors.proton_pass.run_command", fake)
    result = run_collector(ProtonPassCollector(), ctx)
    assert not result.ok
    assert "not logged in" in (result.error or "")
