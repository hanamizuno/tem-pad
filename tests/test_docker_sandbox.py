"""Docker Sandboxes Collector のテスト。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import load_fixture

from tem_pad.collectors.base import CollectorContext, run_collector
from tem_pad.collectors.docker_sandbox import (
    DockerSandboxCollector,
    effective_mode,
    native_audit_available,
    normalize_row,
    parse_policy_log,
    row_decision,
)
from tem_pad.config import Config, DockerSandboxConfig
from tem_pad.procutil import CommandError, CommandResult


def test_parse_policy_log_list_and_grouped():
    rows = parse_policy_log(load_fixture("docker_sandbox", "policy_log_list.json"))
    assert [row_decision(r) for r in rows] == ["allow", "deny"]
    grouped = parse_policy_log(load_fixture("docker_sandbox", "policy_log_grouped.json"))
    assert [row_decision(r) for r in grouped] == ["deny", "allow"]
    assert parse_policy_log(None) == []
    assert parse_policy_log([1, "x"]) == []


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"decision": "ALLOW"}, "allow"),
        ({"blocked": True}, "deny"),
        ({"allowed": False}, "deny"),
        ({"rule": "domain-blocked"}, "deny"),
        ({"rule": "domain-allowed"}, "allow"),
        ({}, "unknown"),
    ],
)
def test_row_decision(row: dict[str, Any], expected: str):
    assert row_decision(row) == expected


def test_normalize_row(now: datetime):
    rows = parse_policy_log(load_fixture("docker_sandbox", "policy_log_list.json"))
    event = normalize_row(rows[1], previous_count=None, host="mac-studio", now=now)
    assert event.kind == "network_egress"
    assert event.decision == "deny"
    assert event.actor == "claude-tem-pad"
    assert event.payload["agent"] == "claude"
    assert event.payload["domain"] == "blocked.example.com"
    assert event.payload["remote_host"] == "blocked.example.com:443"
    assert event.payload["count_delta"] == 1
    assert event.timestamp == datetime(2026, 9, 6, 8, 15, 25, tzinfo=UTC)

    grouped = parse_policy_log(load_fixture("docker_sandbox", "policy_log_grouped.json"))
    epoch_event = normalize_row(grouped[0], previous_count=1, host="h", now=now)
    assert epoch_event.timestamp == datetime.fromtimestamp(1788000000, tz=UTC)
    assert epoch_event.payload["count_delta"] == 2


def test_effective_mode(tmp_path: Path):
    cfg = DockerSandboxConfig(mode="auto", native_audit_dir=tmp_path / "auditkit")
    assert native_audit_available(cfg) is False
    assert effective_mode(cfg) == "policy-log"
    (tmp_path / "auditkit").mkdir()
    (tmp_path / "auditkit" / "audit-x.tmp").write_text("{}")
    assert effective_mode(cfg) == "policy-log"  # .tmp は未完成なので無視
    (tmp_path / "auditkit" / "audit-x.jsonl").write_text("{}")
    assert effective_mode(cfg) == "native"
    cfg.mode = "policy-log"
    assert effective_mode(cfg) == "policy-log"


def test_native_mode_skips_collection(
    ctx: CollectorContext, config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    audit = tmp_path / "auditkit"
    audit.mkdir()
    (audit / "audit-1.jsonl").write_text(load_fixture("docker_sandbox", "native_audit.jsonl"))
    config.docker_sandbox.native_audit_dir = audit

    def fail(command: list[str], **kwargs: Any) -> CommandResult:
        raise AssertionError("native モードでは sbx を呼ばない")

    monkeypatch.setattr("tem_pad.collectors.docker_sandbox.run_command", fail)
    result = run_collector(DockerSandboxCollector(), ctx)
    assert result.skipped
    assert "Alloy" in (result.skip_reason or "")


def test_policy_log_diff_across_runs(
    ctx: CollectorContext, config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config.docker_sandbox.native_audit_dir = tmp_path / "none"
    rows = load_fixture("docker_sandbox", "policy_log_list.json")
    payloads = {"data": json.dumps(rows)}
    calls: list[list[str]] = []

    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        calls.append(list(command))
        return CommandResult(stdout=payloads["data"], stderr="", returncode=0)

    monkeypatch.setattr("tem_pad.collectors.docker_sandbox.run_command", fake)
    collector = DockerSandboxCollector()
    first = run_collector(collector, ctx)
    assert first.ok
    assert first.written == 2
    assert calls[0][1:4] == ["policy", "log", "--json"]

    # 変化なし → イベントなし
    second = run_collector(collector, ctx)
    assert second.written == 0
    assert second.fetched == 0

    # count が増えた行だけイベント化され、増分が載る
    rows[0]["count"] = 50
    rows[0]["last_seen"] = "2026-09-06T08:20:00Z"
    payloads["data"] = json.dumps(rows)
    third = run_collector(collector, ctx)
    assert third.written == 1
    lines = (config.events_dir / "docker-sandbox.jsonl").read_text().splitlines()
    last = json.loads(lines[-1])
    assert last["payload"]["count_delta"] == 8
    assert last["decision"] == "allow"


def test_policy_log_invalid_json(
    ctx: CollectorContext, config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config.docker_sandbox.native_audit_dir = tmp_path / "none"

    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        return CommandResult(stdout="not json", stderr="", returncode=0)

    monkeypatch.setattr("tem_pad.collectors.docker_sandbox.run_command", fake)
    result = run_collector(DockerSandboxCollector(), ctx)
    assert not result.ok
    assert "JSON" in (result.error or "")


def test_policy_log_command_failure(
    ctx: CollectorContext, config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config.docker_sandbox.native_audit_dir = tmp_path / "none"

    def fake(command: list[str], **kwargs: Any) -> CommandResult:
        raise CommandError(command, "sbx: not logged in", returncode=1)

    monkeypatch.setattr("tem_pad.collectors.docker_sandbox.run_command", fake)
    result = run_collector(DockerSandboxCollector(), ctx)
    assert not result.ok


def test_disabled_mode(ctx: CollectorContext, config: Config):
    config.docker_sandbox.mode = "disabled"
    assert run_collector(DockerSandboxCollector(), ctx).skipped
