"""Tailscale Collector のテスト (API はスタブ化)。"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from tests.conftest import load_fixture

from tem_pad.collectors.base import CollectorContext, run_collector
from tem_pad.collectors.tailscale import (
    TailscaleClient,
    TailscaleCollector,
    audit_kind,
    device_snapshot,
    diff_devices,
    normalize_audit_entry,
)
from tem_pad.config import Config


def test_normalize_audit_entries(now: datetime):
    logs = load_fixture("tailscale", "audit_logs.json")["logs"]
    events = [normalize_audit_entry(entry, "mac-studio", now) for entry in logs]

    node_update = events[0]
    assert node_update.kind == "audit_device"
    assert node_update.actor == "alice@example.com"
    assert node_update.action == "UPDATE"
    assert node_update.payload["target_property"] == "KEY_EXPIRY_TIME"
    assert node_update.timestamp == datetime(2026, 9, 6, 8, 0, 0, 123456, tzinfo=UTC)

    assert events[1].kind == "audit_policy"
    assert events[2].kind == "audit_key"
    assert events[2].actor == "ci-oauth-client"
    assert events[2].payload["extra"] == {"someNewField": {"nested": True}}

    unknown = events[3]
    assert unknown.kind == "audit_other"  # target なし・action あり
    assert unknown.timestamp == now  # 壊れた時刻は取得時刻で代用する
    assert unknown.event_id is not None

    ids = {event.event_id for event in events}
    assert len(ids) == len(events)


def test_audit_kind_unknown_without_action_and_target():
    assert audit_kind({}) == "unknown"
    assert audit_kind({"target": {"type": "WHATEVER"}}) == "audit_other"


def test_diff_devices(now: datetime):
    before = device_snapshot(load_fixture("tailscale", "devices_before.json")["devices"])
    after = device_snapshot(load_fixture("tailscale", "devices_after.json")["devices"])
    events = diff_devices(before, after, host="mac-studio", now=now)
    by_kind = {event.kind: event for event in events}
    assert set(by_kind) == {"device_added", "device_removed", "device_changed"}
    added = by_kind["device_added"]
    assert added.payload["device_name"] == "unknown-phone.tail1234.ts.net"
    assert added.payload["authorized"] is False
    assert added.actor == "mallory@example.com"
    changed = by_kind["device_changed"]
    assert set(changed.payload["changes"]) == {"keyExpiryDisabled"}
    assert by_kind["device_removed"].payload["hostname"] == "old-laptop"
    # 差分イベントの ID は決定的 (同じ差分なら同じ ID)
    again = diff_devices(before, after, host="mac-studio", now=now + timedelta(hours=1))
    assert sorted(e.event_id or "" for e in again) == sorted(e.event_id or "" for e in events)
    assert all(e.event_id and e.event_id.startswith("device:") for e in events)


def test_diff_devices_ignores_volatile_fields(now: datetime):
    before = device_snapshot(load_fixture("tailscale", "devices_before.json")["devices"])
    after = device_snapshot(load_fixture("tailscale", "devices_before.json")["devices"])
    # lastSeen / updateAvailable は比較対象外なので差分なし
    assert diff_devices(before, after, host="h", now=now) == []


class _StubClient:
    def __init__(self, audit: list[dict[str, Any]], devices: list[dict[str, Any]]) -> None:
        self.audit = audit
        self.devices_data = devices
        self.calls: list[tuple[str, Any]] = []

    def configuration_audit_logs(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        self.calls.append(("audit", (start, end)))
        return self.audit

    def devices(self) -> list[dict[str, Any]]:
        self.calls.append(("devices", None))
        return self.devices_data


def _patch_client(monkeypatch: pytest.MonkeyPatch, stub: _StubClient) -> None:
    def factory(_config: Config) -> _StubClient:
        return stub

    monkeypatch.setattr("tem_pad.collectors.tailscale.TailscaleClient", factory)


def test_collector_end_to_end_with_dedupe(
    ctx: CollectorContext, config: Config, monkeypatch: pytest.MonkeyPatch
):
    logs = load_fixture("tailscale", "audit_logs.json")["logs"]
    devices_before = load_fixture("tailscale", "devices_before.json")["devices"]
    devices_after = load_fixture("tailscale", "devices_after.json")["devices"]
    stub = _StubClient(logs, devices_before)
    _patch_client(monkeypatch, stub)
    collector = TailscaleCollector()

    first = run_collector(collector, ctx)
    assert first.ok
    assert first.fetched == 4  # 初回は device 差分なし
    assert first.written == 4
    assert any("初回取得" in w for w in first.warnings)
    state = ctx.states.load("tailscale")
    assert "audit_cursor" in state
    assert len(state["devices"]) == 2
    raw_files = list((config.raw_dir / "tailscale").iterdir())
    assert len(raw_files) == 2

    # 2 回目: 同じ監査ログ (overlap) と device の変化。devices_interval は経過済みとみなす
    ctx.now = ctx.now + timedelta(minutes=15)
    stub.devices_data = devices_after
    second = run_collector(collector, ctx)
    assert second.ok
    assert second.duplicates == 4
    assert second.written == 3
    kinds = [
        json.loads(line)["kind"]
        for line in (config.events_dir / "tailscale.jsonl").read_text().splitlines()
    ]
    assert kinds.count("device_added") == 1
    assert kinds.count("device_removed") == 1
    assert kinds.count("device_changed") == 1

    # overlap window は state の cursor から計算される
    start, end = stub.calls[-2][1]
    assert end == ctx.now
    assert (ctx.now - timedelta(minutes=15) - start).total_seconds() == 60


def test_devices_fetch_is_throttled(ctx: CollectorContext, monkeypatch: pytest.MonkeyPatch):
    stub = _StubClient([], [])
    _patch_client(monkeypatch, stub)
    collector = TailscaleCollector()
    run_collector(collector, ctx)
    ctx.now = ctx.now + timedelta(minutes=2)
    run_collector(collector, ctx)
    assert [name for name, _ in stub.calls].count("devices") == 1


def test_collector_error_is_contained(ctx: CollectorContext, monkeypatch: pytest.MonkeyPatch):
    class Boom:
        def configuration_audit_logs(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
            raise RuntimeError("api down")

        def devices(self) -> list[dict[str, Any]]:
            return []

    def factory(_config: Config) -> Boom:
        return Boom()

    monkeypatch.setattr("tem_pad.collectors.tailscale.TailscaleClient", factory)
    result = run_collector(TailscaleCollector(), ctx)
    assert not result.ok
    assert "api down" in (result.error or "")
    assert ctx.states.load("tailscale") == {}  # 失敗時は state を進めない


def test_client_requires_credentials(config: Config, monkeypatch: pytest.MonkeyPatch):
    for name in ("TAILSCALE_OAUTH_CLIENT_ID", "TAILSCALE_OAUTH_CLIENT_SECRET", "TAILSCALE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    client = TailscaleClient(config)
    with pytest.raises(Exception, match="認証情報がありません"):
        client.devices()


def test_client_oauth_exchange(config: Config, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TAILSCALE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("TAILSCALE_OAUTH_CLIENT_SECRET", "csecret")
    seen: list[dict[str, Any]] = []

    class Resp:
        status = 200

        def __init__(self, payload: Any) -> None:
            self._payload = payload

        def json(self) -> Any:
            return self._payload

    def fake_request(url: str, **kwargs: Any) -> Resp:
        seen.append({"url": url, **kwargs})
        if url.endswith("/oauth/token"):
            assert b"client_secret=csecret" in kwargs["data"]
            return Resp({"access_token": "tok123", "expires_in": 3600})
        assert kwargs["headers"]["Authorization"] == "Bearer tok123"
        return Resp({"devices": [{"nodeId": "n1"}]})

    monkeypatch.setattr("tem_pad.collectors.tailscale.request", fake_request)
    client = TailscaleClient(config)
    assert client.devices() == [{"nodeId": "n1"}]
    assert "fields=all" in seen[1]["url"]
    # client secret は URL に含めない
    assert "csecret" not in seen[1]["url"]


def test_audit_entry_secret_values_are_redacted(now: datetime):
    entry = {
        "eventGroupID": "g",
        "actor": {"loginName": "alice@example.com"},
        "target": {"type": "AUTH_KEY", "name": "key"},
        "action": "CREATE",
        "old": "",
        "new": "tskey-auth-kSECRET123456-abcdef",
        "eventTime": "2026-09-06T08:00:00Z",
        "clientSecret": "must-not-appear",
    }
    event = normalize_audit_entry(entry, "h", now)
    text = event.to_json()
    assert "kSECRET123456" not in text
    assert "must-not-appear" not in text
    assert event.payload["new"] == "tskey-<redacted>"


def test_crash_between_append_and_state_save_does_not_duplicate(
    ctx: CollectorContext, config: Config, monkeypatch: pytest.MonkeyPatch
):
    logs = load_fixture("tailscale", "audit_logs.json")["logs"]
    before = load_fixture("tailscale", "devices_before.json")["devices"]
    after = load_fixture("tailscale", "devices_after.json")["devices"]
    stub = _StubClient(logs, before)

    def factory(_config: Config) -> _StubClient:
        return stub

    monkeypatch.setattr("tem_pad.collectors.tailscale.TailscaleClient", factory)
    collector = TailscaleCollector()
    run_collector(collector, ctx)
    saved_state = ctx.states.load("tailscale")

    # 2 回目: device 差分を書いた後、state の保存に失敗したとみなして state を巻き戻す
    ctx.now = ctx.now + timedelta(minutes=15)
    stub.devices_data = after
    second = run_collector(collector, ctx)
    assert second.written == 3
    ctx.states.save("tailscale", saved_state)

    # 3 回目: 同じ差分を再計算するが、JSONL 末尾の ID から既読を復元するので何も書かない
    third = run_collector(collector, ctx)
    assert third.written == 0
    assert third.duplicates == 3 + 4
    lines = (config.events_dir / "tailscale.jsonl").read_text().splitlines()
    assert len(lines) == 4 + 3
