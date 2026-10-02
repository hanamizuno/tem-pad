"""Event モデルと時刻処理のテスト。"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from tem_pad.models import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_UNKNOWN,
    Event,
    format_timestamp,
    normalize_decision,
    parse_timestamp,
)


def test_format_timestamp_uses_z_suffix():
    value = datetime(2026, 9, 6, 8, 0, tzinfo=UTC)
    assert format_timestamp(value) == "2026-09-06T08:00:00Z"


def test_format_timestamp_keeps_microseconds():
    value = datetime(2026, 9, 6, 8, 0, 0, 123456, tzinfo=UTC)
    assert format_timestamp(value) == "2026-09-06T08:00:00.123456Z"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-09-06T08:00:00Z", datetime(2026, 9, 6, 8, 0, tzinfo=UTC)),
        ("2026-09-06T08:00:00+00:00", datetime(2026, 9, 6, 8, 0, tzinfo=UTC)),
        ("2026-09-06T17:00:00+09:00", datetime(2026, 9, 6, 8, 0, tzinfo=UTC)),
        ("2026-09-06T08:00:00.123456789Z", datetime(2026, 9, 6, 8, 0, 0, 123456, tzinfo=UTC)),
        ("2026-09-06T08:00:00", datetime(2026, 9, 6, 8, 0, tzinfo=UTC)),
    ],
)
def test_parse_timestamp(text: str, expected: datetime):
    assert parse_timestamp(text) == expected


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ValueError, match=r"Invalid isoformat|invalid"):
        parse_timestamp("not a timestamp")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("allow", DECISION_ALLOW),
        ("ALLOWED", DECISION_ALLOW),
        ("AUDIT_DECISION_DENY", DECISION_DENY),
        ("blocked", DECISION_DENY),
        ("weird", DECISION_UNKNOWN),
        ("", None),
        (None, None),
    ],
)
def test_normalize_decision(value: str | None, expected: str | None):
    assert normalize_decision(value) == expected


def test_event_roundtrip():
    event = Event(
        timestamp=datetime(2026, 9, 6, 8, 0, tzinfo=UTC),
        source="docker-sandbox",
        kind="network_egress",
        host="mac-studio",
        actor="claude",
        action="connect",
        decision="allow",
        event_id="abc",
        payload={"domain": "example.com", "port": 443},
    )
    line = event.to_json()
    assert "\n" not in line
    data = json.loads(line)
    assert list(data)[:3] == ["timestamp", "source", "kind"]
    restored = Event.from_dict(data)
    assert restored == event


def test_event_from_dict_tolerates_missing_optional_fields():
    event = Event.from_dict({"timestamp": "2026-09-06T08:00:00Z", "source": "x"})
    assert event.kind == "unknown"
    assert event.payload == {}
    assert event.decision is None
