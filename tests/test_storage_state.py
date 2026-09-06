"""JSONL ストア・raw ストア・state のテスト。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from tem_pad.models import Event
from tem_pad.state import SeenIds, StateStore
from tem_pad.storage import EventStore, RawStore, atomic_write_text, safe_name


def _event(source: str, ts: int, event_id: str | None = None) -> Event:
    return Event(
        timestamp=datetime(2026, 9, 6, 8, ts, tzinfo=UTC),
        source=source,
        kind="k",
        event_id=event_id,
    )


def test_event_store_appends_sorted_per_source(tmp_path: Path):
    store = EventStore(tmp_path / "events")
    written = store.append([_event("b", 5), _event("a", 3), _event("a", 1)])
    assert written == 3
    assert sorted(store.list_sources()) == ["a", "b"]
    lines = (tmp_path / "events" / "a.jsonl").read_text().splitlines()
    assert [json.loads(line)["timestamp"] for line in lines] == [
        "2026-09-06T08:01:00Z",
        "2026-09-06T08:03:00Z",
    ]


def test_event_store_iter_skips_broken_lines(tmp_path: Path):
    store = EventStore(tmp_path / "events")
    store.append([_event("a", 1)])
    path = store.path_for("a")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("this is not json\n")
        handle.write('{"source": "a"}\n')  # timestamp 欠落
        handle.write("\n")
    events = list(store.iter_events("a"))
    assert len(events) == 1


def test_event_store_iter_missing_source(tmp_path: Path):
    store = EventStore(tmp_path / "events")
    assert list(store.iter_events("nope")) == []


def test_raw_store_writes_unique_files(tmp_path: Path):
    raw = RawStore(tmp_path / "raw")
    first = raw.write_json("tailscale", "audit", {"a": 1})
    second = raw.write_json("tailscale", "audit", {"a": 2})
    assert first != second
    assert first.parent == tmp_path / "raw" / "tailscale"
    assert json.loads(first.read_text())["a"] == 1
    assert (first.stat().st_mode & 0o777) == 0o600


def test_safe_name():
    assert safe_name("proton-pass") == "proton-pass"
    assert "/" not in safe_name("../evil/../x")
    assert not safe_name("../evil/../x").startswith(".")
    assert safe_name("") == "unnamed"


def test_atomic_write_text_replaces(tmp_path: Path):
    path = tmp_path / "state" / "x.json"
    atomic_write_text(path, "one")
    atomic_write_text(path, "two")
    assert path.read_text() == "two"
    assert list(path.parent.iterdir()) == [path]


def test_state_store_roundtrip_and_corruption(tmp_path: Path):
    store = StateStore(tmp_path / "state")
    assert store.load("x") == {}
    store.save("x", {"cursor": "abc", "n": 1})
    assert store.load("x") == {"cursor": "abc", "n": 1}
    store.path_for("x").write_text("{not json")
    assert store.load("x") == {}
    store.path_for("x").write_text("[1, 2]")
    assert store.load("x") == {}


def test_seen_ids_is_bounded_and_ordered():
    seen = SeenIds(limit=3)
    assert seen.add("a") is True
    assert seen.add("b") is True
    assert seen.add("a") is False  # 既読
    assert seen.add("c") is True
    assert seen.add("d") is True  # b が押し出される (a は再参照で新しくなった)
    assert "b" not in seen
    assert "a" in seen
    assert seen.to_list() == ["a", "c", "d"]


def test_seen_ids_from_state_tolerates_bad_shape():
    assert len(SeenIds.from_state({"seen_ids": "oops"})) == 0
    assert len(SeenIds.from_state({"seen_ids": ["x", 1]})) == 2
