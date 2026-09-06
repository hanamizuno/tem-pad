"""``tem-pad inspect``: 取得済み JSONL の簡易確認。"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import TextIO

from tem_pad.config import Config
from tem_pad.models import Event
from tem_pad.storage import EventStore


def select_events(
    store: EventStore,
    *,
    sources: Iterable[str] | None = None,
    kind: str | None = None,
    decision: str | None = None,
    actor: str | None = None,
    contains: str | None = None,
) -> Iterator[Event]:
    """条件に合うイベントを時系列順に返す。"""
    names = list(sources) if sources else store.list_sources()
    collected: list[Event] = []
    for name in names:
        for event in store.iter_events(name):
            if kind and event.kind != kind:
                continue
            if decision and event.decision != decision:
                continue
            if actor and event.actor != actor:
                continue
            if contains and contains not in event.to_json():
                continue
            collected.append(event)
    collected.sort(key=lambda item: item.timestamp)
    yield from collected


def format_line(event: Event) -> str:
    """人間向けの 1 行表現。"""
    summary = _summarize_payload(event)
    parts = [
        event.to_dict()["timestamp"],
        f"{event.source}/{event.kind}",
        event.decision or "-",
        event.actor or "-",
        event.action or "-",
    ]
    if summary:
        parts.append(summary)
    return "  ".join(str(part) for part in parts)


def _summarize_payload(event: Event) -> str:
    keys = (
        "remote_host",
        "host",
        "domain",
        "item",
        "vault",
        "device_name",
        "target_name",
        "sandbox",
        "reason",
    )
    pieces: list[str] = []
    for key in keys:
        value = event.payload.get(key)
        if value not in (None, ""):
            pieces.append(f"{key}={value}")
    return " ".join(pieces)


def run_inspect(
    config: Config,
    out: TextIO,
    *,
    sources: list[str] | None,
    kind: str | None,
    decision: str | None,
    actor: str | None,
    contains: str | None,
    limit: int,
    as_json: bool,
) -> int:
    """inspect コマンド本体。終了コードを返す。"""
    store = EventStore(config.events_dir)
    events = list(
        select_events(
            store,
            sources=sources,
            kind=kind,
            decision=decision,
            actor=actor,
            contains=contains,
        )
    )
    if limit > 0:
        events = events[-limit:]
    for event in events:
        if as_json:
            out.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        else:
            out.write(format_line(event) + "\n")
    if not events and not as_json:
        out.write("該当するイベントはありません\n")
    return 0
