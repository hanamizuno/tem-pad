"""Collector の共通インターフェースと実行ラッパー。

各 Collector は :class:`Collector` プロトコルを実装し、
``collect()`` で :class:`Event` のリストを返す。重複排除・JSONL 追記・
state 保存は :func:`run_collector` が一括で行う。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from tem_pad.config import Config
from tem_pad.models import Event, utc_now
from tem_pad.state import SeenIds, StateStore
from tem_pad.storage import EventStore, RawStore

logger = logging.getLogger(__name__)


def _empty_str_list() -> list[str]:
    return []


@dataclass(slots=True)
class CollectorContext:
    """Collector に渡す実行環境。"""

    config: Config
    events: EventStore
    raw: RawStore
    states: StateStore
    now: datetime = field(default_factory=utc_now)
    # True なら書き込みを行わず、取得と正規化だけ実施する
    dry_run: bool = False

    @classmethod
    def from_config(cls, config: Config, *, dry_run: bool = False) -> CollectorContext:
        """設定からストア群を構築する。"""
        return cls(
            config=config,
            events=EventStore(config.events_dir),
            raw=RawStore(config.raw_dir),
            states=StateStore(config.state_dir),
            dry_run=dry_run,
        )


@dataclass(slots=True)
class CollectResult:
    """1 回の収集結果。"""

    source: str
    fetched: int = 0
    written: int = 0
    duplicates: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    warnings: list[str] = field(default_factory=_empty_str_list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        """致命的エラーなしで終わったか。"""
        return self.error is None


@dataclass(slots=True)
class CollectOutput:
    """Collector が返す生の結果。"""

    events: list[Event]
    # 保存する state。None なら state を更新しない (取得失敗時など)
    state: dict[str, Any] | None
    warnings: list[str] = field(default_factory=_empty_str_list)
    skipped: bool = False
    skip_reason: str | None = None


class Collector(Protocol):
    """Collector が満たすべきインターフェース。"""

    name: str

    def enabled(self, config: Config) -> bool:
        """設定上有効か。"""
        ...

    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput:
        """イベントを取得し正規化する。

        Args:
            ctx: 実行環境。
            state: 前回保存した state (存在しなければ空 dict)。
        """
        ...


def run_collector(collector: Collector, ctx: CollectorContext) -> CollectResult:
    """Collector を実行し、重複排除・書き込み・state 保存まで行う。

    Collector 内の例外はここで捕まえ、結果に ``error`` として載せる。
    ``collect all`` で 1 つの失敗が他へ波及しないようにするため。
    """
    result = CollectResult(source=collector.name)
    if not collector.enabled(ctx.config):
        result.skipped = True
        result.skip_reason = "設定で無効化されています"
        return result

    state = ctx.states.load(collector.name)
    try:
        output = collector.collect(ctx, state)
    except Exception as exc:  # 1 Collector の失敗を全体へ波及させない
        logger.exception("collector %s failed", collector.name)
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.warnings = list(output.warnings)
    result.fetched = len(output.events)
    if output.skipped:
        result.skipped = True
        result.skip_reason = output.skip_reason
        return result

    seen = SeenIds.from_state(state, limit=ctx.config.general.dedupe_window)
    fresh: list[Event] = []
    for event in output.events:
        if event.event_id is not None and not seen.add(event.event_id):
            result.duplicates += 1
            continue
        fresh.append(event)

    if ctx.dry_run:
        result.written = 0
        return result

    result.written = ctx.events.append(fresh)
    if output.state is not None:
        new_state = dict(output.state)
        new_state["seen_ids"] = seen.to_list()
        new_state["last_run"] = ctx.now.isoformat()
        ctx.states.save(collector.name, new_state)
    return result
