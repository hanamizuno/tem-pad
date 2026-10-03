"""Collector の共通インターフェースと実行ラッパー。

各 Collector は :class:`Collector` プロトコルを実装し、``collect()`` で
:class:`Event` のリストを含む :class:`CollectOutput` を返す。重複排除・
JSONL への追記・state の保存は :func:`run_collector` がまとめて行う。
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
from collections.abc import Generator
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
    # True なら取得と正規化だけ行い、書き込まない
    dry_run: bool = False

    @classmethod
    def from_config(cls, config: Config, *, dry_run: bool = False) -> CollectorContext:
        """設定からストア群を構築する。"""
        return cls(
            config=config,
            events=EventStore(config.events_dir),
            raw=RawStore(config.raw_dir, disabled_sources=config.raw_disabled_sources()),
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
    raw_pruned: int = 0
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
    """Collector が返す結果 (重複排除前)。"""

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


class LockBusyError(RuntimeError):
    """同じ source の Collector が別プロセスで実行中。"""


@contextlib.contextmanager
def source_lock(states: StateStore, source: str) -> Generator[None]:
    """source 単位のプロセス間ロック (``state/<source>.lock`` への flock)。

    launchd の定期実行と手動実行が重なっても、同じ state を読んで同じ
    イベントを二重に書かないようにする。ロックを取れなければ待たずに
    :class:`LockBusyError` を送出する。
    """
    lock_path = states.path_for(source).with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusyError(f"{source} は別プロセスが収集中です") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_collector(collector: Collector, ctx: CollectorContext) -> CollectResult:
    """Collector を実行し、重複排除・書き込み・state 保存まで行う。

    ``collect all`` で 1 つの失敗が他に波及しないよう、Collector 内の例外は
    ここで捕まえて結果の ``error`` に入れる。
    """
    result = CollectResult(source=collector.name)
    if not collector.enabled(ctx.config):
        result.skipped = True
        result.skip_reason = "設定で無効化されています"
        return result
    try:
        with source_lock(ctx.states, collector.name):
            return _run_locked(collector, ctx, result)
    except LockBusyError as exc:
        result.skipped = True
        result.skip_reason = str(exc)
        return result
    except OSError as exc:
        # state や JSONL の読み書き失敗も、その source だけの失敗として扱う
        logger.exception("collector %s storage failure", collector.name)
        result.error = f"{type(exc).__name__}: {exc}"
        return result


def _run_locked(
    collector: Collector, ctx: CollectorContext, result: CollectResult
) -> CollectResult:
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
    # 前回 append 後、state 保存前に落ちた場合に備えて JSONL 末尾の ID も既読に加える
    for event_id in ctx.events.recent_event_ids(collector.name, ctx.config.general.dedupe_window):
        seen.add(event_id)
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
    result.raw_pruned = ctx.raw.prune(
        collector.name,
        older_than_days=ctx.config.general.raw_retention_days,
        now=ctx.now.timestamp(),
    )
    return result
