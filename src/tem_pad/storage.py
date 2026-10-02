"""JSONL イベントストアと raw ログの保存。

Collector は Loki へ直接 push せず、ここで書いた JSONL を Alloy が tail する。
そのため「1 イベント = 1 行」で、各行が単独で完結するように書く。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, cast

from tem_pad.models import Event, format_timestamp, utc_now

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> None:
    """ディレクトリを 0700 で作成し、既存で緩い権限なら 0700 に直す。"""
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    if path.stat().st_mode & 0o077:
        path.chmod(PRIVATE_DIR_MODE)


def ensure_private_file(path: Path) -> None:
    """既存ファイルの権限が緩ければ 0600 に直す。"""
    if path.exists() and path.stat().st_mode & 0o077:
        path.chmod(PRIVATE_FILE_MODE)


def atomic_write_text(path: Path, text: str, *, mode: int = PRIVATE_FILE_MODE) -> None:
    """一時ファイルに書いてから rename し、書きかけの状態を残さない。"""
    ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(mode)
        tmp_path.replace(path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def safe_name(value: str) -> str:
    """ファイル名に使えない文字を ``_`` に置き換える。"""
    cleaned = _SAFE_NAME.sub("_", value).strip("._")
    return cleaned or "unnamed"


class EventStore:
    """source ごとの JSONL ファイル (``events/<source>.jsonl``) への追記。"""

    def __init__(self, events_dir: Path) -> None:
        """Args: events_dir: JSONL を置くディレクトリ。"""
        self.events_dir = events_dir

    def path_for(self, source: str) -> Path:
        """source に対応する JSONL のパス。"""
        return self.events_dir / f"{safe_name(source)}.jsonl"

    def append(self, events: Iterable[Event]) -> int:
        """イベントを追記し、書いた件数を返す。

        source ごとのファイルに振り分け、timestamp で安定ソートして
        時系列順に書く。
        """
        by_source: dict[str, list[Event]] = {}
        for event in events:
            by_source.setdefault(event.source, []).append(event)
        written = 0
        for source, items in by_source.items():
            items.sort(key=lambda item: item.timestamp)
            path = self.path_for(source)
            ensure_private_dir(path.parent)
            ensure_private_file(path)
            # 監査ログは機微情報を含むため、umask に関係なく新規ファイルは 0600 で作る
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                for event in items:
                    handle.write(event.to_json())
                    handle.write("\n")
                    written += 1
                handle.flush()
                os.fsync(handle.fileno())
        return written

    def recent_event_ids(self, source: str, limit: int) -> list[str]:
        """JSONL 末尾 ``limit`` 行に含まれる event_id を古い順に返す。

        state の保存前にプロセスが落ちても、書き終えたイベントの ID を
        ここから復元して重複排除に使えるようにする。
        """
        path = self.path_for(source)
        if limit <= 0 or not path.exists():
            return []
        ids: list[str] = []
        for line in _tail_lines(path, limit):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                event_id = cast("dict[str, Any]", data).get("event_id")
                if isinstance(event_id, str) and event_id:
                    ids.append(event_id)
        return ids

    def iter_events(self, source: str) -> Iterator[Event]:
        """JSONL を先頭から読む。壊れた行は読み飛ばす。"""
        path = self.path_for(source)
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict):
                    try:
                        yield Event.from_dict(cast("dict[str, Any]", data))
                    except (KeyError, ValueError):
                        continue

    def list_sources(self) -> list[str]:
        """JSONL が存在する source 名の一覧。"""
        if not self.events_dir.exists():
            return []
        return sorted(path.stem for path in self.events_dir.glob("*.jsonl"))


def _tail_lines(path: Path, limit: int, *, block_size: int = 64 * 1024) -> list[str]:
    """ファイル末尾の最大 ``limit`` 行を、ファイル内の順序のまま返す。"""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        chunks: list[bytes] = []
        newlines = 0
        while position > 0 and newlines <= limit:
            read_size = min(block_size, position)
            position -= read_size
            handle.seek(position)
            chunk = handle.read(read_size)
            chunks.append(chunk)
            newlines += chunk.count(b"\n")
        data = b"".join(reversed(chunks))
    lines = data.decode("utf-8", errors="replace").splitlines()
    return [line for line in lines if line.strip()][-limit:]


class RawStore:
    """取得した生データを ``raw/<source>/<timestamp>-<name>.<ext>`` に保存する。

    再処理や証跡に使う。secret の除去は Collector の責務なので、
    呼び出し側で取り除いてから渡すこと。
    """

    def __init__(self, raw_dir: Path, *, disabled_sources: Iterable[str] = ()) -> None:
        """Args: raw_dir: raw ログのルート。disabled_sources: 保存しない source 名。"""
        self.raw_dir = raw_dir
        self.disabled_sources = set(disabled_sources)

    def enabled_for(self, source: str) -> bool:
        """その source の raw 保存が有効か。"""
        return source not in self.disabled_sources

    def write_text(self, source: str, name: str, text: str, *, ext: str = "txt") -> Path | None:
        """テキストを保存し、書いたパスを返す。保存が無効な source なら None。"""
        if not self.enabled_for(source):
            return None
        directory = self.raw_dir / safe_name(source)
        ensure_private_dir(directory)
        stamp = format_timestamp(utc_now()).replace(":", "").replace("-", "")
        path = directory / f"{stamp}-{safe_name(name)}.{ext}"
        counter = 1
        while path.exists():
            path = directory / f"{stamp}-{safe_name(name)}-{counter}.{ext}"
            counter += 1
        atomic_write_text(path, text)
        return path

    def write_json(self, source: str, name: str, data: Any) -> Path | None:  # noqa: ANN401
        """JSON 化して保存する。保存が無効な source なら None。"""
        text = json.dumps(data, ensure_ascii=False, indent=1, default=str)
        return self.write_text(source, name, text, ext="json")

    def prune(self, source: str, *, older_than_days: int, now: float | None = None) -> int:
        """更新時刻が ``older_than_days`` 日より古い raw ファイルを削除し、件数を返す。

        ``older_than_days`` が 0 以下なら何もしない。
        """
        if older_than_days <= 0:
            return 0
        directory = self.raw_dir / safe_name(source)
        if not directory.is_dir():
            return 0
        cutoff = (now if now is not None else time.time()) - older_than_days * 86400
        removed = 0
        for path in directory.iterdir():
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed
