"""JSONL イベントストアと raw ログの保存。

Collector は Loki へ直接 push せず、ここで書いた JSONL を Alloy が tail する。
そのため書き込みは「1 イベント = 1 行」「行単位で完結」を守る。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, cast

from tem_pad.models import Event, format_timestamp, utc_now

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """一時ファイルへ書いてから rename することで途中状態を残さない。"""
    path.parent.mkdir(parents=True, exist_ok=True)
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

        時系列順に書くため timestamp で安定ソートする。source が混在して
        いても、それぞれのファイルへ振り分ける。
        """
        by_source: dict[str, list[Event]] = {}
        for event in events:
            by_source.setdefault(event.source, []).append(event)
        written = 0
        for source, items in by_source.items():
            items.sort(key=lambda item: item.timestamp)
            path = self.path_for(source)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                for event in items:
                    handle.write(event.to_json())
                    handle.write("\n")
                    written += 1
                handle.flush()
                os.fsync(handle.fileno())
        return written

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


class RawStore:
    """取得した生データを ``raw/<source>/<timestamp>-<name>.<ext>`` に保存する。

    再処理・証跡用。secret が含まれ得るデータは呼び出し側で取り除いてから
    渡すこと (保存前に確認するのは Collector の責務)。
    """

    def __init__(self, raw_dir: Path) -> None:
        """Args: raw_dir: raw ログのルートディレクトリ。"""
        self.raw_dir = raw_dir

    def write_text(self, source: str, name: str, text: str, *, ext: str = "txt") -> Path:
        """テキストを保存し、書いたパスを返す。"""
        directory = self.raw_dir / safe_name(source)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = format_timestamp(utc_now()).replace(":", "").replace("-", "")
        path = directory / f"{stamp}-{safe_name(name)}.{ext}"
        counter = 1
        while path.exists():
            path = directory / f"{stamp}-{safe_name(name)}-{counter}.{ext}"
            counter += 1
        atomic_write_text(path, text)
        return path

    def write_json(self, source: str, name: str, data: Any) -> Path:  # noqa: ANN401
        """JSON 化して保存する。"""
        text = json.dumps(data, ensure_ascii=False, indent=1, default=str)
        return self.write_text(source, name, text, ext="json")
