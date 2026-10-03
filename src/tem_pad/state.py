"""増分収集のための state 管理。

state は ``state/<source>.json`` に保存する。書き込みは atomic に行い、
Collector が途中で落ちても壊れた JSON を残さない。

重複排除には、最近見た event_id を上限付きで保持するリストを使う。
overlap で同じイベントを再取得しても、このリストにあれば捨てる。
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from tem_pad.storage import atomic_write_text, safe_name


class StateStore:
    """source ごとの state (JSON dict) の読み書き。"""

    def __init__(self, state_dir: Path) -> None:
        """Args: state_dir: state ファイルを置くディレクトリ。"""
        self.state_dir = state_dir

    def path_for(self, source: str) -> Path:
        """source に対応する state ファイルのパス。"""
        return self.state_dir / f"{safe_name(source)}.json"

    def load(self, source: str) -> dict[str, Any]:
        """state を読む。存在しない・壊れている場合は空 dict。"""
        path = self.path_for(source)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): v for k, v in cast("dict[Any, Any]", data).items()}

    def save(self, source: str, state: dict[str, Any]) -> None:
        """state を atomic に保存する。"""
        text = json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True, default=str)
        atomic_write_text(self.path_for(source), text + "\n")


class SeenIds:
    """上限付きの既読 event_id 集合。挿入順を保ち、上限を超えたら古いものから捨てる。"""

    def __init__(self, ids: Iterable[str] = (), *, limit: int = 5000) -> None:
        """Args: ids: 初期 ID 列。limit: 保持する最大件数。"""
        self.limit = max(1, limit)
        self._ids: OrderedDict[str, None] = OrderedDict()
        for value in ids:
            self.add(value)

    def __contains__(self, value: object) -> bool:
        """ID が既読か。"""
        return value in self._ids

    def __len__(self) -> int:
        """保持している ID 数。"""
        return len(self._ids)

    def add(self, value: str) -> bool:
        """ID を追加する。新規なら ``True``、既読なら ``False`` を返す。"""
        if value in self._ids:
            self._ids.move_to_end(value)
            return False
        self._ids[value] = None
        while len(self._ids) > self.limit:
            self._ids.popitem(last=False)
        return True

    def to_list(self) -> list[str]:
        """JSON 保存用のリスト (古い順)。"""
        return list(self._ids)

    @classmethod
    def from_state(
        cls, state: dict[str, Any], key: str = "seen_ids", *, limit: int = 5000
    ) -> SeenIds:
        """state dict から復元する。形式が壊れていれば空。"""
        raw = state.get(key)
        if not isinstance(raw, list):
            return cls(limit=limit)
        return cls((str(item) for item in cast("list[Any]", raw)), limit=limit)
