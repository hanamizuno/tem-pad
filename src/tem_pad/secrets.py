"""secret の参照と解決。

設定ファイルには secret の「取り出し方」だけを書き、値そのものは
環境変数・外部コマンド (Proton Pass CLI や macOS ``security`` など)・
権限を絞ったファイルから実行時に読む。解決した値はログに出さない。
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast


class SecretError(RuntimeError):
    """secret を解決できなかったときに送出する。値は含めない。"""


@dataclass(slots=True, frozen=True)
class SecretRef:
    """secret の取得元。いずれか 1 つだけを指定する。

    Attributes:
        env: 環境変数名。
        command: 実行して標準出力 (1 行目) を値として使うコマンド。
        file: 値を 1 行で保持するファイルのパス。
    """

    env: str | None = None
    command: tuple[str, ...] = field(default_factory=tuple)
    file: Path | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SecretRef:
        """TOML のインラインテーブルから生成する。"""
        env = raw.get("env")
        command_raw = raw.get("command")
        file_raw = raw.get("file")
        command: tuple[str, ...] = ()
        if isinstance(command_raw, list):
            command = tuple(str(part) for part in cast("list[Any]", command_raw))
        elif isinstance(command_raw, str):
            command = (command_raw,)
        return cls(
            env=str(env) if env else None,
            command=command,
            file=Path(str(file_raw)).expanduser() if file_raw else None,
        )

    def describe(self) -> str:
        """doctor 表示用の説明 (値を含まない)。"""
        if self.env:
            return f"env:{self.env}"
        if self.command:
            return f"command:{self.command[0]}"
        if self.file:
            return f"file:{self.file}"
        return "unset"

    def is_configured(self) -> bool:
        """取得元が 1 つ以上指定されているか。"""
        return bool(self.env or self.command or self.file)

    def resolve(self, *, timeout: float = 30.0) -> str | None:
        """値を取り出す。取得元が未設定・空なら ``None``。

        Raises:
            SecretError: コマンド失敗やファイル読み取り失敗。
        """
        if self.env:
            value = os.environ.get(self.env, "")
            return value.strip() or None
        if self.command:
            return _run_secret_command(self.command, timeout=timeout)
        if self.file:
            try:
                text = self.file.read_text(encoding="utf-8")
            except OSError as exc:
                raise SecretError(f"secret ファイルを読めません: {self.file}") from exc
            first_line = text.strip().splitlines()[0] if text.strip() else ""
            return first_line or None
        return None


def _run_secret_command(command: tuple[str, ...], *, timeout: float) -> str | None:
    try:
        # secret を返すコマンドは設定ファイルで利用者が明示したもののみ実行する
        completed = subprocess.run(  # noqa: S603
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        raise SecretError(f"secret コマンドを起動できません: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SecretError(f"secret コマンドがタイムアウトしました: {command[0]}") from exc
    if completed.returncode != 0:
        # stderr に値が混ざる可能性があるため出力内容は含めない
        raise SecretError(
            f"secret コマンドが失敗しました (exit={completed.returncode}): {command[0]}"
        )
    lines = completed.stdout.strip().splitlines()
    return lines[0].strip() if lines else None
