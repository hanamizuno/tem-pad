"""外部コマンド実行の共通ヘルパー。

secret を引数に渡さない、エラーメッセージに出力を丸ごと含めない、
という方針をここでまとめて守る。
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tem_pad.sanitize import redact_text


class CommandError(RuntimeError):
    """外部コマンドが失敗したときに送出する。"""

    def __init__(
        self, command: Sequence[str], message: str, *, returncode: int | None = None
    ) -> None:
        """Args: command: 実行したコマンド。message: 説明。returncode: 終了コード。"""
        super().__init__(f"{command[0]}: {message}")
        self.command = list(command)
        self.returncode = returncode


@dataclass(slots=True)
class CommandResult:
    """コマンド実行結果。"""

    stdout: str
    stderr: str
    returncode: int


def which(name: str) -> str | None:
    """PATH または絶対パスから実行ファイルを探す。"""
    return shutil.which(name)


def run_command(
    command: Sequence[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    stderr_preview: int = 300,
) -> CommandResult:
    """コマンドを実行して結果を返す。

    Args:
        command: 実行するコマンドと引数。
        timeout: タイムアウト (秒)。
        env: 追加・上書きする環境変数 (None なら継承のみ)。
        check: 非 0 終了を :class:`CommandError` にするか。
        stderr_preview: エラーに含める stderr の最大文字数。

    Raises:
        CommandError: 起動失敗・タイムアウト・非 0 終了 (check=True 時)。
    """
    import os  # noqa: PLC0415  (環境変数のマージにだけ使う)

    merged_env = None
    if env:
        merged_env = {**os.environ, **env}
    try:
        # 実行するコマンドは設定ファイル由来のパスと固定の引数のみ
        completed = subprocess.run(  # noqa: S603
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=merged_env,
        )
    except FileNotFoundError as exc:
        raise CommandError(command, "コマンドが見つかりません") from exc
    except PermissionError as exc:
        raise CommandError(command, "実行権限がありません") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(command, f"{timeout:.0f} 秒でタイムアウトしました") from exc
    result = CommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )
    if check and completed.returncode != 0:
        # stderr は原因調査に必要なので、secret が混ざっていても漏れないよう伏せ字にして含める
        preview = redact_text(completed.stderr.strip().replace("\n", " ")[:stderr_preview])
        raise CommandError(
            command,
            f"exit={completed.returncode} {preview}".strip(),
            returncode=completed.returncode,
        )
    return result
