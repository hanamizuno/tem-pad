"""secret 混入に対する共通の防御層。

外部 API / CLI の応答をイベントや raw に保存する前に通す。

* キー名ベース: ``password`` / ``token`` / ``secret`` などのキーを再帰的に削除する。
* 値ベース: 既知の secret 形式 (Tailscale の ``tskey-…``、Proton Pass の
  ``pst_…::…`` など) に一致する部分文字列を伏せ字にする。JSON のどこに
  ある値にも (監査ログの ``old`` / ``new`` など) 適用する。

監査ログに secret が含まれない想定でも、将来の仕様変更や誤設定に備えて
すべての source で使う。
"""

from __future__ import annotations

import re
from typing import Any, cast

# 値が secret である可能性が高いキー名 (大文字小文字を区別しない部分一致)
SECRET_KEY_PATTERN = re.compile(
    r"(password|secret|token|totp|private|credential|passphrase)", re.IGNORECASE
)

# 既知の secret 値の形式。誤検知を避けるため接頭辞付きのものに限る
SECRET_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Tailscale の auth key / API access token / OAuth client secret
    (re.compile(r"tskey-[A-Za-z0-9_-]{6,}"), "tskey-<redacted>"),
    # Proton Pass の personal access token (``pst_xxx::KEY`` の形)
    (re.compile(r"pst_[A-Za-z0-9_-]{6,}(?:::[A-Za-z0-9_-]+)?"), "pst_<redacted>"),
    # 一般的な Bearer トークン表記
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer <redacted>"),
)

REDACTED = "<redacted>"


def redact_text(text: str) -> str:
    """文字列中の既知 secret 形式を伏せ字にする。"""
    for pattern, replacement in SECRET_VALUE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize(data: Any) -> Any:  # noqa: ANN401
    """JSON 由来のデータから secret らしいキーを削除し、値の secret 形式を伏せる。"""
    if isinstance(data, dict):
        return {
            str(key): sanitize(value)
            for key, value in cast("dict[Any, Any]", data).items()
            if not SECRET_KEY_PATTERN.search(str(key))
        }
    if isinstance(data, list):
        return [sanitize(item) for item in cast("list[Any]", data)]
    if isinstance(data, str):
        return redact_text(data)
    return data


def sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    """戻り値の型を dict のまま保つ :func:`sanitize` のラッパー。"""
    return cast("dict[str, Any]", sanitize(data))
