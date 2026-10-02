"""標準ライブラリだけで済ませる最小限の HTTP ヘルパー。"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class HttpError(RuntimeError):
    """HTTP 呼び出しの失敗。レスポンス本文は先頭のみ保持する。"""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        """Args: message: 説明。status: HTTP ステータス (あれば)。"""
        super().__init__(message)
        self.status = status


@dataclass(slots=True)
class HttpResponse:
    """HTTP レスポンス。"""

    status: int
    body: bytes

    def json(self) -> Any:  # noqa: ANN401
        """本文を JSON として解釈する。"""
        return json.loads(self.body.decode("utf-8"))

    def text(self) -> str:
        """本文を UTF-8 文字列にする。"""
        return self.body.decode("utf-8", errors="replace")


def request(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 30.0,
) -> HttpResponse:
    """HTTP リクエストを送る。

    Raises:
        HttpError: 接続失敗または 4xx/5xx。
    """
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310  (https 固定の API URL)
    req.add_header("User-Agent", "tem-pad")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return HttpResponse(status=resp.status, body=resp.read())
    except urllib.error.HTTPError as exc:
        preview = exc.read(300).decode("utf-8", errors="replace").replace("\n", " ")
        raise HttpError(f"HTTP {exc.code} {exc.reason}: {preview}", status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"接続に失敗しました: {exc.reason}") from exc
    except TimeoutError as exc:
        raise HttpError("タイムアウトしました") from exc


def form_encode(fields: Mapping[str, str]) -> bytes:
    """application/x-www-form-urlencoded 本文を作る。"""
    return urllib.parse.urlencode(fields).encode("ascii")


def probe(url: str, *, timeout: float = 3.0) -> tuple[bool, str]:
    """疎通を確認し、(成功したか, 説明) を返す。"""
    try:
        resp = request(url, timeout=timeout)
    except HttpError as exc:
        return False, str(exc)
    return True, f"HTTP {resp.status}"
