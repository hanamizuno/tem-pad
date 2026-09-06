"""``tem-pad doctor`` で使う診断結果の型。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    """診断結果の種別。"""

    OK = "OK"
    WARN = "WARN"
    NG = "NG"
    SKIP = "SKIP"


@dataclass(slots=True)
class CheckResult:
    """1 項目の診断結果。

    Attributes:
        name: 項目名 (例: ``Tailscale API reachable``)。
        status: 結果。
        detail: 補足。secret や個人情報を含めない。
        hint: NG/WARN の場合に利用者が次にすべきこと。
    """

    name: str
    status: Status
    detail: str = ""
    hint: str = ""

    @classmethod
    def ok(cls, name: str, detail: str = "") -> CheckResult:
        """OK の結果を作る。"""
        return cls(name, Status.OK, detail)

    @classmethod
    def warn(cls, name: str, detail: str = "", hint: str = "") -> CheckResult:
        """WARN の結果を作る。"""
        return cls(name, Status.WARN, detail, hint)

    @classmethod
    def ng(cls, name: str, detail: str = "", hint: str = "") -> CheckResult:
        """NG の結果を作る。"""
        return cls(name, Status.NG, detail, hint)

    @classmethod
    def skip(cls, name: str, detail: str = "") -> CheckResult:
        """SKIP の結果を作る (設定で無効など)。"""
        return cls(name, Status.SKIP, detail)
