"""共通イベントモデル (Envelope + source 固有 payload)。

すべての Collector は取得した生データを :class:`Event` に正規化して
JSONL として書き出す。Envelope の各フィールドは Loki の label 設計と
対応しており、高 cardinality な値は必ず ``payload`` 側に入れる。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

# kind の値は source ごとに定義するが、未知のイベントは必ずこの値を使う
KIND_UNKNOWN = "unknown"

# decision の正規化済み値 (Loki label にするため種類を絞る)
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_UNKNOWN = "unknown"


def utc_now() -> datetime:
    """現在時刻を UTC の aware datetime で返す。"""
    return datetime.now(tz=UTC)


def format_timestamp(value: datetime) -> str:
    """datetime を RFC 3339 (UTC, Z 終端) 文字列にする。

    naive datetime は UTC として扱う。ミリ秒以下は保持する。
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    text = value.isoformat(timespec="microseconds" if value.microsecond else "seconds")
    return text.replace("+00:00", "Z")


def parse_timestamp(text: str) -> datetime:
    """RFC 3339 風の文字列を aware datetime (UTC) に変換する。

    末尾 ``Z`` と ``+00:00`` の両方を受け付け、ナノ秒精度は
    マイクロ秒に丸める。tz 情報がない場合は UTC とみなす。
    """
    raw = text.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    # Python の fromisoformat は小数部 7 桁以上を受け付けないため丸める
    if "." in raw:
        head, _, tail = raw.partition(".")
        digits = ""
        rest = ""
        for index, char in enumerate(tail):
            if char.isdigit():
                digits += char
            else:
                rest = tail[index:]
                break
        digits = digits[:6].ljust(6, "0")
        raw = f"{head}.{digits}{rest}"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_decision(value: str | None) -> str | None:
    """様々な表現の allow/deny を共通値へ寄せる。

    判定できない非空文字列は :data:`DECISION_UNKNOWN` にする。
    ``None`` や空文字は ``None`` のまま (判定が存在しないイベント)。
    """
    if value is None:
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    if lowered in {"allow", "allowed", "accept", "permit", "audit_decision_allow"}:
        return DECISION_ALLOW
    if lowered in {
        "deny",
        "denied",
        "block",
        "blocked",
        "reject",
        "audit_decision_deny",
    }:
        return DECISION_DENY
    return DECISION_UNKNOWN


def _empty_payload() -> dict[str, Any]:
    return {}


@dataclass(slots=True)
class Event:
    """正規化済みイベント (共通 Envelope)。

    Attributes:
        timestamp: イベント発生時刻 (UTC)。
        source: 取得元 (``tailscale`` / ``proton-pass`` など)。
        kind: source 内でのイベント種別。未知なら ``unknown``。
        host: イベントを観測したホスト名 (config の ``general.host``)。
        actor: 行為者 (ユーザー名、Agent 名、プロセス名など)。
        action: 行為 (``connect`` / ``ItemRead`` / ``CREATE`` など)。
        decision: ``allow`` / ``deny`` / ``unknown`` / None。
        event_id: source 内で一意な ID。重複排除に使う。
        payload: source 固有の詳細。高 cardinality な値はここに置く。
    """

    timestamp: datetime
    source: str
    kind: str
    host: str | None = None
    actor: str | None = None
    action: str | None = None
    decision: str | None = None
    event_id: str | None = None
    payload: dict[str, Any] = field(default_factory=_empty_payload)

    def to_dict(self) -> dict[str, Any]:
        """JSON 化可能な dict にする。キー順は Envelope 定義順。"""
        return {
            "timestamp": format_timestamp(self.timestamp),
            "source": self.source,
            "kind": self.kind,
            "host": self.host,
            "actor": self.actor,
            "action": self.action,
            "decision": self.decision,
            "event_id": self.event_id,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        """1 行の JSON 文字列にする (JSONL 用。改行を含まない)。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        """:meth:`to_dict` の逆変換。inspect コマンド等で使う。"""
        payload_raw = data.get("payload")
        payload: dict[str, Any] = (
            {str(k): v for k, v in cast("dict[Any, Any]", payload_raw).items()}
            if isinstance(payload_raw, dict)
            else {}
        )
        return cls(
            timestamp=parse_timestamp(str(data["timestamp"])),
            source=str(data["source"]),
            kind=str(data.get("kind") or KIND_UNKNOWN),
            host=_opt_str(data.get("host")),
            actor=_opt_str(data.get("actor")),
            action=_opt_str(data.get("action")),
            decision=_opt_str(data.get("decision")),
            event_id=_opt_str(data.get("event_id")),
            payload=payload,
        )


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)
