"""tests/fixtures から正規化済みのサンプル JSONL を生成する。

Phase 2 の end-to-end 確認 (sample JSONL -> Alloy -> Loki -> Grafana) や、
利用者が手元の Alloy/Loki 設定を検証するのに使う。実データは含まない。

使い方::

    uv run python scripts/make_sample_events.py [出力ディレクトリ] [--now]

出力先の既定は deploy/sample/events/。--now を付けると timestamp を現在時刻付近へずらし、
Loki の reject_old_samples で弾かれないようにする。
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tem_pad.collectors import docker_sandbox, little_snitch, proton_pass, tailscale  # noqa: E402
from tem_pad.config import ProtonPassConfig  # noqa: E402
from tem_pad.models import Event  # noqa: E402
from tem_pad.storage import EventStore  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
HOST = "sample-host"


def _load(*parts: str) -> Any:  # noqa: ANN401
    return json.loads(FIXTURES.joinpath(*parts).read_text(encoding="utf-8"))


def build_events(now: datetime) -> list[Event]:
    """fixture から全 source のイベントを作る。"""
    events: list[Event] = []

    audit: dict[str, Any] = _load("tailscale", "audit_logs.json")
    events.extend(tailscale.normalize_audit_entry(e, HOST, now) for e in audit["logs"])
    before: dict[str, Any] = _load("tailscale", "devices_before.json")
    after: dict[str, Any] = _load("tailscale", "devices_after.json")
    events.extend(
        tailscale.diff_devices(
            tailscale.device_snapshot(before["devices"]),
            tailscale.device_snapshot(after["devices"]),
            host=HOST,
            now=now,
        )
    )

    agents = proton_pass.parse_agents(_load("proton_pass", "agent_list.json"))
    records = proton_pass.parse_monitor_records(_load("proton_pass", "agent_monitor.json"))
    cfg = ProtonPassConfig()
    for agent in agents[:1]:
        events.extend(
            proton_pass.normalize_record(agent, r, host=HOST, now=now, cfg=cfg) for r in records
        )

    csv_text = (FIXTURES / "little_snitch" / "log_traffic.csv").read_text(encoding="utf-8")
    events.extend(
        little_snitch.normalize_row(row, host=HOST, fallback=now)
        for row in little_snitch.parse_csv(csv_text)
    )

    rows = docker_sandbox.parse_policy_log(_load("docker_sandbox", "policy_log_list.json"))
    rows += docker_sandbox.parse_policy_log(_load("docker_sandbox", "policy_log_grouped.json"))
    events.extend(
        docker_sandbox.normalize_row(row, previous_count=None, host=HOST, now=now) for row in rows
    )
    return events


def main(argv: list[str]) -> int:
    """エントリポイント。"""
    args = [a for a in argv if not a.startswith("--")]
    out_dir = Path(args[0]) if args else ROOT / "deploy" / "sample" / "events"
    shift_to_now = "--now" in argv
    now = datetime.now(tz=UTC)
    events = build_events(now)
    if shift_to_now:
        # fixture の時刻は数日に散らばっているため、順序を保ったまま直近 30 分に詰める
        # (Loki の reject_old_samples や too-new 判定を避ける)
        ordered = sorted(events, key=lambda e: e.timestamp)
        step = timedelta(minutes=30) / max(len(ordered), 1)
        for index, event in enumerate(ordered):
            event.timestamp = now - timedelta(minutes=30) + step * index
    out_dir.mkdir(parents=True, exist_ok=True)
    for path in out_dir.glob("*.jsonl"):
        path.unlink()
    written = EventStore(out_dir).append(events)
    sys.stdout.write(f"{written} events -> {out_dir}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
