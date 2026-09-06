"""Collector のレジストリ。"""

from __future__ import annotations

from tem_pad.collectors.base import Collector


def all_collectors() -> list[Collector]:
    """定義済み Collector を CLI の表示順で返す。"""
    from tem_pad.collectors.docker_sandbox import DockerSandboxCollector  # noqa: PLC0415
    from tem_pad.collectors.little_snitch import LittleSnitchCollector  # noqa: PLC0415
    from tem_pad.collectors.proton_pass import ProtonPassCollector  # noqa: PLC0415
    from tem_pad.collectors.tailscale import TailscaleCollector  # noqa: PLC0415

    return [
        TailscaleCollector(),
        ProtonPassCollector(),
        LittleSnitchCollector(),
        DockerSandboxCollector(),
    ]


def collector_names() -> list[str]:
    """Collector 名の一覧。"""
    return [collector.name for collector in all_collectors()]


def get_collector(name: str) -> Collector:
    """名前で Collector を取得する。

    Raises:
        KeyError: 未知の名前。
    """
    for collector in all_collectors():
        if collector.name == name:
            return collector
    raise KeyError(name)
