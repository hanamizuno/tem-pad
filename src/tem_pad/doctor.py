"""``tem-pad doctor``: 実行環境と各連携先の状態を診断する。

credential の値は出力しない。NG のときは次に取るべき対応を hint として示す。
"""

from __future__ import annotations

import os
import platform
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TextIO

from tem_pad import __version__
from tem_pad.checks import CheckResult, Status
from tem_pad.config import Config
from tem_pad.httputil import probe

CheckFunc = Callable[[Config], list[CheckResult]]


def general_checks(config: Config) -> list[CheckResult]:
    """Python / 設定 / データディレクトリの確認。"""
    results: list[CheckResult] = []
    py = platform.python_version()
    results.append(CheckResult.ok("Python runtime", f"{py} / tem-pad {__version__}"))

    if config.path is None:
        results.append(
            CheckResult.warn(
                "config readable",
                "設定ファイルが見つからないため既定値で動作しています",
                "~/.config/tem-pad/config.toml を作成してください (docs/setup.md 参照)",
            )
        )
    else:
        results.append(CheckResult.ok("config readable", str(config.path)))

    data_dir = config.general.data_dir
    try:
        for sub in (config.events_dir, config.raw_dir, config.state_dir):
            sub.mkdir(parents=True, exist_ok=True)
        probe_file = data_dir / ".doctor-write-test"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink()
        results.append(CheckResult.ok("data_dir writable", str(data_dir)))
    except OSError as exc:
        results.append(
            CheckResult.ng(
                "data_dir writable",
                f"{data_dir}: {exc.strerror or exc}",
                "general.data_dir のパスと権限を確認してください",
            )
        )
    _check_permissions(data_dir, results)
    return results


def _check_permissions(data_dir: Path, results: list[CheckResult]) -> None:
    if not data_dir.exists():
        return
    mode = data_dir.stat().st_mode & 0o777
    if mode & 0o077:
        results.append(
            CheckResult.warn(
                "data_dir permissions",
                f"{data_dir} が他ユーザーから読める権限です (0{mode:o})",
                f"chmod 700 {data_dir} を推奨します (監査ログには機微情報が含まれます)",
            )
        )
    else:
        results.append(CheckResult.ok("data_dir permissions", f"0{mode:o}"))


def stack_checks(config: Config) -> list[CheckResult]:
    """Alloy / Loki / Grafana の疎通確認。"""
    results: list[CheckResult] = []
    ep = config.endpoints
    ok, detail = probe(f"{ep.alloy_url}/-/ready")
    if ok:
        results.append(CheckResult.ok("Alloy running", ep.alloy_url))
    else:
        results.append(
            CheckResult.ng(
                "Alloy running",
                detail,
                "Grafana Alloy を起動してください (docs/setup.md の Alloy 節)。"
                " ポートが異なる場合は endpoints.alloy_url を設定します",
            )
        )
    ok, detail = probe(f"{ep.loki_url}/ready")
    if ok:
        results.append(CheckResult.ok("Loki reachable", ep.loki_url))
    else:
        results.append(
            CheckResult.ng(
                "Loki reachable",
                detail,
                "docker compose up -d で Loki を起動してください",
            )
        )
    ok, detail = probe(f"{ep.grafana_url}/api/health")
    if ok:
        results.append(CheckResult.ok("Grafana reachable", ep.grafana_url))
    else:
        results.append(
            CheckResult.ng(
                "Grafana reachable",
                detail,
                "docker compose up -d で Grafana を起動してください",
            )
        )
    return results


def collector_checks(config: Config) -> list[CheckResult]:
    """各 Collector が提供する診断を集約する。"""
    from tem_pad.collectors.docker_sandbox import doctor_checks as ds_checks  # noqa: PLC0415
    from tem_pad.collectors.little_snitch import doctor_checks as ls_checks  # noqa: PLC0415
    from tem_pad.collectors.proton_pass import doctor_checks as pp_checks  # noqa: PLC0415
    from tem_pad.collectors.tailscale import doctor_checks as ts_checks  # noqa: PLC0415

    results: list[CheckResult] = []
    for func in (ts_checks, pp_checks, ls_checks, ds_checks):
        results.extend(func(config))
    return results


def run_all_checks(config: Config, *, extra: Iterable[CheckFunc] = ()) -> list[CheckResult]:
    """すべての診断を実行する。"""
    results: list[CheckResult] = []
    for func in (general_checks, collector_checks, stack_checks, *extra):
        results.extend(func(config))
    return results


_MARK = {Status.OK: "✓", Status.WARN: "!", Status.NG: "✗", Status.SKIP: "-"}


def render(results: Iterable[CheckResult], out: TextIO) -> int:
    """結果を表示し、NG があれば 1、なければ 0 を返す。"""
    exit_code = 0
    use_unicode = "utf" in (getattr(out, "encoding", "") or "").lower()
    for result in results:
        mark = _MARK[result.status] if use_unicode else result.status.value
        line = f"{mark} {result.status.value:<4} {result.name}"
        if result.detail:
            line += f": {result.detail}"
        out.write(line + "\n")
        if result.hint and result.status in (Status.NG, Status.WARN):
            out.write(f"       → {result.hint}\n" if use_unicode else f"       -> {result.hint}\n")
        if result.status is Status.NG:
            exit_code = 1
    return exit_code


def is_macos() -> bool:
    """macOS 上で動いているか。"""
    return sys.platform == "darwin"


def env_flag(name: str) -> bool:
    """環境変数に空でない値が設定されているか (値自体は返さない)。"""
    return bool(os.environ.get(name))
