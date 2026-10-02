"""CLI と doctor / inspect のテスト。"""

from __future__ import annotations

import fcntl
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tem_pad.checks import CheckResult, Status
from tem_pad.cli import main
from tem_pad.collectors.base import CollectorContext, run_collector
from tem_pad.collectors.little_snitch import LittleSnitchCollector
from tem_pad.config import Config, GeneralConfig
from tem_pad.doctor import general_checks, render
from tem_pad.models import Event
from tem_pad.storage import EventStore


def test_help_and_version(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "collect" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "tem-pad" in capsys.readouterr().out


def test_config_show_hides_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-very-secret")
    cfg = tmp_path / "config.toml"
    cfg.write_text('[general]\nhost = "h"\n', encoding="utf-8")
    assert main(["-c", str(cfg), "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "env:TAILSCALE_API_KEY" in out
    assert "tskey-very-secret" not in out


def test_config_error_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[docker_sandbox]\nmode = "nope"\n', encoding="utf-8")
    assert main(["-c", str(cfg), "config", "show"]) == 2
    assert "設定エラー" in capsys.readouterr().err


def test_render_exit_code(capsys: pytest.CaptureFixture[str]):
    results = [
        CheckResult.ok("a", "fine"),
        CheckResult.warn("b", "meh", "do this"),
        CheckResult.skip("c"),
    ]
    assert render(results, sys.stdout) == 0
    assert render([*results, CheckResult.ng("d", "bad", "fix it")], sys.stdout) == 1
    out = capsys.readouterr().out
    assert "fix it" in out
    assert Status.NG.value in out


def test_general_checks_create_dirs(tmp_path: Path):
    cfg = Config(general=GeneralConfig(host="h", data_dir=tmp_path / "d"))
    results = general_checks(cfg)
    names = {r.name: r.status for r in results}
    assert names["data_dir writable"] is Status.OK
    assert (tmp_path / "d" / "events").is_dir()


def test_inspect_filters(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[general]\nhost = "h"\ndata_dir = "{tmp_path / "data"}"\n', encoding="utf-8")
    store = EventStore(tmp_path / "data" / "events")
    store.append(
        [
            Event(
                timestamp=datetime(2026, 9, 6, 8, 0, tzinfo=UTC),
                source="docker-sandbox",
                kind="network_egress",
                actor="claude-x",
                action="connect",
                decision="deny",
                payload={"domain": "evil.example"},
            ),
            Event(
                timestamp=datetime(2026, 9, 6, 8, 1, tzinfo=UTC),
                source="little-snitch",
                kind="connection",
                actor="curl",
                decision="allow",
                payload={"remote_host": "ok.example"},
            ),
        ]
    )
    assert main(["-c", str(cfg), "inspect", "-d", "deny"]) == 0
    out = capsys.readouterr().out
    assert "evil.example" in out
    assert "ok.example" not in out

    assert main(["-c", str(cfg), "inspect", "--json", "-s", "little-snitch"]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert '"source": "little-snitch"' in out

    assert main(["-c", str(cfg), "inspect", "-g", "nothing-matches"]) == 0
    assert "該当するイベントはありません" in capsys.readouterr().out


def test_collect_dry_run_with_all_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        f"""
[general]
host = "h"
data_dir = "{tmp_path / "data"}"
[tailscale]
enabled = false
[proton_pass]
enabled = false
[little_snitch]
enabled = false
[docker_sandbox]
enabled = false
""",
        encoding="utf-8",
    )
    assert main(["-c", str(cfg), "collect", "all", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert out.count("skip") == 4


def test_collector_skips_when_locked(tmp_path: Path):
    cfg = Config(general=GeneralConfig(host="h", data_dir=tmp_path / "d"))
    cfg.little_snitch.use_sudo = False
    ctx = CollectorContext.from_config(cfg)
    lock_path = ctx.states.path_for("little-snitch").with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as other:
        fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # 別プロセス相当
        result = run_collector(LittleSnitchCollector(), ctx)
    assert result.skipped
    assert "別プロセス" in (result.skip_reason or "")


def test_raw_disabled_via_config(tmp_path: Path):
    cfg = Config(general=GeneralConfig(host="h", data_dir=tmp_path / "d"))
    cfg.proton_pass.save_raw = False
    ctx = CollectorContext.from_config(cfg)
    assert ctx.raw.enabled_for("proton-pass") is False
    assert ctx.raw.enabled_for("tailscale") is True
    assert cfg.raw_disabled_sources() == {"proton-pass"}
