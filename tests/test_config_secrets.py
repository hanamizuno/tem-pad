"""設定と secret 参照のテスト。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tem_pad.config import ConfigError, config_from_dict, load_config, resolve_config_path
from tem_pad.secrets import SecretError, SecretRef


def test_defaults_when_config_missing(tmp_path: Path):
    cfg = load_config(tmp_path / "missing.toml")
    assert cfg.path is None
    assert cfg.tailscale.enabled is True
    assert cfg.docker_sandbox.mode == "auto"
    assert cfg.events_dir == cfg.general.data_dir / "events"


def test_load_toml(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[general]
host = "mac-studio"
data_dir = "~/tem-pad-data"

[tailscale]
enabled = true
tailnet = "example.com"
oauth_client_secret = { command = ["security", "find-generic-password", "-w", "-s", "x"] }

[proton_pass]
redact_mode = "hash"

[docker_sandbox]
mode = "policy-log"
native_audit_dir = "/tmp/auditkit"
""",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.path == path
    assert cfg.general.host == "mac-studio"
    assert cfg.general.data_dir == Path("~/tem-pad-data").expanduser()
    assert cfg.tailscale.tailnet == "example.com"
    assert cfg.tailscale.oauth_client_secret.command[0] == "security"
    assert cfg.proton_pass.redact_mode == "hash"
    assert cfg.docker_sandbox.mode == "policy-log"
    assert cfg.docker_sandbox.native_audit_dir == Path("/tmp/auditkit")


def test_invalid_mode_rejected():
    with pytest.raises(ConfigError, match=r"docker_sandbox\.mode"):
        config_from_dict({"docker_sandbox": {"mode": "bogus"}})


def test_invalid_types_rejected():
    with pytest.raises(ConfigError):
        config_from_dict({"tailscale": {"enabled": "yes"}})
    with pytest.raises(ConfigError):
        config_from_dict({"tailscale": {"audit_overlap_seconds": "60"}})
    with pytest.raises(ConfigError):
        config_from_dict({"tailscale": {"api_key": "plain-text-secret"}})


def test_broken_toml(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text("[general\nhost = ", encoding="utf-8")
    with pytest.raises(ConfigError, match="構文エラー"):
        load_config(path)


def test_resolve_config_path_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("TEM_PAD_CONFIG", str(tmp_path / "c.toml"))
    assert resolve_config_path() == tmp_path / "c.toml"
    assert resolve_config_path(tmp_path / "other.toml") == tmp_path / "other.toml"


def test_secret_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_SECRET", "  value  ")
    assert SecretRef(env="MY_SECRET").resolve() == "value"
    monkeypatch.delenv("MY_SECRET")
    assert SecretRef(env="MY_SECRET").resolve() is None
    assert SecretRef(env="MY_SECRET").describe() == "env:MY_SECRET"


def test_secret_file(tmp_path: Path):
    path = tmp_path / "s"
    path.write_text("first\nsecond\n")
    assert SecretRef(file=path).resolve() == "first"
    with pytest.raises(SecretError):
        SecretRef(file=tmp_path / "missing").resolve()


def test_secret_command():
    ref = SecretRef(command=(sys.executable, "-c", "print('tok')"))
    assert ref.resolve() == "tok"
    failing = SecretRef(command=(sys.executable, "-c", "import sys; print('leak'); sys.exit(3)"))
    with pytest.raises(SecretError) as excinfo:
        failing.resolve()
    assert "leak" not in str(excinfo.value)


def test_secret_unset():
    ref = SecretRef()
    assert ref.resolve() is None
    assert ref.is_configured() is False
    assert ref.describe() == "unset"
