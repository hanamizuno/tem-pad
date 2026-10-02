"""設定ファイル (TOML) の読み込み。

secret は設定ファイルに書かず、:mod:`tem_pad.secrets` の参照
(環境変数 / コマンド / ファイル) で指定する。
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from tem_pad.secrets import SecretRef

DEFAULT_CONFIG_PATH = Path("~/.config/tem-pad/config.toml")
DEFAULT_DATA_DIR = Path("~/.local/share/tem-pad")
CONFIG_ENV = "TEM_PAD_CONFIG"

DOCKER_SANDBOX_MODES = ("auto", "native", "policy-log", "disabled")
DEFAULT_LITTLE_SNITCH_CLI = "/Applications/Little Snitch.app/Contents/Components/littlesnitch"


def _empty_str_list() -> list[str]:
    return []


class ConfigError(ValueError):
    """設定ファイルの内容が不正なときに送出する。"""


@dataclass(slots=True)
class GeneralConfig:
    """``[general]`` セクション。"""

    host: str
    data_dir: Path
    # 1 source あたり state に保持する既読 event_id の上限
    dedupe_window: int = 5000
    # raw ログを保持する日数。0 以下なら自動削除しない
    raw_retention_days: int = 180


@dataclass(slots=True)
class TailscaleConfig:
    """``[tailscale]`` セクション。"""

    enabled: bool = True
    # 取得した生データを raw/ に保存するか
    save_raw: bool = True
    # ハイフン 1 文字は「API 資格情報が属する tailnet」を意味する Tailscale の省略記法
    tailnet: str = "-"
    api_base_url: str = "https://api.tailscale.com"
    # 監査ログを前回終端の何秒前から重ねて取るか。API 側の遅延に備える
    audit_overlap_seconds: int = 60
    # 初回実行時に何時間前まで遡って取るか
    audit_initial_lookback_hours: int = 24
    # 1 回の取得で遡る最大時間。長期停止後の巨大取得を避ける
    audit_max_window_hours: int = 24 * 7
    # device 一覧の取得間隔の秒数。collect tailscale をより短い周期で呼んでも
    # この間隔未満なら device 取得はスキップする
    devices_interval_seconds: int = 600
    oauth_client_id: SecretRef = field(
        default_factory=lambda: SecretRef(env="TAILSCALE_OAUTH_CLIENT_ID")
    )
    oauth_client_secret: SecretRef = field(
        default_factory=lambda: SecretRef(env="TAILSCALE_OAUTH_CLIENT_SECRET")
    )
    # OAuth を使わない場合のフォールバック (API access token)
    api_key: SecretRef = field(default_factory=lambda: SecretRef(env="TAILSCALE_API_KEY"))
    # OAuth token 取得時に要求する scope。空なら client の全 scope
    oauth_scopes: list[str] = field(default_factory=_empty_str_list)
    timeout_seconds: float = 30.0


@dataclass(slots=True)
class ProtonPassConfig:
    """``[proton_pass]`` セクション。"""

    enabled: bool = True
    save_raw: bool = True
    cli_path: str = "pass-cli"
    # agent monitor の --limit。Agent ごとの前回位置から差分を取る
    monitor_limit: int = 200
    # 収集対象を絞る場合に Agent 名を列挙する (空なら全 Agent)
    agents: list[str] = field(default_factory=_empty_str_list)
    # item・vault・reason を保存前に加工する方式 (plain, hash, drop のいずれか)
    redact_mode: str = "plain"
    timeout_seconds: float = 60.0


@dataclass(slots=True)
class LittleSnitchConfig:
    """``[little_snitch]`` セクション。"""

    enabled: bool = True
    save_raw: bool = True
    cli_path: str = DEFAULT_LITTLE_SNITCH_CLI
    # littlesnitch は多くの操作で root を要求する。sudo 経由で実行するか
    use_sudo: bool = True
    # 前回取得終端から何秒前まで重ねて取り直すか
    overlap_seconds: int = 60
    initial_lookback_minutes: int = 60
    timeout_seconds: float = 120.0


@dataclass(slots=True)
class DockerSandboxConfig:
    """``[docker_sandbox]`` セクション。"""

    enabled: bool = True
    save_raw: bool = True
    mode: str = "auto"
    sbx_path: str = "sbx"
    # native audit JSONL の場所。空なら OS 既定 (macOS: ~/Library/Logs/...)
    native_audit_dir: Path | None = None
    policy_log_limit: int = 1000
    timeout_seconds: float = 60.0


@dataclass(slots=True)
class EndpointsConfig:
    """``[endpoints]`` セクション。doctor が疎通確認に使う URL。"""

    loki_url: str = "http://127.0.0.1:3100"
    grafana_url: str = "http://127.0.0.1:3000"
    alloy_url: str = "http://127.0.0.1:12345"


@dataclass(slots=True)
class Config:
    """tem-pad 全体の設定。"""

    general: GeneralConfig
    tailscale: TailscaleConfig = field(default_factory=TailscaleConfig)
    proton_pass: ProtonPassConfig = field(default_factory=ProtonPassConfig)
    little_snitch: LittleSnitchConfig = field(default_factory=LittleSnitchConfig)
    docker_sandbox: DockerSandboxConfig = field(default_factory=DockerSandboxConfig)
    endpoints: EndpointsConfig = field(default_factory=EndpointsConfig)
    # 読み込んだ設定ファイルのパス (存在しなければ None)
    path: Path | None = None

    @property
    def events_dir(self) -> Path:
        """正規化済み JSONL の置き場所。"""
        return self.general.data_dir / "events"

    @property
    def raw_dir(self) -> Path:
        """raw log の置き場所。"""
        return self.general.data_dir / "raw"

    @property
    def state_dir(self) -> Path:
        """state ファイルの置き場所。"""
        return self.general.data_dir / "state"

    def raw_disabled_sources(self) -> set[str]:
        """raw 保存を無効にした source 名の集合。"""
        pairs = (
            ("tailscale", self.tailscale.save_raw),
            ("proton-pass", self.proton_pass.save_raw),
            ("little-snitch", self.little_snitch.save_raw),
            ("docker-sandbox", self.docker_sandbox.save_raw),
        )
        return {name for name, enabled in pairs if not enabled}


def default_host() -> str:
    """ホスト名の既定値 (``.local`` などのサフィックスを除いた短い名前)。"""
    name = os.uname().nodename if hasattr(os, "uname") else "localhost"
    return name.split(".", 1)[0] or "localhost"


def resolve_config_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """設定ファイルのパスを決める。

    優先順: 明示引数 > ``TEM_PAD_CONFIG`` 環境変数 > 既定パス。
    """
    if explicit is not None:
        return Path(explicit).expanduser()
    env_value = os.environ.get(CONFIG_ENV)
    if env_value:
        return Path(env_value).expanduser()
    return DEFAULT_CONFIG_PATH.expanduser()


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """設定ファイルを読み込む。存在しない場合は既定値で構成する。"""
    resolved = resolve_config_path(path)
    if resolved.exists():
        with resolved.open("rb") as handle:
            try:
                raw = tomllib.load(handle)
            except tomllib.TOMLDecodeError as exc:
                raise ConfigError(f"設定ファイルの構文エラー: {resolved}: {exc}") from exc
        config = config_from_dict(raw)
        config.path = resolved
        return config
    return config_from_dict({})


def config_from_dict(raw: dict[str, Any]) -> Config:
    """TOML を dict 化したものから :class:`Config` を組み立てる。"""
    general_raw = _section(raw, "general")
    general = GeneralConfig(
        host=str(general_raw.get("host") or default_host()),
        data_dir=Path(str(general_raw.get("data_dir") or DEFAULT_DATA_DIR)).expanduser(),
        dedupe_window=_int(general_raw, "dedupe_window", 5000),
        raw_retention_days=_int(general_raw, "raw_retention_days", 180),
    )

    ts_raw = _section(raw, "tailscale")
    tailscale = TailscaleConfig(
        enabled=_bool(ts_raw, "enabled", default=True),
        save_raw=_bool(ts_raw, "save_raw", default=True),
        tailnet=str(ts_raw.get("tailnet") or "-"),
        api_base_url=str(ts_raw.get("api_base_url") or "https://api.tailscale.com").rstrip("/"),
        audit_overlap_seconds=_int(ts_raw, "audit_overlap_seconds", 60),
        audit_initial_lookback_hours=_int(ts_raw, "audit_initial_lookback_hours", 24),
        audit_max_window_hours=_int(ts_raw, "audit_max_window_hours", 24 * 7),
        devices_interval_seconds=_int(ts_raw, "devices_interval_seconds", 600),
        oauth_client_id=_secret(ts_raw, "oauth_client_id", "TAILSCALE_OAUTH_CLIENT_ID"),
        oauth_client_secret=_secret(ts_raw, "oauth_client_secret", "TAILSCALE_OAUTH_CLIENT_SECRET"),
        api_key=_secret(ts_raw, "api_key", "TAILSCALE_API_KEY"),
        oauth_scopes=_str_list(ts_raw, "oauth_scopes"),
        timeout_seconds=_float(ts_raw, "timeout_seconds", 30.0),
    )

    pp_raw = _section(raw, "proton_pass")
    redact_mode = str(pp_raw.get("redact_mode") or "plain")
    if redact_mode not in {"plain", "hash", "drop"}:
        raise ConfigError(f"proton_pass.redact_mode が不正です: {redact_mode}")
    proton_pass = ProtonPassConfig(
        enabled=_bool(pp_raw, "enabled", default=True),
        save_raw=_bool(pp_raw, "save_raw", default=True),
        cli_path=str(pp_raw.get("cli_path") or "pass-cli"),
        monitor_limit=_int(pp_raw, "monitor_limit", 200),
        agents=_str_list(pp_raw, "agents"),
        redact_mode=redact_mode,
        timeout_seconds=_float(pp_raw, "timeout_seconds", 60.0),
    )

    ls_raw = _section(raw, "little_snitch")
    little_snitch = LittleSnitchConfig(
        enabled=_bool(ls_raw, "enabled", default=True),
        save_raw=_bool(ls_raw, "save_raw", default=True),
        cli_path=str(ls_raw.get("cli_path") or DEFAULT_LITTLE_SNITCH_CLI),
        use_sudo=_bool(ls_raw, "use_sudo", default=True),
        overlap_seconds=_int(ls_raw, "overlap_seconds", 60),
        initial_lookback_minutes=_int(ls_raw, "initial_lookback_minutes", 60),
        timeout_seconds=_float(ls_raw, "timeout_seconds", 120.0),
    )

    ds_raw = _section(raw, "docker_sandbox")
    mode = str(ds_raw.get("mode") or "auto")
    if mode not in DOCKER_SANDBOX_MODES:
        raise ConfigError(
            f"docker_sandbox.mode が不正です: {mode} (候補: {', '.join(DOCKER_SANDBOX_MODES)})"
        )
    native_dir_raw = ds_raw.get("native_audit_dir")
    docker_sandbox = DockerSandboxConfig(
        enabled=_bool(ds_raw, "enabled", default=True),
        save_raw=_bool(ds_raw, "save_raw", default=True),
        mode=mode,
        sbx_path=str(ds_raw.get("sbx_path") or "sbx"),
        native_audit_dir=Path(str(native_dir_raw)).expanduser() if native_dir_raw else None,
        policy_log_limit=_int(ds_raw, "policy_log_limit", 1000),
        timeout_seconds=_float(ds_raw, "timeout_seconds", 60.0),
    )

    ep_raw = _section(raw, "endpoints")
    endpoints = EndpointsConfig(
        loki_url=str(ep_raw.get("loki_url") or "http://127.0.0.1:3100").rstrip("/"),
        grafana_url=str(ep_raw.get("grafana_url") or "http://127.0.0.1:3000").rstrip("/"),
        alloy_url=str(ep_raw.get("alloy_url") or "http://127.0.0.1:12345").rstrip("/"),
    )

    return Config(
        general=general,
        tailscale=tailscale,
        proton_pass=proton_pass,
        little_snitch=little_snitch,
        docker_sandbox=docker_sandbox,
        endpoints=endpoints,
    )


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] はテーブルである必要があります")
    return {str(k): v for k, v in cast("dict[Any, Any]", value).items()}


def _bool(section: dict[str, Any], key: str, *, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} は true/false で指定してください")
    return value


def _int(section: dict[str, Any], key: str, default: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} は整数で指定してください")
    return value


def _float(section: dict[str, Any], key: str, default: float) -> float:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} は数値で指定してください")
    return float(value)


def _str_list(section: dict[str, Any], key: str) -> list[str]:
    value = section.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f"{key} は文字列の配列で指定してください")
    return [str(item) for item in cast("list[Any]", value)]


def _secret(section: dict[str, Any], key: str, default_env: str) -> SecretRef:
    value = section.get(key)
    if value is None:
        return SecretRef(env=default_env)
    if not isinstance(value, dict):
        raise ConfigError(
            f"{key} は {{ env = ... }} / {{ command = [...] }} / {{ file = ... }}"
            " の形式で指定してください"
        )
    return SecretRef.from_dict({str(k): v for k, v in cast("dict[Any, Any]", value).items()})
