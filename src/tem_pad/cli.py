"""tem-pad の CLI エントリポイント。"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from tem_pad import __version__
from tem_pad.collectors import all_collectors, collector_names, get_collector
from tem_pad.collectors.base import CollectorContext, CollectResult, run_collector
from tem_pad.config import Config, ConfigError, load_config
from tem_pad.doctor import render, run_all_checks
from tem_pad.inspect_cmd import run_inspect


def build_parser() -> argparse.ArgumentParser:
    """引数パーサを構築する。"""
    parser = argparse.ArgumentParser(
        prog="tem-pad",
        description="個人開発環境の監査ログを収集・正規化して Loki/Grafana で確認するツール",
    )
    parser.add_argument("--version", action="version", version=f"tem-pad {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        help="設定ファイルのパス (既定: ~/.config/tem-pad/config.toml)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="デバッグログを stderr に出す")

    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="イベントを収集して JSONL に追記する")
    collect.add_argument(
        "source",
        choices=[*collector_names(), "all"],
        help="収集対象",
    )
    collect.add_argument(
        "--dry-run", action="store_true", help="取得と正規化のみ行い、書き込みしない"
    )

    sub.add_parser("doctor", help="実行環境と連携先を診断する")

    inspect = sub.add_parser("inspect", help="取得済みイベントを表示する")
    inspect.add_argument("-s", "--source", action="append", help="source で絞る (複数指定可)")
    inspect.add_argument("-k", "--kind", help="kind で絞る")
    inspect.add_argument("-d", "--decision", help="decision で絞る (allow/deny)")
    inspect.add_argument("-a", "--actor", help="actor で絞る")
    inspect.add_argument("-g", "--grep", help="JSON 表現に含まれる文字列で絞る")
    inspect.add_argument(
        "-n", "--limit", type=int, default=50, help="末尾から表示する件数 (0 で全件)"
    )
    inspect.add_argument("--json", action="store_true", help="JSONL で出力する")

    config_cmd = sub.add_parser("config", help="設定を表示する")
    config_cmd.add_argument(
        "action",
        choices=["show", "path"],
        help="show: 有効な設定 / path: 設定ファイルの場所",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI のメイン関数。終了コードを返す。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"設定エラー: {exc}\n")
        return 2

    if args.command == "collect":
        return cmd_collect(config, args.source, dry_run=args.dry_run)
    if args.command == "doctor":
        return render(run_all_checks(config), sys.stdout)
    if args.command == "inspect":
        return run_inspect(
            config,
            sys.stdout,
            sources=args.source,
            kind=args.kind,
            decision=args.decision,
            actor=args.actor,
            contains=args.grep,
            limit=args.limit,
            as_json=args.json,
        )
    if args.command == "config":
        return cmd_config(config, args.action)
    parser.error("unknown command")
    return 2


def cmd_collect(config: Config, source: str, *, dry_run: bool) -> int:
    """collect サブコマンド。1 つでも失敗すれば 1 を返す。"""
    ctx = CollectorContext.from_config(config, dry_run=dry_run)
    collectors = all_collectors() if source == "all" else [get_collector(source)]
    exit_code = 0
    for collector in collectors:
        result = run_collector(collector, ctx)
        sys.stdout.write(format_result(result) + "\n")
        if not result.ok:
            exit_code = 1
    return exit_code


def format_result(result: CollectResult) -> str:
    """収集結果を 1 行にまとめる。"""
    if result.error:
        return f"[{result.source}] NG {result.error}"
    if result.skipped:
        return f"[{result.source}] skip ({result.skip_reason or 'no reason'})"
    line = (
        f"[{result.source}] fetched={result.fetched} written={result.written}"
        f" duplicates={result.duplicates}"
    )
    if result.raw_pruned:
        line += f" raw_pruned={result.raw_pruned}"
    if result.warnings:
        line += " warnings=" + "; ".join(result.warnings)
    return line


def cmd_config(config: Config, action: str) -> int:
    """config サブコマンド。secret の値は表示しない。"""
    if action == "path":
        sys.stdout.write(f"{config.path or '(未作成: 既定値で動作中)'}\n")
        return 0
    ts = config.tailscale
    pp = config.proton_pass
    ls = config.little_snitch
    ds = config.docker_sandbox
    ep = config.endpoints
    lines = [
        f"config: {config.path or '(既定値)'}",
        f"host: {config.general.host}",
        f"data_dir: {config.general.data_dir}",
        (
            f"tailscale: enabled={ts.enabled} tailnet={ts.tailnet}"
            f" oauth_client_id={ts.oauth_client_id.describe()}"
            f" oauth_client_secret={ts.oauth_client_secret.describe()}"
            f" api_key={ts.api_key.describe()}"
        ),
        f"proton_pass: enabled={pp.enabled} cli={pp.cli_path} redact_mode={pp.redact_mode}",
        f"little_snitch: enabled={ls.enabled} cli={ls.cli_path} use_sudo={ls.use_sudo}",
        f"docker_sandbox: enabled={ds.enabled} mode={ds.mode}",
        f"endpoints: loki={ep.loki_url} grafana={ep.grafana_url} alloy={ep.alloy_url}",
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
