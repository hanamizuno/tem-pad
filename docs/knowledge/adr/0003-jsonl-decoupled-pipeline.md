---
type: ADR
title: Collector は Loki へ直接 push せず JSONL を介して Alloy に渡す
description: 収集・正規化と転送・保存を疎結合にする決定とその理由
tags: [tem-pad, architecture, loki]
timestamp: 2026-09-06T00:00:00Z
---

# Collector は Loki へ直接 push せず JSONL を介して Alloy に渡す

## 状況

tem-pad は Tailscale / Proton Pass / Little Snitch / Docker Sandboxes から監査ログを集めて Grafana で見る。Collector から Loki の push API を直接呼べば、実装は短く済む。

## 決定

Collector は `~/.local/share/tem-pad/events/<source>.jsonl` に正規化済みイベントを追記するだけにし、Loki への転送は Grafana Alloy (macOS ネイティブ) が JSONL を tail して行う。raw レスポンスは `raw/<source>/` に別途保存する。

## 理由

- Loki が停止・再構築中でも収集を止めない (JSONL に溜まる)。
- schema を変えたときに raw から再 normalize できる。
- Loki 以外 (別ホスト、S3、SIEM、NAS archive) への移行が Alloy 設定の変更で済む。
- Collector を「1 回実行して終わる CLI」にでき、launchd の `StartInterval` で定期実行できる。

## 影響

- Alloy が別プロセスとして必要になる (Homebrew か LaunchAgent)。
- Loki の label は、Alloy が Envelope の `source` / `host` / `kind` / `decision` だけを抜き出して付ける。Alloy にはビジネスロジックを置かない。
- 詳細は `/docs/architecture.md` を参照。
