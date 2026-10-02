# tem-pad

個人開発環境 (Mac Studio 1 台) のセキュリティ・監査ログを集約し、Grafana から横断的に確認するための軽量なログ収集・観測基盤です。汎用 SIEM ではなく、「AI Agent と自分の Mac が、いつ・どこへ・何をしたか」を 1 つのタイムラインで追えることを目的にしています。

対象 (初期):

| source | 取得元 | 主なイベント |
|---|---|---|
| `tailscale` | Tailscale API (Configuration audit log / device 一覧) | 設定変更、device 追加・削除・変更、policy 変更、key 関連 |
| `proton-pass` | `pass-cli agent monitor` (Token for Agents 監査ログ) | Agent による item 読み取り・更新、reason の有無 |
| `little-snitch` | `littlesnitch log-traffic` (CSV) | Mac 上プロセスの外部通信、deny |
| `docker-sandbox` | native audit JSONL または `sbx policy log --json` | Sandbox 内 Agent の外部通信、allow/deny |

## アーキテクチャ

```text
Tailscale API ──────────┐
Proton Pass CLI ────────┤
Little Snitch CLI ──────┤    tem-pad collect (Python, launchd で定期実行)
sbx policy log ─────────┤       raw 保存 → normalize → dedupe
                        ▼
      ~/.local/share/tem-pad/events/<source>.jsonl   (共通 Envelope + payload)
                        │  tail
                        ▼
                  Grafana Alloy (macOS ネイティブ)   ← Docker native audit JSONL も直接 tail
                        │  push (source/host/kind/decision だけを label に)
                        ▼
                  Loki (Docker Compose, 127.0.0.1:3100, 90 日保持)
                        │
                        ▼
                  Grafana (Docker Compose, 127.0.0.1:3000)
```

Collector は Loki へ直接 push しません。JSONL を介した疎結合にすることで、Loki 停止中も収集を続けられ、Loki/Grafana を作り直しても raw と JSONL から復元でき、将来別のバックエンドへも移せます。詳細は [docs/architecture.md](docs/architecture.md)。

## クイックスタート

```bash
# 1. Collector をインストール (uv)
uv tool install .            # または開発用に: uv sync && uv run tem-pad --help

# 2. 設定ファイルを作る (secret は書かない)
mkdir -p ~/.config/tem-pad && cp docs/config.example.toml ~/.config/tem-pad/config.toml

# 3. Loki / Grafana を起動
cp example.env .env          # GRAFANA_ADMIN_PASSWORD を書き換える
docker compose up -d

# 4. Alloy を起動 (Homebrew 例)
brew install grafana/grafana/alloy
TEM_PAD_DATA_DIR=$HOME/.local/share/tem-pad TEM_PAD_LOKI_URL=http://127.0.0.1:3100 \
TEM_PAD_HOST=$(hostname -s) TEM_PAD_DOCKER_AUDIT_DIR=$HOME/Library/Logs/com.docker.sandboxes/sandboxes/auditkit \
alloy run --storage.path=$HOME/.local/share/tem-pad/alloy deploy/alloy/config.alloy

# 5. 診断して収集
tem-pad doctor
tem-pad collect all
tem-pad inspect -n 20
```

手順の詳細 (Tailscale OAuth client の作成、Little Snitch の権限、launchd 登録、Tailscale Serve でのリモート閲覧) は [docs/setup.md](docs/setup.md) にあります。

## CLI

```text
tem-pad collect {tailscale,proton-pass,little-snitch,docker-sandbox,all} [--dry-run]
tem-pad doctor
tem-pad inspect [-s SOURCE] [-k KIND] [-d allow|deny] [-a ACTOR] [-g TEXT] [-n N] [--json]
tem-pad config {show,path}
```

`collect all` は 1 つの source が失敗しても他を続け、失敗があれば終了コード 1 を返します。`doctor` は credential の値を一切表示しません。

## データの置き場所

既定は `~/.local/share/tem-pad/` です。

```text
~/.local/share/tem-pad/
├── events/<source>.jsonl   # 正規化済み (Alloy が tail する)
├── raw/<source>/           # 取得した生データ (再処理・証跡用。secret は保存しない)
├── state/<source>.json     # 増分取得のカーソルと既読 event_id
└── alloy/                  # Alloy の positions (--storage.path)
```

macOS の慣習では `~/Library/Application Support` ですが、次の理由で XDG 風のパスを既定にしています。

- パスに空白を含まないため、Alloy の glob・launchd・sudoers の記述が単純になる。
- Linux でも同じ既定値で動き、fixture やドキュメントを共通化できる。
- Proton Pass CLI など一部のツールも Linux では `~/.local/share` を使っており違和感が少ない。

`general.data_dir` で変更できます。監査ログには機微情報が含まれるため、ディレクトリは `chmod 700` を推奨します (`doctor` が警告します)。

## ログ形式

共通 Envelope + source 固有 `payload` です。

```json
{
  "timestamp": "2026-09-06T08:00:00Z",
  "source": "docker-sandbox",
  "kind": "network_egress",
  "host": "mac-studio",
  "actor": "claude-tem-pad",
  "action": "connect",
  "decision": "deny",
  "event_id": "policy-log:…",
  "payload": {"domain": "blocked.example.com", "sandbox": "claude-tem-pad", "rule": "default-deny"}
}
```

Loki の label は `source` / `host` / `kind` / `decision` (+ 固定の `schema`) のみで、domain・IP・item・sandbox ID などは本文 JSON に置き `| json` で検索します。フィールド定義と kind の一覧は [docs/log-schema.md](docs/log-schema.md)。

Grafana Explore での例:

```logql
{source="docker-sandbox", decision="deny"} | json
{source="docker-sandbox"} | json | payload_agent="claude" | line_format "{{.payload_domain}}"
{source="little-snitch"} | json | payload_process=~"(?i)docker|claude"
{source="proton-pass", kind="agent_write"} | json
{source="tailscale", kind="device_added"} | json
```

## Docker Sandboxes の 2 方式について

Docker の native audit log (JSON Lines) は **Docker AI Governance の有償プランと、組織ポリシーの強制** が前提で、個人アカウントでは生成されません。そのため個人環境では `mode = "auto"` が自動的に `policy-log` (`sbx policy log --json`) にフォールバックします。

| | native audit | policy-log (fallback) |
|---|---|---|
| 粒度 | 接続ごと (決定 + 実行結果) | sandbox × host × 判定ごとの集計 (件数・最終時刻) |
| Agent 名 | `agent` フィールドで確定 | sandbox 名の先頭 (`claude-xxx` → `claude`) からの推定 |
| filesystem / tool 等 | あり | network のみ |
| 取り込み | Alloy が JSONL を直接 tail | tem-pad が差分イベント化 (`payload.count_delta`) |

`auto` で native が検出されると Collector は何もせず、Alloy 側の設定 (`TEM_PAD_DOCKER_AUDIT_DIR`) が JSONL を読みます。両方を同時に収集して重複させないためです。

## セキュリティ方針

- secret を設定ファイルへ書かない。環境変数・外部コマンド (`security`, `pass-cli`)・0600 ファイルから実行時に読む。
- secret をコマンド引数に渡さない。CLI の stderr は先頭のみをエラーに含める。
- イベント・raw の保存前に共通 sanitizer を通し、secret らしいキー (`password`, `token`, …) を削除し、既知の secret 形式 (`tskey-…`, `pst_…`) を伏せ字にする。
- `events/` `raw/` `state/` は 0700 / 0600 で作成する。raw は既定 180 日で自動削除し、source 単位で保存を止められる。
- 外部コマンドの stderr はエラーメッセージに含める前に伏せ字化する。source ごとにプロセス間ロックを取り、二重実行を防ぐ。
- Loki/Grafana は `127.0.0.1` にのみ bind。LAN へ公開しない。リモートは Tailscale Serve。
- Docker socket やホスト全体を mount しない。
- Little Snitch のためだけに全体を root で動かさない。sudoers で `littlesnitch log-traffic` だけを許可する。
- `events/` `raw/` `state/` は `.gitignore` 済み。

## 開発

```bash
uv sync
uv run task lint      # ruff + pyright (strict)
uv run task test      # pytest (外部サービスには接続しない。fixture ベース)
uv run task test_cov
uv run python scripts/make_sample_events.py   # fixture からサンプル JSONL を再生成
```

外部仕様 (Tailscale API、pass-cli、Little Snitch CLI、sbx) について、指示書の想定と現行仕様の差分や、実機で未確認の点は [docs/implementation-notes.md](docs/implementation-notes.md) にまとめています。

## 非目標 (MVP)

独自 SIEM、IDS/IPS、packet capture、AI による異常判定、自動遮断、WAX610/ルーター syslog、NAS archive、モバイル/独自 Web UI は作りません。syslog は将来 Alloy の `loki.source.syslog` を足すだけで済む構造を意識しています。

## ライセンス

MIT
