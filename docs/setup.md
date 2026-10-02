# セットアップ (Mac Studio)

前提: macOS、[uv](https://docs.astral.sh/uv/)、Docker Desktop (または Docker Sandboxes を含む Docker 環境)、Homebrew。

## 1. tem-pad のインストール

```bash
git clone https://github.com/hanamizuno/tem-pad.git ~/develop/tem-pad
cd ~/develop/tem-pad
uv tool install .                # ~/.local/bin/tem-pad
tem-pad --help
```

開発しながら使う場合は `uv sync` して `uv run tem-pad ...` でもよい。

## 2. 設定ファイル

```bash
mkdir -p ~/.config/tem-pad
cp docs/config.example.toml ~/.config/tem-pad/config.toml
chmod 700 ~/.config/tem-pad
mkdir -p ~/.local/share/tem-pad && chmod 700 ~/.local/share/tem-pad
```

`general.host` を自分のホスト名にし、不要な source は `enabled = false` にする。secret の値は設定ファイルに書かない (次節)。

## 3. Tailscale

### OAuth client の作成

長期運用のため API access token ではなく OAuth client を使う。

1. Tailscale 管理コンソール → Settings → OAuth clients → Generate OAuth client。
2. scope は **読み取りのみ** を選ぶ。必要なのは device 一覧の読み取りと Configuration audit log の読み取りで、現行 UI の scope 名は `devices:core:read` と `logs:configuration:read` に相当する (作成画面で最新の名称を確認する。書き込み系 scope は付けない。tag は device 書き込み scope のときだけ必須なので不要)。
3. client ID と client secret を控える。secret はこの 1 回しか表示されない。

### secret の保存

macOS キーチェーンに入れる例:

```bash
security add-generic-password -a "$USER" -s tem-pad-tailscale-client-id -w      # 対話入力
security add-generic-password -a "$USER" -s tem-pad-tailscale-client-secret -w
```

`config.toml`:

```toml
[tailscale]
oauth_client_id     = { command = ["security", "find-generic-password", "-w", "-s", "tem-pad-tailscale-client-id"] }
oauth_client_secret = { command = ["security", "find-generic-password", "-w", "-s", "tem-pad-tailscale-client-secret"] }
```

環境変数 `TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET` でもよい (launchd の plist に直書きはしない)。Proton Pass に入れて `pass-cli item view pass://…` で読む方法も使える (利用者セッションが必要)。

`tem-pad doctor` で `Tailscale API reachable: devices=N` が出れば完了。初回の `collect tailscale` は device 一覧を基準として保存するだけで、差分イベントは 2 回目以降に出る。

## 4. Proton Pass

1. `pass-cli` をインストールし、**利用者アカウント**でログインする (`pass-cli login`)。Agent の監査ログは Agent 自身のセッションからは他 Agent 分が見えないため、利用者セッションが必要。
2. `pass-cli agent list --output json` と `pass-cli agent monitor <name> --output json --limit 5` が動くことを確認する。
3. `tem-pad collect proton-pass --dry-run -v` で取得できることを確認する。

セッションは数時間で切れるので、launchd で回す場合は再ログインの運用が必要 (`doctor` の `Proton Pass authenticated` で検知できる)。`redact_mode = "hash"` にすると item / vault / reason をハッシュ化して保存する。

## 5. Little Snitch

Little Snitch の CLI は root 権限を要求する。tem-pad 全体を root で動かさず、`log-traffic` サブコマンドだけを sudoers で許可する。

1. Little Snitch → Settings → Security で「Allow access from terminal」(ターミナルからのアクセス) を有効にする。
2. sudoers に断片を追加する (`__USER__` を自分のユーザー名に):

   ```bash
   sudo visudo -f /etc/sudoers.d/tem-pad
   # deploy/launchd/sudoers.d-tem-pad.example の内容を貼り付ける
   ```

3. 確認:

   ```bash
   sudo -n "/Applications/Little Snitch.app/Contents/Components/littlesnitch" log-traffic \
     --begin-date "$(date -v-2M '+%Y-%m-%d %H:%M:%S')" --end-date "$(date -v-1M '+%Y-%m-%d %H:%M:%S')" | head -3
   tem-pad collect little-snitch --dry-run -v
   ```

CSV の 1 行目 (ヘッダ) を `docs/implementation-notes.md` の想定と比べ、違いがあれば fixture (`tests/fixtures/little_snitch/log_traffic.csv`) を実出力 (個人情報を除いたもの) に置き換える。

代替案として、root の LaunchDaemon で `tem-pad collect little-snitch` だけを動かす方法もあるが、`~/.local/share/tem-pad` の所有権が混ざるため既定では sudoers 方式を採る。

## 6. Docker Sandboxes

- 個人アカウントでは Docker AI Governance の native audit JSONL は生成されないため、`mode = "auto"` は `sbx policy log --json` を使う。`sbx policy log --json --limit 5` が動けばよい。
- AI Governance が有効な環境では `~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit/*.jsonl` を Alloy が直接読む。`tem-pad doctor` の `Docker Sandbox audit mode` が `native` と表示され、Collector は自動的に何もしなくなる。

## 7. Loki / Grafana (Docker Compose)

```bash
cp example.env .env
$EDITOR .env                      # GRAFANA_ADMIN_PASSWORD を設定
docker compose up -d
docker compose ps
curl -s http://127.0.0.1:3100/ready
open http://127.0.0.1:3000        # admin / .env のパスワード
```

- 両方とも `127.0.0.1` にのみ bind している。LAN に開けない。
- retention は Loki 側で 90 日 (`deploy/loki/config.yaml` の `retention_period`)。
- Data Source (Loki) と dashboard (`deploy/grafana/dashboards/*.json`) は起動時に自動 provision される。
- 初期化したいときは `docker compose down -v`。JSONL と raw は残るので Alloy の positions を消せば再投入できる (`rm -rf ~/.local/share/tem-pad/alloy`)。

## 8. Grafana Alloy (macOS ネイティブ)

```bash
brew install grafana/grafana/alloy
```

Homebrew の service を使う場合は `/opt/homebrew/etc/alloy/config.alloy` を本リポジトリの `deploy/alloy/config.alloy` へのシンボリックリンクにし、環境変数を `brew services` の plist に足すのが面倒なので、本リポジトリの LaunchAgent を使うのが簡単:

```bash
deploy/launchd/install.sh --load
```

これで次の 2 つが `~/Library/LaunchAgents` に置かれ、登録される。

| Label | 内容 |
|---|---|
| `com.tem-pad.alloy` | `alloy run deploy/alloy/config.alloy` を常駐。`TEM_PAD_DATA_DIR` などの環境変数を設定済み |
| `com.tem-pad.collect` | `tem-pad collect all` を 60 秒ごとに実行 |

Alloy の設定を手で動かして確認するには:

```bash
TEM_PAD_DATA_DIR=$HOME/.local/share/tem-pad \
TEM_PAD_LOKI_URL=http://127.0.0.1:3100 \
TEM_PAD_HOST=$(hostname -s) \
TEM_PAD_DOCKER_AUDIT_DIR=$HOME/Library/Logs/com.docker.sandboxes/sandboxes/auditkit \
alloy run --server.http.listen-addr=127.0.0.1:12345 --storage.path=$HOME/.local/share/tem-pad/alloy deploy/alloy/config.alloy
```

`http://127.0.0.1:12345` で Alloy の UI とコンポーネントの状態が見える。

### サンプルデータで経路を確認する

実データを入れる前に、fixture から作ったサンプル JSONL で `Alloy → Loki → Grafana` を確認できる。

```bash
uv run python scripts/make_sample_events.py /tmp/tem-pad-sample/events --now
TEM_PAD_DATA_DIR=/tmp/tem-pad-sample TEM_PAD_LOKI_URL=http://127.0.0.1:3100 TEM_PAD_HOST=sample \
TEM_PAD_DOCKER_AUDIT_DIR=/tmp/tem-pad-sample/auditkit \
alloy run --storage.path=/tmp/tem-pad-sample/alloy deploy/alloy/config.alloy
# Grafana Explore で {source="docker-sandbox"} | json
```

## 9. 収集の定期実行

`deploy/launchd/install.sh --load` で登録した `com.tem-pad.collect` が 60 秒ごとに `tem-pad collect all` を実行する。source ごとの実効間隔は次の通り。

| source | 実効間隔 | 仕組み |
|---|---|---|
| Tailscale audit | 60 秒ごとに API 呼び出し (60 秒 overlap) | 軽い呼び出しなので毎回。負荷を下げたい場合は plist の `StartInterval` を 300 に |
| Tailscale devices | 10 分 (`devices_interval_seconds`) | state の `devices_fetched_at` で抑制 |
| Proton Pass | 60 秒ごと | Agent 数 × `agent monitor` |
| Little Snitch | 60 秒ごと (終端は現在 - 90 秒) | 完了した 1 分区間だけを取る |
| Docker policy log | 60 秒ごと | 前回集計との差分のみイベント化 |

ログは `~/Library/Logs/tem-pad/collect.log` に出る。`tem-pad doctor` を定期的に見て NG を確認する。手動で `tem-pad collect` を実行して定期実行と重なった場合は、後から始まった方が `skip (… 別プロセスが収集中です)` となる。

raw ログは `general.raw_retention_days` (既定 180 日) を過ぎたものが `collect` 時に削除される。

## 10. リモートから Grafana を見る (Tailscale Serve)

Grafana は `127.0.0.1:3000` にしか bind していない。Tailnet 内から見るには Mac Studio で Tailscale Serve を使う。

```bash
tailscale serve --bg https+insecure://127.0.0.1:3000   # または: tailscale serve --bg 3000
tailscale serve status
```

`https://mac-studio.<tailnet>.ts.net/` で開ける。`.env` の `GRAFANA_ROOT_URL` をその URL にすると Grafana のリンクが正しくなる。tem-pad が Serve を自動設定することはない。Funnel (インターネット公開) は使わない。

## 11. 動作確認チェックリスト

```bash
tem-pad doctor                       # すべて OK か WARN
tem-pad collect all                  # 各 source の fetched/written が出る
tem-pad inspect -n 20                # JSONL に書かれている
curl -s 'http://127.0.0.1:3100/loki/api/v1/label/source/values'   # 4 source が見える
```

Grafana → Dashboards → tem-pad フォルダに Overview / AI Agent / Mac Network / Tailscale がある。

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `Tailscale API reachable: HTTP 403` | OAuth client の scope に読み取り権限がない。`logs:configuration:read` / `devices:core:read` を確認 |
| `Proton Pass authenticated: NG` | `pass-cli login` (利用者アカウント)。PAT セッションでは他 Agent のログは見えない |
| `Little Snitch access available: NG` | sudoers 断片、Little Snitch のターミナルアクセス許可、`cli_path` を確認 |
| `Docker / sbx CLI available: NG` | `sbx ls` で認証を確認。`sbx login` |
| Alloy が送れない (`timestamp too old`) | JSONL の timestamp が 7 日以上前。`reject_old_samples_max_age` を延ばすか、古い行を退避 |
| Grafana に何も出ない | `http://127.0.0.1:12345` で `loki.source.file` の targets を確認。`TEM_PAD_DATA_DIR` の glob が合っているか |
