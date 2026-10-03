# 実装メモ (外部仕様の確認結果と差分)

指示書の想定、実装時 (2026-09-06) に確認できた現行仕様、実機で未確認の点をまとめる。実機 (Mac Studio) で確認したら本ファイルと fixture を更新する。

## 調査環境の制約

実装は Docker Sandboxes (deny-by-default network) 内で行った。到達できた一次情報は次の通り。

| 対象 | 到達できた資料 | 到達できなかった資料 |
|---|---|---|
| Tailscale | 公式 Go クライアント `tailscale/tailscale-client-go-v2` (devices / oauth / logging のソース)、GitHub issue #15969, #16911 | `tailscale.com/api`, `tailscale.com/kb/*` (ネットワークポリシーで遮断) |
| Proton Pass | `protonpass/pass-cli` リポジトリの docs (`commands/agent.md`, `personal-access-token.md`, `get-started/configuration.md`)、CHANGELOG (2.3.3) | `protonpass.github.io` (同内容の公開版) |
| Docker Sandboxes | `docs.docker.com/ai/sandboxes/governance/audit/*`, `monitor-and-enforce/monitoring`, `access-controls/local`, `troubleshooting`, release notes | (なし) |
| Little Snitch | Web 検索のスニペット (`help.obdev.at/littlesnitch6/cmd-log-traffic`)、`Neo23x0/littlesnitch-log-exporter` の README (LS5 の CSV 例) | `help.obdev.at` 本文 |
| Grafana | `grafana/alloy` の docs ソース、`grafana/loki` の `loki-local-config.yaml`、`grafana/grafana` の provisioning docs | `grafana.com/docs` |

## Tailscale

### 想定と現状

| 項目 | 指示書の想定 | 確認できた現行仕様 | 対応 |
|---|---|---|---|
| 認証 | OAuth client 優先 | client credentials: `POST /api/v2/oauth/token` に `client_id` / `client_secret` (form)。`access_token` を Bearer で使う (Go client `oauth.go`, issue #15969)。API access token は Basic 認証のユーザー名 | 両対応。OAuth があれば優先 |
| scope | 最小限 | 読み取り scope は `devices:core:read` と `logs:configuration:read` という名称 (検索スニペットで確認。`tailscale.com/kb/1623` 本文は未確認) | `oauth_scopes` は既定で空 (client に付与した全 scope を使う)。client 作成時に UI 上の名称を確認するよう setup.md に記載 |
| 監査ログ API | `GET /api/v2/tailnet/{tailnet}/logging/configuration?start=&end=` | エンドポイントは存在を確認 (Go client の `LoggingResource` は logstream 設定と network flow logs のみで、configuration audit の取得メソッドは v2.10.1 時点で未実装)。レスポンスは `{"logs": [...]}`、エントリは `eventGroupID`, `origin`, `actor{id,loginName,displayName,type}`, `target{id,name,type,property}`, `action`, `old`, `new`, `eventTime`, `deferredAt` (公式 KB の要約から) | 上記フィールドを payload に写し、未知フィールドは `payload.extra` に残す。`target.type` の実際の値 (`NODE`, `USER`, `POLICY_FILE` 等) は **実機で要確認**。`kind` 判定は部分一致なので多少の違いは吸収する |
| 共有 device | - | OAuth token では他 tailnet から共有された device が一覧に出ない (issue #16911) | 制約として記載のみ |
| device API | `GET /api/v2/tailnet/{tailnet}/devices` | `fields=all` で詳細フィールドを含む。`nodeId` が推奨識別子 | `fields=all` で取得し、`nodeId` をキーに差分 |

### 実機で確認すること

- 監査ログレスポンスの実フィールド名と `target.type` / `action` の値。1 件を `raw/tailscale/` から匿名化して `tests/fixtures/tailscale/audit_logs.json` に反映する。
- `start`/`end` の最大範囲と、指定できる過去の上限 (KB では 90 日保持)。

## Proton Pass CLI (2.3.3)

| 項目 | 指示書の想定 | 現行仕様 | 対応 |
|---|---|---|---|
| Agent 一覧 | `pass-cli agent list --output json` | 同じ。human 出力は `- [pat_abc123]: my-agent (expires: ...)`。JSON のキー名はドキュメントに記載なし | `name`/`agent_name`/`title`、`id`/`pat_id` など候補キーを順に探す |
| 監査ログ | `pass-cli agent monitor <agent> --limit ... --output json` | 同じ。利用者セッションでは `<NAME>` 必須、Agent 自身のセッションでは省略可。既定 limit 100。human 出力は `[record_001] action=ItemRead vault="..." item="..." reason="..." (object_id=item_xyz)` | `record_id`/`id`、`action`、`vault`/`share_id`、`item`/`object_id`、`reason`、時刻は epoch (秒/ミリ秒) と ISO の両対応 |
| 監査対象操作 | - | `item view/create/update/trash/untrash/move`, `vault update` が reason 必須 | 変更系を `agent_write` に分類 |
| 取得位置 | Agent ごとの前回位置を state に保存 | `agent monitor` は直近 `--limit` 件を返すのみで、cursor / since / ページングはドキュメント上存在しない | 毎回直近 N 件を取得して `event_id` で重複排除。取得件数が N 件に達したら取りこぼしの可能性があるとして warning を出し、state に `limit_reached` を記録する。CLI にページングが追加されたら `last_record_id` まで遡る実装に変える |
| セッション | - | Agent/PAT セッションは 2 時間で失効、session lock 不可。セッション保存先 macOS: `~/Library/Application Support/proton-pass-cli/.session/` | doctor で `pass-cli info` を確認 |
| 注意 | - | 2.2.1 で「agent audit log を誤った形式で保存する」バグ修正あり | 2.2.1 以降を前提 |

### 実機で確認すること

- `agent monitor` に `--since` / cursor / ページングに相当するオプションが増えていないか (`pass-cli agent monitor --help`)。
- `agent list` / `agent monitor` の JSON キー名。確認後に候補キーを絞り、fixture を実出力ベースに置き換える。
- `--output json` の出力に人間向けの行が混ざるか (混ざる場合も `parse_json_output` が最初の JSON を拾う)。

## Docker Sandboxes

| 項目 | 指示書の想定 | 現行仕様 | 対応 |
|---|---|---|---|
| native audit | Docker AI Governance の JSONL があれば Alloy で直接 tail | **有償の AI Governance プラン + 強制された組織ポリシー + サインイン済みユーザーが前提。個人アカウントは非対応。** 出力先 macOS: `~/Library/Logs/com.docker.sandboxes/sandboxes/auditkit/audit-<utc>-<uuid>-<seq>.jsonl`。`.tmp` に書いて atomic rename、5 分/1000 件/50 MiB で確定。`.jsonl` は自動削除されない (削除は収集側の責任) | `mode = auto` は `.jsonl` の存在で判定。Alloy は `*.jsonl` のみ読む。個人環境では policy-log にフォールバック |
| record schema | - | 共通: `audit_event_id`, `timestamp`, `schema_version` (例 1.82.0), `category` (MANAGEMENT/EVALUATION/EXECUTION), `decision` (`AUDIT_DECISION_ALLOW/DENY/APPROVAL_REQUIRED/APPROVED/REJECTED`), `username`, `user_email`, `org_id`, `org_name`, `audit_session_id`, `resource_id`, `os`, `app_version`, `client_name`, `hostname`, `deny_reason[]`, `action_type`, `agent`。`action_type`: `session`, `network_egress`, `filesystem_mount`, `tool_invocation`, `resource_read`, `server_registration`, `prompt`, `network_execution`, `filesystem_execution`, `tool_execution`, `resource_execution`, `policy_sync`, `pii_detection`, `c_score_report`, `policy_action` | Alloy 側で `action_type` → `kind`、`decision` → allow/deny に写す。`user_email` を含むため Loki に入れる前に除去したい場合は `stage.replace` を追加する |
| fallback | `sbx policy log --json` | 存在を確認。`--limit N`, `--type network`, sandbox 名の位置引数。表示列は SANDBOX / TYPE / HOST / PROXY / RULE / REASON / LAST SEEN / COUNT、Blocked と Allowed に分かれる。**記録は network のみ**、filesystem は未対応。JSON のキー名はドキュメントに記載なし | 配列と `{blocked: [...], allowed: [...]}` の両形式、キー名の候補 (`sandbox`, `host`, `proxy`, `rule`, `reason`, `last_seen`/`lastSeen`, `count`, `decision`) に対応。集計値なので前回との差分だけをイベント化 |
| PROXY 列 | - | `forward` / `forward-bypass` / `transparent` / `network` / `browser-open` | payload.proxy にそのまま保存 |

### 実機で確認すること

- `sbx policy log --json --limit 5` の出力形式 (トップレベルが配列か、blocked/allowed で分かれるか、`last_seen` の形式)。確認後に fixture を置き換える。
- `--limit` が `--json` と併用できるか。できなければ `policy_log_limit` を無視する実装に変える。

## Little Snitch 6

| 項目 | 指示書の想定 | 現行仕様 (検索スニペット) | 対応 |
|---|---|---|---|
| CLI | Little Snitch 6 の CLI | `/Applications/Little Snitch.app/Contents/Components/littlesnitch`。`log-traffic` は `-b/--begin-date <YYYY-MM-DD HH:MM:SS>`, `-e/--end-date`, `-s/--stream`。出力は CSV で 1 行目がヘッダ。多くのサブコマンドが root を要求 | poll 方式 (`--begin-date`/`--end-date`)。`sudo -n` 経由。ヘッダ名で列を解決 |
| CSV 列 | timestamp, direction, executable, parent app, remote host, IP, port, protocol, counts, bytes | LS5 の実例: `date,direction,uid,ipAddress,remoteHostname,protocol,port,connectCount,denyCount,byteCountIn,byteCountOut,connectingExecutable,parentAppExecutable` (LS6 で同じかは未確認) | 列名の候補を持つ寛容なパーサ。未知列は `payload.extra` |
| 日時の timezone | - | `--begin-date` がローカル時刻か UTC か未確認。CSV の `date` は例では UTC (`Z` 付き) | 引数はローカル時刻で渡す (要確認)。CSV は RFC 3339 として解釈 |
| 権限 | root を最小化 | Settings → Security の「ターミナルからのアクセスを許可」が必要 | sudoers で `log-traffic *` のみ許可 |

### 実機で確認すること

- `littlesnitch log-traffic --help` の実オプション名と、`--begin-date` の timezone。
- CSV ヘッダ。LS6 で列が変わっていれば `_COLUMNS` の候補と fixture を更新。
- 1 分集計の境界 (`SETTLE_SECONDS = 90` で足りるか)。

## Grafana Alloy / Loki / Grafana

- Alloy 1.19.2、Loki 3.5.3、Grafana 12.1.1 でサンプル JSONL の end-to-end (JSONL → Alloy → Loki → label 付与) を Linux コンテナ上で確認した。macOS ネイティブの Alloy でも設定ファイルは同一。
- `loki.source.file` は `local.file_match` で glob を展開する構成にした。positions は `--storage.path` 配下に保存される。
- Loki は `schema v13` + TSDB、`retention_period: 2160h` (90 日)、compactor で削除。`discover_service_name: []` で自動 `service_name` label を無効化。
- `decision` が null のイベントに label を付けないため、Alloy では `stage.match` の selector (`| json | decision =~ "allow|deny|unknown"`) で条件付きで `stage.labels` を適用している。無条件に適用すると label 値が `"<no value>"` になることを確認した。

## 指示書からの意図的な変更

| 項目 | 指示書 | 実装 | 理由 |
|---|---|---|---|
| ディレクトリ構成 | `tests/` にテスト | `tests/` (top-level) + `tests/fixtures/` | 指示書どおり。テンプレートの「co-located tests」規約からは変更し、AGENTS.md を更新 |
| Python | 3.12+ | `requires-python >= 3.12`、開発環境は 3.14 | 互換性を広く保つ。`tomllib`/`datetime.UTC` は 3.11+ で利用可 |
| Envelope | 8 フィールド | 8 フィールド + `event_id` | 重複排除と Loki 上での同一性確認のため |
| Tailscale devices の周期 | 10 分 | `collect tailscale` 内で `devices_interval_seconds` (既定 600 秒) で実行頻度を抑える | launchd の job を 1 つにまとめるため |
| launchd | source ごとの job | `collect all` を 60 秒ごと 1 job | 各 Collector が自前で間隔・overlap を持つため。分けたい場合は plist を複製する |
| データ置き場 | `~/.local/share/tem-pad` | 同じ (README に理由を記載) | パスに空白がなく Alloy/launchd/sudoers の記述が単純 |
