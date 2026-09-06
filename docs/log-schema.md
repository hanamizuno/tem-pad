# ログスキーマ

すべてのイベントは共通 Envelope を持ち、source 固有の値は `payload` に入れる。JSONL の 1 行が 1 イベント。

## Envelope

| フィールド | 型 | 説明 | Loki label |
|---|---|---|---|
| `timestamp` | string (RFC 3339, UTC, `Z` 終端) | イベント発生時刻。取得元に時刻がなければ取得時刻 | (時刻) |
| `source` | string | `tailscale` / `proton-pass` / `little-snitch` / `docker-sandbox` | yes |
| `kind` | string | source 内の種別 (下表)。判別不能なら `unknown` | yes |
| `host` | string \| null | 観測ホスト (`general.host`) | yes |
| `actor` | string \| null | 行為者 (ユーザー、Agent、プロセス名、sandbox 名) | no |
| `action` | string \| null | 行為 (`connect`, `ItemRead`, `UPDATE`, `added` など) | no |
| `decision` | `allow` \| `deny` \| `unknown` \| null | 判定。判定を持たないイベントは null | yes (null なら付けない) |
| `event_id` | string \| null | source 内で一意な ID。重複排除に使う。差分イベントは null | no |
| `payload` | object | source 固有。以下参照 | no |

Alloy は固定 label `schema="tem-pad-v1"` を付ける。Docker native audit を直接 tail した行には `schema="docker-audit-native"`, `source="docker-sandbox"` を付け、`action_type` を `kind` に、`AUDIT_DECISION_*` を `allow`/`deny` に写す。

## kind 一覧

### tailscale

| kind | 由来 | payload の主なキー |
|---|---|---|
| `audit_device` | audit log, target.type が NODE/DEVICE | `event_group_id`, `origin`, `actor_id`, `actor_type`, `target_id`, `target_name`, `target_type`, `target_property`, `old`, `new` |
| `audit_user` | target.type が USER | 同上 |
| `audit_policy` | target.type が POLICY/ACL | 同上 |
| `audit_key` | target.type が KEY/AUTH_KEY/OAUTH/API | 同上 |
| `audit_tailnet` | target.type が TAILNET/DNS/SETTING | 同上 |
| `audit_other` | 上記以外の target.type、または target なし | 同上 (+ `extra` に未知フィールド) |
| `device_added` | device 一覧の差分 | `node_id`, `device_name`, `hostname`, `os`, `user`, `tags`, `authorized`, `addresses`, `is_external`, `is_ephemeral` |
| `device_removed` | 同上 | 同上 |
| `device_changed` | 同上 | 同上 + `changes: {field: {old, new}}` |

`actor` は audit では `actor.loginName` (なければ displayName / id)、device 系では device の `user`。`action` は audit の `action` (CREATE/UPDATE/DELETE 等)、device 系では `added`/`removed`/`changed`。

### proton-pass

| kind | 条件 | payload |
|---|---|---|
| `agent_read` | action に create/update/trash/move/delete 等を含まない | `agent`, `agent_id`, `record_id`, `vault`, `vault_id`, `item`, `item_id`, `reason`, `reason_missing` |
| `agent_write` | 変更系 action | 同上 |
| `unknown` | action なし | 同上 |

`actor` は Agent 名、`action` は監査記録の action (`ItemRead` 等)。`vault` / `vault_id` / `item` / `item_id` / `reason` は `proton_pass.redact_mode` で `sha256:<16 桁>` に置換 (`hash`) または null (`drop`) にできる。`reason_missing` は reason が空のときに true。

### little-snitch

| kind | 条件 | payload |
|---|---|---|
| `connection` | denyCount が 0 | `direction`, `uid`, `remote_ip`, `remote_host`, `protocol`, `protocol_number`, `port`, `connect_count`, `deny_count`, `bytes_in`, `bytes_out`, `executable`, `process`, `parent_app` |
| `connection_denied` | denyCount > 0 | 同上 |

`actor` は実行ファイル名 (`process`)、`action` は out なら `connect`、in なら `accept`、`decision` は deny の有無。CSV に未知の列があれば `extra` に入る。

### docker-sandbox (policy-log モード)

| kind | payload |
|---|---|
| `network_egress` | `sandbox`, `agent` (sandbox 名からの推定), `policy_type`, `remote_host`, `domain`, `proxy`, `rule`, `reason`, `count`, `count_delta`, `last_seen`, `collection_mode="policy-log"` |

`actor` は sandbox 名、`action` は `connect`、`decision` は allow/deny。`count_delta` は前回取得からの増分 (初回は count そのもの)。

### docker-sandbox (native audit を Alloy が直接読む場合)

Docker の record schema そのまま。主なフィールド: `audit_event_id`, `timestamp`, `schema_version`, `category`, `decision`, `audit_session_id`, `resource_id`, `client_name`, `hostname`, `deny_reason[]`, `action_type`, `<action_type>` オブジェクト, `agent`。`action_type` は `network_egress`, `filesystem_mount`, `tool_invocation`, `resource_read`, `session`, `network_execution` など。

## LogQL の例

```logql
# 過去 24 時間に Claude がアクセスした外部 domain (policy-log)
{source="docker-sandbox"} | json | payload_agent="claude" | line_format "{{.payload_domain}}"

# Docker Sandbox で DENY された通信
{source="docker-sandbox", decision="deny"} | json

# Little Snitch 上で Docker / Claude 関連プロセスが通信した相手
{source="little-snitch"} | json | payload_process=~"(?i)docker|claude|com\\.docker.*"
  | line_format "{{.payload_process}} -> {{.payload_remote_host}}:{{.payload_port}}"

# Proton Pass Agent がアクセスした item
{source="proton-pass"} | json | line_format "{{.actor}} {{.action}} {{.payload_vault}}/{{.payload_item}} ({{.payload_reason}})"

# Tailnet へ追加された device
{source="tailscale", kind="device_added"} | json

# reason なしの Agent アクセス
{source="proton-pass"} | json | payload_reason_missing="true"
```

## 互換性の方針

- フィールドの追加は後方互換。削除・意味変更をする場合は Alloy の `schema` label の値を上げる。
- 未知のイベントは捨てず `kind="unknown"` または `payload.extra` / `payload.raw` に残す。
- raw を保存しているので、schema 変更後の再 normalize が可能。
