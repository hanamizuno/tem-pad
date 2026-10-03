# アーキテクチャ

## 全体像

```text
 source            raw            normalize        JSONL           ship        store      view
─────────    ──────────────    ─────────────    ───────────    ──────────    ───────    ───────
Tailscale  →  raw/tailscale/  →  Event(...)   →  events/       →  Alloy    →  Loki   →  Grafana
pass-cli   →  raw/proton-pass →  Event(...)   →   *.jsonl         (tail)     (TSDB)     (Explore
littlesnitch→ raw/little-snitch→ Event(...)   →                                          + dashboards)
sbx        →  raw/docker-sandbox→Event(...)   →
Docker native audit JSONL ───────────────────────────────────→  Alloy (直接 tail)
```

各段は前後に依存しないよう分けている。

| 段 | 実装 | 責務 |
|---|---|---|
| Collector | `src/tem_pad/collectors/*.py` | 取得、raw 保存、正規化、state 管理 |
| Runner | `collectors/base.py::run_collector` | 有効判定、例外の封じ込め、重複排除、JSONL 追記、state の atomic 保存 |
| Storage | `storage.py` / `state.py` | JSONL 追記 (1 行 1 イベント)、raw の保存、state の atomic write、有界の既読 ID |
| Ship | `deploy/alloy/config.alloy` | JSONL の tail、label 付与、Loki push |
| Store | `deploy/loki/config.yaml` + `compose.yaml` | single-node Loki、TSDB、90 日 retention |
| View | `deploy/grafana/` | Data Source provisioning、dashboard |

## なぜ Collector が Loki へ直接 push しないか

- Loki が停止・再構築されていても収集は続く (JSONL に溜まり、Alloy が後から送る)。
- raw と JSONL が残るので、schema を変えたときに再 normalize できる。
- Loki 以外 (別ホストの Loki、S3、SIEM) へ移すときも Alloy の設定変更だけで済む。
- Collector を「1 回実行して終わる CLI」にできる。launchd の `StartInterval` で定期実行するだけで済み、常駐プロセスを監視する必要もない。

## Collector の共通契約

```python
class Collector(Protocol):
    name: str

    def enabled(self, config: Config) -> bool: ...
    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput: ...
```

- `collect()` は `Event` のリストと、保存したい新しい `state` を返す。失敗時は例外を投げる。Runner はそれを捕捉して `state` を進めないので、次回は同じ区間を取り直す。
- 重複排除は Runner が `event_id` で行う。すべての Collector が決定的な `event_id` を付ける (device 差分も `device:<nodeId>:<kind>:<差分のハッシュ>`)。
- 既読 ID は `state["seen_ids"]` に有界リスト (既定 5000 件) で保存する。overlap window で再取得した分はここで除外される。
- **クラッシュ耐性**: JSONL への append と state 保存は別操作なので、その間でクラッシュすると state は古いまま残る。そこで Runner は毎回 JSONL の末尾 (既定 5000 行) から `event_id` を読み直して既読集合に加える。これにより、古い state から同じイベントを再生成しても二重には書き込まない。

## 増分取得と overlap

| source | カーソル | overlap | 重複排除キー |
|---|---|---|---|
| tailscale (audit) | `audit_cursor` = 前回終了時刻 | 60 秒 | エントリ内容の sha256 |
| tailscale (devices) | `devices` = 前回スナップショット | なし (差分) | なし |
| proton-pass | Agent ごとの `last_record_id` (参考値) | 常に直近 N 件を取得 | `agent:record_id` |
| little-snitch | `cursor` = 前回終了時刻 (現在 - 90 秒) | 60 秒 | CSV 行の sha256 |
| docker-sandbox (policy-log) | `rows` = 前回の集計行 (count, last_seen) | なし (差分) | 行内容の sha256 |

Little Snitch は 1 分粒度の集計行を返すため、集計中の直近区間を取得すると、次回に数値が変わって二重計上になる。そのため終端を「現在 - 90 秒」にしている。

## Loki の label 設計

label は `source` / `host` / `kind` / `decision` / `schema` (固定値) だけ。cardinality を増やす値 (remote IP、domain、PID、process path、Proton Pass の item/vault、sandbox ID、audit session ID、Tailscale device ID) は本文 JSON に置き、LogQL の `| json` で検索する。

Alloy 側では `stage.json` で Envelope の 5 フィールドだけを抜き出し、`stage.labels` で label 化する。`decision` が `null` のイベントには label を付けない。

## raw log

`raw/<source>/<UTC 時刻>-<名前>.json|csv` に、取得したレスポンスを保存する。保存前には共通 sanitizer (`sanitize.py`) を通し、`password` / `token` / `secret` などのキーを削除したうえで、既知の secret 形式 (`tskey-…`, `pst_…::…`, `Bearer …`) に一致する値を伏せ字にする。監査ログには本来 secret が含まれないはずだが、API の仕様変更や設定ミスに備える防御層として全 source に適用している。

`events/`、`raw/`、`state/` のディレクトリは 0700、ファイルは 0600 で作成し、既存の権限が緩ければ書き込み時に修正する (umask には依存しない)。

保持期間は `general.raw_retention_days` (既定 180 日) で指定し、`collect` のたびに source ごとに古いファイルを削除する。`<source>.save_raw = false` で source 単位に保存を止められる。ただし証跡が残らなくなるため、Little Snitch のような高頻度な source に限るのが望ましい。将来は NAS などへの append-only archive を追加し、raw と JSONL を rsync で複製する想定である。

## 並行実行の排他

Runner は source ごとに `state/<source>.lock` へ `flock` を掛け、取得できなければ待たずにスキップする (`collect` の出力に「別プロセスが収集中」と表示される)。これにより、launchd の定期実行と手動実行が重なっても、同じ state から同じイベントを二重に書き込まない。

## 権限分離

- tem-pad 本体、Alloy、Grafana/Loki コンテナはすべてユーザー権限。
- Little Snitch CLI だけが root を要求するため、sudoers で `littlesnitch log-traffic *` のみ NOPASSWD 許可し、`sudo -n` で呼ぶ。他のサブコマンド (ルールの書き換えなど) は許可しない。
- Loki/Grafana は `127.0.0.1` にのみ bind し、リモートからは Tailscale Serve で到達する。

## 将来の拡張点

- WAX610 / ルーター syslog: Alloy に `loki.source.syslog` を足し、`source="syslog"` などの label を付ける。tem-pad 側の変更は不要。
- first-seen 検出 (Phase 2 以降): `events/*.jsonl` を読んで (actor, domain) などの組み合わせの初出を別 JSONL (`events/first-seen.jsonl`) に書く小さな Collector として追加できる。
- NAS archive: `events/` と `raw/` を append-only で別ホストへ複製する。
