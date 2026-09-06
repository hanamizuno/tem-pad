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
- Collector の実装を「1 回走って終わる CLI」に保てるため、launchd の `StartInterval` で回すだけでよく、常駐プロセスの健全性を気にしなくてよい。

## Collector の共通契約

```python
class Collector(Protocol):
    name: str

    def enabled(self, config: Config) -> bool: ...
    def collect(self, ctx: CollectorContext, state: dict[str, Any]) -> CollectOutput: ...
```

- `collect()` は `Event` のリストと、保存したい新しい `state` を返す。失敗時は例外を投げ、Runner が捕まえて `state` を進めない (次回同じ区間を取り直す)。
- 重複排除は Runner が `event_id` で行う。すべての Collector が決定的な `event_id` を付ける (device 差分も `device:<nodeId>:<kind>:<差分のハッシュ>`)。
- 既読 ID は `state["seen_ids"]` に有界リスト (既定 5000 件) で保存する。overlap window で再取得した分はここで落ちる。
- **クラッシュ耐性**: JSONL への append と state 保存は別操作なので、その間で落ちると state は古いまま残る。Runner は毎回 JSONL の末尾 (既定 5000 行) から `event_id` を読み直して既読集合に加えるため、古い state から同じイベントを再計算しても重複して書かない。

## 増分取得と overlap

| source | カーソル | overlap | 重複排除キー |
|---|---|---|---|
| tailscale (audit) | `audit_cursor` = 前回終了時刻 | 60 秒 | エントリ内容の sha256 |
| tailscale (devices) | `devices` = 前回スナップショット | なし (差分) | なし |
| proton-pass | Agent ごとの `last_record_id` (参考値) | 常に直近 N 件を取得 | `agent:record_id` |
| little-snitch | `cursor` = 前回終了時刻 (現在 - 90 秒) | 60 秒 | CSV 行の sha256 |
| docker-sandbox (policy-log) | `rows` = 前回の集計行 (count, last_seen) | なし (差分) | 行内容の sha256 |

Little Snitch は 1 分粒度の集計行を返すため、集計中の直近区間を取ると次回に数値が変わって二重計上になる。そのため終端を「現在 - 90 秒」にしている。

## Loki の label 設計

label は `source` / `host` / `kind` / `decision` / `schema` (固定値) だけ。cardinality を増やす値 (remote IP、domain、PID、process path、Proton Pass の item/vault、sandbox ID、audit session ID、Tailscale device ID) は本文 JSON に置き、LogQL の `| json` で検索する。

Alloy 側では `stage.json` で Envelope の 5 フィールドだけを抜き、`stage.labels` で label 化する。`decision` が `null` のイベントには label を付けない。

## raw log

`raw/<source>/<UTC 時刻>-<名前>.json|csv` に、取得したレスポンスを保存する。保存前に共通 sanitizer (`sanitize.py`) を通し、`password` / `token` / `secret` などのキーを削除し、既知の secret 形式 (`tskey-…`, `pst_…::…`, `Bearer …`) に一致する値を伏せ字にする。監査ログに secret が含まれない想定でも、API の仕様変更や誤設定に備えた防御層として全 source に適用する。

`events/`、`raw/`、`state/` のディレクトリは 0700、ファイルは 0600 で作成し、緩い権限を見つけたら書き込み時に直す (umask に依存しない)。

retention は `general.raw_retention_days` (既定 180 日) で、`collect` のたびに source ごとの古いファイルを削除する。`<source>.save_raw = false` で source 単位に保存を止められるが、証跡が残らなくなるので高頻度な source (Little Snitch など) に限るのが望ましい。将来は NAS 等への append-only archive を追加する予定で、そのときに raw と JSONL を rsync する形を想定している。

## 並行実行の排他

Runner は source ごとに `state/<source>.lock` へ `flock` を掛け、取れなければ待たずに skip する (`collect` の出力に「別プロセスが収集中」と出る)。launchd の定期実行と手動実行が重なったときに、同じ state から同じイベントを二重に書くのを防ぐ。

## 権限分離

- tem-pad 本体、Alloy、Grafana/Loki コンテナはすべてユーザー権限。
- Little Snitch CLI だけが root を要求するため、sudoers で `littlesnitch log-traffic *` のみ NOPASSWD 許可し、`sudo -n` で呼ぶ。他のサブコマンド (rule の書き換え等) は許可しない。
- Loki/Grafana は `127.0.0.1` にのみ bind し、リモートからは Tailscale Serve で到達する。

## 将来の拡張点

- WAX610 / ルーター syslog: Alloy に `loki.source.syslog` を足し、`source="syslog"` などの label を付ける。tem-pad 側の変更は不要。
- first-seen 検出 (Phase 2 以降): `events/*.jsonl` を読んで (actor, domain) などの組み合わせの初出を別 JSONL (`events/first-seen.jsonl`) に書く小さな Collector として追加できる。
- NAS archive: `events/` と `raw/` を append-only で別ホストへ複製する。
