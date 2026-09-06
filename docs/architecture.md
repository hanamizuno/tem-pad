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
- 重複排除は Runner が `event_id` で行う。`event_id` が `None` のイベント (device 差分など) は排除しない。
- 既読 ID は `state["seen_ids"]` に有界リスト (既定 5000 件) で保存する。overlap window で再取得した分はここで落ちる。

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

`raw/<source>/<UTC 時刻>-<名前>.json|csv` に、取得したレスポンスをそのまま保存する。例外は secret の混入が疑われる場合で、Proton Pass では `password` / `token` などのキーを保存前に落とす。

retention は MVP では手動 (`find ~/.local/share/tem-pad/raw -mtime +180 -delete` など)。将来は NAS 等への append-only archive を追加する予定で、そのときに raw と JSONL を rsync する形を想定している。

## 権限分離

- tem-pad 本体、Alloy、Grafana/Loki コンテナはすべてユーザー権限。
- Little Snitch CLI だけが root を要求するため、sudoers で `littlesnitch log-traffic *` のみ NOPASSWD 許可し、`sudo -n` で呼ぶ。他のサブコマンド (rule の書き換え等) は許可しない。
- Loki/Grafana は `127.0.0.1` にのみ bind し、リモートからは Tailscale Serve で到達する。

## 将来の拡張点

- WAX610 / ルーター syslog: Alloy に `loki.source.syslog` を足し、`source="syslog"` などの label を付ける。tem-pad 側の変更は不要。
- first-seen 検出 (Phase 2 以降): `events/*.jsonl` を読んで (actor, domain) などの組み合わせの初出を別 JSONL (`events/first-seen.jsonl`) に書く小さな Collector として追加できる。
- NAS archive: `events/` と `raw/` を append-only で別ホストへ複製する。
