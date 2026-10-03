---
type: ADR
title: src レイアウトと top-level tests/ を採用する
description: テンプレートの co-located tests 規約から変更した理由
tags: [tem-pad, conventions]
timestamp: 2026-09-06T00:00:00Z
---

# src レイアウトと top-level tests/ を採用する

## 状況

テンプレートは top-level package (`myapp/`) と co-located tests (`myapp/tests/`) を規約にしていた。tem-pad は `tem-pad` コマンドとして `uv tool install` される CLI で、source ごとの fixture を多数持つ。

## 決定

- パッケージは `src/tem_pad/` に置き、hatchling でビルドして `[project.scripts]` で `tem-pad` を提供する。
- テストは top-level `tests/` に置き、fixture は `tests/fixtures/<source>/` に集約する。`pythonpath = ["."]` で `tests.conftest` を import できるようにする。

## 理由

- fixture は source をまたいで使う (`scripts/make_sample_events.py` がサンプル JSONL を生成する) ため、1 か所にまとまっている方が都合がよい。
- `uv tool install .` で editable でない wheel をビルドする際、src レイアウトならテストや fixture が wheel に混入しない。

## 影響

- AGENTS.md の構成節を更新した。pytest の `--import-mode=importlib` はそのまま使う。
