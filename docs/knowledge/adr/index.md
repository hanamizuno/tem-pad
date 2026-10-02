---
type: Index
title: Architecture Decision Records
description: Log of near-irreversible design decisions and the reasoning behind them
tags: [adr]
timestamp: 2026-06-30T00:00:00Z
---

# Architecture Decision Records

Record near-irreversible design decisions and **the reasoning behind them**, in chronological order. The format is a lightweight [MADR](https://adr.github.io/madr/)-style note.

## Naming

`NNNN-kebab-case-title.md` (four-digit zero-padded sequence number).

## Status vocabulary

* **Proposed** — under discussion; may not be implemented yet.
* **Accepted** — adopted; should match the current code.
* **Superseded** — replaced by a newer ADR. Note `Superseded by ADR-XXXX` in both the frontmatter `tags` and the body `# Status` section.
* **Deprecated** — retired without a direct replacement.

When the status of an ADR changes, update both the frontmatter `tags:` and the `# Status` section of the ADR body, and append an entry to [/docs/knowledge/log.md](/docs/knowledge/log.md).

## Index

* [0004-src-layout-and-top-level-tests.md](0004-src-layout-and-top-level-tests.md) — src レイアウトと top-level `tests/` を採用し、テンプレートの co-located tests 規約から変更した理由。
* [0003-jsonl-decoupled-pipeline.md](0003-jsonl-decoupled-pipeline.md) — Collector は Loki へ直接 push せず JSONL を介して Alloy に渡す。
* [0002-coexist-sbx-with-devcontainer.md](0002-coexist-sbx-with-devcontainer.md) — Run sbx alongside the Dev Container as a staged migration, and the criteria for retiring the latter's agent tooling.
