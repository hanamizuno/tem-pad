"""共通フィクスチャ。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tem_pad.collectors.base import CollectorContext
from tem_pad.config import Config, GeneralConfig

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(*parts: str) -> Any:
    path = FIXTURES.joinpath(*parts)
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return text


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 6, 9, 0, tzinfo=UTC)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    cfg = Config(general=GeneralConfig(host="test-host", data_dir=tmp_path / "data"))
    cfg.little_snitch.use_sudo = False
    return cfg


@pytest.fixture
def ctx(config: Config, now: datetime) -> CollectorContext:
    context = CollectorContext.from_config(config)
    context.now = now
    return context
