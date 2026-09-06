"""共通 sanitizer と保存時の権限のテスト。"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tem_pad.models import Event
from tem_pad.procutil import CommandError, run_command
from tem_pad.sanitize import redact_text, sanitize
from tem_pad.storage import EventStore, RawStore


def test_sanitize_removes_secret_keys_recursively():
    data = {"item": "x", "Password": "p", "nested": [{"token": "t", "ok": 1}], "n": None}
    assert sanitize(data) == {"item": "x", "nested": [{"ok": 1}], "n": None}


def test_sanitize_redacts_known_secret_values_anywhere():
    data = {
        "old": "tskey-auth-kAbCdEf123456-XyZ",
        "new": ["pst_abcdefgh12345::TOKENKEY", "plain"],
        "note": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    }
    result = sanitize(data)
    assert result["old"] == "tskey-<redacted>"
    assert result["new"] == ["pst_<redacted>", "plain"]
    assert "abcdefghijklmnop" not in result["note"]
    assert "<redacted>" in result["note"]


def test_redact_text_leaves_normal_text():
    text = "connectCount,denyCount,tskey,pst_x,example.com"
    assert redact_text(text) == text  # 接頭辞だけ・短すぎるものは対象外


def test_event_store_creates_private_files_and_dirs(tmp_path: Path):
    store = EventStore(tmp_path / "data" / "events")
    store.append(
        [Event(timestamp=datetime(2026, 9, 6, tzinfo=UTC), source="s", kind="k", event_id="a")]
    )
    path = store.path_for("s")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    # 既存ファイルの緩い権限は append 時に直される
    path.chmod(0o644)
    store.append(
        [Event(timestamp=datetime(2026, 9, 6, tzinfo=UTC), source="s", kind="k", event_id="b")]
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_raw_store_directory_is_private(tmp_path: Path):
    raw = RawStore(tmp_path / "raw")
    path = raw.write_json("tailscale", "x", {"a": 1})
    assert path is not None
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600


def test_recent_event_ids_reads_tail(tmp_path: Path):
    store = EventStore(tmp_path / "events")
    events = [
        Event(
            timestamp=datetime(2026, 9, 6, 0, i, tzinfo=UTC),
            source="s",
            kind="k",
            event_id=f"id{i}",
        )
        for i in range(10)
    ]
    events.append(Event(timestamp=datetime(2026, 9, 6, 1, tzinfo=UTC), source="s", kind="k"))
    store.append(events)
    assert store.recent_event_ids("s", 3) == ["id8", "id9"]  # event_id None の行は除く
    assert store.recent_event_ids("s", 100) == [f"id{i}" for i in range(10)]
    assert store.recent_event_ids("missing", 5) == []
    assert store.recent_event_ids("s", 0) == []


def test_command_error_redacts_stderr():
    script = (
        "import sys; sys.stderr.write('auth failed for tskey-api-kSECRET0123456789'); sys.exit(1)"
    )
    with pytest.raises(CommandError) as excinfo:
        run_command([sys.executable, "-c", script], timeout=10)
    assert "kSECRET0123456789" not in str(excinfo.value)
    assert "tskey-<redacted>" in str(excinfo.value)
    assert excinfo.value.returncode == 1
