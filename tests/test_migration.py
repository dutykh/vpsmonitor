"""Migration of the legacy logs/alert_history.json.

The naive timestamps in that file were written with datetime.now(), i.e. the
host's LOCAL time (Asia/Dubai, +04). Verified against the log archive: a naive
entry of 22:00:30 matches a 22:00:30 local log line. The old code applied
replace(tzinfo=utc) to them, placing them four hours in the FUTURE and
over-suppressing alerts.
Author: Dr. Denys Dutykh.
"""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import monitor

DUBAI = ZoneInfo("Asia/Dubai")


def write_history(tmp_path, payload):
    path = tmp_path / "alert_history.json"
    path.write_text(json.dumps(payload))
    return path


def test_naive_timestamps_are_local_not_utc(tmp_path, engine, monkeypatch):
    """A naive 22:00:30 Dubai entry is 18:00:30 UTC, not 22:00:30 UTC."""
    path = write_history(tmp_path, {"https://example.com": "2026-01-18T22:00:30.789566"})
    report = engine.migrate_legacy_history(path, local_tz="Asia/Dubai")
    assert report["tz_fixed"] == 1

    naive = datetime.fromisoformat("2026-01-18T22:00:30.789566")
    correct = naive.replace(tzinfo=DUBAI).astimezone(timezone.utc)
    wrong = naive.replace(tzinfo=timezone.utc)
    assert correct.hour == 18 and wrong.hour == 22
    assert (wrong - correct) == timedelta(hours=4)


def test_stale_entries_dropped(tmp_path, engine):
    path = write_history(tmp_path, {
        "https://example.com": "2026-01-18T22:00:30+00:00",
        "https://events.gone.example": "2025-12-09T15:00:18",
        "https://www.events.gone.example": "2025-12-09T15:00:19",
    })
    report = engine.migrate_legacy_history(path, local_tz="Asia/Dubai")
    assert report["dropped_stale"] == 2


def test_healthy_target_does_not_inherit_a_cooldown(tmp_path, engine, config):
    """Carrying a stale cooldown onto a healthy target IS the swallowed-outage bug."""
    engine.apply(config.websites[0], True, {"status_code": 200, "error": None},
                 monitor.now_utc())
    path = write_history(tmp_path, {"https://example.com": "2026-01-18T22:00:30+00:00"})
    report = engine.migrate_legacy_history(path, local_tz="Asia/Dubai")
    assert report["skipped_up"] == 1
    assert report["imported"] == 0


def test_migration_runs_only_once(tmp_path, engine):
    path = write_history(tmp_path, {"https://example.com": "2026-01-18T22:00:30+00:00"})
    first = engine.migrate_legacy_history(path, local_tz="Asia/Dubai")
    second = engine.migrate_legacy_history(path, local_tz="Asia/Dubai")
    assert second == {"imported": 0, "skipped_up": 0, "dropped_stale": 0, "tz_fixed": 0}
    assert sum(first.values()) > 0


def test_raw_history_is_preserved_before_import(tmp_path, engine, db):
    payload = {"https://example.com": "2026-01-18T22:00:30+00:00"}
    engine.migrate_legacy_history(write_history(tmp_path, payload), local_tz="Asia/Dubai")
    assert json.loads(db.get_meta("legacy_alert_history_raw")) == payload


def test_corrupt_history_does_not_crash(tmp_path, engine):
    path = tmp_path / "alert_history.json"
    path.write_text("{ this is not json")
    assert engine.migrate_legacy_history(path, local_tz="Asia/Dubai")["imported"] == 0


def test_missing_file_is_fine(tmp_path, engine):
    assert engine.migrate_legacy_history(tmp_path / "nope.json")["imported"] == 0


def test_parse_dt_handles_both_shapes():
    assert monitor._parse_dt("2026-01-18T22:00:30+00:00").tzinfo is not None
    assert monitor._parse_dt("2026-01-18T22:00:30").tzinfo is not None
    assert monitor._parse_dt(None) is None
    assert monitor._parse_dt("garbage") is None
