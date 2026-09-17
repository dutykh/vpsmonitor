"""Incident state machine.

The first test here is the reason this rewrite exists: under the old
implementation a site that went down, recovered, then failed again inside the
cooldown window was silently NOT alerted.
Author: Dr. Denys Dutykh.
"""
from datetime import timedelta

import monitor

OK = {"status_code": 200, "response_time_ms": 12.0, "error": None}


def fail(error="Unexpected status code: 503", code=503):
    return {"status_code": code, "response_time_ms": 9.0, "error": error}


def test_reoutage_after_recovery_alerts_again(engine, config):
    """THE bug: down -> alert -> recover -> down again 20 min later -> must alert."""
    target = config.websites[0]
    t0 = monitor.now_utc()

    first = engine.apply(target, False, fail(), t0)
    assert first.kind == "DOWN"

    recovered = engine.apply(target, True, dict(OK), t0 + timedelta(minutes=10))
    assert recovered.kind == "RESOLVED"

    # 20 minutes later, well inside the old 1-hour cooldown.
    again = engine.apply(target, False, fail(), t0 + timedelta(minutes=30))
    assert again.kind == "DOWN", "a new outage must alert even inside the old cooldown"
    assert again.incident_id != first.incident_id, "it must be a NEW incident"


def test_recovery_reports_duration(engine, config):
    target = config.websites[0]
    t0 = monitor.now_utc()
    engine.apply(target, False, fail(), t0)
    resolved = engine.apply(target, True, dict(OK), t0 + timedelta(hours=2, minutes=30))
    assert resolved.kind == "RESOLVED"
    assert 8900 < resolved.duration_s < 9100
    assert monitor.human_duration(resolved.duration_s) == "2h 30m"


def test_repeated_failures_do_not_spam(engine, config):
    """Hourly checks during an outage must follow the escalation ladder."""
    target = config.websites[0]
    t0 = monitor.now_utc()
    kinds = []
    for hour in range(8):
        tr = engine.apply(target, False, fail(), t0 + timedelta(seconds=hour * 3600 - 3))
        kinds.append(tr.kind)
    assert kinds[0] == "DOWN"
    assert [i for i, k in enumerate(kinds) if k] == [0, 1, 3, 7]


def test_only_one_open_incident_per_target(engine, config, db):
    target = config.websites[0]
    t0 = monitor.now_utc()
    for hour in range(5):
        engine.apply(target, False, fail(), t0 + timedelta(hours=hour))
    rows = db.query("SELECT * FROM incidents WHERE status = 'open'")
    assert len(rows) == 1
    assert rows[0]["checks_failed"] == 5


def test_cold_start_does_not_alert_but_still_opens_incident(engine, config, db):
    target = config.websites[0]
    t0 = monitor.now_utc()
    tr = engine.apply(target, False, fail(), t0, cold_start=True)
    assert tr.kind is None, "the very first run must not page about pre-existing failures"
    assert tr.suppressed_by == "cold_start"
    assert len(db.query("SELECT * FROM incidents WHERE status = 'open'")) == 1


def test_suppressed_incident_still_alerts_if_it_persists(engine, config):
    """Suppression must never permanently silence a lasting outage."""
    target = config.websites[0]
    t0 = monitor.now_utc()
    engine.apply(target, False, fail(), t0, cold_start=True)
    later = engine.apply(target, False, fail(), t0 + timedelta(hours=1))
    assert later.kind == "DOWN"


def test_no_resolved_email_for_never_alerted_incident(engine, config):
    target = config.websites[0]
    t0 = monitor.now_utc()
    engine.apply(target, False, fail(), t0, cold_start=True)
    resolved = engine.apply(target, True, dict(OK), t0 + timedelta(minutes=5))
    assert resolved.kind is None, "never announce resolving something never announced"


def test_targets_are_independent(engine, config):
    apex, www = config.websites[0], config.websites[1]
    t0 = monitor.now_utc()
    assert engine.apply(apex, False, fail(), t0).kind == "DOWN"
    assert engine.apply(www, True, dict(OK), t0).kind is None
    assert engine.apply(www, False, fail(), t0 + timedelta(minutes=1)).kind == "DOWN"


def test_one_run_timestamp_keeps_twins_in_step(engine, config):
    """apex and www checked in the same run must never straddle a threshold.

    Previously each alert stamped its own datetime.now(), so twins drifted apart
    by a few seconds and alerted on alternate hours.
    """
    apex, www = config.websites[0], config.websites[1]
    t0 = monitor.now_utc()
    engine.apply(apex, False, fail(), t0)
    engine.apply(www, False, fail(), t0)
    for hour in range(1, 6):
        run_ts = t0 + timedelta(seconds=hour * 3600 - 3)
        a = engine.apply(apex, False, fail(), run_ts)
        w = engine.apply(www, False, fail(), run_ts)
        assert bool(a.kind) == bool(w.kind), f"twins diverged at hour {hour}"


def test_failure_threshold_delays_incident(db, monkeypatch):
    monkeypatch.setenv("FAILURE_THRESHOLD", "2")
    cfg = monitor.Config()
    ids = db.sync_targets(cfg.targets)
    eng = monitor.IncidentEngine(db, cfg, ids)
    target = cfg.websites[0]
    t0 = monitor.now_utc()
    assert eng.apply(target, False, fail(), t0).kind is None
    assert eng.apply(target, False, fail(), t0 + timedelta(hours=1)).kind == "DOWN"
