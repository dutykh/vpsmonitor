"""Summaries: the classic table, the brief form for a chat, JSON, and --print.
Author: Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and
Technology, Abu Dhabi, UAE)."""
import json
from datetime import timedelta

import pytest

import monitor

OK = {"status_code": 200, "response_time_ms": 120.0, "error": None}


def fail(code=503):
    return {"status_code": code, "response_time_ms": 9.0,
            "error": f"Unexpected status code: {code}"}


@pytest.fixture
def world(db, config):
    """Two targets checked a few times, a completed run, and certificate rows for
    both hosts and for one no longer monitored."""
    config.ssl_check_enabled = True
    ids = db.sync_targets(config.targets)
    engine = monitor.IncidentEngine(db, config, ids)
    now = monitor.now_utc()
    for minutes in (50, 40, 30, 20, 10):
        for target in config.targets:
            engine.apply(target, True, dict(OK), now - timedelta(minutes=minutes))
    db.execute("INSERT INTO runs(started_at, finished_at, n_targets) VALUES(?,?,2)",
               ((now - timedelta(minutes=1)).isoformat(), now.isoformat()))
    for host, days in (("example.com", 40), ("www.example.com", 60), ("gone.example", 3)):
        db.execute("INSERT INTO certs(host, not_after, issuer, last_checked_at) VALUES(?,?,?,?)",
                   (host, (now + timedelta(days=days, hours=1)).isoformat(), "Let's Encrypt",
                    now.isoformat()))
    return db, config, engine, now


def test_brief_on_a_quiet_day(world):
    db, config, _engine, _now = world
    subject, text = monitor.Reporter(db, config).render_brief(1, "Daily")
    first = text.splitlines()[0]
    assert first.startswith("✅ Daily summary: all 2 targets up, 100.00% uptime over the 24 hours to ")
    assert first.endswith("no incident.")
    assert "Slowest answers (p95): example.com 120 ms" in text
    assert ("Certificates: 2 valid certificates, the earliest expiring in 40 days "
            "(example.com).") in text
    assert "gone.example" not in text
    assert subject == "[Daily] Uptime 100.00%, no incident"


def test_brief_names_what_is_down_and_what_happened(world):
    db, config, engine, now = world
    apex, www = config.targets
    engine.apply(www, False, fail(), now - timedelta(minutes=8))
    engine.apply(www, True, dict(OK), now - timedelta(minutes=3))
    engine.apply(apex, False, fail(), now - timedelta(minutes=2))
    subject, text = monitor.Reporter(db, config).render_brief(1, "Daily")
    lines = text.splitlines()
    assert lines[0].startswith("❌ Daily summary: 1 of 2 targets down now")
    assert lines[0].endswith("2 incidents.")
    assert any(line.startswith("Down now: example.com since ") and "(HTTP 503)" in line
               for line in lines)
    assert any(line.startswith("Incidents: www.example.com at ") and
               "for 5m (HTTP 503)" in line for line in lines)
    assert "1 down now" in subject


def test_every_line_of_the_brief_begins_with_a_word(world):
    db, config, engine, now = world
    engine.apply(config.targets[0], False, fail(), now - timedelta(minutes=2))
    _, text = monitor.Reporter(db, config).render_brief(7, "Weekly")
    for line in text.splitlines()[1:]:
        assert line[0].isalpha(), line


def test_a_stopped_monitor_is_reported(world):
    db, config, _engine, now = world
    db.execute("UPDATE runs SET finished_at = ?", ((now - timedelta(hours=3)).isoformat(),))
    subject, text = monitor.Reporter(db, config).render_brief(1, "Daily")
    assert text.startswith("❌")
    assert "The monitor itself has not completed a check since" in text
    assert "the monitor is not running" in subject


def test_slow_targets_are_flagged(world, monkeypatch):
    db, config, _engine, _now = world
    config.slow_threshold_ms = 100
    reporter = monitor.Reporter(db, config)
    _, text = reporter.render_brief(1, "Daily")
    assert "Slow (p95 above 100 ms): example.com 120 ms" in text
    _, table, html = reporter.render(1, "Daily")
    assert "⏱" in table and "#d64545" in html


def test_expiring_certificates_are_named(world):
    db, config, _engine, now = world
    db.execute("UPDATE certs SET not_after = ? WHERE host = 'www.example.com'",
               ((now + timedelta(days=5, hours=1)).isoformat(),))
    _, text = monitor.Reporter(db, config).render_brief(1, "Daily")
    assert "Certificates expiring soon: www.example.com in 5 days." in text
    assert text.startswith("⚠️")


def test_json_for_other_programs(world):
    db, config, _engine, _now = world
    data = json.loads(monitor.Reporter(db, config).render_json(1, "Daily"))
    assert data["overall_uptime"] == 100.0 and data["monitor_stale"] is False
    assert [t["site"] for t in data["targets"]] == ["example.com", "example.com"]
    assert {c["host"] for c in data["certificates"]} == {"example.com", "www.example.com"}
    assert data["incidents"] == [] and data["version"] == monitor.__version__


def test_classic_table_lists_monitored_certificates_only(world):
    db, config, _engine, _now = world
    _, table, html = monitor.Reporter(db, config).render(1, "Daily")
    assert "gone.example" not in table and "gone.example" not in html
    assert "example.com" in table


def test_no_data_is_not_a_perfect_score(db, config):
    db.sync_targets(config.targets)
    subject, text = monitor.Reporter(db, config).render_brief(1, "Daily")
    assert "n/a uptime" in text and "Uptime n/a" in subject
    assert "The monitor has not completed a check yet." in text


def test_an_outage_begun_before_the_period_is_listed(world):
    db, config, engine, now = world
    target = config.targets[0]
    engine.apply(target, False, fail(), now - timedelta(days=8))
    engine.apply(target, True, dict(OK), now - timedelta(hours=1))
    _, text = monitor.Reporter(db, config).render_brief(7, "Weekly")
    assert "Incidents: example.com at " in text


def test_removed_targets_leave_the_summaries(world, monkeypatch):
    db, _config, _engine, _now = world
    monkeypatch.setenv("WEBSITES", "https://example.com")
    _, text = monitor.Reporter(db, monitor.Config()).render_brief(1, "Daily")
    assert "all 1 target" not in text and "the only target up" in text


def test_print_shows_the_summary_and_sends_nothing(world, monkeypatch, capsys):
    db, _config, _engine, _now = world
    monkeypatch.setattr(monitor, "DB_PATH", db.path)

    def refuse(*_a, **_k):
        raise AssertionError("--print must not send")
    monkeypatch.setattr(monitor, "_smtp_connect", refuse)
    assert monitor.main(["--report", "daily", "--print", "--format", "brief"]) == 0
    assert capsys.readouterr().out.startswith("✅ Daily summary: all 2 targets up")
    assert monitor.main(["--report", "weekly", "--print", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["period_days"] == 7


def test_a_summary_routed_nowhere_is_not_sent(world, monkeypatch):
    db, _config, _engine, _now = world
    monkeypatch.setattr(monitor, "DB_PATH", db.path)
    monkeypatch.setenv("ROUTE_SUMMARY", "none")

    def refuse(*_a, **_k):
        raise AssertionError("ROUTE_SUMMARY=none must not send")
    monkeypatch.setattr(monitor, "_smtp_connect", refuse)
    assert monitor.main(["--report", "daily"]) == 0


def test_print_goes_with_report_only(capsys):
    assert monitor.main(["--status", "--print"]) == 2
    assert "--print and --format go with --report" in capsys.readouterr().err
