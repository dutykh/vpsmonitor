"""Alerts that must not be lost, history that must not vanish, and a monitor that
must keep running: the defects found by the audit of November 2026.
Author: Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and
Technology, Abu Dhabi, UAE)."""
import json
import os
import socket
import sqlite3
import threading
import time
from datetime import timedelta

import pytest

import monitor

OK = {"status_code": 200, "response_time_ms": 12.0, "error": None}


def fail(code=503):
    return {"status_code": code, "response_time_ms": 9.0,
            "error": f"Unexpected status code: {code}"}


def at(t0, minutes):
    return t0 + timedelta(minutes=minutes)


# -- undelivered alerts are sent again ---------------------------------------

@pytest.mark.parametrize("state, again", [
    ("failed", "DOWN"), ("dry-run", "DOWN"), ("sent", None), ("fallback", None),
    ("skipped", None)])
def test_an_undelivered_outage_alert_is_sent_at_the_next_pass(engine, config, state, again):
    """A DOWN whose mail failed used to be followed by nothing until a STILL DOWN
    an hour later."""
    target, t0 = config.websites[0], monitor.now_utc()
    first = engine.apply(target, False, fail(), t0)
    assert first.kind == "DOWN"
    first.delivery = state
    engine.settle([first])
    assert engine.apply(target, False, fail(), at(t0, 5)).kind == again


def test_an_undelivered_reminder_is_tried_again(engine, config):
    target, t0 = config.websites[0], monitor.now_utc()
    first = engine.apply(target, False, fail(), t0)
    first.delivery = "sent"
    engine.settle([first])
    reminder = engine.apply(target, False, fail(), at(t0, 60))
    assert reminder.kind == "REALERT"
    reminder.delivery = "failed"
    engine.settle([reminder])
    assert engine.apply(target, False, fail(), at(t0, 65)).kind == "REALERT"


def test_an_undelivered_recovery_is_resent_for_a_day(engine, config):
    target, t0 = config.websites[0], monitor.now_utc()
    down = engine.apply(target, False, fail(), t0)
    down.delivery = "sent"
    engine.settle([down])
    up = engine.apply(target, True, dict(OK), at(t0, 10))
    assert up.kind == "RESOLVED"
    up.delivery = "failed"
    engine.settle([up])
    pending = engine.pending_recoveries(at(t0, 15), [])
    assert [p.incident_id for p in pending] == [up.incident_id]
    assert pending[0].duration_s == 600
    pending[0].delivery = "sent"
    engine.settle(pending)
    assert engine.pending_recoveries(at(t0, 20), []) == []
    assert engine.pending_recoveries(at(t0, 2 * 24 * 60), []) == []


def test_a_run_whose_mail_fails_alerts_at_the_next_run(tmp_path, monkeypatch, config):
    """End to end: the mail server refuses at the first run, accepts at the second."""
    attempts = {"n": 0}

    class Server:
        sent = []

        def login(self, *_a):
            pass

        def send_message(self, msg):
            Server.sent.append(msg["Subject"])

        def close(self):
            pass

    def connect(*_a, **_k):
        attempts["n"] += 1
        if attempts["n"] <= 2:
            raise ConnectionRefusedError("mail server down")
        return Server()

    monkeypatch.setattr(monitor, "_smtp_connect", connect)
    monkeypatch.setattr(monitor.time, "sleep", lambda _s: None)
    mon = monitor.WebsiteMonitor(config)
    monkeypatch.setattr(mon.checker, "check", lambda t: (False, fail()))
    mon.db.set_meta("first_run_done", "yes")
    mon.run_checks()
    assert Server.sent == []
    mon.run_checks()
    mon.close()
    assert len(Server.sent) == 1 and Server.sent[0].startswith("[DOWN] example.com")


# -- the engine survives its own accidents ------------------------------------

def test_a_lost_incident_pointer_is_repaired(engine, config, db):
    """A run killed between writing an incident and pointing its target at it used
    to make every later pass fail on the one-open-incident index."""
    target, t0 = config.websites[0], monitor.now_utc()
    first = engine.apply(target, False, fail(), t0)
    db.execute("UPDATE targets SET open_incident_id = NULL")
    later = engine.apply(target, False, fail(), at(t0, 5))
    assert later.incident_id == first.incident_id
    assert len(db.query("SELECT id FROM incidents WHERE status = 'open'")) == 1


def test_an_outage_is_dated_from_its_first_failed_check(db, monkeypatch):
    monkeypatch.setenv("FAILURE_THRESHOLD", "3")
    config = monitor.Config()
    engine = monitor.IncidentEngine(db, config, db.sync_targets(config.targets))
    target, t0 = config.websites[0], monitor.now_utc()
    assert engine.apply(target, False, fail(), t0).kind is None
    assert engine.apply(target, False, fail(), at(t0, 5)).kind is None
    down = engine.apply(target, False, fail(), at(t0, 10))
    assert down.kind == "DOWN" and down.started_at == t0 and down.duration_s == 600
    up = engine.apply(target, True, dict(OK), at(t0, 15))
    assert up.duration_s == 900
    assert db.query_one("SELECT checks_failed FROM incidents")["checks_failed"] == 3


# -- flapping ----------------------------------------------------------------

@pytest.fixture
def flappy(db, monkeypatch):
    monkeypatch.setenv("FLAP_CHANGES", "4")
    monkeypatch.setenv("FLAP_WINDOW", "6")
    monkeypatch.setenv("FLAP_HOLD", "600")
    config = monitor.Config()
    return monitor.IncidentEngine(db, config, db.sync_targets(config.targets)), config


def test_flapping_is_announced_once_and_holds_short_outages(flappy):
    engine, config = flappy
    target, t0 = config.websites[0], monitor.now_utc()
    seq = [True, False, True, False, True]            # four changes: flapping
    events = [engine.apply(target, ok, dict(OK) if ok else fail(), at(t0, 5 * i))
              for i, ok in enumerate(seq)]
    assert [e.flap_event for e in events] == [None, None, None, None, "start"]
    assert events[-1].flapping
    short = engine.apply(target, False, fail(), at(t0, 25))
    assert short.kind is None and short.suppressed_by == "flap"
    back = engine.apply(target, True, dict(OK), at(t0, 30))
    assert back.kind is None and back.flap_event is None


def test_a_lasting_outage_of_a_flapping_target_is_announced(flappy):
    engine, config = flappy
    target, t0 = config.websites[0], monitor.now_utc()
    for i, ok in enumerate([True, False, True, False, True]):
        engine.apply(target, ok, dict(OK) if ok else fail(), at(t0, 5 * i))
    kinds = [engine.apply(target, False, fail(), at(t0, 25 + 5 * i)).kind for i in range(4)]
    assert kinds == [None, None, "DOWN", None]          # held 10 minutes, then announced


def test_a_flapping_target_that_settles_up_is_announced_steady(flappy):
    engine, config = flappy
    target, t0 = config.websites[0], monitor.now_utc()
    for i, ok in enumerate([True, False, True, False, True]):
        engine.apply(target, ok, dict(OK) if ok else fail(), at(t0, 5 * i))
    events = [engine.apply(target, True, dict(OK), at(t0, 25 + 5 * i)).flap_event
              for i in range(6)]
    assert events == [None, None, None, None, "stop", None]


def test_an_undelivered_flapping_notice_is_noticed_again(flappy):
    engine, config = flappy
    target, t0 = config.websites[0], monitor.now_utc()
    events = [engine.apply(target, ok, dict(OK) if ok else fail(), at(t0, 5 * i))
              for i, ok in enumerate([True, False, True, False, True])]
    events[-1].flap_delivery = "failed"
    engine.settle([events[-1]])
    again = engine.apply(target, False, fail(), at(t0, 25))
    assert again.flap_event == "start"


def test_flapping_can_be_turned_off(db, monkeypatch):
    monkeypatch.setenv("FLAP_CHANGES", "0")
    config = monitor.Config()
    engine = monitor.IncidentEngine(db, config, db.sync_targets(config.targets))
    target, t0 = config.websites[0], monitor.now_utc()
    kinds = [engine.apply(target, i % 2 == 0, dict(OK) if i % 2 == 0 else fail(),
                          at(t0, 5 * i)).kind for i in range(10)]
    assert kinds.count("DOWN") == 5 and kinds.count("RESOLVED") == 4


# -- history is kept ------------------------------------------------------------

def test_a_removed_target_keeps_its_history_for_a_week(db, config):
    ids = db.sync_targets(config.targets)
    db.execute("UPDATE targets SET last_checked_at = ?", (monitor.now_utc().isoformat(),))
    assert db.prune_targets([config.websites[0].name], grace_days=7) == 0
    old = (monitor.now_utc() - timedelta(days=8)).isoformat()
    db.execute("UPDATE targets SET last_checked_at = ? WHERE id = ?",
               (old, ids[config.websites[1].name]))
    assert db.prune_targets([config.websites[0].name], grace_days=7) == 1


def test_a_dry_run_with_other_targets_deletes_nothing(db, config, monkeypatch, tmp_path):
    engine = monitor.IncidentEngine(db, config, db.sync_targets(config.targets))
    engine.apply(config.websites[1], False, fail(), monitor.now_utc())
    monkeypatch.setenv("WEBSITES", "https://other.example.org")
    monitor.WebsiteMonitor(monitor.Config(), dry_run=True, db_path=db.path).close()
    assert db.query_one("SELECT COUNT(*) n FROM targets")["n"] == 3
    assert db.query_one("SELECT COUNT(*) n FROM incidents")["n"] == 1


def test_split_days_are_added_up_at_roll_up(db, config, monkeypatch):
    """A day straddling the retention cutoff is rolled up in two passes; the
    second used to replace the first instead of adding to it."""
    tid = db.sync_targets(config.targets)[config.websites[0].name]
    base = monitor.now_utc().replace(hour=6, minute=0, second=0, microsecond=0) \
        - timedelta(days=100)
    for hour, ms in ((0, 100.0), (1, 100.0), (12, 300.0), (13, 300.0)):
        db.execute("INSERT INTO checks(target_id, ts, healthy, total_ms) VALUES(?,?,1,?)",
                   (tid, (base + timedelta(hours=hour)).isoformat(), ms))
    real_now = monitor.now_utc
    monkeypatch.setattr(monitor, "now_utc", lambda: base + timedelta(days=90, hours=6))
    db.enforce_retention(90)
    monkeypatch.setattr(monitor, "now_utc", lambda: base + timedelta(days=90, hours=18))
    db.enforce_retention(90)
    monkeypatch.setattr(monitor, "now_utc", real_now)
    row = db.query_one("SELECT * FROM daily_stats")
    assert row["checks"] == 4 and row["avg_ms"] == pytest.approx(200.0)
    assert row["max_ms"] == 300.0


def test_p95_is_the_nearest_rank(db, config):
    tid = db.sync_targets(config.targets)[config.websites[0].name]
    now = monitor.now_utc().isoformat()
    for value in range(1, 21):
        db.execute("INSERT INTO checks(target_id, ts, healthy, total_ms) VALUES(?,?,1,?)",
                   (tid, now, float(value)))
    since = (monitor.now_utc() - timedelta(days=1)).isoformat()
    assert monitor.Reporter(db, config)._p95(config.websites[0].name, since) == 19.0


def test_a_database_of_an_earlier_version_gains_the_new_columns(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
                     "url TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'website', grp TEXT, "
                     "status TEXT NOT NULL DEFAULT 'unknown', consecutive_failures INTEGER "
                     "NOT NULL DEFAULT 0, consecutive_successes INTEGER NOT NULL DEFAULT 0, "
                     "open_incident_id INTEGER, last_checked_at TEXT, last_ok_at TEXT, "
                     "last_change_at TEXT)")
        conn.execute("CREATE TABLE notifications (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
                     "dedup_key TEXT NOT NULL UNIQUE, state TEXT NOT NULL DEFAULT 'pending', "
                     "created_at TEXT NOT NULL, sent_at TEXT, attempts INTEGER NOT NULL "
                     "DEFAULT 0, last_error TEXT, subject TEXT NOT NULL)")
        conn.execute("INSERT INTO targets(name, url) VALUES('a', 'https://a.example')")
    db = monitor.Database(path)
    columns = {r[1] for r in db.query("PRAGMA table_info(targets)")}
    assert {"failing_since", "flapping_since"} <= columns
    assert "channels" in {r[1] for r in db.query("PRAGMA table_info(notifications)")}
    assert db.query_one("SELECT name FROM targets")["name"] == "a"
    db.close()
    monitor.Database(path).close()         # a second start finds nothing to add


# -- certificates ------------------------------------------------------------------

def test_a_failed_probe_keeps_what_the_last_good_one_learnt(db, config, monkeypatch):
    config.ssl_check_enabled = True
    mon = monitor.WebsiteMonitor(config, dry_run=True, db_path=db.path)
    expiry = (monitor.now_utc() + timedelta(days=10)).isoformat()
    mon.db.execute("INSERT INTO certs(host, not_after, issuer, last_checked_at, warn_stage) "
                   "VALUES('example.com', ?, 'CA', ?, 2)",
                   (expiry, (monitor.now_utc() - timedelta(days=1)).isoformat()))
    monkeypatch.setattr(monitor, "check_certificate", lambda host, port=443, timeout=10: {
        "host": host, "not_after": None, "issuer": None, "error": "timed out"})
    assert mon._check_certificates(monitor.now_utc()) == []
    row = mon.db.query_one("SELECT * FROM certs WHERE host = 'example.com'")
    assert row["not_after"] == expiry and row["warn_stage"] == 2 and row["error"] == "timed out"
    mon.close()


def test_the_certificate_is_probed_on_the_port_of_the_address(monkeypatch):
    monkeypatch.setenv("WEBSITES", "https://example.com:8443/,https://example.org")
    monkeypatch.setenv("SSL_CHECK_ENABLED", "true")
    config = monitor.Config()
    assert config.cert_hosts() == ["example.com:8443", "example.org"]
    assert monitor.split_cert_key("example.com:8443") == ("example.com", 8443)
    assert monitor.split_cert_key("[::1]:8443") == ("::1", 8443)
    assert monitor.split_cert_key("example.org") == ("example.org", 443)


def test_stale_certificates_are_forgotten(db, config):
    config.ssl_check_enabled = True
    db.execute("INSERT INTO certs(host, not_after) VALUES('gone.example', '2030-01-01')")
    db.execute("INSERT INTO certs(host, not_after) VALUES('example.com', '2030-01-01')")
    monitor.WebsiteMonitor(config, db_path=db.path).close()
    hosts = {r["host"] for r in db.query("SELECT host FROM certs")}
    assert hosts == {"example.com"}


# -- a broken configuration -----------------------------------------------------------

def test_the_broken_configuration_notice_is_rate_limited(monkeypatch):
    """One typo in WEBSITES used to mean a notice at every run, 288 a day."""
    monkeypatch.setenv("WEBSITES", "htps://example.com")
    sent = []
    monkeypatch.setattr(monitor, "_emergency_notify", lambda s, b: sent.append(s) or True)
    assert monitor.main([]) == 2
    assert monitor.main([]) == 2
    assert len(sent) == 1
    monkeypatch.setenv("WEBSITES", "ftp://example.com")      # a different error
    assert monitor.main([]) == 2
    assert len(sent) == 2


def test_the_watchdog_message_survives_a_broken_target_list(monkeypatch):
    monkeypatch.setenv("WEBSITES", "htps://example.com")
    seen = []

    class Server:
        def login(self, *_a):
            pass

        def send_message(self, msg):
            seen.append(msg["Subject"])

        def close(self):
            pass

    monkeypatch.setattr(monitor, "_smtp_connect", lambda *a, **k: Server())
    assert monitor.main(["--notify", "[SECURITY] Watchdog alert"]) == 0
    assert seen == ["[SECURITY] Watchdog alert"]


def test_the_watchdog_message_survives_broken_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTE_DOWN", "smoke-signals")
    bodies = []

    class Server:
        def login(self, *_a):
            pass

        def send_message(self, msg):
            bodies.append((msg["Subject"], msg.get_payload(decode=True).decode()))

        def close(self):
            pass

    monkeypatch.setattr(monitor, "_smtp_connect", lambda *a, **k: Server())
    note = tmp_path / "finding.txt"
    note.write_text("a miner was found")
    assert monitor.main(["--notify", "[SECURITY] x", "--body-file", str(note)]) == 0
    subject, body = bodies[0]
    assert subject == "[SECURITY] x" and "a miner was found" in body
    assert "configuration of the website monitor is broken" in body


# -- the checks keep to their time ----------------------------------------------------------

def trickling_server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def serve():
        conn, _ = sock.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
        try:
            for _ in range(60):
                conn.sendall(b"x")
                time.sleep(0.25)
        except OSError:
            pass
        conn.close()
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_a_trickling_server_cannot_hold_the_run(monkeypatch):
    """One byte at a time kept a check reading forever, and the lock of that run
    kept every later run from checking anything."""
    monkeypatch.setenv("TIMEOUT", "2")
    monkeypatch.setenv("MAX_RETRIES", "1")
    config = monitor.Config()
    port = trickling_server()
    target = monitor.Target(name="slow", url=f"http://127.0.0.1:{port}/",
                            expect_text="never there")
    start = time.monotonic()
    healthy, details = monitor.Checker(config).check(target)
    assert time.monotonic() - start < 6
    assert healthy is False and "Timeout" in details["error"]


def test_an_accept_header_of_ones_own_is_kept(config, monkeypatch):
    seen = {}

    class Response:
        status_code = 200

        def close(self):
            pass

    class Session:
        headers = {}

        def request(self, method, url, **kwargs):
            seen.update(kwargs["headers"] or {})
            return Response()

    checker = monitor.Checker(config)
    monkeypatch.setattr(checker, "_session", lambda: Session())
    target = monitor.Target(name="api", url="http://127.0.0.1:9/health", kind="api",
                            expected_status=200, headers={"accept": "application/vnd.x+json"})
    assert checker.check(target)[0] is True
    assert seen == {"accept": "application/vnd.x+json"}


# -- targets.toml says what it does not understand -------------------------------------------------

def write_toml(tmp_path, text):
    path = tmp_path / "targets.toml"
    path.write_text(text)
    return path


def test_unknown_tables_and_keys_are_reported(tmp_path, caplog):
    path = write_toml(tmp_path, '[[website]]\nurl = "https://example.com"\n'
                                'expected_text = "Welcome"\n\n'
                                '[[apis]]\nurl = "http://127.0.0.1:1/h"\n')
    with caplog.at_level("ERROR"):
        config = monitor.Config(targets_file=path)
    assert len(config.targets) == 1
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "unknown key 'expected_text'" in text and "Unknown table 'apis'" in text


def test_quoted_values_mean_what_they_say(tmp_path):
    path = write_toml(tmp_path, '[[api]]\nurl = "http://127.0.0.1:1/h"\n'
                                'expected_status = "200"\nverify_ssl = "false"\n')
    api = monitor.Config(targets_file=path).api_endpoints[0]
    assert api.expected_status == 200 and api.verify_ssl is False


@pytest.mark.parametrize("line, message", [
    ('verify_ssl = "maybe"', "verify_ssl must be true or false"),
    ('expected_status = "ok"', "expected_status must be a whole number"),
    ('timeout = -1', "timeout must be a positive number"),
    ('expect = "(unclosed"\nexpect_regex = true', "not a valid regular expression"),
])
def test_wrong_values_are_refused(tmp_path, line, message):
    path = write_toml(tmp_path, f'[[website]]\nurl = "https://example.com"\n{line}\n')
    with pytest.raises(monitor.ConfigError, match=message):
        monitor.Config(targets_file=path)


# -- logs ------------------------------------------------------------------------------

def test_logs_go_to_the_file_of_their_day_and_the_old_file_is_folded_in(tmp_path):
    logs = monitor.LOG_DIR
    logs.mkdir(parents=True)
    old = logs / "monitor.log"
    old.write_text("an old line\n")
    yesterday = time.time() - 86400
    os.utime(old, (yesterday, yesterday))
    monitor.setup_logging("INFO", console_level="CRITICAL")
    monitor.logger.info("a new line")
    day_old = time.strftime("%Y%m%d", time.localtime(yesterday))
    day_now = time.strftime("%Y%m%d")
    assert not old.exists()
    assert "an old line" in (logs / f"monitor_{day_old}.log").read_text()
    assert "a new line" in (logs / f"monitor_{day_now}.log").read_text()
    for handler in list(monitor.logger.handlers):
        monitor.logger.removeHandler(handler)
        handler.close()


def test_an_archive_keeps_the_age_of_its_log(tmp_path):
    logs = monitor.LOG_DIR
    logs.mkdir(parents=True)
    log = logs / "monitor_20250101.log"
    log.write_text("x\n")
    old = time.time() - 100 * 86400
    os.utime(log, (old, old))
    monitor.compress_old_logs(retention_days=90, archive_days=365)
    archive = logs / "monitor_20250101.log.gz"
    assert archive.exists() and abs(archive.stat().st_mtime - old) < 2


def test_a_corrupt_notice_stamp_is_harmless(monkeypatch):
    monitor.DATA_DIR.mkdir(parents=True)
    (monitor.DATA_DIR / ".broken-notice").write_text("not json")
    assert monitor._broken_notice_due("anything") is True
    monitor._broken_notice_sent("anything")
    assert json.loads((monitor.DATA_DIR / ".broken-notice").read_text())["error"]
