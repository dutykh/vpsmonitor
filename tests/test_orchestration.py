"""Run-level guards: locking, monitoring gaps, and monitor-side failures.
Author: Dr. Denys Dutykh."""
from datetime import timedelta

import pytest

import monitor


@pytest.fixture
def mon(tmp_path, monkeypatch, config):
    monkeypatch.setattr(monitor, "DATA_DIR", tmp_path)
    m = monitor.WebsiteMonitor(config, dry_run=True, db_path=tmp_path / "m.db")
    yield m
    m.close()


def result(url, ok, error=None, fail_class=None, code=None):
    return (monitor.Target(name=url, url=url), ok,
            {"status_code": code, "error": error, "fail_class": fail_class,
             "response_time_ms": 1.0})


class TestMonitorSideFailureDetection:
    """If nearly everything fails at once with network errors, suspect ourselves.

    Without this, one upstream DNS failure on the monitoring host pages the
    operator about every site they own simultaneously.
    """

    def test_mass_network_failure_is_flagged(self, mon):
        results = [result(f"https://s{i}.example.com", False,
                          "Request failed: Name or service not known", "dns")
                   for i in range(10)]
        banner = mon._detect_monitor_side_failure(results)
        assert banner is not None and "monitoring host" in banner

    def test_localhost_failure_sharpens_the_diagnosis(self, mon):
        results = [result(f"https://s{i}.example.com", False,
                          "Request failed: Connection refused", "conn")
                   for i in range(9)]
        results.append(result("http://127.0.0.1:8000/health", False,
                              "Request failed: Connection refused", "conn"))
        assert "very likely local" in mon._detect_monitor_side_failure(results)

    def test_mass_http_503_is_NOT_flagged(self, mon):
        """A real mass outage of your own sites must still alert normally."""
        results = [result(f"https://s{i}.example.com", False,
                          "Unexpected status code: 503", "http_status", 503)
                   for i in range(10)]
        assert mon._detect_monitor_side_failure(results) is None

    def test_partial_failure_is_not_flagged(self, mon):
        results = [result(f"https://s{i}.example.com", i > 2,
                          "Timeout after 30 seconds" if i <= 2 else None,
                          "timeout" if i <= 2 else None) for i in range(10)]
        assert mon._detect_monitor_side_failure(results) is None

    def test_tiny_target_list_is_never_flagged(self, mon):
        results = [result("https://a.example.com", False, "Timeout", "timeout")]
        assert mon._detect_monitor_side_failure(results) is None


class TestGapDetection:
    def test_no_gap_on_first_run(self, mon):
        assert mon._detect_gap(monitor.now_utc()) is None

    def test_long_gap_is_reported(self, mon):
        now = monitor.now_utc()
        mon.db.execute(
            "INSERT INTO runs(started_at, finished_at, n_targets) VALUES(?,?,0)",
            ((now - timedelta(hours=9)).isoformat(), (now - timedelta(hours=9)).isoformat()))
        banner = mon._detect_gap(now)
        assert banner is not None and "Monitoring gap" in banner
        assert "lower bounds" in banner

    def test_normal_cadence_is_not_a_gap(self, mon):
        now = monitor.now_utc()
        mon.db.execute(
            "INSERT INTO runs(started_at, finished_at, n_targets) VALUES(?,?,0)",
            ((now - timedelta(minutes=5)).isoformat(),
             (now - timedelta(minutes=5)).isoformat()))
        assert mon._detect_gap(now) is None


class TestSingleInstanceLock:
    def test_second_instance_is_refused(self, tmp_path):
        path = tmp_path / "test.lock"
        with monitor.SingleInstanceLock(path):
            with pytest.raises(RuntimeError, match="already in progress"):
                with monitor.SingleInstanceLock(path):
                    pass

    def test_lock_is_released_on_exit(self, tmp_path):
        path = tmp_path / "test.lock"
        with monitor.SingleInstanceLock(path):
            pass
        with monitor.SingleInstanceLock(path):
            pass  # must not raise


class TestRetention:
    def test_old_checks_roll_up_into_daily_stats(self, db, config):
        ids = db.sync_targets(config.targets)
        tid = ids[config.websites[0].name]
        old = (monitor.now_utc() - timedelta(days=200)).isoformat()
        for _ in range(10):
            db.execute(
                "INSERT INTO checks(target_id, ts, healthy, total_ms) VALUES(?,?,1,100.0)",
                (tid, old))
        db.enforce_retention(days=90)
        assert db.query("SELECT COUNT(*) n FROM checks")[0]["n"] == 0
        rolled = db.query("SELECT * FROM daily_stats")
        assert len(rolled) == 1 and rolled[0]["checks"] == 10

    def test_recent_checks_are_kept(self, db, config):
        ids = db.sync_targets(config.targets)
        tid = ids[config.websites[0].name]
        db.execute(
            "INSERT INTO checks(target_id, ts, healthy, total_ms) VALUES(?,?,1,50.0)",
            (tid, monitor.now_utc().isoformat()))
        db.enforce_retention(days=90)
        assert db.query("SELECT COUNT(*) n FROM checks")[0]["n"] == 1


class TestTargetSync:
    def test_removed_targets_are_pruned(self, db, config):
        db.sync_targets(config.targets)
        assert db.query("SELECT COUNT(*) n FROM targets")[0]["n"] == 2
        removed = db.prune_targets([config.websites[0].name])
        assert removed == 1
        assert db.query("SELECT COUNT(*) n FROM targets")[0]["n"] == 1

    def test_sync_is_idempotent(self, db, config):
        first = db.sync_targets(config.targets)
        second = db.sync_targets(config.targets)
        assert first == second
