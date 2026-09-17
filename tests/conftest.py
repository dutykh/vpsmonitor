"""Shared fixtures. Author: Dr. Denys Dutykh."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Give every test a self-contained configuration and an empty database."""
    for key in list(os.environ):
        if key.startswith(("SMTP_", "ALERT_", "WEBSITES", "API_ENDPOINTS", "CHECK_",
                           "TIMEOUT", "MAX_", "LOG_", "SSL_", "HEARTBEAT", "GROUP_",
                           "FAILURE_", "DB_", "TARGETS_", "SLOW_", "USER_AGENT")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SMTP_USERNAME", "monitor@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("ALERT_EMAIL", "alerts@example.com")
    monkeypatch.setenv("WEBSITES", "https://example.com,https://www.example.com")
    monkeypatch.setenv("SSL_CHECK_ENABLED", "false")


@pytest.fixture
def db(tmp_path):
    import monitor
    database = monitor.Database(tmp_path / "test.db")
    yield database
    database.close()


@pytest.fixture
def config():
    import monitor
    return monitor.Config()


@pytest.fixture
def engine(db, config):
    import monitor
    ids = db.sync_targets(config.targets)
    return monitor.IncidentEngine(db, config, ids)
