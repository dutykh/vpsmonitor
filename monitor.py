#!/usr/bin/env python3
"""
Website Monitor - production website / API / TLS monitoring with email alerting.

Monitors websites and JSON API endpoints, tracks incidents in SQLite, and sends
grouped email alerts on failure and on recovery.

Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
License: GPL-3.0
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import json
import logging
import logging.handlers
import os
import re
import shutil
import smtplib
import socket
import sqlite3
import ssl
import sys
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.exceptions import RequestException, SSLError, Timeout

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

__version__ = "2.0.0"

# The project root is the directory holding this script, NOT the current working
# directory. The previous version resolved logs/ and .env relative to CWD, which
# only worked because the crontab entry happened to `cd` first.
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitor.db"
LOCK_PATH = DATA_DIR / ".monitor.lock"
LEGACY_HISTORY = LOG_DIR / "alert_history.json"

load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger("website_monitor")

UTC = timezone.utc


def now_utc() -> datetime:
    return datetime.now(UTC)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp, treating naive values as UTC (legacy records)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def registrable_domain(url_or_host: str) -> str:
    """Group key for coalescing alerts: example.com and www.example.com share one.

    Deliberately simple (no PSL dependency): strip a leading 'www.' and keep the
    last two labels. Good enough to pair apex/www twins, which is the actual goal.
    """
    host = url_or_host
    if "://" in host:
        host = urlparse(host).hostname or host
    host = (host or "").lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    if _IP_RE.match(host):
        return host
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SECRET_KEY_RE = re.compile(r"(token|secret|key|password|passwd|auth|cookie)", re.I)


def redact(data: Any, limit: int = 600) -> str:
    """Render response data for an email without leaking credentials or flooding it."""
    if data is None:
        return "N/A"
    if isinstance(data, dict):
        safe = {
            k: ("<redacted>" if _SECRET_KEY_RE.search(str(k)) else v)
            for k, v in data.items()
        }
        text = json.dumps(safe, indent=2, default=str)
    else:
        text = json.dumps(data, indent=2, default=str) if not isinstance(data, str) else data
    if len(text) > limit:
        text = text[:limit] + f"\n... (truncated, {len(text)} chars total)"
    return text


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class ColoredFormatter(logging.Formatter):
    """Colored console formatter. Formatters are built once, not per record."""

    COLORS = {
        logging.DEBUG: "\x1b[38;21m",
        logging.INFO: "\x1b[32m",
        logging.WARNING: "\x1b[33m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[31;1m",
    }
    RESET = "\x1b[0m"
    FMT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    def __init__(self, use_color: bool = True):
        super().__init__(self.FMT, datefmt="%Y-%m-%d %H:%M:%S")
        self.use_color = use_color
        self._formatters = {
            level: logging.Formatter(
                (color + self.FMT + self.RESET) if use_color else self.FMT,
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            for level, color in self.COLORS.items()
        }
        self._default = logging.Formatter(self.FMT, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        return self._formatters.get(record.levelno, self._default).format(record)


def _daily_namer(default_name: str) -> str:
    """Keep the historical logs/monitor_YYYYMMDD.log naming under rotation."""
    base, _, suffix = default_name.rpartition(".")
    # base is '<dir>/monitor.log', suffix is '2026-09-17'
    directory = os.path.dirname(base)
    return os.path.join(directory, f"monitor_{suffix.replace('-', '')}.log")


def setup_logging(log_level: str = "INFO", console_level: Optional[str] = None,
                  retention_days: int = 90) -> logging.Logger:
    """Configure logging. Safe to call more than once (handlers are not duplicated)."""
    LOG_DIR.mkdir(exist_ok=True, parents=True)

    logger.setLevel(getattr(logging, str(log_level).upper(), logging.INFO))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    # Console. Colors only on a real terminal, so cron.log never fills with ANSI
    # escapes. Under cron (not a TTY) only WARNING+ is echoed, which stops every
    # line being written twice - once to cron.log via stdout, once to the daily log.
    is_tty = sys.stderr.isatty()
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ColoredFormatter(use_color=is_tty))
    if console_level:
        console.setLevel(getattr(logging, console_level.upper(), logging.INFO))
    else:
        console.setLevel(logging.INFO if is_tty else logging.WARNING)
    logger.addHandler(console)

    # Rotating daily file. Rotation is what fixes the --continuous mode never
    # rolling over at midnight, and gives retention for free.
    file_handler = logging.handlers.TimedRotatingFileHandler(
        LOG_DIR / "monitor.log", when="midnight", backupCount=retention_days,
        encoding="utf-8", utc=False,
    )
    file_handler.namer = _daily_namer
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    )
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    return logger


def compress_old_logs(retention_days: int = 90, archive_days: int = 365) -> None:
    """Gzip daily logs past retention, delete gzipped archives past archive_days."""
    if retention_days <= 0:
        return
    now = time.time()
    try:
        for path in LOG_DIR.glob("monitor_*.log"):
            if now - path.stat().st_mtime > retention_days * 86400:
                with open(path, "rb") as src, gzip.open(f"{path}.gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                path.unlink()
        if archive_days > 0:
            for path in LOG_DIR.glob("monitor_*.log.gz"):
                if now - path.stat().st_mtime > archive_days * 86400:
                    path.unlink()
    except OSError as exc:
        logger.warning("Log maintenance failed: %s", exc)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised when the monitor cannot run with the supplied configuration."""


@dataclass
class Target:
    """A single thing to monitor."""

    name: str
    url: str
    kind: str = "website"              # "website" | "api"
    expected_status: Optional[int] = None   # None => any 2xx/3xx is healthy
    expected_response: Dict[str, Any] = field(default_factory=dict)
    expect_text: Optional[str] = None       # substring or regex the body must contain
    expect_regex: bool = False
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    verify_ssl: bool = True
    allow_redirects: Optional[bool] = None
    timeout: Optional[int] = None
    check_cert: Optional[bool] = None

    @property
    def group(self) -> str:
        return registrable_domain(self.url)

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()

    @property
    def is_https(self) -> bool:
        return urlparse(self.url).scheme == "https"

    def follows_redirects(self) -> bool:
        if self.allow_redirects is not None:
            return self.allow_redirects
        return self.kind == "website"

    def wants_cert_check(self) -> bool:
        if self.check_cert is not None:
            return self.check_cert
        return self.is_https and self.verify_ssl


def _coerce(value: str) -> Any:
    """Coerce a config string to bool/int/float where unambiguous."""
    low = value.strip().lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    text = value.strip()
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return value


def _env_int(key: str, default: int) -> int:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", key, raw, default)
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = (os.getenv(key) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_list(key: str, default: Sequence[int]) -> List[int]:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return list(default)
    out = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return sorted(out, reverse=True) or list(default)


class Config:
    """Runtime configuration, from environment/.env plus optional targets.toml."""

    def __init__(self, targets_file: Optional[Path] = None):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = _env_int("SMTP_PORT", 587)
        self.smtp_security = (os.getenv("SMTP_SECURITY", "starttls") or "starttls").lower()
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_timeout = _env_int("SMTP_TIMEOUT", 30)
        self.alert_email = [
            addr.strip() for addr in (os.getenv("ALERT_EMAIL") or "").split(",") if addr.strip()
        ]

        self.timeout = _env_int("TIMEOUT", 30)
        self.max_retries = max(1, _env_int("MAX_RETRIES", 3))
        self.max_workers = max(1, _env_int("MAX_WORKERS", 8))
        self.check_interval = _env_int("CHECK_INTERVAL", 300)
        self.alert_cooldown = _env_int("ALERT_COOLDOWN", 3600)
        self.failure_threshold = max(1, _env_int("FAILURE_THRESHOLD", 1))
        self.group_alerts = _env_bool("GROUP_ALERTS", True)
        self.slow_threshold_ms = _env_int("SLOW_THRESHOLD_MS", 0)

        self.ssl_check_enabled = _env_bool("SSL_CHECK_ENABLED", True)
        self.ssl_warn_days = _env_list("SSL_WARN_DAYS", (21, 14, 7, 3, 1))

        self.heartbeat_url = (os.getenv("HEARTBEAT_URL") or "").strip()
        self.user_agent = (
            os.getenv("USER_AGENT") or f"Website-Monitor/{__version__} (+https://github.com/dutykh/vpsmonitor)"
        )

        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_retention_days = _env_int("LOG_RETENTION_DAYS", 90)
        self.log_archive_days = _env_int("LOG_ARCHIVE_DAYS", 365)
        self.db_retention_days = _env_int("DB_RETENTION_DAYS", 90)

        self.targets: List[Target] = []
        chosen = targets_file or self._default_targets_file()
        if chosen and chosen.exists():
            self.targets = self._load_toml_targets(chosen)
            self.targets_source = str(chosen)
        else:
            self.targets = self._load_env_targets()
            self.targets_source = ".env"

        self.validate()

    # -- target loading ----------------------------------------------------

    @staticmethod
    def _default_targets_file() -> Optional[Path]:
        configured = (os.getenv("TARGETS_FILE") or "").strip()
        if configured:
            path = Path(configured)
            return path if path.is_absolute() else BASE_DIR / path
        default = BASE_DIR / "targets.toml"
        return default if default.exists() else None

    def _load_env_targets(self) -> List[Target]:
        """Backward-compatible WEBSITES / API_ENDPOINTS parsing."""
        targets: List[Target] = []
        seen = set()

        for url in (os.getenv("WEBSITES") or "").split(","):
            url = url.strip()
            if not url:
                continue
            if url in seen:
                logger.warning("Duplicate website in WEBSITES, ignoring: %s", url)
                continue
            seen.add(url)
            targets.append(Target(name=url, url=url, kind="website"))

        targets.extend(self._parse_api_endpoints(os.getenv("API_ENDPOINTS") or ""))
        return targets

    def _parse_api_endpoints(self, apis_str: str) -> List[Target]:
        """Parse 'name|url|expected_status|key:value,key2:value2' records, ';'-separated.

        Malformed records are reported rather than silently dropped - a typo used to
        disable a whole endpoint with no visible sign.
        """
        targets: List[Target] = []
        if not apis_str.strip():
            return targets

        for raw in apis_str.split(";"):
            record = raw.strip()
            if not record:
                continue
            parts = record.split("|")
            if len(parts) < 2 or not parts[0].strip() or not parts[1].strip():
                logger.error(
                    "Ignoring malformed API_ENDPOINTS record %r "
                    "(expected 'name|url[|status[|key:value,...]]')", record,
                )
                continue

            expected_status: Optional[int] = 200
            if len(parts) > 2 and parts[2].strip():
                try:
                    expected_status = int(parts[2].strip())
                except ValueError:
                    logger.error(
                        "API %r: expected_status %r is not a number, defaulting to 200",
                        parts[0], parts[2],
                    )

            expected_response: Dict[str, Any] = {}
            if len(parts) > 3 and parts[3].strip():
                for kv in parts[3].split(","):
                    if ":" not in kv:
                        if kv.strip():
                            logger.error(
                                "API %r: ignoring malformed expectation %r (want 'key:value')",
                                parts[0], kv.strip(),
                            )
                        continue
                    key, value = kv.split(":", 1)
                    expected_response[key.strip()] = _coerce(value)

            targets.append(Target(
                name=parts[0].strip(), url=parts[1].strip(), kind="api",
                expected_status=expected_status, expected_response=expected_response,
            ))
        return targets

    def _load_toml_targets(self, path: Path) -> List[Target]:
        if tomllib is None:  # pragma: no cover
            raise ConfigError("targets.toml requires Python 3.11+ (tomllib)")
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, ValueError) as exc:
            raise ConfigError(f"Could not parse {path}: {exc}") from exc

        targets: List[Target] = []
        for kind, key in (("website", "website"), ("api", "api")):
            for entry in data.get(key, []) or []:
                if not isinstance(entry, dict) or not entry.get("url"):
                    logger.error("Ignoring %s entry without a url in %s: %r", kind, path, entry)
                    continue
                url = str(entry["url"]).strip()
                targets.append(Target(
                    name=str(entry.get("name") or url),
                    url=url,
                    kind=kind,
                    expected_status=entry.get("expected_status", 200 if kind == "api" else None),
                    expected_response=dict(entry.get("expected_response") or {}),
                    expect_text=entry.get("expect") or entry.get("expect_text"),
                    expect_regex=bool(entry.get("expect_regex", False)),
                    method=str(entry.get("method", "GET")).upper(),
                    headers=dict(entry.get("headers") or {}),
                    verify_ssl=bool(entry.get("verify_ssl", True)),
                    allow_redirects=entry.get("allow_redirects"),
                    timeout=entry.get("timeout"),
                    check_cert=entry.get("check_cert"),
                ))
        return targets

    # -- validation --------------------------------------------------------

    def validate(self) -> None:
        if not self.smtp_username or not self.smtp_password:
            raise ConfigError(
                "SMTP credentials not configured (set SMTP_USERNAME and SMTP_PASSWORD in .env)"
            )
        if not self.alert_email:
            raise ConfigError("Alert email not configured (set ALERT_EMAIL in .env)")
        if self.smtp_security not in ("starttls", "ssl", "plain"):
            raise ConfigError(
                f"SMTP_SECURITY must be starttls, ssl or plain (got {self.smtp_security!r})"
            )
        if not self.targets:
            raise ConfigError(
                f"No websites or APIs configured for monitoring (source: {self.targets_source})"
            )

        names = set()
        for target in self.targets:
            if not target.url.startswith(("http://", "https://")):
                raise ConfigError(f"Invalid URL for {target.name!r}: {target.url}")
            if target.name in names:
                raise ConfigError(f"Duplicate target name: {target.name!r}")
            names.add(target.name)

    @property
    def websites(self) -> List[Target]:
        return [t for t in self.targets if t.kind == "website"]

    @property
    def api_endpoints(self) -> List[Target]:
        return [t for t in self.targets if t.kind == "api"]


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------

# A closed vocabulary, so incidents can be compared and grouped without
# string-matching exception text. "aborted" means we never got an answer
# (the run hit its deadline) - that is missing data, not a failure, and it is
# deliberately excluded from the state machine and from uptime denominators.
FAIL_CLASSES = ("dns", "conn", "tls", "timeout", "http_status", "content", "aborted", "unknown")


def classify_failure(error: Optional[str], status_code: Optional[int]) -> Optional[str]:
    if not error:
        return None
    low = error.lower()
    if low.startswith("ssl error") or "certificate" in low or "tls" in low:
        return "tls"
    if "timeout" in low or "timed out" in low:
        return "timeout"
    if "name or service not known" in low or "nodename nor servname" in low \
            or "failed to resolve" in low or "name resolution" in low:
        return "dns"
    if "connection refused" in low or "connection reset" in low \
            or "connection aborted" in low or "network is unreachable" in low \
            or "no route to host" in low:
        return "conn"
    if status_code is not None:
        if "expected status" in low or "unexpected status code" in low:
            return "http_status"
        return "content"
    if low.startswith("request failed"):
        return "conn"
    return "unknown"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    url                 TEXT NOT NULL,
    kind                TEXT NOT NULL DEFAULT 'website',
    grp                 TEXT,
    status              TEXT NOT NULL DEFAULT 'unknown',   -- unknown | up | down
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    open_incident_id    INTEGER,
    last_checked_at     TEXT,
    last_ok_at          TEXT,
    last_change_at      TEXT
);

-- One row per probe. This is the data behind uptime % and latency trends; the
-- previous version threw all of it away as unstructured text.
CREATE TABLE IF NOT EXISTS checks (
    id            INTEGER PRIMARY KEY,
    target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    run_id        INTEGER,
    ts            TEXT NOT NULL,
    healthy       INTEGER NOT NULL,
    status_code   INTEGER,
    ttfb_ms       REAL,
    total_ms      REAL,
    fail_class    TEXT,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target_id, ts);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);

-- Rolled-up history so old raw rows can be pruned without losing the record.
CREATE TABLE IF NOT EXISTS daily_stats (
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    day         TEXT NOT NULL,
    checks      INTEGER NOT NULL,
    failures    INTEGER NOT NULL,
    avg_ms      REAL,
    max_ms      REAL,
    PRIMARY KEY (target_id, day)
);

-- The escalation clock lives HERE, on the incident, never on the target. That is
-- the structural fix for the swallowed-re-outage bug: resolving an incident
-- destroys its notification state, so the next outage necessarily starts at step 0.
CREATE TABLE IF NOT EXISTS incidents (
    id                INTEGER PRIMARY KEY,
    target_id         INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    grp               TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'open',      -- open | resolved
    started_at        TEXT NOT NULL,
    confirmed_at      TEXT,
    ended_at          TEXT,
    fail_class        TEXT,
    first_error       TEXT,
    last_error        TEXT,
    status_code       INTEGER,
    checks_failed     INTEGER NOT NULL DEFAULT 0,
    notify_count      INTEGER NOT NULL DEFAULT 0,
    last_notified_at  TEXT,
    next_notify_at    TEXT,
    resolved_notified INTEGER NOT NULL DEFAULT 0,
    suppressed_by     TEXT
);
-- THE invariant: at most one open incident per target, enforced by the database.
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_one_open
    ON incidents(target_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_incidents_target ON incidents(target_id, started_at);

-- Audit trail + idempotency guard for outbound email.
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL,
    dedup_key  TEXT NOT NULL UNIQUE,
    state      TEXT NOT NULL DEFAULT 'pending',   -- pending | sent | failed
    created_at TEXT NOT NULL,
    sent_at    TEXT,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    subject    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    n_targets   INTEGER NOT NULL DEFAULT 0,
    n_failed    INTEGER NOT NULL DEFAULT 0,
    version     TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);

CREATE TABLE IF NOT EXISTS certs (
    host            TEXT PRIMARY KEY,
    not_after       TEXT,
    issuer          TEXT,
    last_checked_at TEXT,
    warn_stage      INTEGER NOT NULL DEFAULT 0,
    last_warned_at  TEXT,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_certs_expiry ON certs(not_after);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    """SQLite state store.

    One connection guarded by a re-entrant lock. SQLite serialises writes anyway,
    and the check workload is network-bound, so a single guarded connection is
    simpler and safer than a pool while remaining correct under ThreadPoolExecutor.
    """

    def __init__(self, path: Path = DB_PATH):
        self.path = path
        path.parent.mkdir(exist_ok=True, parents=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- meta --------------------------------------------------------------

    def get_meta(self, key: str) -> Optional[str]:
        row = self.query_one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- targets -----------------------------------------------------------

    def sync_targets(self, targets: Iterable[Target]) -> Dict[str, int]:
        """Upsert configured targets, return {name: id}."""
        ids: Dict[str, int] = {}
        with self._lock:
            for target in targets:
                self._conn.execute(
                    "INSERT INTO targets(name, url, kind, grp) VALUES(?,?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET url=excluded.url, "
                    "kind=excluded.kind, grp=excluded.grp",
                    (target.name, target.url, target.kind, target.group),
                )
            self._conn.commit()
            for row in self._conn.execute("SELECT id, name FROM targets"):
                ids[row["name"]] = row["id"]
        return ids

    def prune_targets(self, keep_names: Iterable[str]) -> int:
        """Remove targets no longer configured (and their history, via cascade)."""
        keep = set(keep_names)
        removed = 0
        with self._lock:
            rows = self._conn.execute("SELECT id, name FROM targets").fetchall()
            for row in rows:
                if row["name"] not in keep:
                    self._conn.execute("DELETE FROM targets WHERE id = ?", (row["id"],))
                    removed += 1
            self._conn.commit()
        return removed

    def record_check(self, target_id: int, healthy: bool, details: Dict[str, Any],
                     run_id: Optional[int] = None) -> None:
        self.execute(
            "INSERT INTO checks(target_id, run_id, ts, healthy, status_code, "
            "ttfb_ms, total_ms, fail_class, error) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                target_id, run_id, details.get("timestamp") or now_utc().isoformat(),
                1 if healthy else 0, details.get("status_code"),
                details.get("ttfb_ms"), details.get("response_time_ms"),
                details.get("fail_class"), details.get("error"),
            ),
        )

    # -- retention ---------------------------------------------------------

    def enforce_retention(self, days: int) -> None:
        """Roll raw checks older than `days` into daily_stats, then delete them."""
        if days <= 0:
            return
        cutoff = (now_utc() - timedelta(days=days)).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO daily_stats(target_id, day, checks, failures, avg_ms, max_ms)
                SELECT target_id, substr(ts, 1, 10), COUNT(*),
                       SUM(CASE WHEN healthy = 0 THEN 1 ELSE 0 END),
                       AVG(total_ms), MAX(total_ms)
                  FROM checks WHERE ts < ?
                 GROUP BY target_id, substr(ts, 1, 10)
                ON CONFLICT(target_id, day) DO UPDATE SET
                       checks = excluded.checks, failures = excluded.failures,
                       avg_ms = excluded.avg_ms, max_ms = excluded.max_ms
                """,
                (cutoff,),
            )
            deleted = self._conn.execute("DELETE FROM checks WHERE ts < ?", (cutoff,)).rowcount
            self._conn.commit()
        if deleted:
            logger.info("Retention: rolled up and pruned %d raw check rows", deleted)

    def maybe_vacuum(self) -> None:
        last = _parse_dt(self.get_meta("last_vacuum"))
        if last and (now_utc() - last) < timedelta(days=30):
            return
        with self._lock:
            self._conn.execute("VACUUM")
        self.set_meta("last_vacuum", now_utc().isoformat())


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------

class Checker:
    """Performs HTTP checks for both website and API targets."""

    def __init__(self, config: Config):
        self.config = config
        self._local = threading.local()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({
                "User-Agent": self.config.user_agent,
                "Accept": "*/*",
            })
            self._local.session = session
        return session

    def check(self, target: Target) -> Tuple[bool, Dict[str, Any]]:
        """Run a target check with retries. Returns (is_healthy, details)."""
        timeout = target.timeout or self.config.timeout
        last_error: Optional[str] = None
        last_details: Optional[Dict[str, Any]] = None
        tls_completed = False

        for attempt in range(self.config.max_retries):
            try:
                session = self._session()
                headers = dict(target.headers) if target.headers else None
                if target.kind == "api":
                    headers = {**(headers or {}), "Accept": "application/json"}

                # stream=True so time-to-first-byte is measured without waiting
                # for the whole body; the body is only read when we need it.
                start = time.monotonic()
                response = session.request(
                    target.method, target.url, timeout=timeout,
                    verify=target.verify_ssl, allow_redirects=target.follows_redirects(),
                    headers=headers, stream=True,
                )
                ttfb_ms = round((time.monotonic() - start) * 1000, 2)
                tls_completed = tls_completed or target.is_https

                needs_body = bool(
                    target.expect_text or (target.kind == "api" and target.expected_response)
                )
                body = ""
                try:
                    if needs_body:
                        body = response.text
                finally:
                    total_ms = round((time.monotonic() - start) * 1000, 2)
                    response.close()

                healthy, error, response_data = self._evaluate(target, response, body)
                details: Dict[str, Any] = {
                    "status_code": response.status_code,
                    "ttfb_ms": ttfb_ms,
                    "response_time_ms": total_ms,
                    "error": error,
                    "ssl_valid": True if target.is_https else None,
                    "response_data": response_data,
                    "timestamp": now_utc().isoformat(),
                }
                if healthy:
                    return True, details
                last_error = error
                last_details = details

            except SSLError as exc:
                last_error = f"SSL error: {exc}"
                last_details = None
                logger.warning("SSL error for %s: %s", target.url, exc)
            except Timeout:
                last_error = f"Timeout after {timeout} seconds"
                last_details = None
                logger.warning("Timeout for %s", target.url)
            except RequestException as exc:
                last_error = f"Request failed: {exc}"
                last_details = None
                logger.warning("Request error for %s: %s", target.url, exc)
            except Exception as exc:  # noqa: BLE001 - never let one target kill the run
                last_error = f"Unexpected error: {exc}"
                last_details = None
                logger.error("Unexpected error for %s: %s", target.url, exc, exc_info=True)

            if attempt < self.config.max_retries - 1:
                time.sleep(2 ** (attempt + 1))

        if last_details is not None:
            return False, last_details

        return False, {
            "status_code": None,
            "ttfb_ms": None,
            "response_time_ms": None,
            "error": last_error or "Unknown error",
            # Only claim anything about TLS if a handshake actually completed.
            # The old code inferred this from the error string and reported
            # "SSL Valid: True" for DNS failures and connection refusals.
            "ssl_valid": False if (last_error or "").startswith("SSL error") else None,
            "response_data": None,
            "timestamp": now_utc().isoformat(),
        }

    def _evaluate(self, target: Target, response: requests.Response,
                  body: str) -> Tuple[bool, Optional[str], Any]:
        """Decide whether a response is healthy. Returns (healthy, error, data)."""
        code = response.status_code

        if target.expected_status is not None:
            status_ok = code == target.expected_status
            status_err = f"Expected status {target.expected_status}, got {code}"
        else:
            # 429 means the server is alive and rate-limiting us, not down.
            status_ok = (200 <= code < 400) or code == 429
            status_err = f"Unexpected status code: {code}"

        response_data: Any = None
        if target.kind == "api" and target.expected_response:
            try:
                response_data = json.loads(body) if body else None
            except ValueError:
                return False, f"Invalid JSON response (status {code})", {"error": "Invalid JSON"}
            if not isinstance(response_data, dict):
                return False, f"Expected a JSON object, got {type(response_data).__name__}", response_data
            for key, expected in target.expected_response.items():
                if key not in response_data:
                    return False, f"Missing key {key!r} in API response", response_data
                if response_data[key] != expected:
                    return (False,
                            f"API field {key!r} is {response_data[key]!r}, expected {expected!r}",
                            response_data)

        if not status_ok:
            return False, status_err, response_data

        if target.expect_text:
            if target.expect_regex:
                found = re.search(target.expect_text, body) is not None
            else:
                found = target.expect_text in body
            if not found:
                kind = "pattern" if target.expect_regex else "text"
                return False, f"Response did not contain expected {kind}: {target.expect_text!r}", response_data

        return True, None, response_data


def check_certificate(host: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """Fetch TLS certificate expiry for a host.

    Deliberately independent of the HTTP check and of whatever issues the cert,
    so a silent renewal failure in the ACME client is still caught.
    """
    result: Dict[str, Any] = {"host": host, "not_after": None, "issuer": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        if not cert:
            result["error"] = "No certificate returned"
            return result
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        result["not_after"] = not_after.isoformat()
        issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificate verification failed: {exc.verify_message or exc}"
    except (OSError, ValueError) as exc:
        result["error"] = f"Certificate check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# Alert scheduling (pure functions - no I/O, no clock, no database)
# ---------------------------------------------------------------------------

# Offsets from the moment an incident was confirmed. Gaps are 1h, 2h, 4h, 8h,
# 12h, 24h, then daily. A 30-hour outage produces 6 emails instead of the 30 a
# flat hourly cooldown would produce - and instead of the unpredictable 15 the
# previous implementation actually produced.
ESCALATION_OFFSETS: Tuple[int, ...] = (
    0,          # the initial DOWN alert, sent on confirmation
    3600,       # +1h
    3 * 3600,   # +3h
    7 * 3600,   # +7h
    15 * 3600,  # +15h
    27 * 3600,  # +27h
    51 * 3600,  # +51h
)
ESCALATION_TAIL = 24 * 3600     # thereafter, once a day
JITTER_SLACK = 300              # must stay below half the smallest gap (3600s)


def plan_next_notification(elapsed: float, notify_count: int,
                           slack: int = JITTER_SLACK) -> Tuple[int, int]:
    """Given seconds elapsed since confirmation, return (notify_count, next_offset).

    Offsets are absolute from the confirmation time, never "last sent + delay",
    so scheduling drift cannot accumulate over a long outage. The `slack` term is
    applied here as well as in `is_notification_due` - without it, firing three
    seconds early at one step would compress every subsequent step and slide the
    schedule back toward hourly.
    """
    elapsed = max(0.0, elapsed)
    count = 0
    for offset in ESCALATION_OFFSETS:
        if elapsed + slack >= offset:
            count += 1
        else:
            break
    count = max(count, notify_count + 1)

    if count < len(ESCALATION_OFFSETS):
        return count, ESCALATION_OFFSETS[count]
    extra = count - len(ESCALATION_OFFSETS) + 1
    return count, ESCALATION_OFFSETS[-1] + extra * ESCALATION_TAIL


def is_notification_due(elapsed: float, next_offset: Optional[float],
                        slack: int = JITTER_SLACK) -> bool:
    """Is a re-alert due?

    The `slack` is what fixes the production bug where ALERT_COOLDOWN equalled the
    cron period: a run arriving 3 seconds early measured 3597s against a 3600s
    threshold and silently skipped, so alerts alternated between odd and even
    hours. Anything within `slack` of the threshold counts as due.
    """
    if next_offset is None:
        return True
    return elapsed + slack >= next_offset


def flap_score(window: Sequence[bool], min_samples: int = 6) -> float:
    """Weighted state-change ratio over recent checks. window[0] is most recent.

    A target that is simply down for 12 hours has zero transitions and so scores
    0 - long outages are never mistaken for flapping.
    """
    if len(window) < min_samples:
        return 0.0
    transitions = len(window) - 1
    if transitions < 1:
        return 0.0
    num = den = 0.0
    for i in range(transitions):
        weight = 1.5 - (i / max(1, transitions - 1)) if transitions > 1 else 1.0
        den += weight
        if window[i] != window[i + 1]:
            num += weight
    return num / den if den else 0.0


@dataclass
class Transition:
    """What one check did to a target's state, and what should be emailed."""

    target: Target
    healthy: bool
    details: Dict[str, Any]
    kind: Optional[str] = None       # None | "DOWN" | "REALERT" | "RESOLVED"
    incident_id: Optional[int] = None
    started_at: Optional[datetime] = None
    duration_s: Optional[float] = None
    suppressed_by: Optional[str] = None


class IncidentEngine:
    """Applies check results to persistent state and decides what to notify.

    Every decision in a run uses one canonical timestamp (`run_ts`). The previous
    implementation stamped `datetime.now()` separately inside each alert, so two
    targets in the same run could land on opposite sides of a cooldown threshold -
    which is why apex and www twins drifted apart and alerted on alternate hours.
    """

    def __init__(self, db: Database, config: Config, target_ids: Dict[str, int]):
        self.db = db
        self.config = config
        self.target_ids = target_ids

    def apply(self, target: Target, healthy: bool, details: Dict[str, Any],
              run_ts: datetime, run_id: Optional[int] = None,
              cold_start: bool = False, suppress: Optional[str] = None) -> Transition:
        target_id = self.target_ids[target.name]
        details.setdefault("fail_class",
                           classify_failure(details.get("error"), details.get("status_code")))
        self.db.record_check(target_id, healthy, details, run_id=run_id)

        row = self.db.query_one("SELECT * FROM targets WHERE id = ?", (target_id,))
        prev_status = row["status"] if row else "unknown"
        open_id = row["open_incident_id"] if row else None
        cfails = (row["consecutive_failures"] if row else 0) or 0
        csucc = (row["consecutive_successes"] if row else 0) or 0

        transition = Transition(target=target, healthy=healthy, details=details)
        ts = run_ts.isoformat()

        if healthy:
            csucc += 1
            cfails = 0
            if open_id:
                transition = self._resolve(target, open_id, run_ts, details, transition)
            new_status = "up"
        else:
            cfails += 1
            csucc = 0
            new_status = "down" if cfails >= self.config.failure_threshold else prev_status
            if new_status == "down":
                transition = self._open_or_escalate(
                    target, target_id, open_id, run_ts, details, transition,
                    cold_start=cold_start, suppress=suppress,
                )
            else:
                # Below the failure threshold: recorded, but not yet an incident.
                new_status = "unknown" if prev_status == "unknown" else prev_status

        refreshed = self.db.query_one(
            "SELECT open_incident_id FROM targets WHERE id = ?", (target_id,))
        self.db.execute(
            "UPDATE targets SET status = ?, consecutive_failures = ?, "
            "consecutive_successes = ?, last_checked_at = ?, "
            "last_ok_at = CASE WHEN ? THEN ? ELSE last_ok_at END, "
            "last_change_at = CASE WHEN status != ? THEN ? ELSE last_change_at END "
            "WHERE id = ?",
            (new_status, cfails, csucc, ts, 1 if healthy else 0, ts,
             new_status, ts, target_id),
        )
        if refreshed:
            transition.incident_id = refreshed["open_incident_id"] or transition.incident_id
        return transition

    def _open_or_escalate(self, target: Target, target_id: int, open_id: Optional[int],
                          run_ts: datetime, details: Dict[str, Any],
                          transition: Transition, cold_start: bool,
                          suppress: Optional[str]) -> Transition:
        ts = run_ts.isoformat()
        error = details.get("error")
        fail_class = details.get("fail_class")

        if not open_id:
            reason = suppress or ("cold_start" if cold_start else None)
            count, next_offset = (0, 0) if reason else plan_next_notification(0.0, 0)
            cur = self.db.execute(
                "INSERT INTO incidents(target_id, grp, status, started_at, confirmed_at, "
                "fail_class, first_error, last_error, status_code, checks_failed, "
                "notify_count, last_notified_at, next_notify_at, suppressed_by) "
                "VALUES(?,?,'open',?,?,?,?,?,?,1,?,?,?,?)",
                (target_id, target.group, ts, ts, fail_class, error, error,
                 details.get("status_code"), count,
                 ts if count else None,
                 (run_ts + timedelta(seconds=next_offset)).isoformat() if count else None,
                 reason),
            )
            incident_id = cur.lastrowid
            self.db.execute("UPDATE targets SET open_incident_id = ? WHERE id = ?",
                            (incident_id, target_id))
            transition.incident_id = incident_id
            transition.started_at = run_ts
            transition.suppressed_by = reason
            if not reason:
                transition.kind = "DOWN"
            return transition

        inc = self.db.query_one("SELECT * FROM incidents WHERE id = ?", (open_id,))
        if inc is None:
            self.db.execute("UPDATE targets SET open_incident_id = NULL WHERE id = ?", (target_id,))
            return transition

        confirmed = _parse_dt(inc["confirmed_at"]) or _parse_dt(inc["started_at"]) or run_ts
        elapsed = (run_ts - confirmed).total_seconds()
        next_at = _parse_dt(inc["next_notify_at"])
        next_offset = (next_at - confirmed).total_seconds() if next_at else None

        self.db.execute(
            "UPDATE incidents SET checks_failed = checks_failed + 1, last_error = ?, "
            "status_code = COALESCE(?, status_code) WHERE id = ?",
            (error, details.get("status_code"), open_id),
        )
        transition.incident_id = open_id
        transition.started_at = _parse_dt(inc["started_at"])

        if inc["suppressed_by"] in ("mute", "flap"):
            transition.suppressed_by = inc["suppressed_by"]
            return transition

        if is_notification_due(elapsed, next_offset):
            count, offset = plan_next_notification(elapsed, inc["notify_count"] or 0)
            self.db.execute(
                "UPDATE incidents SET notify_count = ?, last_notified_at = ?, "
                "next_notify_at = ?, suppressed_by = NULL WHERE id = ?",
                (count, ts, (confirmed + timedelta(seconds=offset)).isoformat(), open_id),
            )
            # A previously suppressed incident that is still down gets its first
            # real alert now, so suppression can never silence a lasting outage.
            transition.kind = "DOWN" if (inc["notify_count"] or 0) == 0 else "REALERT"
            transition.duration_s = (run_ts - (transition.started_at or run_ts)).total_seconds()
        return transition

    def _resolve(self, target: Target, open_id: int, run_ts: datetime,
                 details: Dict[str, Any], transition: Transition) -> Transition:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id = ?", (open_id,))
        ts = run_ts.isoformat()
        self.db.execute(
            "UPDATE incidents SET status = 'resolved', ended_at = ? WHERE id = ?", (ts, open_id))
        self.db.execute(
            "UPDATE targets SET open_incident_id = NULL WHERE open_incident_id = ?", (open_id,))
        if inc is None:
            return transition

        started = _parse_dt(inc["started_at"]) or run_ts
        transition.incident_id = open_id
        transition.started_at = started
        transition.duration_s = (run_ts - started).total_seconds()
        # Never announce the resolution of a problem the operator was never told about.
        if (inc["notify_count"] or 0) > 0:
            transition.kind = "RESOLVED"
            self.db.execute("UPDATE incidents SET resolved_notified = 1 WHERE id = ?", (open_id,))
        else:
            transition.suppressed_by = inc["suppressed_by"] or "never_alerted"
        return transition

    # -- legacy migration --------------------------------------------------

    def migrate_legacy_history(self, path: Path = LEGACY_HISTORY,
                               local_tz: Optional[str] = None) -> Dict[str, int]:
        """Import alert_history.json once, preserving cooldown state for live outages.

        Timestamps without a timezone were written by an older build using
        `datetime.now()`, i.e. the host's LOCAL time (verified against the log
        archive: a naive 22:00:30 entry matches a 22:00:30 local log line). The
        previous code treated them as UTC, placing them four hours in the future
        and over-suppressing. They are converted from the local zone here.
        """
        report = {"imported": 0, "skipped_up": 0, "dropped_stale": 0, "tz_fixed": 0}
        if self.db.get_meta("legacy_import_at") or not path.exists():
            return report
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            logger.warning("Could not read legacy alert history: %s", exc)
            self.db.set_meta("legacy_import_at", now_utc().isoformat())
            return report

        self.db.set_meta("legacy_alert_history_raw", json.dumps(raw))
        try:
            tz = ZoneInfo(local_tz) if local_tz else datetime.now().astimezone().tzinfo
        except Exception:  # noqa: BLE001
            tz = UTC

        by_url = {t.url: t for t in self.config.targets}
        for url, stamp in raw.items():
            target = by_url.get(url)
            if target is None:
                report["dropped_stale"] += 1
                logger.info("Legacy history: dropping stale entry for %s", url)
                continue
            try:
                dt = datetime.fromisoformat(stamp)
            except (TypeError, ValueError):
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=tz).astimezone(UTC)
                report["tz_fixed"] += 1
            else:
                dt = dt.astimezone(UTC)

            row = self.db.query_one("SELECT id, status FROM targets WHERE name = ?", (target.name,))
            if row is None or row["status"] != "down":
                # A stale cooldown on a healthy target has no meaning in the new
                # model - carrying it forward is precisely the swallowed-outage bug.
                report["skipped_up"] += 1
                continue
            report["imported"] += 1

        self.db.set_meta("legacy_import_at", now_utc().isoformat())
        logger.info(
            "Legacy alert history imported: %(imported)d carried forward, "
            "%(skipped_up)d healthy targets skipped, %(dropped_stale)d stale entries dropped, "
            "%(tz_fixed)d naive timestamps converted from local time", report,
        )
        try:
            path.rename(path.with_suffix(".json.migrated"))
        except OSError:
            pass
        return report


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

class EmailNotifier:
    """Builds and sends coalesced alert email."""

    def __init__(self, config: Config, db: Optional[Database] = None, dry_run: bool = False):
        self.config = config
        self.db = db
        self.dry_run = dry_run

    # -- transport ---------------------------------------------------------

    def _connect(self) -> smtplib.SMTP:
        timeout = self.config.smtp_timeout or None
        if self.config.smtp_security == "ssl":
            context = ssl.create_default_context()
            return smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port,
                                    timeout=timeout, context=context)
        server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port, timeout=timeout)
        if self.config.smtp_security == "starttls":
            server.starttls(context=ssl.create_default_context())
        return server

    def send(self, subject: str, body: str, html: Optional[str] = None,
             dedup_key: Optional[str] = None, kind: str = "ALERT") -> bool:
        """Send one email. Returns True if it was accepted by the SMTP server."""
        if self.dry_run:
            logger.warning("[dry-run] would send: %s", subject)
            logger.debug("[dry-run] body:\n%s", body)
            return False

        if dedup_key and self.db is not None:
            existing = self.db.query_one(
                "SELECT state FROM notifications WHERE dedup_key = ?", (dedup_key,))
            if existing and existing["state"] == "sent":
                logger.debug("Notification %s already sent, skipping", dedup_key)
                return False
            self.db.execute(
                "INSERT INTO notifications(kind, dedup_key, state, created_at, subject) "
                "VALUES(?,?,'pending',?,?) ON CONFLICT(dedup_key) DO NOTHING",
                (kind, dedup_key, now_utc().isoformat(), subject),
            )

        msg = MIMEMultipart("alternative")
        msg["From"] = self.config.smtp_username or ""
        msg["To"] = ", ".join(self.config.alert_email)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        # A stable Message-ID lets the mail client thread/collapse a duplicate if
        # we crash between a successful send and recording that it was sent.
        msg["Message-ID"] = make_msgid(domain="vpsmonitor.local")
        msg["Auto-Submitted"] = "auto-generated"
        msg.attach(MIMEText(body, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))

        last_error: Optional[str] = None
        for attempt in range(2):
            try:
                with closing(self._connect()) as server:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                    server.send_message(msg)
                if dedup_key and self.db is not None:
                    self.db.execute(
                        "UPDATE notifications SET state='sent', sent_at=?, "
                        "attempts=attempts+1 WHERE dedup_key = ?",
                        (now_utc().isoformat(), dedup_key),
                    )
                logger.info("Sent: %s", subject)
                return True
            except (smtplib.SMTPException, OSError) as exc:
                last_error = str(exc)
                logger.warning("SMTP attempt %d failed: %s", attempt + 1, exc)
                if attempt == 0:
                    time.sleep(5)

        logger.error("Failed to send %r after 2 attempts: %s", subject, last_error)
        if dedup_key and self.db is not None:
            self.db.execute(
                "UPDATE notifications SET state='failed', attempts=attempts+1, "
                "last_error=? WHERE dedup_key = ?", (last_error, dedup_key))
        return False

    # -- composition -------------------------------------------------------

    def dispatch(self, transitions: Sequence[Transition], run_ts: datetime,
                 banner: Optional[str] = None) -> int:
        """Group transitions into as few emails as possible and send them."""
        downs = [t for t in transitions if t.kind in ("DOWN", "REALERT")]
        ups = [t for t in transitions if t.kind == "RESOLVED"]
        sent = 0

        if downs:
            for subject, body, html, key in self._compose_down(downs, run_ts, banner):
                sent += 1 if self.send(subject, body, html, key, "DOWN") else 0
        if ups:
            for subject, body, html, key in self._compose_resolved(ups, run_ts):
                sent += 1 if self.send(subject, body, html, key, "RESOLVED") else 0
        return sent

    def _groups(self, transitions: Sequence[Transition]) -> List[List[Transition]]:
        if not self.config.group_alerts:
            return [[t] for t in transitions]
        buckets: Dict[str, List[Transition]] = {}
        for t in transitions:
            buckets.setdefault(t.target.group, []).append(t)
        return [buckets[k] for k in sorted(buckets)]

    @staticmethod
    def _stamp(run_ts: datetime) -> str:
        local = run_ts.astimezone()
        return (f"{run_ts.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                f"({local.strftime('%H:%M %Z')})")

    def _compose_down(self, downs: Sequence[Transition], run_ts: datetime,
                      banner: Optional[str]) -> List[Tuple[str, str, str, str]]:
        out = []
        # One email per run covering every affected domain: the apex/www twins that
        # used to generate two near-identical alerts now appear as two lines in one.
        groups = self._groups(downs)
        all_in_one = self.config.group_alerts
        chunks = [downs] if all_in_one else groups

        for chunk in chunks:
            chunk = list(chunk)
            domains = sorted({t.target.group for t in chunk})
            realert = all(t.kind == "REALERT" for t in chunk)
            tag = "STILL DOWN" if realert else "DOWN"
            if len(domains) == 1:
                subject = f"[{tag}] {domains[0]} — {len(chunk)} target(s) failing"
            else:
                subject = (f"[{tag}] {len(domains)} domains / {len(chunk)} targets — "
                           + ", ".join(domains[:3])
                           + ("…" if len(domains) > 3 else ""))

            lines = [f"{'Website/API Monitoring Alert':^68}", "=" * 68, ""]
            if banner:
                lines += [f"!! {banner}", ""]
            lines += [f"Time: {self._stamp(run_ts)}", ""]
            for domain in domains:
                members = [t for t in chunk if t.target.group == domain]
                lines.append(f"── {domain} " + "─" * max(0, 64 - len(domain)))
                for t in members:
                    d = t.details
                    down_for = (f", down for {human_duration(t.duration_s)}"
                                if t.duration_s else "")
                    lines.append(f"  ✗ {t.target.name}{down_for}")
                    lines.append(f"      URL:    {t.target.url}")
                    lines.append(f"      Error:  {d.get('error', 'Unknown')}")
                    lines.append(f"      Status: {d.get('status_code', 'N/A')}"
                                 f"   Class: {d.get('fail_class', 'unknown')}")
                    if d.get("response_time_ms") is not None:
                        lines.append(f"      Time:   {d['response_time_ms']} ms")
                    if t.target.kind == "api" and d.get("response_data") is not None:
                        lines.append("      Body:   " + redact(d["response_data"]).replace("\n", "\n              "))
                lines.append("")
            classes = sorted({t.details.get("fail_class") or "unknown" for t in chunk})
            if len(classes) > 1:
                lines += [f"Note: mixed failure types in this alert ({', '.join(classes)}) — "
                          "these may be unrelated problems.", ""]
            lines += [
                "Suggested checks:",
                "  1. Confirm the site is reachable from another network",
                "  2. Check the web server / container and its logs",
                "  3. Verify TLS certificate and DNS records",
                "  4. Review recent deployments or configuration changes",
                "",
                f"-- Website Monitor v{__version__}",
            ]
            body = "\n".join(lines)
            key = f"DOWN:{run_ts.isoformat()}:" + ",".join(
                sorted(str(t.incident_id) for t in chunk))
            out.append((subject, body, self._html_down(chunk, run_ts, banner), key))
        return out

    def _compose_resolved(self, ups: Sequence[Transition],
                          run_ts: datetime) -> List[Tuple[str, str, str, str]]:
        domains = sorted({t.target.group for t in ups})
        longest = max((t.duration_s or 0) for t in ups)
        if len(domains) == 1:
            subject = (f"[RESOLVED] {domains[0]} — back up after "
                       f"{human_duration(longest)}")
        else:
            subject = (f"[RESOLVED] {len(domains)} domains / {len(ups)} targets — "
                       f"back up after {human_duration(longest)}")

        lines = [f"{'Service Restored':^68}", "=" * 68, "",
                 f"Time: {self._stamp(run_ts)}", ""]
        for domain in domains:
            members = [t for t in ups if t.target.group == domain]
            lines.append(f"── {domain} " + "─" * max(0, 64 - len(domain)))
            for t in members:
                lines.append(f"  ✓ {t.target.name}")
                lines.append(f"      URL:      {t.target.url}")
                if t.started_at:
                    lines.append(f"      Down at:  {t.started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                lines.append(f"      Duration: {human_duration(t.duration_s or 0)}")
                if t.details.get("response_time_ms") is not None:
                    lines.append(f"      Now:      HTTP {t.details.get('status_code')} "
                                 f"in {t.details['response_time_ms']} ms")
            lines.append("")
        lines.append(f"-- Website Monitor v{__version__}")
        body = "\n".join(lines)
        key = f"RESOLVED:{run_ts.isoformat()}:" + ",".join(
            sorted(str(t.incident_id) for t in ups))
        return [(subject, body, self._html_resolved(ups, run_ts), key)]

    # -- HTML --------------------------------------------------------------

    @staticmethod
    def _shell(title: str, accent: str, rows: str, footer: str) -> str:
        return f"""<html><body style="margin:0;padding:24px;background:#f4f5f7;
font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2933">
<table role="presentation" width="100%" style="max-width:640px;margin:0 auto;
background:#fff;border-radius:10px;overflow:hidden;border:1px solid #e4e7eb">
<tr><td style="background:{accent};color:#fff;padding:18px 24px;font-size:17px;font-weight:600">
{title}</td></tr>
<tr><td style="padding:20px 24px">{rows}</td></tr>
<tr><td style="padding:14px 24px;background:#fafbfc;border-top:1px solid #e4e7eb;
font-size:12px;color:#7b8794">{footer}</td></tr></table></body></html>"""

    def _html_down(self, chunk: Sequence[Transition], run_ts: datetime,
                   banner: Optional[str]) -> str:
        rows = []
        if banner:
            rows.append(f'<p style="margin:0 0 14px;padding:10px 12px;background:#fff4e5;'
                        f'border-left:3px solid #f0932b;font-size:13px">{banner}</p>')
        rows.append(f'<p style="margin:0 0 16px;font-size:13px;color:#52606d">'
                    f'{self._stamp(run_ts)}</p>')
        for domain in sorted({t.target.group for t in chunk}):
            rows.append(f'<p style="margin:16px 0 6px;font-weight:600;font-size:14px">{domain}</p>')
            for t in (x for x in chunk if x.target.group == domain):
                d = t.details
                dur = (f' · down {human_duration(t.duration_s)}' if t.duration_s else '')
                rows.append(
                    f'<table role="presentation" width="100%" style="margin:0 0 8px;'
                    f'border-left:3px solid #d64545;background:#fdf3f3"><tr><td style="padding:10px 12px">'
                    f'<div style="font-weight:600;font-size:13px">{t.target.name}{dur}</div>'
                    f'<div style="font-size:12px;color:#52606d;margin-top:3px">'
                    f'{d.get("error", "Unknown error")}</div>'
                    f'<div style="font-size:11px;color:#7b8794;margin-top:4px">'
                    f'HTTP {d.get("status_code", "N/A")} · {d.get("fail_class", "unknown")}'
                    f'</div></td></tr></table>')
        return self._shell("Monitoring Alert", "#d64545", "".join(rows),
                           f"Website Monitor v{__version__}")

    def _html_resolved(self, ups: Sequence[Transition], run_ts: datetime) -> str:
        rows = [f'<p style="margin:0 0 16px;font-size:13px;color:#52606d">'
                f'{self._stamp(run_ts)}</p>']
        for t in ups:
            rows.append(
                f'<table role="presentation" width="100%" style="margin:0 0 8px;'
                f'border-left:3px solid #2f9e44;background:#f2fbf4"><tr><td style="padding:10px 12px">'
                f'<div style="font-weight:600;font-size:13px">{t.target.name}</div>'
                f'<div style="font-size:12px;color:#52606d;margin-top:3px">'
                f'Recovered after {human_duration(t.duration_s or 0)}</div></td></tr></table>')
        return self._shell("Service Restored", "#2f9e44", "".join(rows),
                           f"Website Monitor v{__version__}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class SingleInstanceLock:
    """Prevents overlapping runs. Without it, two cron runs both see the same
    open incident, both find it due, and both email."""

    def __init__(self, path: Path = LOCK_PATH):
        self.path = path
        self._fh = None

    def __enter__(self) -> "SingleInstanceLock":
        self.path.parent.mkdir(exist_ok=True, parents=True)
        self._fh = open(self.path, "w")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._fh.close()
            self._fh = None
            raise RuntimeError("another monitor run is already in progress") from exc
        self._fh.write(f"{os.getpid()}\n")
        self._fh.flush()
        return self

    def __exit__(self, *exc_info) -> None:
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()


class WebsiteMonitor:
    """Main monitoring orchestrator."""

    def __init__(self, config: Optional[Config] = None, dry_run: bool = False,
                 db_path: Path = DB_PATH):
        self.config = config or Config()
        self.dry_run = dry_run
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        self.db = Database(db_path)
        self.checker = Checker(self.config)
        self.target_ids = self.db.sync_targets(self.config.targets)
        removed = self.db.prune_targets(t.name for t in self.config.targets)
        if removed:
            logger.info("Pruned %d target(s) no longer in the configuration", removed)
            self.target_ids = self.db.sync_targets(self.config.targets)
        self.engine = IncidentEngine(self.db, self.config, self.target_ids)
        self.notifier = EmailNotifier(self.config, self.db, dry_run=dry_run)

    def close(self) -> None:
        self.db.close()

    # -- a single pass -----------------------------------------------------

    def run_checks(self) -> List[Transition]:
        run_ts = now_utc()
        started = time.monotonic()
        cur = self.db.execute(
            "INSERT INTO runs(started_at, n_targets, version) VALUES(?,?,?)",
            (run_ts.isoformat(), len(self.config.targets), __version__),
        )
        run_id = cur.lastrowid

        cold_start = self.db.get_meta("first_run_done") is None
        gap_banner = self._detect_gap(run_ts)
        if cold_start:
            self.engine.migrate_legacy_history()

        logger.info("Running %d checks (%d websites, %d APIs) with %d workers",
                    len(self.config.targets), len(self.config.websites),
                    len(self.config.api_endpoints), self.config.max_workers)

        results: List[Tuple[Target, bool, Dict[str, Any]]] = []
        workers = min(self.config.max_workers, max(1, len(self.config.targets)))
        if workers > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="chk") as pool:
                futures = {pool.submit(self.checker.check, t): t for t in self.config.targets}
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        healthy, details = future.result()
                    except Exception as exc:  # noqa: BLE001
                        healthy, details = False, {
                            "status_code": None, "ttfb_ms": None, "response_time_ms": None,
                            "error": f"Checker crashed: {exc}", "ssl_valid": None,
                            "response_data": None, "timestamp": now_utc().isoformat(),
                        }
                    results.append((target, healthy, details))
        else:
            for target in self.config.targets:
                healthy, details = self.checker.check(target)
                results.append((target, healthy, details))

        # Keep configuration order in the log and in emails, not completion order.
        order = {t.name: i for i, t in enumerate(self.config.targets)}
        results.sort(key=lambda r: order.get(r[0].name, 0))

        suppress = self._detect_monitor_side_failure(results)
        banner = gap_banner or suppress

        transitions: List[Transition] = []
        for target, healthy, details in results:
            transition = self.engine.apply(
                target, healthy, details, run_ts, run_id=run_id,
                cold_start=cold_start,
                suppress="monitor_network" if suppress and not healthy else None,
            )
            transitions.append(transition)
            label = "API" if target.kind == "api" else "Website"
            if healthy:
                logger.info("✓ %s: %s - OK (%s, %sms)", label, target.name,
                            details.get("status_code"), details.get("response_time_ms"))
            else:
                logger.error("✗ %s: %s - FAILED: %s", label, target.name,
                             details.get("error"))

        if self.config.ssl_check_enabled:
            transitions_ssl = self._check_certificates(run_ts)
        else:
            transitions_ssl = []

        n_failed = sum(1 for _, healthy, _ in results if not healthy)
        self.notifier.dispatch(transitions, run_ts, banner=banner)
        for subject, body in transitions_ssl:
            self.notifier.send(subject, body, kind="SSL",
                               dedup_key=f"SSL:{subject}:{run_ts.date()}")

        duration_ms = int((time.monotonic() - started) * 1000)
        self.db.execute(
            "UPDATE runs SET finished_at = ?, duration_ms = ?, n_failed = ? WHERE id = ?",
            (now_utc().isoformat(), duration_ms, n_failed, run_id),
        )
        self.db.set_meta("first_run_done", now_utc().isoformat())
        self._housekeeping()
        self._heartbeat(n_failed)
        logger.info("Run complete in %.1fs — %d/%d healthy",
                    duration_ms / 1000, len(results) - n_failed, len(results))
        return transitions

    # -- guards ------------------------------------------------------------

    def _detect_gap(self, run_ts: datetime) -> Optional[str]:
        row = self.db.query_one(
            "SELECT started_at FROM runs WHERE finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1")
        if not row:
            return None
        last = _parse_dt(row["started_at"])
        if not last:
            return None
        gap = (run_ts - last).total_seconds()
        expected = self.config.check_interval or 3600
        if gap > max(3 * expected, 3 * 3600):
            return (f"Monitoring gap of {human_duration(gap)} since the last completed run — "
                    f"outage start times in this alert are lower bounds.")
        return None

    def _detect_monitor_side_failure(
            self, results: Sequence[Tuple[Target, bool, Dict[str, Any]]]) -> Optional[str]:
        """If nearly everything fails at once with network-ish errors, suspect us, not them.

        A localhost target is the discriminator: if 127.0.0.1 is also unreachable
        the problem is almost certainly on this host.
        """
        if len(results) < 4:
            return None
        failed = [(t, d) for t, ok, d in results if not ok]
        if len(failed) / len(results) < 0.8:
            return None
        network_ish = sum(
            1 for _, d in failed
            if (d.get("fail_class") or classify_failure(d.get("error"), d.get("status_code")))
            in ("dns", "conn", "timeout")
        )
        if network_ish < len(failed) * 0.8:
            return None
        local_down = any(
            t.host in ("127.0.0.1", "localhost", "::1") for t, _ in failed)
        detail = (" A localhost target also failed, so this is very likely local."
                  if local_down else "")
        return (f"{len(failed)}/{len(results)} targets failed at once with network errors — "
                f"this may be a problem with the monitoring host or its network, "
                f"not with the sites themselves.{detail}")

    # -- certificates ------------------------------------------------------

    def _check_certificates(self, run_ts: datetime) -> List[Tuple[str, str]]:
        """Probe TLS expiry at most once a day per host; warn on threshold crossings."""
        alerts: List[Tuple[str, str]] = []
        hosts: Dict[str, Target] = {}
        for target in self.config.targets:
            if target.wants_cert_check() and target.host:
                hosts.setdefault(target.host, target)

        for host in sorted(hosts):
            row = self.db.query_one("SELECT * FROM certs WHERE host = ?", (host,))
            last = _parse_dt(row["last_checked_at"]) if row else None
            if last and (run_ts - last) < timedelta(hours=12):
                continue
            info = check_certificate(host)
            not_after = _parse_dt(info["not_after"])
            days_left = (not_after - run_ts).days if not_after else None
            prev_stage = (row["warn_stage"] if row else 0) or 0

            stage = 0
            if days_left is not None:
                for i, threshold in enumerate(self.config.ssl_warn_days, start=1):
                    if days_left <= threshold:
                        stage = i
            self.db.execute(
                "INSERT INTO certs(host, not_after, issuer, last_checked_at, warn_stage, error) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                "not_after=excluded.not_after, issuer=excluded.issuer, "
                "last_checked_at=excluded.last_checked_at, warn_stage=excluded.warn_stage, "
                "error=excluded.error",
                (host, info["not_after"], info["issuer"], run_ts.isoformat(), stage, info["error"]),
            )
            if info["error"]:
                logger.warning("Certificate check failed for %s: %s", host, info["error"])
                continue
            logger.info("Certificate %s expires in %s days (%s)", host, days_left, info["issuer"])
            if stage > prev_stage and days_left is not None:
                self.db.execute("UPDATE certs SET last_warned_at = ? WHERE host = ?",
                                (run_ts.isoformat(), host))
                subject = f"[TLS] Certificate for {host} expires in {days_left} day(s)"
                body = (
                    f"TLS Certificate Expiry Warning\n{'=' * 40}\n\n"
                    f"Host:      {host}\n"
                    f"Expires:   {not_after.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                    f"Days left: {days_left}\n"
                    f"Issuer:    {info['issuer']}\n\n"
                    "TLS on this host is terminated by a reverse proxy with its own ACME\n"
                    "client. Renewal normally happens automatically around 30 days before\n"
                    "expiry; this warning means it has not happened yet. Check the proxy's\n"
                    "ACME logs and that its account/storage file is writable.\n\n"
                    f"-- Website Monitor v{__version__}\n"
                )
                alerts.append((subject, body))
        return alerts

    # -- periodic chores ---------------------------------------------------

    def _housekeeping(self) -> None:
        today = now_utc().date().isoformat()
        if self.db.get_meta("last_housekeeping") == today:
            return
        try:
            self.db.enforce_retention(self.config.db_retention_days)
            compress_old_logs(self.config.log_retention_days, self.config.log_archive_days)
            self.db.maybe_vacuum()
            self.db.set_meta("last_housekeeping", today)
        except Exception as exc:  # noqa: BLE001 - chores must never break a run
            logger.warning("Housekeeping failed: %s", exc)

    def _heartbeat(self, n_failed: int) -> None:
        """Ping a dead-man's-switch service. This is the only mechanism that can
        detect the monitor itself being dead, which nothing previously could."""
        if not self.config.heartbeat_url or self.dry_run:
            return
        try:
            requests.get(self.config.heartbeat_url, timeout=10,
                         params={"failed": n_failed} if n_failed else None)
            logger.debug("Heartbeat sent")
        except RequestException as exc:
            logger.warning("Heartbeat failed: %s", exc)

    # -- modes -------------------------------------------------------------

    def run_once(self) -> int:
        try:
            transitions = self.run_checks()
            return sum(1 for t in transitions if not t.healthy)
        except Exception as exc:  # noqa: BLE001
            logger.critical("Critical error during monitoring: %s", exc, exc_info=True)
            return -1

    def run_continuous(self) -> None:
        interval = self.config.check_interval
        logger.info("Starting continuous monitoring (interval: %ds)", interval)
        while True:
            try:
                started = time.monotonic()
                self.run_checks()
                # Subtract the run's own duration so the cadence stays fixed
                # rather than drifting by however long the checks took.
                time.sleep(max(5.0, interval - (time.monotonic() - started)))
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                return
            except Exception as exc:  # noqa: BLE001
                logger.critical("Critical error: %s", exc, exc_info=True)
                time.sleep(60)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

class Reporter:
    """Builds uptime summaries from the stored check history."""

    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config

    def stats(self, days: int) -> List[Dict[str, Any]]:
        since = (now_utc() - timedelta(days=days)).isoformat()
        rows = self.db.query(
            """
            SELECT t.name, t.url, t.kind, t.status,
                   COUNT(c.id)                                    AS checks,
                   SUM(CASE WHEN c.healthy = 0 THEN 1 ELSE 0 END) AS failures,
                   AVG(CASE WHEN c.healthy = 1 THEN c.total_ms END) AS avg_ms,
                   MAX(CASE WHEN c.healthy = 1 THEN c.total_ms END) AS max_ms
              FROM targets t LEFT JOIN checks c
                ON c.target_id = t.id AND c.ts >= ?
             GROUP BY t.id ORDER BY t.id
            """, (since,))
        out = []
        for row in rows:
            checks = row["checks"] or 0
            failures = row["failures"] or 0
            out.append({
                "name": row["name"], "url": row["url"], "kind": row["kind"],
                "status": row["status"], "checks": checks, "failures": failures,
                "uptime": (100.0 * (checks - failures) / checks) if checks else None,
                "avg_ms": row["avg_ms"], "max_ms": row["max_ms"],
                "p95_ms": self._p95(row["name"], since),
            })
        return out

    def _p95(self, name: str, since: str) -> Optional[float]:
        rows = self.db.query(
            "SELECT c.total_ms FROM checks c JOIN targets t ON t.id = c.target_id "
            "WHERE t.name = ? AND c.ts >= ? AND c.healthy = 1 AND c.total_ms IS NOT NULL "
            "ORDER BY c.total_ms", (name, since))
        values = [r["total_ms"] for r in rows]
        if not values:
            return None
        return values[min(len(values) - 1, int(len(values) * 0.95))]

    def incidents(self, days: int) -> List[sqlite3.Row]:
        since = (now_utc() - timedelta(days=days)).isoformat()
        return self.db.query(
            "SELECT i.*, t.name FROM incidents i JOIN targets t ON t.id = i.target_id "
            "WHERE i.started_at >= ? ORDER BY i.started_at DESC", (since,))

    def certs(self) -> List[sqlite3.Row]:
        return self.db.query(
            "SELECT * FROM certs WHERE not_after IS NOT NULL ORDER BY not_after")

    def render(self, days: int, title: str) -> Tuple[str, str, str]:
        stats = self.stats(days)
        incidents = self.incidents(days)
        certs = self.certs()
        now = now_utc()

        measured = [s for s in stats if s["uptime"] is not None]
        overall = sum(s["uptime"] for s in measured) / len(measured) if measured else 100.0
        down_now = [s for s in stats if s["status"] == "down"]

        subject = f"[{title}] Uptime {overall:.2f}% — {len(incidents)} incident(s)"
        if down_now:
            subject += f" — {len(down_now)} DOWN now"

        lines = [f"{title + ' Monitoring Report':^72}", "=" * 72, "",
                 f"Period:  last {days} day(s), to {now.strftime('%Y-%m-%d %H:%M')} UTC",
                 f"Overall: {overall:.3f}% uptime across {len(stats)} targets", ""]
        lines.append(f"{'TARGET':<42}{'UPTIME':>9}{'AVG':>9}{'P95':>9}")
        lines.append("-" * 72)
        for s in stats:
            uptime = f"{s['uptime']:.2f}%" if s["uptime"] is not None else "n/a"
            avg = f"{s['avg_ms']:.0f}ms" if s["avg_ms"] else "n/a"
            p95 = f"{s['p95_ms']:.0f}ms" if s["p95_ms"] else "n/a"
            flag = "  ✗" if s["status"] == "down" else ""
            lines.append(f"{s['name'][:41]:<42}{uptime:>9}{avg:>9}{p95:>9}{flag}")
        lines.append("")

        if incidents:
            lines += [f"Incidents ({len(incidents)}):", "-" * 72]
            for inc in incidents[:25]:
                start = _parse_dt(inc["started_at"])
                end = _parse_dt(inc["ended_at"])
                dur = human_duration((end - start).total_seconds()) if (start and end) else "ongoing"
                lines.append(f"  {start.strftime('%m-%d %H:%M') if start else '?':<12}"
                             f"{inc['name'][:34]:<36}{dur:>10}  {inc['fail_class'] or ''}")
            lines.append("")
        else:
            lines += ["No incidents in this period.", ""]

        if certs:
            lines += ["TLS certificates:", "-" * 72]
            for cert in certs:
                exp = _parse_dt(cert["not_after"])
                days_left = (exp - now).days if exp else None
                mark = "  ⚠" if (days_left is not None and days_left <= 21) else ""
                lines.append(f"  {cert['host'][:40]:<42}"
                             f"{(str(days_left) + ' days') if days_left is not None else 'unknown':>12}"
                             f"  {cert['issuer'] or ''}{mark}")
            lines.append("")
        lines.append(f"-- Website Monitor v{__version__}")

        html = self._html(title, days, overall, stats, incidents, certs, now)
        return subject, "\n".join(lines), html

    def _html(self, title: str, days: int, overall: float, stats, incidents,
              certs, now: datetime) -> str:
        def bar(pct: Optional[float]) -> str:
            if pct is None:
                return '<span style="color:#9aa5b1">n/a</span>'
            color = "#2f9e44" if pct >= 99.9 else "#f0932b" if pct >= 99 else "#d64545"
            return (f'<span style="color:{color};font-weight:600">{pct:.2f}%</span>')

        def ms(value: Optional[float]) -> str:
            return f"{value:.0f} ms" if value else "\u2014"

        cell = ('<td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
                'text-align:right;font-size:12px;color:#616e7c">')
        rows = "".join(
            '<tr><td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
            'font-size:13px">' + s["name"][:46] + '</td>'
            '<td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
            'text-align:right;font-size:13px">' + bar(s["uptime"]) + '</td>'
            + cell + ms(s["avg_ms"]) + '</td>'
            + cell + ms(s["p95_ms"]) + '</td></tr>'
            for s in stats)

        inc_html = ""
        if incidents:
            items = []
            for inc in incidents[:15]:
                start = _parse_dt(inc["started_at"])
                end = _parse_dt(inc["ended_at"])
                dur = human_duration((end - start).total_seconds()) if (start and end) else "ongoing"
                items.append(
                    f'<li style="margin:4px 0;font-size:12px;color:#52606d">'
                    f'<strong>{inc["name"]}</strong> — {dur}'
                    f'<span style="color:#9aa5b1"> · {inc["fail_class"] or ""} · '
                    f'{start.strftime("%b %d %H:%M") if start else ""} UTC</span></li>')
            inc_html = ('<p style="margin:22px 0 6px;font-weight:600;font-size:14px">Incidents</p>'
                        f'<ul style="margin:0;padding-left:18px">{"".join(items)}</ul>')

        cert_html = ""
        if certs:
            items = []
            for cert in certs:
                exp = _parse_dt(cert["not_after"])
                left = (exp - now).days if exp else None
                color = ("#d64545" if left is not None and left <= 7
                         else "#f0932b" if left is not None and left <= 21 else "#616e7c")
                items.append(
                    f'<li style="margin:4px 0;font-size:12px;color:#52606d">{cert["host"]} — '
                    f'<span style="color:{color};font-weight:600">'
                    f'{left if left is not None else "?"} days</span></li>')
            cert_html = ('<p style="margin:22px 0 6px;font-weight:600;font-size:14px">'
                         'TLS certificates</p>'
                         f'<ul style="margin:0;padding-left:18px">{"".join(items)}</ul>')

        color = "#2f9e44" if overall >= 99.9 else "#f0932b" if overall >= 99 else "#d64545"
        return EmailNotifier._shell(
            f"{title} Report",
            "#334e68",
            f'<p style="margin:0 0 4px;font-size:30px;font-weight:700;color:{color}">'
            f'{overall:.2f}%</p>'
            f'<p style="margin:0 0 18px;font-size:12px;color:#7b8794">'
            f'average uptime · last {days} day(s) · {len(stats)} targets</p>'
            f'<table role="presentation" width="100%" style="border-collapse:collapse">'
            f'<tr><th style="text-align:left;padding:6px 8px;font-size:11px;color:#7b8794;'
            f'text-transform:uppercase;border-bottom:2px solid #e4e7eb">Target</th>'
            f'<th style="text-align:right;padding:6px 8px;font-size:11px;color:#7b8794;'
            f'text-transform:uppercase;border-bottom:2px solid #e4e7eb">Uptime</th>'
            f'<th style="text-align:right;padding:6px 8px;font-size:11px;color:#7b8794;'
            f'text-transform:uppercase;border-bottom:2px solid #e4e7eb">Avg</th>'
            f'<th style="text-align:right;padding:6px 8px;font-size:11px;color:#7b8794;'
            f'text-transform:uppercase;border-bottom:2px solid #e4e7eb">p95</th></tr>'
            f'{rows}</table>{inc_html}{cert_html}',
            f"Website Monitor v{__version__} · generated {now.strftime('%Y-%m-%d %H:%M')} UTC")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_status(db: Database, config: Config) -> None:
    reporter = Reporter(db, config)
    stats = reporter.stats(7)
    now = now_utc()
    print(f"\n  Website Monitor v{__version__} — status at "
          f"{now.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
    print(f"  {'TARGET':<40}{'STATE':>9}{'7d UPTIME':>12}{'AVG':>10}{'LAST SEEN':>18}")
    print("  " + "-" * 87)
    rows = {r["name"]: r for r in db.query("SELECT * FROM targets")}
    for s in stats:
        row = rows.get(s["name"])
        state = (row["status"] if row else "unknown").upper()
        mark = {"UP": "✓", "DOWN": "✗"}.get(state, "?")
        uptime = f"{s['uptime']:.2f}%" if s["uptime"] is not None else "n/a"
        avg = f"{s['avg_ms']:.0f}ms" if s["avg_ms"] else "n/a"
        last = _parse_dt(row["last_checked_at"]) if row else None
        seen = last.strftime("%m-%d %H:%M UTC") if last else "never"
        print(f"  {s['name'][:39]:<40}{mark + ' ' + state:>9}{uptime:>12}{avg:>10}{seen:>18}")

    open_incidents = db.query(
        "SELECT i.*, t.name FROM incidents i JOIN targets t ON t.id = i.target_id "
        "WHERE i.status = 'open' ORDER BY i.started_at")
    if open_incidents:
        print(f"\n  Open incidents ({len(open_incidents)}):")
        for inc in open_incidents:
            started = _parse_dt(inc["started_at"])
            dur = human_duration((now - started).total_seconds()) if started else "?"
            print(f"    ✗ {inc['name']} — down {dur} ({inc['fail_class'] or 'unknown'})"
                  f" — {inc['last_error'] or ''}")
    certs = reporter.certs()
    if certs:
        print("\n  TLS certificates:")
        for cert in certs:
            exp = _parse_dt(cert["not_after"])
            left = (exp - now).days if exp else None
            warn = "  ⚠" if (left is not None and left <= 21) else ""
            print(f"    {cert['host']:<42}{str(left) + ' days' if left is not None else '?':>10}"
                  f"  {cert['issuer'] or ''}{warn}")
    print()


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="monitor.py",
        description="Website, API and TLS monitoring with email alerting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  monitor.py                      run one pass (cron default)\n"
               "  monitor.py --dry-run -v         check everything, send nothing\n"
               "  monitor.py --status             show current state from the database\n"
               "  monitor.py --report weekly      email an uptime summary\n"
               "  monitor.py --check https://x.y  probe one URL and exit\n"
               "  monitor.py --test-email         verify SMTP settings\n",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true",
                      help="run a single pass and exit (the default)")
    mode.add_argument("--continuous", action="store_true",
                      help="loop forever using CHECK_INTERVAL")
    mode.add_argument("--status", action="store_true",
                      help="print current state and exit")
    mode.add_argument("--report", choices=("daily", "weekly", "monthly"),
                      help="email an uptime summary and exit")
    mode.add_argument("--check", metavar="URL",
                      help="probe a single URL and exit (no state, no email)")
    mode.add_argument("--test-email", action="store_true",
                      help="send a test message to ALERT_EMAIL and exit")
    mode.add_argument("--notify", metavar="SUBJECT",
                      help="send an arbitrary message (for other scripts to reuse)")

    parser.add_argument("--body-file", metavar="PATH",
                        help="with --notify: read the email body from this file")
    parser.add_argument("--dry-run", action="store_true",
                        help="perform checks and update state but never send email")
    parser.add_argument("--config", metavar="PATH", help="path to a targets.toml file")
    parser.add_argument("-v", "--verbose", action="store_true", help="log INFO to the console")
    parser.add_argument("-q", "--quiet", action="store_true", help="log only errors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def _emergency_notify(subject: str, body: str) -> None:
    """Best-effort alert when the monitor itself cannot start.

    A broken .env used to produce a silent traceback in cron.log and nothing else.
    """
    try:
        server_host = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        port = int(os.getenv("SMTP_PORT", "587") or 587)
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        recipients = [a.strip() for a in (os.getenv("ALERT_EMAIL") or "").split(",") if a.strip()]
        if not (username and password and recipients):
            return
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = username
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        with closing(smtplib.SMTP(server_host, port, timeout=30)) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(username, password)
            server.send_message(msg)
        logger.info("Sent configuration-failure notification")
    except Exception as exc:  # noqa: BLE001 - this path must never raise
        logger.error("Could not send configuration-failure notification: %s", exc)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    console_level = "DEBUG" if args.verbose else "ERROR" if args.quiet else None
    # Logging is configured BEFORE the configuration is parsed, so that a bad
    # .env produces a real log entry instead of a bare traceback.
    setup_logging(os.getenv("LOG_LEVEL", "INFO"), console_level=console_level)

    # --check needs no configuration at all: it is a standalone probe.
    if args.check:
        target = Target(name=args.check, url=args.check,
                        kind="api" if "/api" in args.check else "website")
        if not target.url.startswith(("http://", "https://")):
            print(f"Not a valid URL: {args.check}", file=sys.stderr)
            return 2
        probe_cfg = Config.__new__(Config)
        probe_cfg.timeout = _env_int("TIMEOUT", 30)
        probe_cfg.max_retries = 1
        probe_cfg.user_agent = f"Website-Monitor/{__version__}"
        healthy, details = Checker(probe_cfg).check(target)
        print(json.dumps({"url": target.url, "healthy": healthy, **{
            k: v for k, v in details.items() if k != "response_data"}}, indent=2, default=str))
        if target.is_https and target.host:
            print(json.dumps(check_certificate(target.host), indent=2, default=str))
        return 0 if healthy else 1

    try:
        config = Config(targets_file=Path(args.config) if args.config else None)
    except ConfigError as exc:
        logger.critical("Configuration error: %s", exc)
        _emergency_notify(
            "[MONITOR BROKEN] Website monitor cannot start",
            f"The website monitor failed to start at "
            f"{now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC.\n\n"
            f"Configuration error: {exc}\n\n"
            f"Host: {socket.gethostname()}\nPath: {BASE_DIR}\n\n"
            "No websites are being monitored until this is fixed.\n",
        )
        return 2
    except Exception as exc:  # noqa: BLE001
        logger.critical("Unexpected startup failure: %s", exc, exc_info=True)
        return 2

    setup_logging(config.log_level, console_level=console_level,
                  retention_days=config.log_retention_days)

    if args.test_email:
        notifier = EmailNotifier(config)
        ok = notifier.send(
            "[TEST] Website Monitor configuration check",
            f"This is a test message from the website monitor on "
            f"{socket.gethostname()}.\n\n"
            f"Sent: {now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"SMTP: {config.smtp_server}:{config.smtp_port} ({config.smtp_security})\n"
            f"Targets configured: {len(config.targets)} "
            f"({len(config.websites)} websites, {len(config.api_endpoints)} APIs)\n"
            f"Config source: {config.targets_source}\n\n"
            "If you received this, alerting works.\n",
            kind="TEST")
        print("Test email sent." if ok else "Test email FAILED - see the log.")
        return 0 if ok else 1

    if args.notify:
        body = ""
        if args.body_file:
            try:
                body = Path(args.body_file).read_text(errors="replace")[-8000:]
            except OSError as exc:
                body = f"(could not read {args.body_file}: {exc})"
        body = (f"Host: {socket.gethostname()}\n"
                f"Time: {now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n{body}")
        ok = EmailNotifier(config, dry_run=args.dry_run).send(args.notify, body, kind="NOTIFY")
        return 0 if ok else 1

    if args.status:
        db = Database()
        try:
            print_status(db, config)
        finally:
            db.close()
        return 0

    if args.report:
        days = {"daily": 1, "weekly": 7, "monthly": 30}[args.report]
        db = Database()
        try:
            subject, body, html = Reporter(db, config).render(days, args.report.capitalize())
            notifier = EmailNotifier(config, db, dry_run=args.dry_run)
            if args.dry_run:
                print(body)
                return 0
            ok = notifier.send(subject, body, html, kind="SUMMARY",
                               dedup_key=f"SUMMARY:{args.report}:{now_utc().date()}")
            return 0 if ok else 1
        finally:
            db.close()

    # Default: one monitoring pass, guarded against overlapping runs.
    try:
        with SingleInstanceLock():
            monitor = WebsiteMonitor(config, dry_run=args.dry_run)
            try:
                if args.continuous:
                    monitor.run_continuous()
                    return 0
                failures = monitor.run_once()
                return 0 if failures == 0 else 1
            finally:
                monitor.close()
    except RuntimeError as exc:
        logger.warning("Skipping this run: %s", exc)
        return 0


if __name__ == "__main__":
    sys.exit(main())
