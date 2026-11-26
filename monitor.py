#!/usr/bin/env python3
"""
Website Monitor - production website / API / TLS monitoring with alerting.

Monitors websites and JSON API endpoints, tracks incidents in SQLite, and sends
grouped alerts on failure and on recovery, by email, through a command of one's
own (a chat client, a push service), or both, as each kind of message is routed.

Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
License: GPL-3.0
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import json
import math
import logging
import os
import re
import shlex
import shutil
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
from html import escape as _esc
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo
from urllib.parse import urlparse

import requests
import urllib3
from dotenv import load_dotenv
from requests.exceptions import RequestException, SSLError, Timeout

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

__version__ = "2.4.0"

# The project root is the directory holding this script, NOT the current working
# directory. The previous version resolved logs/ and .env relative to CWD, which
# only worked because the crontab entry happened to `cd` first.
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitor.db"
LOCK_PATH = DATA_DIR / ".monitor.lock"

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


def site_of(url_or_host: str) -> str:
    """The site a target belongs to: its host name, lower-cased, without the port
    and without a leading 'www.'.

    Alerts are grouped by site, which pairs apex and www twins (example.com and
    www.example.com) and keeps distinct subdomains apart. The previous key, the
    last two labels of the host, announced an outage of photo.example.com or of
    api.example.com as an outage of example.com.
    """
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    else:
        host = url_or_host
        if host.count(":") == 1:          # host:port, but not an IPv6 literal
            host = host.split(":", 1)[0]
    host = host.lower().rstrip(".")
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    return host


def cert_key(host: str, port: Optional[int]) -> str:
    """'example.com' for port 443, 'example.com:8443' or '[::1]:8443' otherwise."""
    if not port or port == 443:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def split_cert_key(key: str) -> Tuple[str, int]:
    if key.startswith("["):
        host, _, rest = key[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 443
    if key.count(":") == 1:
        host, port = key.split(":")
        if port.isdigit():
            return host, int(port)
    return key, 443


def plural(count: int, word: str, many: Optional[str] = None) -> str:
    """'1 target', '2 targets'."""
    return f"{count} {word if count == 1 else (many or word + 's')}"


_SECRET_KEY_RE = re.compile(r"(token|secret|key|password|passwd|auth|cookie)", re.I)


def _redacted(data: Any, depth: int = 0) -> Any:
    """Replace the values of secret-looking keys, at every level of nesting."""
    if depth > 20:
        return "<nested too deep>"
    if isinstance(data, dict):
        return {k: ("<redacted>" if _SECRET_KEY_RE.search(str(k)) else _redacted(v, depth + 1))
                for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_redacted(v, depth + 1) for v in data]
    return data


def redact(data: Any, limit: int = 600) -> str:
    """Render response data for an email without leaking credentials or flooding it."""
    if data is None:
        return "N/A"
    if isinstance(data, str):
        text = mask_secrets(data)
    else:
        text = json.dumps(_redacted(data), indent=2, default=str)
    if len(text) > limit:
        text = text[:limit] + f"\n... (truncated, {len(text)} chars total)"
    return text


_URL_USERINFO_RE = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@", re.I)
_SECRET_PARAM_RE = re.compile(
    r"([?&;](?:[^=&\s]*(?:token|secret|key|password|passwd|auth|signature|sig|session)"
    r"[^=&\s]*)=)[^&\s'\"<>]+", re.I)


def mask_secrets(text: Optional[str]) -> str:
    """Mask the password of a URL (user:***@host) and the values of secret-looking
    query parameters (?api_key=***), wherever a URL is shown: alert bodies, logs,
    summaries and the error texts of the HTTP library, which repeat the URL."""
    if not text:
        return text or ""
    return _SECRET_PARAM_RE.sub(r"\1***", _URL_USERINFO_RE.sub(r"\1***@", text))


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


class DailyFileHandler(logging.Handler):
    """Append each record to logs/monitor_YYYYMMDD.log, the file of its local date.

    Every invocation (the five-minute pass, a summary, --notify, a --continuous
    loop) writes to the dated file of the moment and nothing is ever renamed.
    Rotation by renaming, as before, let a short invocation rotate first after
    midnight, after which a long-running process kept writing into yesterday's
    file and never rotated again.
    """

    def __init__(self, directory: Path, prefix: str = "monitor_"):
        super().__init__()
        self.directory = directory
        self.prefix = prefix
        self._day: Optional[str] = None
        self._stream: Optional[Any] = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            day = time.strftime("%Y%m%d", time.localtime(record.created))
            if day != self._day or self._stream is None:
                if self._stream is not None:
                    self._stream.close()
                self._stream = open(self.directory / f"{self.prefix}{day}.log", "a",
                                    encoding="utf-8")
                self._day = day
            self._stream.write(self.format(record) + "\n")
            self._stream.flush()
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)

    def close(self) -> None:
        self.acquire()
        try:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
        finally:
            self.release()
        super().close()


def _adopt_rotating_log() -> None:
    """Fold the monitor.log of the rotating handler of earlier versions into the
    dated file of its last day, once; the rename makes the move happen once even
    when two processes start at the same moment."""
    old = LOG_DIR / "monitor.log"
    if not old.exists():
        return
    moving = LOG_DIR / f"monitor.log.adopting-{os.getpid()}"
    try:
        os.rename(old, moving)
    except OSError:
        return
    try:
        day = time.strftime("%Y%m%d", time.localtime(moving.stat().st_mtime))
        with open(moving, "rb") as src, open(LOG_DIR / f"monitor_{day}.log", "ab") as dst:
            shutil.copyfileobj(src, dst)
        moving.unlink()
    except OSError as exc:
        logger.warning("Could not fold the old monitor.log into the daily log: %s", exc)


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

    # One file per local day, written directly; compress_old_logs() keeps them.
    _adopt_rotating_log()
    file_handler = DailyFileHandler(LOG_DIR)
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
            stat = path.stat()
            if now - stat.st_mtime > retention_days * 86400:
                archive = Path(f"{path}.gz")
                with open(path, "rb") as src, gzip.open(archive, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                # The archive keeps the age of its log, so that LOG_ARCHIVE_DAYS
                # counts from the day logged, not from the day of compression.
                os.utime(archive, (stat.st_atime, stat.st_mtime))
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
    timeout: Optional[float] = None
    check_cert: Optional[bool] = None

    @property
    def site(self) -> str:
        return site_of(self.url)

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()

    @property
    def is_https(self) -> bool:
        return urlparse(self.url).scheme == "https"

    @property
    def cert_key(self) -> str:
        """The host whose certificate is probed, with its port when it is not 443."""
        try:
            port = urlparse(self.url).port
        except ValueError:
            port = None
        return cert_key(self.host, port)

    def follows_redirects(self) -> bool:
        if self.allow_redirects is not None:
            return self.allow_redirects
        return self.kind == "website"

    def wants_cert_check(self) -> bool:
        if self.check_cert is not None:
            return self.check_cert
        return self.is_https and self.verify_ssl


def _coerce(value: str) -> Any:
    """Coerce a config string to bool/int/float where unambiguous; a value in
    double quotes stays a string ("yes", "1.0")."""
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] == '"':
        return stripped[1:-1]
    low = stripped.lower()
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


TOML_KEYS = frozenset((
    "name", "url", "expected_status", "expected_response", "expect", "expect_text",
    "expect_regex", "method", "headers", "verify_ssl", "allow_redirects", "timeout",
    "check_cert",
))


def _toml_bool(entry: Dict[str, Any], key: str, default: Optional[bool],
               where: str) -> Optional[bool]:
    """A boolean of targets.toml; the strings "true" and "false" are accepted, since
    verify_ssl = "false" used to mean True."""
    value = entry.get(key, default)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ConfigError(f"{where}: {key} must be true or false, not {value!r}")


def _toml_int(entry: Dict[str, Any], key: str, default: Optional[int],
              where: str) -> Optional[int]:
    """An integer of targets.toml; a quoted number such as "200" is accepted, since
    it used to fail every check with 'Expected status 200, got 200'."""
    value = entry.get(key, default)
    if value is None or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise ConfigError(f"{where}: {key} must be a whole number, not {value!r}")


def _toml_seconds(entry: Dict[str, Any], key: str, where: str) -> Optional[float]:
    value = entry.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            value = None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        return value
    raise ConfigError(f"{where}: {key} must be a positive number of seconds")


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


# ---------------------------------------------------------------------------
# Kinds of message and their routes
# ---------------------------------------------------------------------------

# Each kind of message has a route, ROUTE_<KIND>, naming the channels that carry
# it: "email", "command" (MESSAGE_COMMAND), both, or "none".
ROUTED_KINDS: Tuple[str, ...] = ("DOWN", "RESOLVED", "TLS", "SUMMARY", "NOTIFY")
CHANNELS: Tuple[str, ...] = ("email", "command")
# Kinds that travel with another kind: a flapping notice is part of the outage
# alerts, the notice that a target is steady again part of the recoveries.
ROUTE_OF: Dict[str, str] = {"FLAP": "DOWN", "STEADY": "RESOLVED"}
# The {level} handed to a command, in the vocabulary of chat notifiers.
MESSAGE_LEVELS: Dict[str, str] = {
    "DOWN": "error", "BROKEN": "error", "FLAP": "warn", "TLS": "warn", "NOTIFY": "warn",
    "RESOLVED": "success", "STEADY": "success", "SUMMARY": "info", "TEST": "info",
}


def _env_route(key: str) -> List[str]:
    """Parse ROUTE_<KIND>: channels separated by commas, '+' or spaces, or 'none'."""
    raw = (os.getenv(key) or "").strip().lower()
    if not raw:
        return ["email"]
    parts = [part for part in re.split(r"[\s,+]+", raw) if part]
    if "none" in parts:
        if len(parts) > 1:
            raise ConfigError(f"{key}={raw!r}: 'none' cannot be combined with a channel")
        return []
    for part in parts:
        if part not in CHANNELS:
            raise ConfigError(f"{key}={raw!r}: unknown channel {part!r} "
                              "(use email, command, both separated by a comma, or none)")
    return list(dict.fromkeys(parts))


class Config:
    """Runtime configuration, from environment/.env plus optional targets.toml."""

    def __init__(self, targets_file: Optional[Path] = None, check_targets: bool = True):
        self.smtp_server = (os.getenv("SMTP_SERVER") or "").strip()
        self.smtp_port = _env_int("SMTP_PORT", 587)
        self.smtp_security = (os.getenv("SMTP_SECURITY", "starttls") or "starttls").lower()
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_timeout = _env_int("SMTP_TIMEOUT", 30)
        self.alert_email = [
            addr.strip() for addr in (os.getenv("ALERT_EMAIL") or "").split(",") if addr.strip()
        ]
        # The sender: SMTP_FROM, else the login, which most servers require anyway.
        self.smtp_from = ((os.getenv("SMTP_FROM") or "").strip()
                          or (self.smtp_username or "").strip())
        self.fallback_command = (os.getenv("FALLBACK_COMMAND") or "").strip()
        self.message_command = (os.getenv("MESSAGE_COMMAND") or "").strip()
        self.routes: Dict[str, List[str]] = {
            kind: _env_route(f"ROUTE_{kind}") for kind in ROUTED_KINDS
        }

        self.timeout = _env_int("TIMEOUT", 30)
        self.max_retries = max(1, _env_int("MAX_RETRIES", 3))
        self.max_workers = max(1, _env_int("MAX_WORKERS", 8))
        self.check_interval = _env_int("CHECK_INTERVAL", 300)
        self.alert_cooldown = _env_int("ALERT_COOLDOWN", 3600)
        self.failure_threshold = max(1, _env_int("FAILURE_THRESHOLD", 1))
        self.group_alerts = _env_bool("GROUP_ALERTS", True)
        self.slow_threshold_ms = _env_int("SLOW_THRESHOLD_MS", 0)

        # Flapping: FLAP_CHANGES changes of state over the last FLAP_WINDOW checks
        # (0 turns it off); while flapping, an outage waits FLAP_HOLD seconds.
        self.flap_changes = max(0, _env_int("FLAP_CHANGES", 6))
        self.flap_window = max(2, _env_int("FLAP_WINDOW", 12))
        self.flap_hold = max(0, _env_int("FLAP_HOLD", 900))

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

        # --notify and the test messages need the channels, not the targets: a
        # typo in a URL must not stop the security watchdog's message.
        self.validate(check_targets)

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

        for table in data:
            if table not in ("website", "api"):
                logger.error("Unknown table %r in %s, ignored: the tables are "
                             "[[website]] and [[api]]", table, path)

        targets: List[Target] = []
        for kind in ("website", "api"):
            entries = data.get(kind, []) or []
            if not isinstance(entries, list):
                raise ConfigError(f"{path}: write [[{kind}]] (an array of tables), not [{kind}]")
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("url"):
                    logger.error("Ignoring %s entry without a url in %s: %r", kind, path, entry)
                    continue
                url = str(entry["url"]).strip()
                where = f"{path}, {kind} {entry.get('name') or url!r}"
                for key in entry:
                    if key not in TOML_KEYS:
                        logger.error("%s: unknown key %r, ignored (valid keys: %s)",
                                     where, key, ", ".join(sorted(TOML_KEYS)))
                expect_text = entry.get("expect") or entry.get("expect_text")
                expect_regex = _toml_bool(entry, "expect_regex", False, where)
                if expect_text and expect_regex:
                    try:
                        re.compile(str(expect_text))
                    except re.error as exc:
                        raise ConfigError(f"{where}: expect is not a valid regular "
                                          f"expression: {exc}") from exc
                headers = entry.get("headers") or {}
                if not isinstance(headers, dict):
                    raise ConfigError(f"{where}: headers must be a table of names and values")
                expected = entry.get("expected_response") or {}
                if not isinstance(expected, dict):
                    raise ConfigError(f"{where}: expected_response must be a table")
                targets.append(Target(
                    name=str(entry.get("name") or url),
                    url=url,
                    kind=kind,
                    expected_status=_toml_int(entry, "expected_status",
                                              200 if kind == "api" else None, where),
                    expected_response=dict(expected),
                    expect_text=str(expect_text) if expect_text else None,
                    expect_regex=bool(expect_regex),
                    method=str(entry.get("method", "GET")).upper(),
                    headers={str(k): str(v) for k, v in headers.items()},
                    verify_ssl=bool(_toml_bool(entry, "verify_ssl", True, where)),
                    allow_redirects=_toml_bool(entry, "allow_redirects", None, where),
                    timeout=_toml_seconds(entry, "timeout", where),
                    check_cert=_toml_bool(entry, "check_cert", None, where),
                ))
        return targets

    # -- validation --------------------------------------------------------

    def uses(self, channel: str) -> bool:
        """Does any route name this channel?"""
        return any(channel in channels for channels in self.routes.values())

    def email_problem(self) -> Optional[str]:
        """Why no email can be sent with these settings, or None when it can."""
        if not self.smtp_server:
            return "SMTP server not configured (set SMTP_SERVER in .env)"
        if bool(self.smtp_username) != bool(self.smtp_password):
            return ("SMTP credentials incomplete: set both SMTP_USERNAME and SMTP_PASSWORD, "
                    "or neither for a server that takes mail without a login")
        if not self.smtp_from:
            return "No sender address: set SMTP_FROM (or SMTP_USERNAME, when it is an address)"
        if not self.alert_email:
            return "Alert email not configured (set ALERT_EMAIL in .env)"
        if self.smtp_security not in ("starttls", "ssl", "plain"):
            return f"SMTP_SECURITY must be starttls, ssl or plain (got {self.smtp_security!r})"
        return None

    def route_text(self) -> str:
        """The routes in one line, for --status and the test message."""
        return ", ".join(f"{kind.lower()} " + ("by " + " and ".join(chans) if chans else "not sent")
                         for kind, chans in self.routes.items())

    def cert_hosts(self) -> List[str]:
        """Certificates probed, as host or host:port, in the order of the targets."""
        if not self.ssl_check_enabled:
            return []
        hosts: Dict[str, None] = {}
        for target in self.targets:
            if target.wants_cert_check() and target.host:
                hosts.setdefault(target.cert_key, None)
        return list(hosts)

    def validate(self, check_targets: bool = True) -> None:
        if self.uses("email"):
            problem = self.email_problem()
            if problem:
                raise ConfigError(problem)
        if self.uses("command") and not self.message_command:
            raise ConfigError("A ROUTE_* setting names the command channel, "
                              "but MESSAGE_COMMAND is empty")
        for key, command in (("FALLBACK_COMMAND", self.fallback_command),
                             ("MESSAGE_COMMAND", self.message_command)):
            if command:
                try:
                    if not shlex.split(command):
                        raise ValueError("no program named")
                except ValueError as exc:
                    raise ConfigError(f"{key} cannot be parsed: {exc}") from exc
        if not check_targets:
            return
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
    last_change_at      TEXT,
    failing_since       TEXT,          -- first failed check of the current streak
    flapping_since      TEXT           -- set while the target is flapping
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
    state      TEXT NOT NULL DEFAULT 'pending',   -- pending | sent | fallback | failed
    created_at TEXT NOT NULL,
    sent_at    TEXT,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    subject    TEXT NOT NULL,
    channels   TEXT                               -- e.g. 'email', 'email,command', 'fallback'
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

# Columns added after a table was first released. CREATE TABLE IF NOT EXISTS
# leaves an existing table as it is, so a database from an earlier version
# gains them here, once.
ADDED_COLUMNS: Tuple[Tuple[str, str, str], ...] = (
    ("targets", "failing_since", "TEXT"),
    ("targets", "flapping_since", "TEXT"),
    ("notifications", "channels", "TEXT"),
)


class Database:
    """SQLite state store.

    One connection guarded by a re-entrant lock. SQLite serialises writes anyway,
    and the check workload is network-bound, so a single guarded connection is
    simpler and safer than a pool while remaining correct under ThreadPoolExecutor.
    """

    def __init__(self, path: Optional[Path] = None):
        path = path or DB_PATH
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
            self._add_missing_columns()
            self._conn.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _add_missing_columns(self) -> None:
        for table, column, decl in ADDED_COLUMNS:
            have = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            if column in have:
                continue
            try:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as exc:
                # Another process (a report run at the same moment) added it first.
                if "duplicate column" not in str(exc).lower():
                    raise

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
                    (target.name, target.url, target.kind, target.site),
                )
            self._conn.commit()
            for row in self._conn.execute("SELECT id, name FROM targets"):
                ids[row["name"]] = row["id"]
        return ids

    def prune_targets(self, keep_names: Iterable[str], grace_days: float = 0) -> int:
        """Remove targets no longer configured, and their history by cascade, once
        they have not been checked for `grace_days`. The grace keeps a renamed
        target, a trial with another targets file or a mistaken edit from wiping
        the history at once."""
        keep = set(keep_names)
        cutoff = (now_utc() - timedelta(days=grace_days)).isoformat()
        removed = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, last_checked_at FROM targets").fetchall()
            for row in rows:
                if row["name"] in keep:
                    continue
                if grace_days and row["last_checked_at"] and row["last_checked_at"] >= cutoff:
                    continue
                self._conn.execute("DELETE FROM targets WHERE id = ?", (row["id"],))
                removed += 1
            self._conn.commit()
        return removed

    def prune_certs(self, keep_hosts: Iterable[str]) -> int:
        """Forget the certificates of hosts no longer monitored. Their rows used to
        stay forever and appear in every summary, their days left running down."""
        keep = set(keep_hosts)
        with self._lock:
            rows = self._conn.execute("SELECT host FROM certs").fetchall()
            stale = [row["host"] for row in rows if row["host"] not in keep]
            for host in stale:
                self._conn.execute("DELETE FROM certs WHERE host = ?", (host,))
            self._conn.commit()
        return len(stale)

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
                       -- A day straddling the cutoff is rolled up in two passes, and
                       -- its first part is deleted after the first: add, never replace.
                       avg_ms = CASE
                           WHEN daily_stats.avg_ms IS NULL THEN excluded.avg_ms
                           WHEN excluded.avg_ms IS NULL THEN daily_stats.avg_ms
                           ELSE (daily_stats.avg_ms * daily_stats.checks
                                 + excluded.avg_ms * excluded.checks)
                                / (daily_stats.checks + excluded.checks) END,
                       max_ms = MAX(COALESCE(daily_stats.max_ms, excluded.max_ms),
                                    COALESCE(excluded.max_ms, daily_stats.max_ms)),
                       checks = daily_stats.checks + excluded.checks,
                       failures = daily_stats.failures + excluded.failures
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

# A body is read up to this size, which is far more than any page needs for an
# `expect` text or an API needs for its health fields.
MAX_BODY_BYTES = 4 * 1024 * 1024


def read_body(response: requests.Response, start: float, timeout: float) -> str:
    """Read the body within `timeout` seconds of `start` and up to MAX_BODY_BYTES.

    The timeout of the HTTP library applies to each read of the socket, so a
    server trickling its answer a byte at a time used to keep a check reading
    forever, and the lock of that run kept every later run from checking
    anything. read1 returns what has arrived instead of waiting for a full
    chunk, which lets the deadline be enforced between reads.
    """
    raw = response.raw
    chunks: List[bytes] = []
    size = 0
    reader = getattr(raw, "read1", None)
    while size < MAX_BODY_BYTES:
        if reader is not None:
            chunk = reader(65536, decode_content=True)
        else:  # urllib3 1.x
            chunk = raw.read(8192, decode_content=True)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if time.monotonic() - start > timeout:
            raise Timeout(f"body not received within {timeout} seconds")
    data = b"".join(chunks)[:MAX_BODY_BYTES]
    return data.decode(response.encoding or "utf-8", errors="replace")


class Checker:
    """Performs HTTP checks for both website and API targets."""

    def __init__(self, config: Config):
        self.config = config
        self._local = threading.local()
        # A target with verify_ssl = false is a deliberate choice: the warning the
        # HTTP library prints at every request would only fill cron.log.
        if any(not t.verify_ssl for t in getattr(config, "targets", [])):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
                if target.kind == "api" and not any(
                        k.lower() == "accept" for k in (headers or {})):
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
                        body = read_body(response, start, timeout)
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
                last_error = mask_secrets(f"SSL error: {exc}")
                last_details = None
                logger.warning("SSL error for %s: %s", mask_secrets(target.url), last_error)
            except Timeout:
                last_error = f"Timeout after {timeout} seconds"
                last_details = None
                logger.warning("Timeout for %s", mask_secrets(target.url))
            except RequestException as exc:
                last_error = mask_secrets(f"Request failed: {exc}")
                last_details = None
                logger.warning("Request error for %s: %s", mask_secrets(target.url), last_error)
            except Exception as exc:  # noqa: BLE001 - never let one target kill the run
                last_error = mask_secrets(f"Unexpected error: {exc}")
                last_details = None
                logger.error("Unexpected error for %s: %s", mask_secrets(target.url), last_error,
                             exc_info=True)

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
        not_after = datetime.strptime(str(cert["notAfter"]),
                                      "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        result["not_after"] = not_after.isoformat()
        fields: Any = cert.get("issuer", ())  # ((("organizationName", "X"),), ...)
        issuer = {k: v for part in fields for k, v in part}
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
                           slack: float = JITTER_SLACK,
                           scale: float = 1.0) -> Tuple[int, float]:
    """Given seconds elapsed since confirmation, return (notify_count, next_offset).

    Offsets are absolute from the confirmation time, never "last sent + delay",
    so scheduling drift cannot accumulate over a long outage. The `slack` term is
    applied here as well as in `is_notification_due` - without it, firing three
    seconds early at one step would compress every subsequent step and slide the
    schedule back toward hourly. `scale` stretches the whole ladder: it is
    ALERT_COOLDOWN / 3600, so that the first reminder comes after ALERT_COOLDOWN.
    """
    elapsed = max(0.0, elapsed)
    offsets = [offset * scale for offset in ESCALATION_OFFSETS]
    tail = ESCALATION_TAIL * scale
    count = 0
    for offset in offsets:
        if elapsed + slack >= offset:
            count += 1
        else:
            break
    if count == len(offsets):
        # Past the last fixed rung, count the daily rungs already behind us too,
        # so that a monitor back from a long gap sends one reminder, not a burst.
        count += int((elapsed + slack - offsets[-1]) // tail)
    count = max(count, notify_count + 1)

    if count < len(offsets):
        return count, offsets[count]
    extra = count - len(offsets) + 1
    return count, offsets[-1] + extra * tail


def is_notification_due(elapsed: float, next_offset: Optional[float],
                        slack: float = JITTER_SLACK) -> bool:
    """Is a re-alert due?

    The `slack` is what fixes the production bug where ALERT_COOLDOWN equalled the
    cron period: a run arriving 3 seconds early measured 3597s against a 3600s
    threshold and silently skipped, so alerts alternated between odd and even
    hours. Anything within `slack` of the threshold counts as due.
    """
    if next_offset is None:
        return True
    return elapsed + slack >= next_offset


def count_changes(window: Sequence[bool]) -> int:
    """Changes of state between consecutive checks of a window.

    A target that is simply down for twelve hours has none, so a long outage is
    never mistaken for flapping.
    """
    return sum(1 for newer, older in zip(window, window[1:]) if newer != older)


@dataclass
class Transition:
    """What one check did to a target's state, and what should be announced."""

    target: Target
    healthy: bool
    details: Dict[str, Any]
    kind: Optional[str] = None       # None | "DOWN" | "REALERT" | "RESOLVED"
    incident_id: Optional[int] = None
    started_at: Optional[datetime] = None
    duration_s: Optional[float] = None
    suppressed_by: Optional[str] = None
    flap_event: Optional[str] = None  # None | "start" | "stop"
    flapping: bool = False
    flap_changes: int = 0
    flap_failures: int = 0
    flap_checks: int = 0
    # What dispatch made of the messages, and what to put back when they failed.
    delivery: Optional[str] = None
    flap_delivery: Optional[str] = None
    prev_notify: Optional[Tuple[int, Optional[str], Optional[str], Optional[str]]] = None
    prev_flapping_since: Optional[str] = None


# A message in one of these states was not delivered and is tried again at the
# next pass. A dry run leaves the alerts to the first real run.
RETRY_STATES = ("failed", "dry-run")


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

    def _scale(self) -> float:
        """ALERT_COOLDOWN stretches the whole ladder; 3600 is the ladder as written."""
        return max(self.config.alert_cooldown, 300) / 3600.0

    def _slack(self) -> float:
        # Always below half the smallest gap of the ladder, whatever its scale.
        return min(float(JITTER_SLACK), 3600.0 * self._scale() / 4)

    def settle(self, transitions: Sequence[Transition]) -> int:
        """After dispatch, put back the alerts whose message was not delivered, so
        that the next pass sends them again, and record the recoveries that were.

        The schedule used to move on when an alert was decided, whatever became of
        its mail: after a failed DOWN the first message was a STILL DOWN an hour
        later, or a RESOLVED for an outage nobody had been told about. Returns the
        number of messages left undelivered.
        """
        undelivered = 0
        for t in transitions:
            if t.kind in ("DOWN", "REALERT") and t.incident_id and t.prev_notify \
                    and t.delivery in RETRY_STATES:
                count, next_at, last_at, suppressed = t.prev_notify
                self.db.execute(
                    "UPDATE incidents SET notify_count = ?, next_notify_at = ?, "
                    "last_notified_at = ?, suppressed_by = ? WHERE id = ? AND status = 'open'",
                    (count, next_at, last_at, suppressed, t.incident_id))
                undelivered += 1
            elif t.kind == "RESOLVED" and t.incident_id:
                if t.delivery in RETRY_STATES:
                    undelivered += 1
                else:
                    self.db.execute("UPDATE incidents SET resolved_notified = 1 WHERE id = ?",
                                    (t.incident_id,))
            if t.flap_event and t.flap_delivery in RETRY_STATES:
                # Undo the change of the flapping state, so that it is noticed again.
                self.db.execute("UPDATE targets SET flapping_since = ? WHERE id = ?",
                                (t.prev_flapping_since, self.target_ids.get(t.target.name)))
                undelivered += 1
        return undelivered

    def pending_recoveries(self, run_ts: datetime, exclude: Iterable[Optional[int]]
                           ) -> List[Transition]:
        """Recoveries of announced outages whose message has not been delivered,
        tried again at each pass for a day."""
        skip = {i for i in exclude if i}
        since = (run_ts - timedelta(days=1)).isoformat()
        rows = self.db.query(
            "SELECT i.*, t.name FROM incidents i JOIN targets t ON t.id = i.target_id "
            "WHERE i.status = 'resolved' AND i.notify_count > 0 AND i.resolved_notified = 0 "
            "AND i.ended_at >= ?", (since,))
        by_name = {t.name: t for t in self.config.targets}
        out: List[Transition] = []
        for row in rows:
            target = by_name.get(row["name"])
            if target is None or row["id"] in skip:
                continue
            started, ended = _parse_dt(row["started_at"]), _parse_dt(row["ended_at"])
            out.append(Transition(
                target=target, healthy=True, kind="RESOLVED", incident_id=row["id"],
                details={"status_code": None, "response_time_ms": None, "error": None},
                started_at=started,
                duration_s=(ended - started).total_seconds() if started and ended else None))
        return out

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
        if not open_id:
            # The incident is the truth, the pointer only a shortcut: a run killed
            # between writing the two would otherwise leave an open incident that
            # nothing points to, and every later pass would fail on the index
            # allowing one open incident per target.
            lost = self.db.query_one(
                "SELECT id FROM incidents WHERE target_id = ? AND status = 'open'", (target_id,))
            if lost:
                open_id = lost["id"]
                self.db.execute("UPDATE targets SET open_incident_id = ? WHERE id = ?",
                                (open_id, target_id))
        cfails = (row["consecutive_failures"] if row else 0) or 0
        csucc = (row["consecutive_successes"] if row else 0) or 0
        failing_since = row["failing_since"] if row else None
        flapping_since = row["flapping_since"] if row else None

        transition = Transition(target=target, healthy=healthy, details=details)
        ts = run_ts.isoformat()
        flapping_since = self._track_flapping(target_id, healthy, ts, flapping_since,
                                              transition, cold_start)

        if healthy:
            csucc += 1
            cfails = 0
            failing_since = None
            if open_id:
                transition = self._resolve(target, open_id, run_ts, details, transition)
            new_status = "up"
        else:
            cfails += 1
            csucc = 0
            if cfails == 1 or not failing_since:
                failing_since = ts
            new_status = "down" if cfails >= self.config.failure_threshold else prev_status
            if new_status == "down":
                transition = self._open_or_escalate(
                    target, target_id, open_id, run_ts, details, transition,
                    cold_start=cold_start, suppress=suppress,
                    failing_since=failing_since, streak=cfails,
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
            "last_change_at = CASE WHEN status != ? THEN ? ELSE last_change_at END, "
            "failing_since = ?, flapping_since = ? "
            "WHERE id = ?",
            (new_status, cfails, csucc, ts, 1 if healthy else 0, ts,
             new_status, ts, failing_since, flapping_since, target_id),
        )
        if refreshed:
            transition.incident_id = refreshed["open_incident_id"] or transition.incident_id
        return transition

    def _track_flapping(self, target_id: int, healthy: bool, ts: str,
                        flapping_since: Optional[str], transition: Transition,
                        cold_start: bool) -> Optional[str]:
        """Decide from the target's last checks whether it flaps; return flapping_since.

        A target starts flapping when its last FLAP_WINDOW checks hold at least
        FLAP_CHANGES changes of state, and stops when they hold none, that is when it
        has kept one state through the whole window. Only a stop while up is
        announced: a target that settles down is announced by its outage alert.
        """
        transition.prev_flapping_since = flapping_since
        if not self.config.flap_changes:
            return None
        if cold_start:
            transition.flapping = bool(flapping_since)
            return flapping_since
        rows = self.db.query(
            "SELECT healthy FROM checks WHERE target_id = ? ORDER BY id DESC LIMIT ?",
            (target_id, self.config.flap_window))
        window = [bool(r["healthy"]) for r in rows]
        changes = count_changes(window)
        transition.flap_changes = changes
        transition.flap_failures = sum(1 for ok in window if not ok)
        transition.flap_checks = len(window)
        if not flapping_since and changes >= self.config.flap_changes:
            flapping_since = ts
            transition.flap_event = "start"
        elif flapping_since and changes == 0 and len(window) >= self.config.flap_window:
            flapping_since = None
            if healthy:
                transition.flap_event = "stop"
        transition.flapping = bool(flapping_since)
        return flapping_since

    def _open_or_escalate(self, target: Target, target_id: int, open_id: Optional[int],
                          run_ts: datetime, details: Dict[str, Any],
                          transition: Transition, cold_start: bool,
                          suppress: Optional[str], failing_since: Optional[str] = None,
                          streak: int = 1) -> Transition:
        ts = run_ts.isoformat()
        error = details.get("error")
        fail_class = details.get("fail_class")

        if not open_id:
            # With FAILURE_THRESHOLD above 1 the outage began at the first failed
            # check of the streak, not at the check that confirmed it.
            started = min(_parse_dt(failing_since) or run_ts, run_ts)
            hold = transition.flapping and self.config.flap_hold > 0
            reason = suppress or ("cold_start" if cold_start else None) or ("flap" if hold else None)
            next_at: Optional[datetime] = None
            count = 0
            if reason == "flap":
                # An outage of a flapping target is announced once it has lasted.
                next_at = run_ts + timedelta(seconds=self.config.flap_hold)
            elif not reason:
                count, offset = plan_next_notification(0.0, 0, slack=self._slack(),
                                                       scale=self._scale())
                next_at = run_ts + timedelta(seconds=offset)
            cur = self.db.execute(
                "INSERT INTO incidents(target_id, grp, status, started_at, confirmed_at, "
                "fail_class, first_error, last_error, status_code, checks_failed, "
                "notify_count, last_notified_at, next_notify_at, suppressed_by) "
                "VALUES(?,?,'open',?,?,?,?,?,?,?,?,?,?,?)",
                (target_id, target.site, started.isoformat(), ts, fail_class, error, error,
                 details.get("status_code"), max(1, streak), count,
                 ts if count else None,
                 next_at.isoformat() if next_at else None,
                 reason),
            )
            incident_id = cur.lastrowid
            self.db.execute("UPDATE targets SET open_incident_id = ? WHERE id = ?",
                            (incident_id, target_id))
            transition.incident_id = incident_id
            transition.started_at = started
            transition.suppressed_by = reason
            if not reason:
                transition.kind = "DOWN"
                transition.prev_notify = (0, None, None, None)
                if started < run_ts:
                    transition.duration_s = (run_ts - started).total_seconds()
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

        if inc["suppressed_by"] == "flap" and not (inc["notify_count"] or 0):
            # Held while the target flaps; announced once the outage has lasted
            # FLAP_HOLD, so that flapping can never silence a lasting outage.
            hold_s = next_offset if next_offset is not None else float(self.config.flap_hold)
            if elapsed + min(JITTER_SLACK, 60) < hold_s:
                transition.suppressed_by = "flap"
                return transition

        if is_notification_due(elapsed, next_offset, slack=self._slack()):
            transition.prev_notify = (inc["notify_count"] or 0, inc["next_notify_at"],
                                      inc["last_notified_at"], inc["suppressed_by"])
            count, offset = plan_next_notification(elapsed, inc["notify_count"] or 0,
                                                   slack=self._slack(), scale=self._scale())
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
        # Never announce the resolution of a problem the operator was never told
        # about. Whether the announcement was delivered is recorded by settle().
        if (inc["notify_count"] or 0) > 0:
            transition.kind = "RESOLVED"
        else:
            transition.suppressed_by = inc["suppressed_by"] or "never_alerted"
        return transition

    # -- legacy migration --------------------------------------------------

    def migrate_legacy_history(self, path: Optional[Path] = None,
                               local_tz: Optional[str] = None) -> Dict[str, int]:
        """Retire alert_history.json of version 1, once.

        The file is kept verbatim in the meta table and renamed. No cooldown is
        carried forward: the escalation clock now lives on each incident, and a
        stale cooldown on a healthy target was precisely the swallowed-outage
        bug; the entries are only counted, for the log.

        Timestamps without a timezone were written by an older build using
        `datetime.now()`, i.e. the host's LOCAL time (verified against the log
        archive: a naive 22:00:30 entry matches a 22:00:30 local log line). The
        previous code treated them as UTC, placing them four hours in the future
        and over-suppressing. They are converted from the local zone here.
        """
        report = {"imported": 0, "skipped_up": 0, "dropped_stale": 0, "tz_fixed": 0}
        path = path or LOG_DIR / "alert_history.json"
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

def _smtp_connect(host: str, port: int, security: str,
                  timeout: Optional[float]) -> smtplib.SMTP:
    """Open an SMTP connection: implicit TLS ("ssl"), none ("plain"), else STARTTLS.
    A timeout of None waits as long as the server takes."""
    wait: Any = timeout  # smtplib's own default is "no timeout", which None stands for
    if security == "ssl":
        return smtplib.SMTP_SSL(host, port, timeout=wait,
                                context=ssl.create_default_context())
    server = smtplib.SMTP(host, port, timeout=wait)
    if security != "plain":
        server.starttls(context=ssl.create_default_context())
    return server


def _sender_domain(address: Optional[str]) -> str:
    """Domain of a sender address, for a Message-ID that spam filters accept."""
    _, bare = parseaddr(address or "")
    if "@" in bare:
        return bare.rsplit("@", 1)[1]
    return socket.getfqdn()


# Kinds of message the spare route may carry. A test message is left out on
# purpose, so that a broken channel is reported as broken, and so is the daily
# summary, which is not worth waking anyone for.
FALLBACK_KINDS = ("DOWN", "RESOLVED", "TLS", "FLAP", "STEADY", "NOTIFY")
COMMAND_TIMEOUT_S = 30
COMMAND_MAX_BODY = 8000
_PLACEHOLDER_RE = re.compile(r"\{(subject|kind|level)\}")

# What a delivery came to, as Notifier.deliver reports it.
DELIVERED_STATES = ("sent", "fallback")
HARMLESS_STATES = ("sent", "fallback", "skipped", "duplicate", "dry-run")


def run_command(command: str, subject: str, body: str, kind: str = "NOTIFY",
                label: str = "Message command") -> Tuple[bool, Optional[str]]:
    """Hand a message to a command of one's own. Returns (delivered, error).

    The command line is split like a shell would, but no shell is involved. In
    each argument, ``{subject}`` becomes the subject, ``{kind}`` the kind of the
    message (down, resolved, tls, flap, steady, summary, notify, test, broken)
    and ``{level}`` its weight in the words of chat notifiers (error, warn,
    success, info), all in one pass, so that a subject containing such a word
    is never rewritten. The body is written to the standard input. The message
    counts as delivered when the command exits with status 0.
    """
    if not command:
        return False, "no command configured"
    values = {"subject": subject, "kind": kind.lower(),
              "level": MESSAGE_LEVELS.get(kind, "info")}
    try:
        argv = [_PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], part)
                for part in shlex.split(command)]
    except ValueError as exc:
        logger.error("%s cannot be parsed: %s", label, exc)
        return False, f"cannot be parsed: {exc}"
    if not argv:
        return False, "empty command"
    try:
        done = subprocess.run(argv, input=body[:COMMAND_MAX_BODY], text=True,
                              capture_output=True, timeout=COMMAND_TIMEOUT_S,
                              check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("%s failed to run: %s", label, exc)
        return False, f"failed to run: {exc}"
    if done.returncode != 0:
        tail = (done.stderr or "").strip()[-200:]
        logger.error("%s exited with status %d: %s", label, done.returncode, tail)
        return False, f"exit status {done.returncode}"
    return True, None


def run_fallback(command: str, subject: str, body: str, kind: str = "NOTIFY") -> bool:
    """Deliver a message by the spare route when its channels could not."""
    ok, _ = run_command(command, subject, body, kind, label="Spare route")
    if ok:
        logger.warning("Delivered by the spare route: %s", subject)
    return ok


class Notifier:
    """Builds coalesced alerts and delivers each message by the channels of its route."""

    def __init__(self, config: Config, db: Optional[Database] = None, dry_run: bool = False):
        self.config = config
        self.db = db
        self.dry_run = dry_run

    # -- transport ---------------------------------------------------------

    def _connect(self) -> smtplib.SMTP:
        return _smtp_connect(self.config.smtp_server, self.config.smtp_port,
                             self.config.smtp_security, self.config.smtp_timeout or None)

    def send(self, subject: str, body: str, html: Optional[str] = None,
             dedup_key: Optional[str] = None, kind: str = "NOTIFY",
             channels: Optional[Sequence[str]] = None) -> bool:
        """Deliver one message. True if a channel of its route, or for the kinds in
        FALLBACK_KINDS the spare route, delivered it."""
        return self.deliver(subject, body, html, dedup_key, kind, channels) in DELIVERED_STATES

    def deliver(self, subject: str, body: str, html: Optional[str] = None,
                dedup_key: Optional[str] = None, kind: str = "NOTIFY",
                channels: Optional[Sequence[str]] = None) -> str:
        """Deliver one message by the channels of its route (or those given).

        Returns 'sent', 'fallback' (the spare route carried it), 'failed',
        'skipped' (the route is none), 'duplicate' (already delivered under this
        dedup_key) or 'dry-run'.
        """
        route = ROUTE_OF.get(kind, kind)
        chosen = list(channels) if channels is not None else self.config.routes.get(
            route, ["email"])
        if not chosen:
            logger.info("Not sent, ROUTE_%s is none: %s", route, subject)
            return "skipped"
        if self.dry_run:
            logger.warning("[dry-run] would send by %s: %s", " and ".join(chosen), subject)
            logger.debug("[dry-run] body:\n%s", body)
            return "dry-run"

        if dedup_key and self.db is not None:
            existing = self.db.query_one(
                "SELECT state FROM notifications WHERE dedup_key = ?", (dedup_key,))
            if existing and existing["state"] in DELIVERED_STATES:
                logger.debug("Notification %s already sent, skipping", dedup_key)
                return "duplicate"
            self.db.execute(
                "INSERT INTO notifications(kind, dedup_key, state, created_at, subject) "
                "VALUES(?,?,'pending',?,?) ON CONFLICT(dedup_key) DO NOTHING",
                (kind, dedup_key, now_utc().isoformat(), subject),
            )

        delivered: List[str] = []
        errors: List[str] = []
        for channel in chosen:
            if channel == "email":
                ok, error = self._send_email(subject, body, html, dedup_key)
            else:
                ok, error = run_command(self.config.message_command, subject, body, kind)
                if ok:
                    logger.info("Sent by command: %s", subject)
            if ok:
                delivered.append(channel)
            else:
                errors.append(f"{channel}: {error}")

        state = "sent" if delivered else "failed"
        if not delivered:
            logger.error("Failed to send %r: %s", subject, "; ".join(errors))
            spare = self.config.fallback_command
            # The spare route is pointless when it is the command that just failed.
            same = "command" in chosen and spare == self.config.message_command
            if kind in FALLBACK_KINDS and spare and not same and \
                    run_fallback(spare, subject, body, kind):
                delivered.append("fallback")
                state = "fallback"

        if dedup_key and self.db is not None:
            self.db.execute(
                "UPDATE notifications SET state=?, sent_at=?, attempts=attempts+1, "
                "last_error=?, channels=? WHERE dedup_key = ?",
                (state, now_utc().isoformat() if delivered else None,
                 "; ".join(errors) or None, ",".join(delivered) or None, dedup_key))
        return state

    def _send_email(self, subject: str, body: str, html: Optional[str],
                    dedup_key: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        problem = self.config.email_problem()
        if problem:
            return False, problem
        msg = MIMEMultipart("alternative")
        msg["From"] = self.config.smtp_from
        msg["To"] = ", ".join(self.config.alert_email)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        # A Message-ID derived from the dedup key lets the mail client collapse a
        # duplicate if we crash between a successful send and recording it.
        domain = _sender_domain(self.config.smtp_from)
        msg["Message-ID"] = (
            f"<{hashlib.sha256(dedup_key.encode()).hexdigest()[:32]}@{domain}>"
            if dedup_key else make_msgid(domain=domain))
        msg["Auto-Submitted"] = "auto-generated"
        msg.attach(MIMEText(body, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))

        last_error: Optional[str] = None
        for attempt in range(2):
            try:
                with closing(self._connect()) as server:
                    # A local relay may take mail without a login.
                    if self.config.smtp_username:
                        server.login(self.config.smtp_username, self.config.smtp_password or "")
                    server.send_message(msg)
                logger.info("Sent: %s", subject)
                return True, None
            except smtplib.SMTPAuthenticationError as exc:
                # A wrong password stays wrong, and the mail server bans an
                # address after a few refused logins: never try twice.
                last_error = f"login refused: {exc}"
                logger.error("SMTP login refused, not retrying: %s", exc)
                break
            except (smtplib.SMTPException, OSError) as exc:
                last_error = str(exc)
                logger.warning("SMTP attempt %d failed: %s", attempt + 1, exc)
                if attempt == 0:
                    time.sleep(5)
        return False, last_error

    # -- composition -------------------------------------------------------

    def dispatch(self, transitions: Sequence[Transition], run_ts: datetime,
                 banner: Optional[str] = None, suspect_self: bool = False) -> int:
        """Group transitions into as few messages as possible and send them.

        Each transition keeps in `delivery` (and `flap_delivery`) what became of
        its message, for IncidentEngine.settle(). Returns the number delivered.
        """
        downs = [t for t in transitions if t.kind in ("DOWN", "REALERT")]
        ups = [t for t in transitions if t.kind == "RESOLVED"]
        flaps = [t for t in transitions if t.flap_event == "start"]
        steadies = [t for t in transitions if t.flap_event == "stop"]
        sent = 0

        def note(items: Sequence[Transition], state: str, attr: str = "delivery") -> None:
            nonlocal sent
            sent += 1 if state in DELIVERED_STATES else 0
            for t in items:
                setattr(t, attr, state)

        if downs:
            for chunk, (subject, body, html, key) in self._compose_down_chunks(
                    downs, run_ts, banner, suspect_self):
                note(chunk, self.deliver(subject, body, html, key, "DOWN"))
        if ups:
            for subject, body, html, key in self._compose_resolved(ups, run_ts):
                note(ups, self.deliver(subject, body, html, key, "RESOLVED"))
        if flaps:
            subject, body, html, key = self._compose_flap(flaps, run_ts, banner)
            note(flaps, self.deliver(subject, body, html, key, "FLAP"), "flap_delivery")
        if steadies:
            subject, body, html, key = self._compose_steady(steadies, run_ts)
            note(steadies, self.deliver(subject, body, html, key, "STEADY"), "flap_delivery")
        return sent

    def _groups(self, transitions: Sequence[Transition]) -> List[List[Transition]]:
        if not self.config.group_alerts:
            return [[t] for t in transitions]
        buckets: Dict[str, List[Transition]] = {}
        for t in transitions:
            buckets.setdefault(t.target.site, []).append(t)
        return [buckets[k] for k in sorted(buckets)]

    @staticmethod
    def _sites_subject(tag: str, items: Sequence[Transition], one: str, many: str) -> str:
        """'[DOWN] photo.example.com: 2 targets failing', or for several sites
        '[DOWN] 3 sites, 4 targets failing: a.org, b.org, c.org'."""
        sites = sorted({t.target.site for t in items})
        if len(sites) == 1:
            return f"[{tag}] {sites[0]}: {one}"
        names = ", ".join(sites[:3]) + ("…" if len(sites) > 3 else "")
        return f"[{tag}] {len(sites)} sites, {many}: {names}"

    @staticmethod
    def _stamp(run_ts: datetime) -> str:
        local = run_ts.astimezone()
        return (f"{run_ts.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                f"({local.strftime('%H:%M %Z')})")

    def _compose_down(self, downs: Sequence[Transition], run_ts: datetime,
                      banner: Optional[str],
                      suspect_self: bool = False) -> List[Tuple[str, str, str, str]]:
        return [message for _, message in
                self._compose_down_chunks(downs, run_ts, banner, suspect_self)]

    def _compose_down_chunks(self, downs: Sequence[Transition], run_ts: datetime,
                             banner: Optional[str], suspect_self: bool = False
                             ) -> List[Tuple[List[Transition], Tuple[str, str, str, str]]]:
        out = []
        # One message per run covering every affected site (GROUP_ALERTS=true), or
        # one per target; within a message the targets are listed site by site.
        groups = self._groups(downs)
        all_in_one = self.config.group_alerts
        chunks = [downs] if all_in_one else groups

        for chunk in chunks:
            chunk = list(chunk)
            sites = sorted({t.target.site for t in chunk})
            realert = all(t.kind == "REALERT" for t in chunk)
            tag = "STILL DOWN" if realert else "DOWN"
            failing = f"{plural(len(chunk), 'target')} failing"
            if suspect_self:
                failing += ", the monitoring host suspected"
            subject = self._sites_subject(tag, chunk, failing, failing)

            lines = [f"{'Website/API Monitoring Alert':^68}", "=" * 68, ""]
            if banner:
                lines += [f"!! {banner}", ""]
            lines += [f"Time: {self._stamp(run_ts)}", ""]
            for site in sites:
                members = [t for t in chunk if t.target.site == site]
                lines.append(f"── {site} " + "─" * max(0, 64 - len(site)))
                for t in members:
                    d = t.details
                    down_for = (f", down for {human_duration(t.duration_s)}"
                                if t.duration_s and t.duration_s >= 60 else "")
                    lines.append(f"  ✗ {mask_secrets(t.target.name)}{down_for}")
                    lines.append(f"      URL:    {mask_secrets(t.target.url)}")
                    lines.append(f"      Error:  {d.get('error', 'Unknown')}")
                    lines.append(f"      Status: {d.get('status_code', 'N/A')}"
                                 f"   Class: {d.get('fail_class', 'unknown')}")
                    if d.get("response_time_ms") is not None:
                        lines.append(f"      Time:   {d['response_time_ms']} ms")
                    if t.target.kind == "api" and d.get("response_data") is not None:
                        lines.append("      Body:   " + redact(d["response_data"]).replace("\n", "\n              "))
                    if t.flapping:
                        lines.append(f"      Note:   flapping, {t.flap_changes} changes of state "
                                     f"in its last {t.flap_checks} checks")
                lines.append("")
            classes = sorted({t.details.get("fail_class") or "unknown" for t in chunk})
            if len(classes) > 1:
                lines += [f"Note: mixed failure types in this alert ({', '.join(classes)}); "
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
            out.append((chunk, (subject, body, self._html_down(chunk, run_ts, banner), key)))
        return out

    def _compose_resolved(self, ups: Sequence[Transition],
                          run_ts: datetime) -> List[Tuple[str, str, str, str]]:
        sites = sorted({t.target.site for t in ups})
        longest = human_duration(max((t.duration_s or 0) for t in ups))
        subject = self._sites_subject("RESOLVED", ups, f"back up after {longest}",
                                      f"{plural(len(ups), 'target')} back up after {longest}")

        lines = [f"{'Service Restored':^68}", "=" * 68, "",
                 f"Time: {self._stamp(run_ts)}", ""]
        for site in sites:
            members = [t for t in ups if t.target.site == site]
            lines.append(f"── {site} " + "─" * max(0, 64 - len(site)))
            for t in members:
                lines.append(f"  ✓ {mask_secrets(t.target.name)}")
                lines.append(f"      URL:      {mask_secrets(t.target.url)}")
                if t.started_at:
                    lines.append(f"      Down at:  {self._stamp(t.started_at)}")
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

    def _flap_lines(self, items: Sequence[Transition], mark: str) -> List[str]:
        lines: List[str] = []
        for site in sorted({t.target.site for t in items}):
            lines.append(f"── {site} " + "─" * max(0, 64 - len(site)))
            for t in (x for x in items if x.target.site == site):
                state = "up now" if t.healthy else (
                    f"down now ({t.details.get('error') or 'unknown error'})")
                lines.append(f"  {mark} {mask_secrets(t.target.name)}: "
                             f"{plural(t.flap_changes, 'change')} of "
                             f"state and {plural(t.flap_failures, 'failed check')} in its last "
                             f"{plural(t.flap_checks, 'check')}, {state}")
            lines.append("")
        return lines

    def _compose_flap(self, flaps: Sequence[Transition], run_ts: datetime,
                      banner: Optional[str]) -> Tuple[str, str, str, str]:
        """One notice when targets start flapping, in place of an alert per change."""
        window = self.config.flap_window
        subject = self._sites_subject(
            "FLAPPING", flaps,
            f"{plural(len(flaps), 'target')} changing state over and over",
            f"{plural(len(flaps), 'target')} changing state over and over")
        hold = human_duration(self.config.flap_hold)
        lines = [f"{'Flapping Detected':^68}", "=" * 68, ""]
        if banner:
            lines += [f"!! {banner}", ""]
        lines += [f"Time: {self._stamp(run_ts)}", ""]
        lines += self._flap_lines(flaps, "~")
        if self.config.flap_hold:
            lines += ["While a target flaps, an outage of it is announced only once it has",
                      f"lasted {hold}, and its recovery only if the outage was announced."]
        lines += [f"A message follows when it has kept one state through {window} checks",
                  "in a row. Intermittent failures often come from an overloaded server,",
                  "a failing backend behind a load balancer, or rate limiting of the",
                  "monitor's requests.", "", f"-- Website Monitor v{__version__}"]
        key = f"FLAP:{run_ts.isoformat()}:" + ",".join(sorted(t.target.name for t in flaps))
        rows = self._html_flap_rows(flaps, "#f0932b", "#fff8ee")
        html = self._shell("Flapping Detected", "#f0932b", rows,
                           f"Website Monitor v{__version__}")
        return subject, "\n".join(lines), html, key

    def _compose_steady(self, steadies: Sequence[Transition],
                        run_ts: datetime) -> Tuple[str, str, str, str]:
        """One notice when flapping targets have held steady (up) through a window."""
        window = self.config.flap_window
        subject = self._sites_subject(
            "STEADY", steadies, f"up through its last {window} checks",
            f"{plural(len(steadies), 'target')} up through their last {window} checks")
        lines = [f"{'Flapping Over':^68}", "=" * 68, "",
                 f"Time: {self._stamp(run_ts)}", ""]
        lines += self._flap_lines(steadies, "✓")
        lines += ["Outages and recoveries of these targets are announced as usual again.",
                  "", f"-- Website Monitor v{__version__}"]
        key = f"STEADY:{run_ts.isoformat()}:" + ",".join(sorted(t.target.name for t in steadies))
        rows = self._html_flap_rows(steadies, "#2f9e44", "#f2fbf4")
        html = self._shell("Flapping Over", "#2f9e44", rows, f"Website Monitor v{__version__}")
        return subject, "\n".join(lines), html, key

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
                        f'border-left:3px solid #f0932b;font-size:13px">{_esc(banner)}</p>')
        rows.append(f'<p style="margin:0 0 16px;font-size:13px;color:#52606d">'
                    f'{_esc(self._stamp(run_ts))}</p>')
        for site in sorted({t.target.site for t in chunk}):
            rows.append(f'<p style="margin:16px 0 6px;font-weight:600;font-size:14px">'
                        f'{_esc(site)}</p>')
            for t in (x for x in chunk if x.target.site == site):
                d = t.details
                dur = (f' · down {human_duration(t.duration_s)}' if t.duration_s else '')
                rows.append(
                    f'<table role="presentation" width="100%" style="margin:0 0 8px;'
                    f'border-left:3px solid #d64545;background:#fdf3f3"><tr><td style="padding:10px 12px">'
                    f'<div style="font-weight:600;font-size:13px">{_esc(mask_secrets(t.target.name))}{dur}</div>'
                    f'<div style="font-size:12px;color:#52606d;margin-top:3px">'
                    f'{_esc(str(d.get("error") or "Unknown error"))}</div>'
                    f'<div style="font-size:11px;color:#7b8794;margin-top:4px">'
                    f'HTTP {_esc(str(d.get("status_code") or "N/A"))} · '
                    f'{_esc(str(d.get("fail_class") or "unknown"))}'
                    f'</div></td></tr></table>')
        return self._shell("Monitoring Alert", "#d64545", "".join(rows),
                           f"Website Monitor v{__version__}")

    def _html_resolved(self, ups: Sequence[Transition], run_ts: datetime) -> str:
        rows = [f'<p style="margin:0 0 16px;font-size:13px;color:#52606d">'
                f'{_esc(self._stamp(run_ts))}</p>']
        for t in ups:
            rows.append(
                f'<table role="presentation" width="100%" style="margin:0 0 8px;'
                f'border-left:3px solid #2f9e44;background:#f2fbf4"><tr><td style="padding:10px 12px">'
                f'<div style="font-weight:600;font-size:13px">{_esc(mask_secrets(t.target.name))}</div>'
                f'<div style="font-size:12px;color:#52606d;margin-top:3px">'
                f'Recovered after {human_duration(t.duration_s or 0)}</div></td></tr></table>')
        return self._shell("Service Restored", "#2f9e44", "".join(rows),
                           f"Website Monitor v{__version__}")

    @staticmethod
    def _html_flap_rows(items: Sequence[Transition], accent: str, background: str) -> str:
        rows = []
        for t in items:
            state = "up now" if t.healthy else "down now"
            rows.append(
                f'<table role="presentation" width="100%" style="margin:0 0 8px;'
                f'border-left:3px solid {accent};background:{background}"><tr>'
                f'<td style="padding:10px 12px">'
                f'<div style="font-weight:600;font-size:13px">{_esc(mask_secrets(t.target.name))}</div>'
                f'<div style="font-size:12px;color:#52606d;margin-top:3px">'
                f'{plural(t.flap_changes, "change")} of state and '
                f'{plural(t.flap_failures, "failed check")} in its last '
                f'{plural(t.flap_checks, "check")}, {state}</div></td></tr></table>')
        return "".join(rows)


# The name of the class before messages could leave by a command as well.
EmailNotifier = Notifier


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class SingleInstanceLock:
    """Prevents overlapping runs. Without it, two cron runs both see the same
    open incident, both find it due, and both email."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or LOCK_PATH
        self._fh: Optional[Any] = None

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


# Days a target absent from the configuration keeps its history before pruning.
TARGET_GRACE_DAYS = 7


class WebsiteMonitor:
    """Main monitoring orchestrator."""

    def __init__(self, config: Optional[Config] = None, dry_run: bool = False,
                 db_path: Optional[Path] = None):
        self.config = config or Config()
        self.dry_run = dry_run
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        self.db = Database(db_path)
        self.checker = Checker(self.config)
        self.target_ids = self.db.sync_targets(self.config.targets)
        if not dry_run:
            removed = self.db.prune_targets((t.name for t in self.config.targets),
                                            grace_days=TARGET_GRACE_DAYS)
            if removed:
                logger.info("Pruned %d target(s) absent from the configuration for %d days",
                            removed, TARGET_GRACE_DAYS)
                self.target_ids = self.db.sync_targets(self.config.targets)
            stale_certs = self.db.prune_certs(self.config.cert_hosts())
            if stale_certs:
                logger.info("Forgot the certificates of %d host(s) no longer monitored",
                            stale_certs)
        self.engine = IncidentEngine(self.db, self.config, self.target_ids)
        self.notifier = Notifier(self.config, self.db, dry_run=dry_run)

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
            try:
                transition = self.engine.apply(
                    target, healthy, details, run_ts, run_id=run_id,
                    cold_start=cold_start,
                    suppress="monitor_network" if suppress and not healthy else None,
                )
            except Exception as exc:  # noqa: BLE001 - one target must not stop the run
                logger.error("Could not record the check of %s: %s",
                             mask_secrets(target.name), exc, exc_info=True)
                transition = Transition(target=target, healthy=healthy, details=details)
            transitions.append(transition)
            label = "API" if target.kind == "api" else "Website"
            if healthy:
                logger.info("✓ %s: %s - OK (%s, %sms)", label, mask_secrets(target.name),
                            details.get("status_code"), details.get("response_time_ms"))
            else:
                logger.error("✗ %s: %s - FAILED: %s", label, mask_secrets(target.name),
                             details.get("error"))

        if self.config.ssl_check_enabled:
            tls_warnings = self._check_certificates(run_ts)
        else:
            tls_warnings = []

        n_failed = sum(1 for _, healthy, _ in results if not healthy)
        # Recoveries announced to nobody yet, because their message failed earlier.
        transitions_out = transitions + self.engine.pending_recoveries(
            run_ts, (t.incident_id for t in transitions if t.kind == "RESOLVED"))
        self.notifier.dispatch(transitions_out, run_ts, banner=banner,
                               suspect_self=bool(suppress))
        undelivered = self.engine.settle(transitions_out)
        for subject, body, host, prev_stage in tls_warnings:
            state = self.notifier.deliver(subject, body, kind="TLS",
                                          dedup_key=f"TLS:{subject}:{run_ts.date()}")
            if state in RETRY_STATES:
                # Probe again at the next pass, and warn again from the old stage.
                self.db.execute(
                    "UPDATE certs SET warn_stage = ?, last_checked_at = NULL WHERE host = ?",
                    (prev_stage, host))
                undelivered += 1

        duration_ms = int((time.monotonic() - started) * 1000)
        self.db.execute(
            "UPDATE runs SET finished_at = ?, duration_ms = ?, n_failed = ? WHERE id = ?",
            (now_utc().isoformat(), duration_ms, n_failed, run_id),
        )
        if not self.dry_run:
            # A dry run (the installer makes one) must not use up the cold start.
            self.db.set_meta("first_run_done", now_utc().isoformat())
        self._housekeeping()
        self._heartbeat(n_failed, undelivered)
        if undelivered and not self.dry_run:
            logger.error("%s left undelivered, to be tried again at the next pass",
                         plural(undelivered, "message"))
        logger.info("Run complete in %.1fs: %d/%d healthy",
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
            return (f"Monitoring gap of {human_duration(gap)} since the last completed run: "
                    f"an outage in this alert may have begun earlier than shown, "
                    f"and lasted longer.")
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
        return (f"{len(failed)}/{len(results)} targets failed at once with network errors; "
                f"this may be a problem with the monitoring host or its network, "
                f"not with the sites themselves.{detail}")

    # -- certificates ------------------------------------------------------

    def _check_certificates(self, run_ts: datetime) -> List[Tuple[str, str, str, int]]:
        """Probe TLS expiry at most twice a day per host; warn on threshold crossings.

        Returns (subject, body, host, previous warning stage) for each warning, so
        that a warning whose message fails can be put back and sent again."""
        alerts: List[Tuple[str, str, str, int]] = []
        for host in sorted(self.config.cert_hosts()):
            row = self.db.query_one("SELECT * FROM certs WHERE host = ?", (host,))
            last = _parse_dt(row["last_checked_at"]) if row else None
            if last and (run_ts - last) < timedelta(hours=12):
                continue
            info = check_certificate(*split_cert_key(host))
            if info["error"]:
                # Keep what the last good probe learnt: wiping the expiry and the
                # warning stage made the host vanish from the summaries, then
                # repeated a warning already sent at the next good probe.
                self.db.execute(
                    "INSERT INTO certs(host, last_checked_at, error) VALUES(?,?,?) "
                    "ON CONFLICT(host) DO UPDATE SET last_checked_at=excluded.last_checked_at, "
                    "error=excluded.error",
                    (host, run_ts.isoformat(), info["error"]))
                logger.warning("Certificate check failed for %s: %s", host, info["error"])
                continue
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
                "VALUES(?,?,?,?,?,NULL) ON CONFLICT(host) DO UPDATE SET "
                "not_after=excluded.not_after, issuer=excluded.issuer, "
                "last_checked_at=excluded.last_checked_at, warn_stage=excluded.warn_stage, "
                "error=NULL",
                (host, info["not_after"], info["issuer"], run_ts.isoformat(), stage),
            )
            logger.info("Certificate %s expires in %s days (%s)", host, days_left, info["issuer"])
            if stage > prev_stage and days_left is not None and not_after is not None:
                self.db.execute("UPDATE certs SET last_warned_at = ? WHERE host = ?",
                                (run_ts.isoformat(), host))
                subject = (f"[TLS] Certificate for {host} expires in "
                           f"{plural(days_left, 'day')}")
                body = (
                    f"TLS Certificate Expiry Warning\n{'=' * 40}\n\n"
                    f"Host:      {host}\n"
                    f"Expires:   {not_after.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                    f"Days left: {days_left}\n"
                    f"Issuer:    {info['issuer']}\n\n"
                    "A certificate renewed automatically (by certbot, acme.sh, Caddy,\n"
                    "Traefik or another ACME client) is normally replaced well before it\n"
                    "expires, so this warning means the renewal has not happened yet.\n"
                    "Check the logs of the renewal client, that it can reach the\n"
                    "certificate authority and answer its challenge (port 80 open, DNS\n"
                    "records right), and that its account and storage files are\n"
                    "writable. A certificate installed by hand has to be replaced by hand.\n\n"
                    f"-- Website Monitor v{__version__}\n"
                )
                alerts.append((subject, body, host, prev_stage))
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

    def _heartbeat(self, n_failed: int, undelivered: int = 0) -> None:
        """Ping a dead-man's-switch service. This is the only mechanism that can
        detect the monitor itself being dead, which nothing previously could."""
        if not self.config.heartbeat_url or self.dry_run:
            return
        params = {key: value for key, value in
                  (("failed", n_failed), ("undelivered", undelivered)) if value}
        try:
            requests.get(self.config.heartbeat_url, timeout=10, params=params or None)
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

def _pct(value: Optional[float], digits: int = 2) -> str:
    return f"{value:.{digits}f}%" if value is not None else "n/a"


# Plain words for the failure classes, for the brief summary.
FAIL_WORDS = {"dns": "name not resolved", "conn": "connection failed", "tls": "TLS error",
              "timeout": "timeout", "content": "unexpected content", "unknown": "error"}


def _short(name: str, url: str) -> str:
    """A target named by its own address, as a chat shows it best: without the
    scheme and the final slash (https://example.com/ is example.com)."""
    if name != url:
        return name
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", name, flags=re.I).rstrip("/")


def _cause(fail_class: Optional[str], status_code: Optional[int]) -> str:
    if status_code and fail_class in (None, "http_status", "content"):
        return f"HTTP {status_code}" if fail_class != "content" else "unexpected content"
    return FAIL_WORDS.get(fail_class or "unknown", fail_class or "error")


class Reporter:
    """Builds uptime summaries from the stored check history, in three forms: the
    classic text and HTML email, a brief message for a chat or a phone, and JSON
    for other programs. All three are drawn from one snapshot of the period."""

    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config

    def _names(self) -> List[str]:
        return [t.name for t in self.config.targets]

    def stats(self, days: int) -> List[Dict[str, Any]]:
        """Per target over the period, for the targets configured now (one removed
        keeps its history for a while, but has no place in a summary)."""
        since = (now_utc() - timedelta(days=days)).isoformat()
        names = self._names()
        marks = ",".join("?" * len(names)) or "NULL"
        rows = self.db.query(
            f"""
            SELECT t.name, t.url, t.kind, t.status,
                   COUNT(c.id)                                    AS checks,
                   SUM(CASE WHEN c.healthy = 0 THEN 1 ELSE 0 END) AS failures,
                   AVG(CASE WHEN c.healthy = 1 THEN c.total_ms END) AS avg_ms,
                   MAX(CASE WHEN c.healthy = 1 THEN c.total_ms END) AS max_ms
              FROM targets t LEFT JOIN checks c
                ON c.target_id = t.id AND c.ts >= ?
             WHERE t.name IN ({marks})
             GROUP BY t.id ORDER BY t.id
            """, (since, *names))
        out = []
        for row in rows:
            checks = row["checks"] or 0
            failures = row["failures"] or 0
            out.append({
                "name": row["name"], "url": row["url"], "kind": row["kind"],
                "site": site_of(row["url"]),
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
        # Nearest rank: the smallest value with at least 95% of the values at or
        # below it (the former index gave the maximum whenever n was a multiple of 20).
        return values[max(0, math.ceil(0.95 * len(values)) - 1)]

    def incidents(self, days: int) -> List[sqlite3.Row]:
        """Incidents that overlapped the period, begun in it, ended in it or still
        open, of the targets configured now."""
        since = (now_utc() - timedelta(days=days)).isoformat()
        names = self._names()
        marks = ",".join("?" * len(names)) or "NULL"
        return self.db.query(
            "SELECT i.*, t.name, t.url FROM incidents i JOIN targets t ON t.id = i.target_id "
            f"WHERE (i.started_at >= ? OR i.ended_at >= ? OR i.status = 'open') "
            f"AND t.name IN ({marks}) ORDER BY i.started_at DESC", (since, since, *names))

    def certs(self) -> List[sqlite3.Row]:
        """Certificates of the hosts monitored now, the soonest to expire first; a
        host whose last probe failed has no expiry and comes last."""
        hosts = set(self.config.cert_hosts())
        rows = self.db.query("SELECT * FROM certs ORDER BY not_after IS NULL, not_after")
        return [row for row in rows if row["host"] in hosts]

    def last_run(self) -> Optional[datetime]:
        row = self.db.query_one(
            "SELECT finished_at FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1")
        return _parse_dt(row["finished_at"]) if row else None

    def snapshot(self, days: int) -> Dict[str, Any]:
        """Everything a summary says, gathered once."""
        now = now_utc()
        stats = self.stats(days)
        limit = self.config.slow_threshold_ms
        for s in stats:
            s["slow"] = bool(limit and s["p95_ms"] and s["p95_ms"] > limit)
            s["name"], s["url"] = mask_secrets(s["name"]), mask_secrets(s["url"])
        measured = [s["uptime"] for s in stats if s["uptime"] is not None]

        incidents = []
        for row in self.incidents(days):
            start, end = _parse_dt(row["started_at"]), _parse_dt(row["ended_at"])
            incidents.append({
                "target": mask_secrets(row["name"]), "url": mask_secrets(row["url"]),
                "site": site_of(row["url"]),
                "started_at": start, "ended_at": end, "open": row["status"] == "open",
                "duration_s": ((end or now) - start).total_seconds() if start else None,
                "fail_class": row["fail_class"], "status_code": row["status_code"],
                "error": mask_secrets(row["last_error"] or row["first_error"]) or None,
                "announced": (row["notify_count"] or 0) > 0,
            })

        certs = []
        for row in self.certs():
            expires = _parse_dt(row["not_after"])
            certs.append({"host": row["host"], "not_after": expires,
                          "days_left": (expires - now).days if expires else None,
                          "issuer": row["issuer"], "error": row["error"]})

        last_run = self.last_run()
        # Three missed passes, and never less than half an hour, mean the monitor
        # itself has stopped: a summary run by another scheduler can say so.
        stale_after = max(3 * max(self.config.check_interval, 60), 1800)
        return {
            "now": now, "days": days, "stats": stats,
            "overall": sum(measured) / len(measured) if measured else None,
            "down": [s for s in stats if s["status"] == "down"],
            "incidents": incidents, "certs": certs, "last_run": last_run,
            "stale": last_run is None or (now - last_run).total_seconds() > stale_after,
            "warn_days": max(self.config.ssl_warn_days) if self.config.ssl_warn_days else 0,
        }

    @staticmethod
    def _subject(snap: Dict[str, Any], title: str) -> str:
        count = len(snap["incidents"])
        subject = (f"[{title}] Uptime {_pct(snap['overall'])}, "
                   + (plural(count, "incident") if count else "no incident"))
        if snap["down"]:
            subject += f", {len(snap['down'])} down now"
        if snap["stale"]:
            subject += ", the monitor is not running"
        return subject

    @staticmethod
    def _stale_text(snap: Dict[str, Any]) -> str:
        last = snap["last_run"]
        if last is None:
            return "The monitor has not completed a check yet."
        local = last.astimezone()
        ago = human_duration((snap["now"] - last).total_seconds())
        return (f"The monitor itself has not completed a check since "
                f"{local.strftime('%d %b %H:%M')} ({local.strftime('%Z')}), {ago} ago; "
                "its timer or cron entry may have stopped.")

    def render(self, days: int, title: str) -> Tuple[str, str, str]:
        """The classic summary: (subject, text table, HTML)."""
        snap = self.snapshot(days)
        stats, incidents, certs, now = snap["stats"], snap["incidents"], snap["certs"], snap["now"]

        lines = [f"{title + ' Monitoring Report':^72}", "=" * 72, "",
                 f"Period:  last {plural(days, 'day')}, to {now.strftime('%Y-%m-%d %H:%M')} UTC",
                 f"Overall: {_pct(snap['overall'], 3)} uptime across "
                 f"{plural(len(stats), 'target')}"]
        if snap["stale"]:
            lines.append("!! " + self._stale_text(snap))
        lines.append("")
        lines.append(f"{'TARGET':<42}{'UPTIME':>9}{'AVG':>9}{'P95':>9}")
        lines.append("-" * 72)
        for s in stats:
            uptime = f"{s['uptime']:.2f}%" if s["uptime"] is not None else "n/a"
            avg = f"{s['avg_ms']:.0f}ms" if s["avg_ms"] else "n/a"
            p95 = f"{s['p95_ms']:.0f}ms" if s["p95_ms"] else "n/a"
            flag = "  ✗" if s["status"] == "down" else "  ⏱" if s["slow"] else ""
            lines.append(f"{s['name'][:41]:<42}{uptime:>9}{avg:>9}{p95:>9}{flag}")
        lines.append("")
        if any(s["slow"] for s in stats):
            lines += [f"⏱ p95 above SLOW_THRESHOLD_MS ({self.config.slow_threshold_ms} ms)", ""]

        if incidents:
            lines += [f"Incidents ({len(incidents)}):", "-" * 72]
            for inc in incidents[:25]:
                start = inc["started_at"]
                dur = "ongoing" if inc["open"] else human_duration(inc["duration_s"] or 0)
                lines.append(f"  {start.strftime('%m-%d %H:%M') if start else '?':<12}"
                             f"{inc['target'][:34]:<36}{dur:>10}  {inc['fail_class'] or ''}")
            lines.append("")
        else:
            lines += ["No incidents in this period.", ""]

        if certs:
            lines += ["TLS certificates:", "-" * 72]
            for cert in certs:
                left = cert["days_left"]
                mark = "  ⚠" if (left is not None and left <= snap["warn_days"]) else ""
                shown = f"{left} days" if left is not None else "unknown"
                lines.append(f"  {cert['host'][:40]:<42}{shown:>12}  "
                             f"{cert['issuer'] or cert['error'] or ''}{mark}")
            lines.append("")
        lines.append(f"-- Website Monitor v{__version__}")

        return self._subject(snap, title), "\n".join(lines), self._html(title, snap)

    def render_brief(self, days: int, title: str) -> Tuple[str, str]:
        """A short summary for a chat or a phone: the verdict first, then only what
        needs attention, the slowest answers and the certificates."""
        snap = self.snapshot(days)
        stats, down, certs = snap["stats"], snap["down"], snap["certs"]
        now = snap["now"].astimezone()
        zone = now.strftime("%Z")
        day_fmt = "%H:%M" if days == 1 else "%d %b %H:%M"

        def at(dt: Optional[datetime]) -> str:
            return dt.astimezone().strftime(day_fmt) if dt else "?"

        def listing(items: List[str], limit: int = 6) -> str:
            shown = ", ".join(items[:limit])
            return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")

        past = [i for i in snap["incidents"] if not i["open"]]
        opened = {i["target"]: i for i in snap["incidents"] if i["open"]}
        below = sorted((s for s in stats if s["uptime"] is not None and s["uptime"] < 100
                        and s["status"] != "down"), key=lambda s: s["uptime"])
        slow = sorted((s for s in stats if s["slow"]), key=lambda s: -s["p95_ms"])
        valid = [c for c in certs if c["days_left"] is not None]
        expiring = [c for c in valid if c["days_left"] <= snap["warn_days"]]
        unchecked = [c for c in certs if c["days_left"] is None]

        if snap["stale"] or down:
            mark = "❌"
        elif snap["incidents"] or below or slow or expiring or unchecked:
            mark = "⚠️"
        else:
            mark = "✅"
        total = len(stats)
        if down:
            state = f"{len(down)} of {plural(total, 'target')} down now"
        elif total == 1:
            state = "the only target up"
        else:
            state = f"all {plural(total, 'target')} up"
        span = "24 hours" if days == 1 else plural(days, "day")
        count = len(snap["incidents"])
        lines = [f"{mark} {title} summary: {state}, {_pct(snap['overall'])} uptime over the "
                 f"{span} to {now.strftime('%H:%M')} ({zone}), "
                 f"{plural(count, 'incident') if count else 'no incident'}."]
        if snap["stale"]:
            lines.append(self._stale_text(snap))
        if down:
            parts = []
            for s in down:
                inc = opened.get(s["name"])
                name = _short(s["name"], s["url"])
                parts.append(f"{name} since {at(inc['started_at'])} "
                             f"({_cause(inc['fail_class'], inc['status_code'])})"
                             if inc else name)
            lines.append(f"Down now: {listing(parts)}.")
        if past:
            lines.append("Incidents: " + listing([
                f"{_short(i['target'], i['url'])} at {at(i['started_at'])} for "
                f"{human_duration(i['duration_s'] or 0)} "
                f"({_cause(i['fail_class'], i['status_code'])})" for i in past]) + ".")
        if below:
            lines.append("Below 100%: " + listing(
                [f"{_short(s['name'], s['url'])} {_pct(s['uptime'])}" for s in below]) + ".")
        if slow:
            lines.append(f"Slow (p95 above {self.config.slow_threshold_ms} ms): " + listing(
                [f"{_short(s['name'], s['url'])} {s['p95_ms']:.0f} ms" for s in slow]) + ".")
        else:
            slowest = sorted((s for s in stats if s["p95_ms"]), key=lambda s: -s["p95_ms"])
            if slowest:
                lines.append("Slowest answers (p95): " + ", ".join(
                    f"{_short(s['name'], s['url'])} {s['p95_ms']:.0f} ms"
                    for s in slowest[:3]) + ".")
        if expiring:
            lines.append("Certificates expiring soon: " + listing(
                [f"{c['host']} in {plural(c['days_left'], 'day')}" for c in expiring]) + ".")
        if unchecked:
            lines.append("Certificate checks failed: " + listing(
                [f"{c['host']} ({c['error'] or 'no answer'})" for c in unchecked]) + ".")
        if valid and not expiring:
            soonest = min(c["days_left"] for c in valid)
            first = [c["host"] for c in valid if c["days_left"] == soonest]
            others = f" and {len(first) - 1} more" if len(first) > 1 else ""
            lines.append(f"Certificates: {plural(len(valid), 'valid certificate')}, the earliest "
                         f"expiring in {plural(soonest, 'day')} ({first[0]}{others}).")
        return self._subject(snap, title), "\n".join(lines)

    def render_json(self, days: int, title: str) -> str:
        """The summary for other programs."""
        snap = self.snapshot(days)

        def iso(dt: Optional[datetime]) -> Optional[str]:
            return dt.isoformat() if dt else None

        data = {
            "monitor": "Website Monitor", "version": __version__,
            "host": socket.gethostname(), "report": title.lower(), "period_days": days,
            "generated_at": iso(snap["now"]), "last_run_at": iso(snap["last_run"]),
            "monitor_stale": snap["stale"], "overall_uptime": snap["overall"],
            "slow_threshold_ms": self.config.slow_threshold_ms or None,
            "targets": [{key: s[key] for key in (
                "name", "url", "kind", "site", "status", "checks", "failures", "uptime",
                "avg_ms", "max_ms", "p95_ms", "slow")} for s in snap["stats"]],
            "incidents": [{
                "target": i["target"], "site": i["site"], "started_at": iso(i["started_at"]),
                "ended_at": iso(i["ended_at"]), "open": i["open"], "duration_s": i["duration_s"],
                "fail_class": i["fail_class"], "status_code": i["status_code"],
                "error": i["error"], "announced": i["announced"]} for i in snap["incidents"]],
            "certificates": [{
                "host": c["host"], "not_after": iso(c["not_after"]), "days_left": c["days_left"],
                "issuer": c["issuer"], "error": c["error"]} for c in snap["certs"]],
        }
        return json.dumps(data, indent=2)

    def _html(self, title: str, snap: Dict[str, Any]) -> str:
        days, overall, stats = snap["days"], snap["overall"], snap["stats"]
        incidents, certs, now = snap["incidents"], snap["certs"], snap["now"]

        def bar(pct: Optional[float]) -> str:
            if pct is None:
                return '<span style="color:#9aa5b1">n/a</span>'
            color = "#2f9e44" if pct >= 99.9 else "#f0932b" if pct >= 99 else "#d64545"
            return (f'<span style="color:{color};font-weight:600">{pct:.2f}%</span>')

        def ms_plain(value: Optional[float]) -> str:
            return f"{value:.0f} ms" if value else "\u2014"

        def ms(value: Optional[float], slow: bool = False) -> str:
            text = ms_plain(value)
            return (f'<span style="color:#d64545;font-weight:600">{text}</span>'
                    if slow and value else text)

        cell = ('<td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
                'text-align:right;font-size:12px;color:#616e7c">')
        rows = "".join(
            '<tr><td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
            'font-size:13px">' + _esc(s["name"][:46]) + '</td>'
            '<td style="padding:7px 8px;border-bottom:1px solid #f0f2f5;'
            'text-align:right;font-size:13px">' + bar(s["uptime"]) + '</td>'
            + cell + ms(s["avg_ms"]) + '</td>'
            + cell + ms(s["p95_ms"], s["slow"]) + '</td></tr>'
            for s in stats)

        stale_html = ""
        if snap["stale"]:
            stale_html = ('<p style="margin:0 0 14px;padding:10px 12px;background:#fdf3f3;'
                          'border-left:3px solid #d64545;font-size:13px">'
                          f'{_esc(self._stale_text(snap))}</p>')

        inc_html = ""
        if incidents:
            items = []
            for inc in incidents[:15]:
                start = inc["started_at"]
                dur = "ongoing" if inc["open"] else human_duration(inc["duration_s"] or 0)
                items.append(
                    f'<li style="margin:4px 0;font-size:12px;color:#52606d">'
                    f'<strong>{_esc(inc["target"])}</strong>, {dur}'
                    f'<span style="color:#9aa5b1"> · {_esc(inc["fail_class"] or "")} · '
                    f'{start.strftime("%b %d %H:%M") if start else ""} UTC</span></li>')
            inc_html = ('<p style="margin:22px 0 6px;font-weight:600;font-size:14px">Incidents</p>'
                        f'<ul style="margin:0;padding-left:18px">{"".join(items)}</ul>')

        cert_html = ""
        if certs:
            items = []
            warn = snap["warn_days"]
            for cert in certs:
                left = cert["days_left"]
                color = ("#d64545" if left is None or left <= min(7, warn)
                         else "#f0932b" if left <= warn else "#616e7c")
                shown = f"{left} days" if left is not None else _esc(cert["error"] or "unknown")
                items.append(
                    f'<li style="margin:4px 0;font-size:12px;color:#52606d">'
                    f'{_esc(cert["host"])}: '
                    f'<span style="color:{color};font-weight:600">{shown}</span></li>')
            cert_html = ('<p style="margin:22px 0 6px;font-weight:600;font-size:14px">'
                         'TLS certificates</p>'
                         f'<ul style="margin:0;padding-left:18px">{"".join(items)}</ul>')

        value = overall if overall is not None else 0.0
        color = "#2f9e44" if value >= 99.9 else "#f0932b" if value >= 99 else "#d64545"
        return Notifier._shell(
            f"{title} Report",
            "#334e68",
            f'{stale_html}'
            f'<p style="margin:0 0 4px;font-size:30px;font-weight:700;color:{color}">'
            f'{_pct(overall)}</p>'
            f'<p style="margin:0 0 18px;font-size:12px;color:#7b8794">'
            f'average uptime · last {plural(days, "day")} · {plural(len(stats), "target")}</p>'
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
    print(f"\n  Website Monitor v{__version__}, status at "
          f"{now.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Messages: {config.route_text()}\n")
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
            held = ", held while flapping" if inc["suppressed_by"] == "flap" else ""
            print(f"    ✗ {inc['name']}: down {dur} ({inc['fail_class'] or 'unknown'}{held}), "
                  f"{inc['last_error'] or ''}")
    flapping = [row for row in rows.values() if row["flapping_since"]]
    if flapping:
        print(f"\n  Flapping ({len(flapping)}):")
        for row in flapping:
            since = _parse_dt(row["flapping_since"])
            print(f"    ~ {row['name']}, since {since.strftime('%m-%d %H:%M UTC') if since else '?'}")
    certs = reporter.certs()
    if certs:
        warn_days = max(config.ssl_warn_days) if config.ssl_warn_days else 0
        print("\n  TLS certificates:")
        for cert in certs:
            exp = _parse_dt(cert["not_after"])
            left = (exp - now).days if exp else None
            warn = "  ⚠" if (left is None or left <= warn_days) else ""
            shown = f"{left} days" if left is not None else "?"
            print(f"    {cert['host']:<42}{shown:>10}"
                  f"  {cert['issuer'] or cert['error'] or ''}{warn}")
    print()


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="monitor.py",
        description="Website, API and TLS monitoring with alerts by email or by a command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  monitor.py                                run one pass (cron default)\n"
               "  monitor.py --dry-run -v                   check everything, send nothing\n"
               "  monitor.py --status                       show current state and routes\n"
               "  monitor.py --report weekly                send an uptime summary\n"
               "  monitor.py --report daily --print --format brief\n"
               "                                            print a short summary for a chat\n"
               "  monitor.py --check https://x.y            probe one URL and exit\n"
               "  monitor.py --test-email                   verify SMTP settings\n"
               "  monitor.py --test-command                 verify MESSAGE_COMMAND\n",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true",
                      help="run a single pass and exit (the default)")
    mode.add_argument("--continuous", action="store_true",
                      help="loop forever using CHECK_INTERVAL")
    mode.add_argument("--status", action="store_true",
                      help="print current state and exit")
    mode.add_argument("--report", choices=("daily", "weekly", "monthly"),
                      help="send an uptime summary by ROUTE_SUMMARY and exit")
    mode.add_argument("--check", metavar="URL",
                      help="probe a single URL and exit (no state, no message)")
    mode.add_argument("--test-email", action="store_true",
                      help="send a test message to ALERT_EMAIL and exit")
    mode.add_argument("--test-command", action="store_true",
                      help="send a test message through MESSAGE_COMMAND and exit")
    mode.add_argument("--notify", metavar="SUBJECT",
                      help="send an arbitrary message by ROUTE_NOTIFY (for other scripts)")

    parser.add_argument("--body-file", metavar="PATH",
                        help="with --notify: read the message body from this file")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="with --report: print the summary instead of sending it")
    parser.add_argument("--format", choices=("text", "brief", "json"),
                        help="with --report: the classic table (text, the default), a short "
                             "message for a chat or a phone (brief), or JSON for other programs")
    parser.add_argument("--dry-run", action="store_true",
                        help="perform checks and update state but never send email")
    parser.add_argument("--config", metavar="PATH", help="path to a targets.toml file")
    parser.add_argument("-v", "--verbose", action="store_true", help="log INFO to the console")
    parser.add_argument("-q", "--quiet", action="store_true", help="log only errors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


# The notice of a broken configuration is repeated at most this often while the
# error stays the same; a different error is announced at once.
BROKEN_REPEAT_S = 6 * 3600


def _broken_stamp() -> Path:
    return DATA_DIR / ".broken-notice"


def _broken_notice_due(error: str) -> bool:
    try:
        stamp = json.loads(_broken_stamp().read_text())
    except (OSError, ValueError):
        return True
    same = stamp.get("error") == hashlib.sha256(error.encode()).hexdigest()
    sent = _parse_dt(stamp.get("sent_at"))
    return not (same and sent and (now_utc() - sent).total_seconds() < BROKEN_REPEAT_S)


def _broken_notice_sent(error: str) -> None:
    try:
        _broken_stamp().parent.mkdir(exist_ok=True, parents=True)
        _broken_stamp().write_text(json.dumps({
            "error": hashlib.sha256(error.encode()).hexdigest(),
            "sent_at": now_utc().isoformat()}))
    except OSError as exc:
        logger.warning("Could not record the configuration-failure notice: %s", exc)


def _emergency_notify(subject: str, body: str) -> bool:
    """Best-effort message when the configuration cannot be used, from the raw
    settings: mail if they allow it, else MESSAGE_COMMAND, else the spare route.
    Returns True when it left.

    A broken .env used to produce a silent traceback in cron.log and nothing else.
    """
    try:
        server_host = (os.getenv("SMTP_SERVER") or "").strip()
        username = (os.getenv("SMTP_USERNAME") or "").strip()
        password = os.getenv("SMTP_PASSWORD") or ""
        sender = (os.getenv("SMTP_FROM") or "").strip() or username
        recipients = [a.strip() for a in (os.getenv("ALERT_EMAIL") or "").split(",") if a.strip()]
        if server_host and sender and recipients and bool(username) == bool(password):
            try:
                msg = MIMEText(body, "plain", "utf-8")
                msg["From"] = sender
                msg["To"] = ", ".join(recipients)
                msg["Subject"] = subject
                msg["Date"] = formatdate(localtime=True)
                msg["Message-ID"] = make_msgid(domain=_sender_domain(sender))
                msg["Auto-Submitted"] = "auto-generated"
                security = (os.getenv("SMTP_SECURITY", "starttls") or "starttls").lower()
                with closing(_smtp_connect(server_host, _env_int("SMTP_PORT", 587),
                                           security, 30)) as server:
                    if username:
                        server.login(username, password)
                    server.send_message(msg)
                logger.info("Sent: %s", subject)
                return True
            except (smtplib.SMTPException, OSError) as exc:
                logger.error("Could not mail %r: %s", subject, exc)
        # A server without mail may still have a command of its own.
        command = (os.getenv("MESSAGE_COMMAND") or "").strip()
        if command and run_command(command, subject, body, "BROKEN")[0]:
            logger.info("Sent by command: %s", subject)
            return True
        spare = (os.getenv("FALLBACK_COMMAND") or "").strip()
        if spare and spare != command:
            return run_fallback(spare, subject, body, "BROKEN")
    except Exception as exc:  # noqa: BLE001 - this path must never raise
        logger.error("Could not send %r: %s", subject, exc)
    return False


def _notify_body(args: argparse.Namespace) -> str:
    body = ""
    if args.body_file:
        try:
            body = Path(args.body_file).read_text(errors="replace")[-8000:]
        except OSError as exc:
            body = f"(could not read {args.body_file}: {exc})"
    return (f"Host: {socket.gethostname()}\n"
            f"Time: {now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n{body}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if (args.print_only or args.format) and not args.report:
        print("--print and --format go with --report", file=sys.stderr)
        return 2
    # The database, its journal and the logs hold an inventory of the servers and
    # their errors: readable by their owner only, with or without install.sh.
    os.umask(0o077)

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

    messaging_only = bool(args.notify or args.test_email or args.test_command)
    try:
        config = Config(targets_file=Path(args.config) if args.config else None,
                        check_targets=not messaging_only)
    except ConfigError as exc:
        logger.critical("Configuration error: %s", exc)
        if args.notify:
            # The message handed over goes out all the same, by the raw settings:
            # a broken configuration must not swallow a security alert.
            body = (_notify_body(args) + "\n\nNote: the configuration of the website "
                    f"monitor is broken ({exc}), so this message left by the raw settings.\n")
            return 0 if _emergency_notify(args.notify, body) else 2
        if _broken_notice_due(str(exc)):
            sent = _emergency_notify(
                "[MONITOR BROKEN] Website monitor cannot start",
                f"The website monitor failed to start at "
                f"{now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC.\n\n"
                f"Configuration error: {exc}\n\n"
                f"Host: {socket.gethostname()}\nPath: {BASE_DIR}\n\n"
                "No websites are being monitored until this is fixed. This notice is\n"
                f"repeated every {human_duration(BROKEN_REPEAT_S)} while the error lasts.\n",
            )
            if sent:
                _broken_notice_sent(str(exc))
        return 2
    except Exception as exc:  # noqa: BLE001
        logger.critical("Unexpected startup failure: %s", exc, exc_info=True)
        return 2

    setup_logging(config.log_level, console_level=console_level,
                  retention_days=config.log_retention_days)

    if args.test_email or args.test_command:
        channel = "email" if args.test_email else "command"
        problem = (config.email_problem() if channel == "email"
                   else None if config.message_command else "MESSAGE_COMMAND is empty")
        if problem:
            print(f"Cannot test the {channel} channel: {problem}", file=sys.stderr)
            return 1
        delivery = (f"SMTP: {config.smtp_server}:{config.smtp_port} ({config.smtp_security})\n"
                    f"Sender: {config.smtp_from}\n" if channel == "email"
                    else "Command: MESSAGE_COMMAND\n")
        state = Notifier(config).deliver(
            "[TEST] Website Monitor configuration check",
            f"This is a test message from the website monitor on "
            f"{socket.gethostname()}, sent by the {channel} channel.\n\n"
            f"Sent: {now_utc().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"{delivery}"
            f"Routes: {config.route_text()}\n"
            f"Spare route: {'configured' if config.fallback_command else 'none'}\n"
            f"Targets configured: {len(config.targets)} "
            f"({len(config.websites)} websites, {len(config.api_endpoints)} APIs)\n"
            f"Config source: {config.targets_source}\n\n"
            "If you received this, the channel works.\n",
            kind="TEST", channels=[channel])
        print(f"Test message sent by {channel}." if state == "sent"
              else f"Test message by {channel} FAILED, see the log.")
        return 0 if state == "sent" else 1

    if args.notify:
        state = Notifier(config, dry_run=args.dry_run).deliver(
            args.notify, _notify_body(args), kind="NOTIFY")
        return 0 if state in HARMLESS_STATES else 1

    if args.status:
        db = Database()
        try:
            print_status(db, config)
        finally:
            db.close()
        return 0

    if args.report:
        days = {"daily": 1, "weekly": 7, "monthly": 30}[args.report]
        title = args.report.capitalize()
        db = Database()
        try:
            reporter = Reporter(db, config)
            html: Optional[str] = None
            if args.format == "brief":
                subject, body = reporter.render_brief(days, title)
            elif args.format == "json":
                subject = f"[{title}] Website Monitor summary"
                body = reporter.render_json(days, title)
            else:
                subject, body, html = reporter.render(days, title)
            if args.print_only or args.dry_run:
                print(body)
                return 0
            state = Notifier(config, db).deliver(
                subject, body, html, kind="SUMMARY",
                dedup_key=f"SUMMARY:{args.report}:{now_utc().date()}")
            return 0 if state in HARMLESS_STATES else 1
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
