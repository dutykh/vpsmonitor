# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-17

A correctness and efficiency release following a full audit of the deployed
system. The crontab entry from 1.x keeps working unchanged.

### Fixed — alerting correctness

- **A repeat outage inside the cooldown window was silently swallowed.** Alert
  state was written when an alert fired but never cleared when a site recovered,
  so a site that went down, came back, and failed again twenty minutes later
  produced no alert at all. Alert state now belongs to an *incident*; resolving
  an incident destroys it, so a new outage always alerts.
- **No recovery notification was ever sent.** A `RESOLVED` email now reports the
  outage duration.
- **`ALERT_COOLDOWN` equal to the check interval caused alerts to alternate.**
  Run-to-run drift meant elapsed time measured ~3597s against a 3600s threshold,
  so alerts fired only on alternate hours — visible in production during a
  30-hour outage. Re-alerts now follow an escalating ladder anchored to the
  incident's confirmation time, compared with a 300-second grace window.
- **Targets checked in the same pass could straddle a threshold.** Each alert
  stamped its own `datetime.now()`, so apex and `www` twins drifted apart by
  seconds and alerted on different hours. One canonical timestamp is now used
  for every decision in a run.
- **Legacy timestamps were misinterpreted.** Naive entries in
  `alert_history.json` were written in local time but read as UTC, placing them
  four hours in the future and over-suppressing alerts. Migration converts them
  from the host's local zone.
- **Nothing alerted when the monitor itself failed.** Configuration was parsed
  before logging was set up, so a broken `.env` produced a bare traceback and
  silence. Logging now initialises first, and a configuration failure sends a
  "monitor broken" email.
- **`smtplib.SMTP` had no timeout** and could hang a cron run indefinitely.
- **`ssl_valid` was inferred from the error string**, reporting "SSL Valid: True"
  for DNS failures and refused connections. TLS status is now only claimed when a
  handshake actually completed.
- Malformed `API_ENDPOINTS` records were silently dropped; they are now logged.
- `verify_ssl` was read from a key the parser never produced (dead configuration).
- Under `--continuous` the log filename was fixed at startup and never rolled
  over at midnight.
- Alert de-duplication keyed on URL, so two API entries sharing a URL collided.
- State was written non-atomically and had no locking, so overlapping runs raced.
- A JSON array response raised `TypeError` into the catch-all handler.

### Added

- SQLite store (`data/monitor.db`) for checks, incidents, certificates and runs
- TLS certificate expiry monitoring with staged warnings
- Daily / weekly / monthly uptime reports (`--report`), plain text and HTML
- Content validation — an `expect` string or regex per target
- Optional `targets.toml` configuration via stdlib `tomllib`
- Concurrent checks via `ThreadPoolExecutor` (`MAX_WORKERS`)
- Alert coalescing by registrable domain (`GROUP_ALERTS`)
- Single-instance locking with `fcntl.flock`
- Dead-man's-switch heartbeat (`HEARTBEAT_URL`)
- Monitoring-gap detection and monitor-side mass-failure detection
- Flap detection with hysteresis
- Cold-start suppression on first run
- `--status`, `--check`, `--test-email`, `--notify`, `--dry-run`, `-v`, `-q`
- `SMTP_SECURITY` for implicit TLS (port 465) and a proper `SSLContext`
- HTML alert and report emails, with `Date` and `Message-ID` headers
- Automatic log rotation, gzip archiving and database retention
- Test suite (85 tests), `Makefile`, GitHub Actions CI, systemd units
- Secret-scanning `pre-commit` hook

### Changed

- **Python 3.11+** is now required (`tomllib`)
- Paths resolve relative to the script, not the working directory
- Console output is TTY-aware: colours only on a terminal, and only warnings and
  above under cron — a healthy run no longer writes anything to `cron.log`
- `requirements.txt` split; the production virtualenv drops from 106 MB to ~17 MB
- Response times distinguish time-to-first-byte from total
- Alert emails redact secret-looking fields and truncate long bodies
- Sanitised `.env.example`, which previously contained real domains and an address

### Security

- `install.sh` enforces `chmod 600 .env` unconditionally and refuses to run if
  `.env` is not git-ignored
- `data/` is created `chmod 700`
- CI fails if `.env` or `data/` becomes tracked

### Migration from 1.x

Automatic on first run. `logs/alert_history.json` is imported (stale entries
dropped, naive timestamps converted from local time), the raw contents are kept
in the database, and the file is renamed to `alert_history.json.migrated`. The
first run suppresses alerts for pre-existing failures.

To roll back: restore `monitor.py` from git, rename
`logs/alert_history.json.migrated` back, and delete `data/`.

## [1.x] - 2025-06-14 .. 2026-03-02

Initial implementation: website and API monitoring, retry with exponential
backoff, email alerts, rate limiting via `alert_history.json`, daily log files,
single-run and continuous modes.
