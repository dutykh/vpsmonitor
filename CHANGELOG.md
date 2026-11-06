# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.3.0] - 2026-11-06

The watchdog reports a busy processor only when the load lasts.

### Changed

- **The processor check waits for the load to last.** Since mid-October it had
  raised five alerts, each for legitimate work seen at a single pass: two
  rebuilds of a website (195% and 266% of one core), a task of the Hermes agent
  (396%), a language server that the agent had started (184%) and the server
  program of the Warp terminal (197%). Five minutes later each was below the
  threshold again. A process is now reported only when it has been above
  `WATCHDOG_CPU_THRESHOLD` at every pass for `WATCHDOG_CPU_PERSIST` seconds,
  15 minutes by default, and on average over that time as well. Until then each
  pass writes one line `CPU watch:` in the log, and no mail goes out. The streaks
  are kept in `.watchdog-cpu` beside the alert file, for the current boot only,
  each process known by its number together with its start time; one pass below
  the threshold starts the count over. The alert now says how long the process
  has been busy, its average over that time and its share over the last window.
  `--cpu-only` reads the streaks and never writes them.
- **`monitor.py --version` reports 2.3.0**; it had stayed at 2.2.0 through 2.2.1.

### Fixed

- **The alert file garbled every processor alert.** The watchdog wrote
  `SECURITY_ALERT` with the findings pasted into the format of `printf`, so that
  the `%` of "266% of one core" was read as a conversion: the text came out
  mangled, and `printf` complained of an invalid number. The findings are now
  passed as an argument. The mail was never affected, since its text was
  already built that way.

### Added

- **A new variable, `WATCHDOG_CPU_PERSIST`,** the number of seconds a process
  must stay busy before it is reported. `0` brings back the report on a single
  window, which the test procedure of the README uses.
- **Four tests of the processor check**, on a busy program of their own: busy
  once, it is only watched; busy at two passes three seconds apart, it is
  reported, and the alert file keeps the text of the finding intact; stopped
  during one pass, it starts its count over; with `WATCHDOG_CPU_PERSIST=0` it is
  reported at once.

## [2.2.1] - 2026-10-23

The watchdog stops taking Chromium's data files for programs, without giving a
program a place to hide.

### Fixed

- **Chromium's temporary folders raised an alarm on every run of the browser.**
  Chromium unpacks the components it downloads (model manifests, a speech engine)
  into `/tmp/org.chromium.Chromium.scoped_dir.XXXXXX` and leaves the execute bit
  on their data files, which the check of the temporary directories reported as
  executables. Inside those folders, and inside Node's `node-compile-cache`, which
  was passed over by name until now, only a program is reported: an ELF binary, a
  script opening with `#!`, or a file the watchdog cannot read. A rule on the
  folder name alone would tell anyone reading this script where to hide a miner.
- **The check of the temporary directories saw nothing on a `noexec` mount.** It
  used `find -executable`, which asks the kernel whether a file may run, and the
  kernel refuses for every file of a `noexec` mount; on a host whose `/tmp` is
  mounted that way the check had never seen anything there. The execute bit is
  now read from the permissions.

### Added

- **A new variable, `WATCHDOG_TMP_DIRS`,** names the temporary directories
  searched (`/tmp /var/tmp` by default), so that the check can be tried on a
  folder of one's own.
- **The first tests of the watchdog**, in `tests/test_watchdog.py`: data files in
  the folders of Chromium and Node are passed over, programs there are reported,
  and every executable file elsewhere is reported as before.

## [2.2.0] - 2026-10-17

Alerts leave through a mail server of one's own, and a message no longer vanishes
when that server is down.

### Added

- **A spare route, `FALLBACK_COMMAND`.** When the mail cannot be sent, the named
  command carries the message instead: no shell is involved, `{subject}` stands
  for the subject, the body arrives on the standard input. Alerts, recoveries,
  certificate warnings, `--notify` messages and the message about a broken
  configuration use it; the test message and the daily summary do not, so that a
  broken mail setting is still reported as broken. A message delivered this way
  is recorded with the state `fallback` and is not mailed again.
- **The test message names the sender and says whether a spare route is set.**

### Changed

- **There is no built-in mail provider.** `SMTP_SERVER` is required, and the
  default `smtp.gmail.com` is gone from the configuration and from the message
  about a broken configuration. The README describes an account on a mail server
  of one's own instead of Gmail.
- **The Message-ID carries the domain of the sender** instead of the invented
  `vpsmonitor.local`, which spam filters score down.

### Fixed

- **A refused login was tried twice per message.** Many servers ban an address
  after a few refused logins, so a wrong password could lock out every other
  service behind the same address. A refused login is now reported once and not
  repeated.
- **The message about a broken configuration ignored `SMTP_SECURITY`** and always
  used STARTTLS, so it failed on an implicit-TLS port. It now shares the
  connection code of the ordinary messages.

## [2.1.0] - 2026-09-18

The security watchdog joins the repository, and the reason it was crying wolf is
removed.

### Added

- **`security-watchdog.sh` is now part of this project.** It previously existed
  as a single unversioned copy on the server it was guarding. Cron runs the
  in-repo path (`$HOME/tools/vpsmonitor/security-watchdog.sh`); there is no
  second copy under `$HOME/tools/` to drift out of date. Deploying an update is
  `git pull` on `main`.
- **A ninth check watches the shell startup files.** They run on every login and
  are the cheapest place to plant something that survives a reboot, so they are
  reported when they become writable by others and when their contents change.
- **`--no-mail`, `--cpu-only` and `--verbose`**, so a new version can be tried on
  a live machine without sending anything.
- **Behaviour is configurable** through `WATCHDOG_CPU_THRESHOLD`,
  `WATCHDOG_CPU_MIN_AGE`, `WATCHDOG_CPU_WINDOW`, `WATCHDOG_USER`,
  `WATCHDOG_HOME`, `WATCHDOG_LOG` and `WATCHDOG_MONITOR_DIR`, instead of paths
  written into the script.

### Fixed

- **The processor check reported processes that were using no processor at all.**
  It read the per cent printed by `ps`, which is lifetime processor time divided
  by lifetime, and for a process a few milliseconds old that is the quotient of
  two quantised near-zero numbers: one clock tick inside four milliseconds reads
  as five hundred per cent. Worse, the check was written as `ps ... | awk ...`,
  and both members of a pipeline start together, so `ps` enumerated its own twin
  on the other side of the pipe while excluding only `ps` by name. In production
  this sent seven alerts in nine hours naming `awk` at between 160 and 500 per
  cent on a machine whose busiest process was using four per cent of one core.
  The check now restricts candidates to processes older than
  `WATCHDOG_CPU_MIN_AGE`, reads `utime` and `stime` from `/proc` at the two ends
  of a `WATCHDOG_CPU_WINDOW` interval, and compares the processor time genuinely
  consumed during that interval. Its own process group is excluded by identifier
  rather than by command name, so nothing escapes the check by choosing a name.
- **The one-message-per-hour limit never held.** The fingerprint was taken over
  the alert text, which contains the process identifier, so every recurrence
  looked like a new kind of alarm. Findings now carry a stable key naming their
  kind, and the fingerprint is taken over those.
- **An alert said nothing useful.** `55593 500 awk` gave the reader no way to
  judge it. A finding now carries the full command line, the owner, the parent,
  the start time and the processor time accumulated.
- **The shell-configuration check never matched.** Its pattern mixed basic and
  extended regular expression syntax, so `base64 -d|bash` was read as a literal
  string containing a pipe character rather than as an alternation.

## [2.0.0] - 2026-09-17

A correctness and efficiency release following a full audit of the deployed
system. The crontab entry from 1.x keeps working unchanged.

### Fixed: alerting correctness

- **A repeat outage inside the cooldown window was silently swallowed.** Alert
  state was written when an alert fired but never cleared when a site recovered,
  so a site that went down, came back, and failed again twenty minutes later
  produced no alert at all. Alert state now belongs to an *incident*; resolving
  an incident destroys it, so a new outage always alerts.
- **No recovery notification was ever sent.** A `RESOLVED` email now reports the
  outage duration.
- **`ALERT_COOLDOWN` equal to the check interval caused alerts to alternate.**
  Run-to-run drift meant elapsed time measured ~3597s against a 3600s threshold,
  so alerts fired only on alternate hours (visible in production during a
  30-hour outage). Re-alerts now follow an escalating ladder anchored to the
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
- Content validation: an `expect` string or regex per target
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
  above under cron; a healthy run no longer writes anything to `cron.log`
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
