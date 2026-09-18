# Website Monitor

Website, API and TLS certificate monitoring for Linux servers, with incident
tracking and grouped email alerts. Single file, standard library plus two
dependencies, no daemon required.

**Author:** Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
**License:** GPL-3.0

---

## Features

- **Website and JSON API monitoring** with status, content and response-validation checks
- **Incident tracking** — an outage is a first-class object with a start, an end and a duration
- **Recovery alerts** — you are told when a site comes back, and how long it was out
- **Escalating re-alerts** (1h, 2h, 4h, 8h, 12h, then daily) instead of a flat cooldown
- **Grouped alerts** — `example.com` and `www.example.com` arrive as one email, not two
- **TLS expiry warnings** at 21/14/7/3/1 days, independent of whatever issues your certificates
- **Uptime history in SQLite** — real uptime percentages, p95 latency and incident history
- **Daily/weekly summary emails** built from that history
- **Concurrent checks** with a configurable worker pool
- **Dead-man's switch** — an outbound heartbeat so you learn if the monitor itself dies
- **Single-instance locking**, so overlapping runs can never double-alert or race state
- **Automatic log rotation** and database retention

## Requirements

- Linux (developed on Ubuntu 22.04)
- **Python 3.11+** (`tomllib` is used for the optional TOML config)
- An SMTP account for alerts

## Quick start

```bash
git clone https://github.com/dutykh/vpsmonitor
cd vpsmonitor
./install.sh                  # creates venv, installs runtime deps, chmod 600 .env
nano .env                     # SMTP credentials, ALERT_EMAIL, WEBSITES
./venv/bin/python monitor.py --test-email
./venv/bin/python monitor.py --dry-run --verbose
```

Then schedule it (`crontab -e`):

```cron
# Checks every 5 minutes - safe, because runs are lock-guarded
*/5 * * * * cd /path/to/vpsmonitor && ./venv/bin/python monitor.py >> logs/cron.log 2>&1

# Daily uptime summary at 08:00
0 8 * * * cd /path/to/vpsmonitor && ./venv/bin/python monitor.py --report daily >> logs/cron.log 2>&1
```

systemd timers are provided in `systemd/` as an alternative (`Persistent=true`
catches up after downtime; `RandomizedDelaySec` avoids hitting every host on the
same second).

## Command line

| Command | Purpose |
|---------|---------|
| `monitor.py` | One check pass, then exit. The mode to use from cron. |
| `monitor.py --continuous` | Loop forever using `CHECK_INTERVAL`. For systemd/PM2/Docker. |
| `monitor.py --status` | Print current up/down state, uptime and certificate expiry. |
| `monitor.py --report daily\|weekly\|monthly` | Email an uptime summary. |
| `monitor.py --check URL` | Probe one URL and print JSON. No config, no state, no email. |
| `monitor.py --test-email` | Verify SMTP settings end to end. |
| `monitor.py --notify "Subject" --body-file F` | Send an arbitrary message (for other scripts). |
| `monitor.py --dry-run` | Run checks and update state, but never send email. |
| `monitor.py -v` / `-q` | More / less console output. |

## Configuration

Everything lives in `.env` (see `.env.example`). Targets may optionally be moved
to a `targets.toml` file for per-target options.

### Email

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_SERVER` | SMTP host | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_SECURITY` | `starttls`, `ssl` (port 465) or `plain` | `starttls` |
| `SMTP_USERNAME` | Username / from-address | *required* |
| `SMTP_PASSWORD` | Password or app-specific password | *required* |
| `ALERT_EMAIL` | Recipient(s), comma-separated | *required* |
| `SMTP_TIMEOUT` | Seconds before giving up on the SMTP server | `30` |

### Targets

| Variable | Description |
|----------|-------------|
| `WEBSITES` | Comma-separated URLs |
| `API_ENDPOINTS` | `name\|url\|expected_status\|key:value,...`, semicolon-separated |
| `TARGETS_FILE` | Path to a `targets.toml` (overrides the two above) |

### Behaviour

| Variable | Description | Default |
|----------|-------------|---------|
| `TIMEOUT` | Per-request timeout, seconds | `30` |
| `MAX_RETRIES` | Attempts per target before declaring it down | `3` |
| `MAX_WORKERS` | Parallel checks (`1` = sequential) | `8` |
| `CHECK_INTERVAL` | Seconds between passes in `--continuous` mode only | `300` |
| `FAILURE_THRESHOLD` | Consecutive failed passes before alerting | `1` |
| `ALERT_COOLDOWN` | Delay before the *first* re-alert; later ones escalate | `3600` |
| `GROUP_ALERTS` | Coalesce same-domain targets into one email | `true` |
| `SLOW_THRESHOLD_MS` | Warn above this 24h p95 latency (`0` disables) | `0` |
| `SSL_CHECK_ENABLED` | Check certificate expiry | `true` |
| `SSL_WARN_DAYS` | Warning thresholds, in days | `21,14,7,3,1` |
| `HEARTBEAT_URL` | Dead-man's-switch ping URL | *(empty)* |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `LOG_RETENTION_DAYS` | Days of uncompressed daily logs | `90` |
| `LOG_ARCHIVE_DAYS` | Days before gzipped logs are deleted | `365` |
| `DB_RETENTION_DAYS` | Days of raw check rows before roll-up | `90` |

### Gmail

1. Enable two-factor authentication.
2. Create an app password at <https://myaccount.google.com/apppasswords>.
3. Use your address as `SMTP_USERNAME` and the app password as `SMTP_PASSWORD`.

## API monitoring

```
API_ENDPOINTS=name|url|expected_status|key:value,key2:value2
```

Records are separated by `;`. Values are coerced to booleans, integers and floats
where unambiguous. Both the status code and every listed JSON field must match.

```bash
# Status code only
API_ENDPOINTS=MyAPI|http://127.0.0.1:8000/api/v1/health|200

# With response validation
API_ENDPOINTS=Scholar|http://127.0.0.1:8000/api/v1/health|200|status:healthy,cache:connected,database:connected

# Several endpoints
API_ENDPOINTS=A|http://127.0.0.1:8000/health|200|status:ok;B|http://127.0.0.1:8001/status|200
```

A malformed record is **reported in the log**, not silently ignored.

## Richer configuration with `targets.toml`

Copy `targets.toml.example` to `targets.toml` when you need per-target options —
content checks, custom headers, methods, per-target timeouts:

```toml
[[website]]
name   = "Main site"
url    = "https://example.com"
expect = "Welcome to Example"     # catches "HTTP 200 but the page is broken"

[[api]]
name            = "Scholar API"
url             = "http://127.0.0.1:8000/api/v1/health"
expected_status = 200
[api.expected_response]
status   = "healthy"
database = "connected"
```

Parsed with the standard library's `tomllib`. If the file is absent the `.env`
variables are used exactly as before.

## How alerting works

A target is either **up** or **down**. A transition creates or closes an
**incident**, and email follows from the incident, never from a per-URL timer.

1. **Goes down** → an incident opens and an alert is sent immediately.
2. **Stays down** → re-alerts follow an escalating ladder: +1h, +3h, +7h, +15h,
   +27h, +51h, then daily. A 30-hour outage produces 6 emails, not 30.
3. **Comes back** → the incident closes and a **RESOLVED** email reports the
   duration. The alert state is destroyed with the incident, so a *new* outage
   ten minutes later alerts immediately.
4. **Grouping** — every alert raised in one pass is coalesced by registrable
   domain, so apex and `www` twins arrive as a single email that still lists each
   target separately.

Guards against false alarms:

- **Overlap** — a second run exits cleanly if one is already in progress.
- **Monitoring gaps** — after a long silence, alerts carry a banner saying outage
  start times are lower bounds.
- **Monitor-side failure** — if ⩾80% of targets fail at once with DNS/connection
  errors, the alert is re-titled to say the monitoring host is the likely cause.
- **Cold start** — the first run after installation records pre-existing failures
  without paging you about all of them at once.
- **Flap detection** — a target oscillating up and down is reported once rather
  than on every transition.

## TLS certificates

Expiry is probed directly over a TLS handshake, at most once every 12 hours per
host, and warnings fire at `SSL_WARN_DAYS` thresholds (each threshold once).

This is deliberately independent of whatever renews your certificates. If ACME
renewal silently stops — a permissions problem on the account file, a rate limit,
a failed challenge — nothing else will tell you until browsers start showing
warnings. `monitor.py --status` shows days remaining for every monitored host.

## Data and logs

```
logs/monitor_YYYYMMDD.log   daily application log, rotated and gzipped
logs/cron.log               only warnings and errors (see below)
data/monitor.db             SQLite: checks, incidents, certificates, runs
```

Console output is **TTY-aware**: colours only on a terminal, and under cron only
warnings and above reach stdout. A healthy run therefore writes nothing to
`cron.log`. Timestamps in the database are UTC; log filenames use local dates.

Retention is automatic — raw check rows are rolled into daily aggregates after
`DB_RETENTION_DAYS` and the database is vacuumed monthly, so the uptime history
is permanent while storage stays flat.

To back the database up, use `VACUUM INTO` rather than `cp` (a plain copy of a
WAL-mode database loses the write-ahead log):

```cron
23 3 * * * sqlite3 /path/to/vpsmonitor/data/monitor.db "VACUUM INTO '/backups/monitor-$(date +\%F).db'"
```

## Reusing the alert channel from other scripts

`--notify` lets any script send mail through the monitor's configured SMTP
account without duplicating credentials:

```bash
./venv/bin/python monitor.py --notify "[SECURITY] watchdog alert on $(hostname)" \
                             --body-file /home/dds/logs/security-watchdog.log
```

## The security watchdog

`security-watchdog.sh` ships beside the monitor and uses exactly that channel.
It looks for the signs of a crypto-miner or a backdoor and mails through the
monitor's SMTP account, so that a compromise at three in the morning is not
discovered at the next login. It runs from cron every five minutes, directly from this repository so there is
no second copy to drift out of date:

```cron
*/5 * * * * /home/dds/tools/vpsmonitor/security-watchdog.sh
```

Nine checks run on each pass: processes consuming the processor, hidden
executables in the home directory, random-named directories, executables dropped
in the temporary directories, processes carrying a known miner or backdoor name,
crontab entries that fetch or decode something, known malware signatures in the
shell configuration, outbound connections to a mining pool, and the shell startup
files, which are reported when they become writable by others or when their
contents change.

The processor check measures over a window rather than trusting the per cent that
`ps` prints. That figure is lifetime processor time divided by lifetime, so for a
process a few milliseconds old it is the quotient of two quantised near-zero
numbers and takes arbitrary values; a single clock tick inside four milliseconds
reads as five hundred per cent. Candidates are therefore restricted to processes
that have already lived `WATCHDOG_CPU_MIN_AGE` seconds, their `utime` and `stime`
are read from `/proc`, and the check waits `WATCHDOG_CPU_WINDOW` seconds and reads
them again. What it compares against `WATCHDOG_CPU_THRESHOLD` is the processor
time genuinely consumed during that window.

| Variable | Meaning | Default |
|----------|---------|---------|
| `WATCHDOG_CPU_THRESHOLD` | Per cent of one core above which a process is reported | `150` |
| `WATCHDOG_CPU_MIN_AGE` | Seconds a process must already have lived to be a candidate | `60` |
| `WATCHDOG_CPU_WINDOW` | Seconds over which its processor use is measured | `15` |
| `WATCHDOG_USER` | Account whose processes are watched | current user |
| `WATCHDOG_HOME` | Home directory inspected | `$HOME` |
| `WATCHDOG_LOG` | Log file | `$HOME/logs/security-watchdog.log` |
| `WATCHDOG_MONITOR_DIR` | Where `monitor.py` and its virtualenv live | `$HOME/tools/vpsmonitor` |

Three flags help when working on it: `--no-mail` runs every check and suppresses
the email, `--cpu-only` runs the processor check alone and prints `clean` or the
finding, and `--verbose` prints the findings to the terminal.

A finding is mailed at most once an hour. The rate limiter fingerprints the
*kind* of finding rather than its text, so a condition that persists across runs
is recognised as one condition even though the process identifiers change.

### Deploying the watchdog to a server

The script is self-contained and has no dependencies beyond the monitor it mails
through. On the host that already carries this repository, point cron at the
in-repo path and keep the working tree on `main`:

```cron
*/5 * * * * /home/dds/tools/vpsmonitor/security-watchdog.sh
```

A fresh clone on another host is the same idea: check the tree out under
`$HOME/tools/vpsmonitor`, ensure `security-watchdog.sh` is executable, and add
the cron line above (adjust the path if the clone lives elsewhere).

Before trusting a new version, run it once with the email suppressed and confirm
it reports what you expect, writing to a scratch log so the real one is untouched:

```bash
WATCHDOG_LOG=/tmp/wd-test.log WATCHDOG_ALERT_FILE=/tmp/wd-test-ALERT \
  /home/dds/tools/vpsmonitor/security-watchdog.sh --no-mail --verbose
```

Then confirm the processor check is quiet on an idle machine and still sees a
real offender. Start a busy loop somewhere that allows execution (`/tmp` is
mounted `noexec` on this server, so the home directory is the place), wait past
the minimum age, and run the check with the threshold lowered to match a
single-core process:

```bash
mkdir -p ~/wdtest && cp "$(command -v bash)" ~/wdtest/zzdecoy
setsid ~/wdtest/zzdecoy -c 'end=$((SECONDS+150)); while [ $SECONDS -lt $end ]; do :; done' &
sleep 65
WATCHDOG_CPU_THRESHOLD=80 /home/dds/tools/vpsmonitor/security-watchdog.sh --cpu-only
pkill -x zzdecoy; rm -rf ~/wdtest
```

Deploying an update is `git pull` on `main`. There is no separate install copy,
so the path in cron does not change. The first clean line appears in the log at
the top of the next hour.

## Development

```bash
make dev      # development virtualenv (kept out of the production one)
make test     # pytest
make cov      # coverage report
make lint     # pylint + mypy
make check    # everything CI runs
```

The production virtualenv holds only `requests` and `python-dotenv` (~17 MB).
Development tooling lives in `requirements-dev.txt` and a separate `.venv-dev`.

## Troubleshooting

**No alerts arriving**
1. `./venv/bin/python monitor.py --test-email`
2. Check `logs/monitor_$(date +%Y%m%d).log`
3. `./venv/bin/python monitor.py --status` — are the targets actually down?
4. Gmail app passwords are revoked when the account password changes.

**Too many alerts** — raise `FAILURE_THRESHOLD` to require consecutive failed
passes, or `ALERT_COOLDOWN` to stretch the escalation ladder.

**False positives** — raise `TIMEOUT`, or add an `expect` string if the site
returns a valid but unhelpful page.

**A run seems to be skipped** — that is the single-instance lock. Look for
"another monitor run is already in progress" in the log.

## Security

- `.env` is `chmod 600` and git-ignored; `install.sh` enforces both and refuses
  to proceed if `.env` is not ignored.
- A `pre-commit` hook (`.githooks/`, enabled by `install.sh`) blocks commits
  containing a real `SMTP_PASSWORD`, `.env`, or the database.
- CI fails if credentials or `data/` ever become tracked.
- Alert emails redact response fields matching `token|secret|key|password` and
  truncate bodies, so API internals are not mailed in cleartext.
- Use an app-specific password, never your main account password.
- `data/` is `chmod 700` — it holds an inventory of your infrastructure.

## Contributing

1. Fork and branch.
2. `make check` must pass.
3. Add tests for new behaviour — especially anything touching alert scheduling.
4. Open a pull request.

## License

GPL-3.0 — see [LICENSE](LICENSE).
