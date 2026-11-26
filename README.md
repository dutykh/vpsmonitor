<!-- Author: Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and Technology, Abu Dhabi, UAE) -->

# Website Monitor

Website, API and TLS certificate monitoring for Linux servers, with incident
tracking and grouped alerts that leave by email, by a command of your own (a
chat client, a push service), or both, each kind of message by the route you
choose. Single file, standard library plus two dependencies, no daemon required.

**Author:** Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
**License:** GPL-3.0

---

## Features

- **Website and JSON API monitoring** with status, content and response-validation checks
- **Incident tracking**: an outage is a first-class object with a start, an end and a duration
- **Recovery alerts**: you are told when a site comes back, and how long it was out
- **Escalating re-alerts** (1h, 2h, 4h, 8h, 12h, then daily) instead of a flat cooldown
- **A route per kind of message**: outages, recoveries, certificate warnings, summaries
  and the messages of other scripts each go by email, by a command, by both, or nowhere
- **Alerts that are not lost**: a message no channel could deliver is tried again at the
  next pass, and a spare route carries it when the mail server is down
- **Grouped alerts**: `example.com` and `www.example.com` arrive as one message, and
  `photo.example.com` is named as itself, never as `example.com`
- **Flap detection**: a target that keeps changing state is announced once, not at every change
- **TLS expiry warnings** at 21/14/7/3/1 days, independent of whatever issues your certificates
- **Uptime history in SQLite**: real uptime percentages, p95 latency and incident history
- **Summaries** by day, week or month, built from that history: a table by email, a short
  message for a chat or a phone, or JSON for other programs, sent or printed
- **Concurrent checks** with a configurable worker pool
- **Dead-man's switch**: an outbound heartbeat so you learn if the monitor itself dies
- **Single-instance locking**, so overlapping runs can never double-alert or race state
- **One log file per day**, compressed and pruned automatically, and database retention

## Requirements

- Linux (developed on Ubuntu 22.04)
- **Python 3.11+** (`tomllib` is used for the optional TOML config)
- A way to deliver messages: an SMTP account (your own mail server, any provider, or a
  local relay that needs no login), a command that carries a message to a chat or a
  push service, or both

## Quick start

```bash
git clone https://github.com/dutykh/vpsmonitor
cd vpsmonitor
./install.sh                  # creates venv, installs runtime deps, chmod 600 .env
nano .env                     # SMTP credentials, ALERT_EMAIL, WEBSITES, routes
./venv/bin/python monitor.py --test-email      # or --test-command
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
same second). They are user units: copy them to `~/.config/systemd/user/`, change
`%h/tools/vpsmonitor` if the clone lives elsewhere, run
`systemctl --user enable --now vpsmonitor.timer vpsmonitor-report.timer`, and have an
administrator run `loginctl enable-linger $USER`, without which user units stop at
logout.

## Command line

| Command | Purpose |
|---------|---------|
| `monitor.py` | One check pass, then exit. The mode to use from cron. |
| `monitor.py --once` | The same single pass, asked for by name. |
| `monitor.py --continuous` | Loop forever using `CHECK_INTERVAL`. For systemd/PM2/Docker. |
| `monitor.py --status` | Print the routes, current up/down state, uptime, flapping targets and certificate expiry. |
| `monitor.py --report daily\|weekly\|monthly` | Send an uptime summary by `ROUTE_SUMMARY`. |
| `monitor.py --report daily --print` | Print the summary instead of sending it. |
| `monitor.py --report daily --format brief\|json` | The short form for a chat or a phone, or JSON for other programs (default: `text`). |
| `monitor.py --check URL` | Probe one URL and print JSON. No config, no state, no message. |
| `monitor.py --test-email` | Verify SMTP settings end to end. |
| `monitor.py --test-command` | Verify `MESSAGE_COMMAND` end to end. |
| `monitor.py --notify "Subject" --body-file F` | Send an arbitrary message by `ROUTE_NOTIFY` (for other scripts). |
| `monitor.py --dry-run` | Run checks and record them, but send nothing; the alerts are left to the first real run. |
| `monitor.py --config PATH` | Read the targets from this `targets.toml`, in place of `TARGETS_FILE` or the `targets.toml` beside the script. |
| `monitor.py -v` / `-q` | More / less console output. |
| `monitor.py --version` | Print the version and exit. |

## Configuration

Everything lives in `.env` (see `.env.example`). Targets may optionally be moved
to a `targets.toml` file for per-target options.

### Messages and routes

Each message the monitor sends has a kind, and each kind a route, a setting
`ROUTE_<KIND>` that names the channels carrying it: `email`, `command`, both
(`email,command`), or `none`. Everything goes by email unless you say otherwise, so
a configuration written for an earlier version keeps working as it was.

| Variable | Carries | Default |
|----------|---------|---------|
| `ROUTE_DOWN` | Outage alerts and their reminders, flapping notices | `email` |
| `ROUTE_RESOLVED` | Recovery notices, notices that a flapping target is steady again | `email` |
| `ROUTE_TLS` | Certificate expiry warnings | `email` |
| `ROUTE_SUMMARY` | Daily, weekly and monthly summaries | `email` |
| `ROUTE_NOTIFY` | Messages handed over by other scripts through `--notify` | `email` |
| `MESSAGE_COMMAND` | The command of the `command` channel | empty |

The command line of `MESSAGE_COMMAND` is split like a shell would split it, but no
shell is involved. In each argument, `{subject}` becomes the subject, `{kind}` the
kind of the message (`down`, `resolved`, `tls`, `flap`, `steady`, `summary`, `notify`,
`test`, `broken`) and `{level}` its weight in the words of chat notifiers (`error`,
`warn`, `success`, `info`); the three are replaced in one pass, so a subject that
contains such a word is never rewritten. The body arrives on the standard input, and
the message counts as delivered when the command exits with status 0. With
[tg-ping](https://github.com/dutykh/tg-ping), for instance, outages can go both to
Telegram and by mail and recoveries to Telegram alone, the program being named by
its absolute path, since no shell expands `~` or `$HOME` there:

```text
MESSAGE_COMMAND=/path/to/tg-ping/bin/tg-ping --level {level} --title {subject}
ROUTE_DOWN=email,command
ROUTE_RESOLVED=command
```

Any program that reads a message on its standard input will do, such as a client
of ntfy, Matrix or Slack, or a few lines of shell around `curl`. The mail settings
are needed only when a route names `email`, so a server without mail can run the
monitor on commands alone. A message is delivered when one channel of its route
delivered it; when none could, the spare route below is tried, and an alert left
undelivered is sent again at the next pass. `monitor.py --status` names the routes
in force, and `monitor.py --test-command` sends a test message through the command.

### Email

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_SERVER` | SMTP host | *required for email* |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_SECURITY` | `starttls`, `ssl` (port 465) or `plain` | `starttls` |
| `SMTP_USERNAME` | Login name, also the sender address unless `SMTP_FROM` is set | empty: no login |
| `SMTP_PASSWORD` | Password of that login (set both or neither) | empty |
| `SMTP_FROM` | Sender address, when it is not the login or there is no login | `SMTP_USERNAME` |
| `ALERT_EMAIL` | Recipient(s), comma-separated | *required for email* |
| `SMTP_TIMEOUT` | Seconds before giving up on the SMTP server | `30` |
| `FALLBACK_COMMAND` | Spare route, see below | empty |

### Targets

| Variable | Description |
|----------|-------------|
| `WEBSITES` | Comma-separated URLs |
| `API_ENDPOINTS` | `name\|url\|expected_status\|key:value,...`, semicolon-separated |
| `TARGETS_FILE` | Path to a `targets.toml` (overrides the two above) |

### Behaviour

| Variable | Description | Default |
|----------|-------------|---------|
| `TIMEOUT` | Per-request timeout, seconds; a body must also arrive within it | `30` |
| `MAX_RETRIES` | Attempts per target before declaring it down | `3` |
| `MAX_WORKERS` | Parallel checks (`1` = sequential) | `8` |
| `CHECK_INTERVAL` | Seconds between passes: the cadence of `--continuous`, and under cron what the summaries expect | `300` |
| `FAILURE_THRESHOLD` | Consecutive failed passes before alerting; the outage is dated from the first | `1` |
| `ALERT_COOLDOWN` | Delay before the *first* re-alert, which sets the scale of the whole ladder | `3600` |
| `GROUP_ALERTS` | One message per pass, the targets listed site by site (`false`: one per target) | `true` |
| `FLAP_CHANGES` | Changes of state over `FLAP_WINDOW` checks that make a target flapping (`0` disables) | `6` |
| `FLAP_WINDOW` | Number of recent checks considered for flapping | `12` |
| `FLAP_HOLD` | Seconds a flapping target's outage must last before it is announced | `900` |
| `SLOW_THRESHOLD_MS` | Flag in the summaries a target whose p95 over the period exceeds this (`0` disables) | `0` |
| `SSL_CHECK_ENABLED` | Check certificate expiry | `true` |
| `SSL_WARN_DAYS` | Warning thresholds, in days | `21,14,7,3,1` |
| `HEARTBEAT_URL` | Dead-man's-switch ping URL | *(empty)* |
| `USER_AGENT` | `User-Agent` header of every request | `Website-Monitor/` with the version and the address of this repository |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `LOG_RETENTION_DAYS` | Days of uncompressed daily logs | `90` |
| `LOG_ARCHIVE_DAYS` | Days before gzipped logs are deleted | `365` |
| `DB_RETENTION_DAYS` | Days of raw check rows before roll-up | `90` |

### Your own mail server

The monitor needs only a login that is allowed to send; nobody has to read its
mailbox. On a mail server of your own, create one account for it (for example
`vpsmonitor@example.org`) and use the full address as the login:

```text
SMTP_SERVER=mail.example.org
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=vpsmonitor@example.org
SMTP_PASSWORD=<a-long-random-password>
ALERT_EMAIL=you@example.net
```

Messages are signed with `SMTP_FROM`, which defaults to `SMTP_USERNAME`, and their
Message-ID carries its domain. A refused login is never repeated: a wrong password
stays wrong, and many servers ban an address after a few refused logins.
Delivery-failure notices from the recipient's host arrive in the mailbox of that
account. A provider whose login is not an address (an API key, a token) takes the
sender in `SMTP_FROM`, and a local relay that accepts mail without a login (Postfix
or nullmailer on port 25) takes `SMTP_SECURITY=plain`, `SMTP_PORT=25`, `SMTP_FROM`
and no `SMTP_USERNAME` or `SMTP_PASSWORD` at all.

### Spare route

A mail server that is down cannot announce that it is down. `FALLBACK_COMMAND`
names a command that carries a message instead when no channel of its route could
deliver it. Its syntax and its placeholders are those of `MESSAGE_COMMAND`, and it
is not run again when it is the very command that just failed. Alerts, recoveries,
flapping notices, certificate warnings and `--notify` messages use it, and so does
the message about a broken configuration. The test messages and the summaries never
do, so that a broken channel shows as broken. With
[tg-ping](https://github.com/dutykh/tg-ping) the spare route is a Telegram message,
the program being named by its absolute path, since no shell expands `~` or `$HOME`
there:

```text
FALLBACK_COMMAND=/path/to/tg-ping/bin/tg-ping --warn --title {subject}
```

A message delivered this way is recorded with the state `fallback` in the
`notifications` table, and it is not sent again by mail.

## API monitoring

```
API_ENDPOINTS=name|url|expected_status|key:value,key2:value2
```

Records are separated by `;`. Values are coerced to booleans, integers and floats
where unambiguous, and a value in double quotes stays a string (`ready:"yes"`).
Both the status code and every listed JSON field must match.

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

Copy `targets.toml.example` to `targets.toml` when you need per-target options,
such as content checks, custom headers, methods or per-target timeouts:

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
variables are used exactly as before. An unknown table (`[[apis]]` for `[[api]]`)
or key (`expected_text` for `expect`) is reported in the log rather than silently
ignored. A quoted number or boolean (`expected_status = "200"`,
`verify_ssl = "false"`) means what it says, while a value that cannot be read, or an
`expect` that is not a valid regular expression when `expect_regex = true`, stops
the monitor with a message naming the target and the key. An `Accept` header of
your own on an API target is kept.

## How alerting works

A target is either **up** or **down**. A transition creates or closes an
**incident**, and messages follow from the incident, never from a per-URL timer.

1. **Goes down** → an incident opens and an alert is sent immediately; with
   `FAILURE_THRESHOLD` above 1, once that many passes in a row have failed, the
   outage being dated from the first of them.
2. **Stays down** → re-alerts follow an escalating ladder: +1h, +3h, +7h, +15h,
   +27h, +51h, then daily, scaled by `ALERT_COOLDOWN`. A 30-hour outage produces 6
   messages, not 30, and a monitor back from a long gap sends one reminder, not one
   per rung it missed.
3. **Comes back** → the incident closes and a **RESOLVED** message reports the
   duration. The alert state is destroyed with the incident, so a *new* outage
   ten minutes later alerts immediately.
4. **Grouping**: every alert raised in one pass is coalesced into one message that
   lists the targets site by site. A site is the host name without a leading `www.`,
   so apex and `www` twins appear together, while an outage of `photo.example.com`
   is announced as `photo.example.com`, never as `example.com`.
5. **Delivery**: the schedule of an alert moves on only once its message has left.
   An alert that no channel and no spare route could deliver is sent again at the
   next pass, and a recovery notice is tried again for a day. A dry run moves
   nothing on, so the first real run announces what the dry run saw.

Guards against false alarms:

- **Overlap**: a second run exits cleanly if one is already in progress.
- **Monitoring gaps**: after a long silence, alerts carry a banner saying that an
  outage may have begun earlier than shown, and lasted longer.
- **Monitor-side failure**: if ⩾80% of at least four targets fail at once with
  DNS, connection or timeout errors, the first pass is held back; if the failure
  persists, the alert says in its subject that the monitoring host is suspected,
  and its body explains why. A failure of your own reverse proxy looks the same
  from inside the server, which is why the alert is delayed and never suppressed.
- **Cold start**: the first real run after installation records pre-existing
  failures without paging you about all of them at once; those that persist are
  announced at the next pass. A dry run does not use the cold start up.
- **Flap detection**: a target whose last `FLAP_WINDOW` checks (12, an hour at a
  five-minute cadence) hold `FLAP_CHANGES` changes of state (6) is flapping. One
  message says so, in place of an alert and a recovery at every change. While it
  flaps, an outage of it is announced only once it has lasted `FLAP_HOLD` (15
  minutes), so that flapping never hides a lasting outage, and a recovery only if
  its outage was announced; one message says when it has kept one state through a
  whole window.

## TLS certificates

Expiry is probed directly over a TLS handshake, on the port of the address
(443 unless it names another), at most once every 12 hours per host, and warnings
fire at `SSL_WARN_DAYS` thresholds (each threshold once). A probe that fails keeps
what the last good one learnt, so a passing network error neither hides the host
from the summaries nor repeats a warning already sent; a warning whose message
could not be delivered is sent again. The certificates of hosts no longer
monitored are forgotten.

This is deliberately independent of whatever renews your certificates. If ACME
renewal silently stops (a permissions problem on the account file, a rate limit,
a failed challenge), nothing else will tell you until browsers start showing
warnings. `monitor.py --status` shows days remaining for every monitored host.

## Summaries

`monitor.py --report daily` (or `weekly`, `monthly`) builds a summary from the
stored history and sends it by `ROUTE_SUMMARY`. It comes in three forms, chosen
with `--format`. The default, `text`, is a table of every target with its uptime,
average and p95 response time, followed by the incidents and the certificates,
sent by mail with an HTML version. The form `brief` is a short message for a chat
or a phone: it opens with the verdict, then names only what needs attention (what
is down now, the incidents of the period, the targets below 100%, the slow ones,
the certificates close to expiry), and ends with the three slowest answers and the
earliest certificate. The form `json` gives the same facts to other programs.

```text
✅ Daily summary: all 29 targets up, 100.00% uptime over the 24 hours to 07:00 (+04), no incident.
Slowest answers (p95): example.com 850 ms, www.example.com 845 ms, shop.example.com 421 ms.
Certificates: 30 valid certificates, the earliest expiring in 29 days (example.com and 8 more).
```

With `--print` the summary is printed instead of sent, so that any scheduler can
deliver it on its own terms. Every form also says when the monitor itself has not
completed a check for three of its passes (by `CHECK_INTERVAL`, and at least half
an hour), which a summary run by another scheduler is in a position to notice. A
short summary in a chat every morning instead of a mail can therefore come from the
monitor's own timer, with `ROUTE_SUMMARY=command` and the line

```cron
0 7 * * * cd /path/to/vpsmonitor && ./venv/bin/python monitor.py --report daily --format brief
```

or from the chat's own scheduler (a bot's or an agent's scheduled task) running
`monitor.py --report daily --print --format brief` and relaying what it prints,
with the summary timer of the monitor switched off.

## Data and logs

```
logs/monitor_YYYYMMDD.log   daily application log, gzipped after LOG_RETENTION_DAYS
logs/cron.log               only warnings and errors (see below)
data/monitor.db             SQLite: checks, incidents, certificates, runs
```

Every invocation writes straight into the file of the current local day, so the
five-minute pass, a summary and a `--notify` can share the folder; no file is ever
renamed. Console output is **TTY-aware**: colours only on a terminal, and under
cron only warnings and above reach stdout. A healthy run therefore writes nothing
to `cron.log`. Timestamps in the database are UTC; log filenames use local dates.
The monitor creates its files readable by their owner only.

Retention is automatic: raw check rows are rolled into daily aggregates after
`DB_RETENTION_DAYS` and the database is vacuumed monthly, so the uptime history
is kept while storage stays flat. A target removed from the configuration leaves
the summaries at once and keeps its history for a week, so that a renamed target
or a mistaken edit costs nothing; a dry run never removes anything.

To back the database up, use `VACUUM INTO` rather than `cp` (a plain copy of a
WAL-mode database loses the write-ahead log):

```cron
23 3 * * * sqlite3 /path/to/vpsmonitor/data/monitor.db "VACUUM INTO '/backups/monitor-$(date +\%F).db'"
```

## Reusing the alert channel from other scripts

`--notify` lets any script send a message by the monitor's channels, as
`ROUTE_NOTIFY` routes it, without duplicating credentials. It exits 0 when the
message was delivered or deliberately routed nowhere, 1 when it could not be
delivered, and 2 when the configuration is broken and even the raw settings could
not carry it; a broken target list does not stop it, since it needs only the
channels:

```bash
./venv/bin/python monitor.py --notify "[SECURITY] watchdog alert on $(hostname)" \
                             --body-file "$HOME/logs/security-watchdog.log"
```

## The security watchdog

`security-watchdog.sh` ships beside the monitor and uses exactly that channel.
It looks for the signs of a crypto-miner or a backdoor and mails through the
monitor's SMTP account (and through its spare route when the mail cannot be sent),
so that a compromise at three in the morning is not
discovered at the next login. It runs from cron every five minutes, directly from this repository so there is
no second copy to drift out of date:

```cron
*/5 * * * * $HOME/tools/vpsmonitor/security-watchdog.sh
```

Nine checks run on each pass: processes that keep the processor busy for a
quarter of an hour, hidden executables in the home directory, random-named
directories, executables dropped in the temporary directories, processes
carrying a known miner or backdoor name, crontab entries that fetch or decode
something, known malware signatures in the shell configuration, outbound
connections to a mining pool, and the shell startup files, which are reported
when they become writable by others or when their contents change.

The processor check measures over a window rather than trusting the per cent that
`ps` prints. That figure is lifetime processor time divided by lifetime, so for a
process a few milliseconds old it is the quotient of two quantised near-zero
numbers and takes arbitrary values; a single clock tick inside four milliseconds
reads as five hundred per cent. Candidates are therefore restricted to processes
that have already lived `WATCHDOG_CPU_MIN_AGE` seconds, their `utime` and `stime`
are read from `/proc`, and the check waits `WATCHDOG_CPU_WINDOW` seconds and reads
them again. What it compares against `WATCHDOG_CPU_THRESHOLD` is the processor
time genuinely consumed during that window.

One busy window is not yet a finding. The rebuild of a website, a language
server that starts, a task of an agent: each keeps several cores busy for a few
minutes, and each used to raise an alert. A process is therefore reported only
when the load lasts. With `r` its share of one core over the window at each
pass, and `C` the processor time it has consumed, the alert at time `t` needs

```text
r > WATCHDOG_CPU_THRESHOLD     at every pass since the streak began at t0
t - t0 ⩾ WATCHDOG_CPU_PERSIST  (15 minutes by default: four passes in a row)
(C(t) - C(t0)) / (t - t0) > WATCHDOG_CPU_THRESHOLD
```

The last condition, on the average over the whole streak, keeps out a program
that happens to be busy at the moments of measurement while idle in between.
Until the streak is long enough, each pass writes one line `CPU watch:` in the
log, and no mail goes out. The streaks are kept in `.watchdog-cpu` beside the
alert file, for the current boot only. A process is known by its number together
with its start time, so that a reused number cannot inherit a streak, and one
pass below the threshold starts the count over.

The check of the temporary directories reads the execute bit from the
permissions, so that it also sees the files of a `noexec` mount, where
`find -executable` sees none. Chromium unpacks the components it downloads into
folders named `org.chromium.Chromium.scoped_dir.XXXXXX` and leaves the execute bit
on their data files, and Node's compile cache, `node-compile-cache`, is treated
alike: inside those folders only a program is reported, that is an ELF binary, a
script opening with `#!`, or a file the watchdog cannot read. A rule on the name
alone would tell anyone reading this script where to hide a miner.

| Variable | Meaning | Default |
|----------|---------|---------|
| `WATCHDOG_CPU_THRESHOLD` | Per cent of one core above which a process is reported | `150` |
| `WATCHDOG_CPU_MIN_AGE` | Seconds a process must already have lived to be a candidate | `60` |
| `WATCHDOG_CPU_WINDOW` | Seconds over which its processor use is measured | `15` |
| `WATCHDOG_CPU_PERSIST` | Seconds a process must stay above the threshold, at every pass and on average, before it is reported (`0` reports a single busy window) | `900` |
| `WATCHDOG_USER` | Account whose processes are watched | current user |
| `WATCHDOG_HOME` | Home directory inspected | `$HOME` |
| `WATCHDOG_TMP_DIRS` | Temporary directories searched for executables, separated by spaces | `/tmp /var/tmp` |
| `WATCHDOG_LOG` | Log file | `$HOME/logs/security-watchdog.log` |
| `WATCHDOG_ALERT_FILE` | File holding the findings while an alert stands, removed by a clean pass; the state of the watchdog (processor streaks, checksums of the shell files, mail stamps) is kept in the same folder | `$HOME/logs/SECURITY_ALERT` |
| `WATCHDOG_MONITOR_DIR` | Where `monitor.py` and its virtualenv live | `$HOME/tools/vpsmonitor` |

Three flags help when working on it: `--no-mail` runs every check and suppresses
the email, `--cpu-only` runs the processor check alone and prints `clean` or the
finding (it reads the streaks but never writes them, so that a test cannot
disturb the count that cron keeps), and `--verbose` prints the findings, and the
processes being watched, to the terminal.

A finding is mailed at most once an hour. The rate limiter fingerprints the
*kind* of finding rather than its text, so a condition that persists across runs
is recognised as one condition even though the process identifiers change.

### Deploying the watchdog to a server

The script is self-contained and has no dependencies beyond the monitor it mails
through. On the host that already carries this repository, point cron at the
in-repo path and keep the working tree on `main`:

```cron
*/5 * * * * $HOME/tools/vpsmonitor/security-watchdog.sh
```

A fresh clone on another host is the same idea: check the tree out under
`$HOME/tools/vpsmonitor`, ensure `security-watchdog.sh` is executable, and add
the cron line above (adjust the path if the clone lives elsewhere).

Before trusting a new version, run it once with the email suppressed and confirm
it reports what you expect, writing to a scratch log so the real one is untouched:

```bash
WATCHDOG_LOG=/tmp/wd-test.log WATCHDOG_ALERT_FILE=/tmp/wd-test-ALERT \
  $HOME/tools/vpsmonitor/security-watchdog.sh --no-mail --verbose
```

The tests in `tests/test_watchdog.py` try the check of the temporary directories
the same way, on a folder of their own given by `WATCHDOG_TMP_DIRS`, and the
processor check on a busy program of their own, with a window of one second and
a persistence of three: busy once, the program is only watched; busy at two
passes three seconds apart, it is reported; stopped during one pass, it starts
its count over; with `WATCHDOG_CPU_PERSIST=0` it is reported at once.

Then confirm the processor check is quiet on an idle machine and still sees a
real offender. Start a busy loop from the home directory (a copy of the shell
placed in `/tmp` would itself be reported by the watchdog's own five-minute run),
wait past the minimum age, and run the check with the threshold lowered to match
a single-core process and the persistence switched off:

```bash
mkdir -p ~/wdtest && cp "$(command -v bash)" ~/wdtest/zzdecoy
setsid ~/wdtest/zzdecoy -c 'end=$((SECONDS+150)); while [ $SECONDS -lt $end ]; do :; done' &
sleep 65
WATCHDOG_CPU_THRESHOLD=80 WATCHDOG_CPU_PERSIST=0 $HOME/tools/vpsmonitor/security-watchdog.sh --cpu-only
pkill -x zzdecoy; rm -rf ~/wdtest
```

The check prints `HIT` and the description of the decoy. Without
`WATCHDOG_CPU_PERSIST=0` the same line prints `clean` and the log gains a line
`CPU watch:`, since the decoy has not been busy for a quarter of an hour.

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
1. `./venv/bin/python monitor.py --test-email` (or `--test-command`)
2. `./venv/bin/python monitor.py --status`: which routes are in force, and are the
   targets actually down?
3. Check `logs/monitor_$(date +%Y%m%d).log`. A line `messages left undelivered`
   means a channel failed; those alerts are sent again at the next pass.
4. A line `SMTP login refused` in the log means the password is wrong. Fix it
   before the next run: the mail server may ban the address after repeated refusals.

**Too many alerts**: set `FAILURE_THRESHOLD=2` to keep quiet about a single failed
pass, such as the few seconds of a restart or a deployment, at the cost of hearing
about a real outage one pass later; raise `ALERT_COOLDOWN` to stretch the
escalation ladder; send recoveries elsewhere (`ROUTE_RESOLVED=command`) or nowhere.

**False positives**: raise `TIMEOUT`, or add an `expect` string if the site
returns a valid but unhelpful page.

**A run seems to be skipped**: that is the single-instance lock. Look for
"another monitor run is already in progress" in the log.

**A summary says the monitor is not running**: look at its timer or its cron entry
(`systemctl --user list-timers`, `crontab -l`). A user timer stops at logout unless
lingering is enabled for the account.

**A broken configuration**: the monitor says so by every channel it can still use,
the first time and then every six hours while the same error lasts; a different
error is announced at once.

## Security

- `.env` is `chmod 600` and git-ignored; `install.sh` enforces both and refuses
  to proceed if `.env` is not ignored.
- A `pre-commit` hook (`.githooks/`, enabled by `install.sh`) blocks commits
  containing a real `SMTP_PASSWORD`, `.env`, or the database.
- CI fails if credentials or `data/` ever become tracked.
- Alerts redact response fields matching `token|secret|key|password|auth|cookie` at
  every level of nesting and truncate bodies, so API internals are not sent in
  cleartext; the password of an address (`user:***@host`) and secret-looking query
  parameters (`?api_key=***`) are masked wherever an address or an error is shown,
  in messages, summaries and logs.
- The HTML part of a message escapes everything the monitored servers send, so a
  response cannot place a link or an image in an alert.
- Use an app-specific password, never your main account password.
- `data/` is `chmod 700`, since it holds an inventory of your infrastructure, and
  the monitor creates its database, journal and logs readable by their owner only,
  with or without `install.sh`.

## Contributing

1. Fork and branch.
2. `make check` must pass.
3. Add tests for new behaviour, especially anything touching alert scheduling.
4. Open a pull request.

## How to cite

The file [`CITATION.cff`](CITATION.cff) describes the program for citation, and
GitHub turns it into a reference, in APA or BibTeX, through the "Cite this
repository" button of the repository page.

## License

GPL-3.0, see [LICENSE](LICENSE).
