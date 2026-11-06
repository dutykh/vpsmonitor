#!/bin/bash
#
# Security Watchdog - detects crypto-miner and backdoor activity on a Linux
# server, and reports it by email through the alert channel of monitor.py.
#
# Runs from cron every five minutes:
#   */5 * * * * /home/dds/tools/vpsmonitor/security-watchdog.sh
#
# Author: Dr. Denys Dutykh (Khalifa University of Science and Technology,
#         Abu Dhabi, UAE)
# License: GPL-3.0
#

WATCH_USER="${WATCHDOG_USER:-$(id -un)}"
WATCH_HOME="${WATCHDOG_HOME:-$HOME}"
LOG="${WATCHDOG_LOG:-$WATCH_HOME/logs/security-watchdog.log}"
ALERT_FILE="${WATCHDOG_ALERT_FILE:-$WATCH_HOME/logs/SECURITY_ALERT}"
STATE_DIR="$(dirname "$ALERT_FILE")"
MONITOR_DIR="${WATCHDOG_MONITOR_DIR:-$WATCH_HOME/tools/vpsmonitor}"
read -ra TMP_DIRS <<< "${WATCHDOG_TMP_DIRS:-/tmp /var/tmp}"

# Processor thresholds. A process is busy when the processor time it actually
# consumes during a window of CPU_WINDOW seconds exceeds CPU_THRESHOLD per cent
# of one core, and when it was already at least CPU_MIN_AGE seconds old when the
# window opened. The age condition matters: the per cent that ps prints is
# lifetime processor time divided by lifetime, which for a process a few
# milliseconds old is the quotient of two quantised near-zero numbers and takes
# arbitrary values. Measuring over a window removes that artefact entirely.
#
# One busy window proves little: the rebuild of a website, a language server
# that starts, a task of an agent each keep several cores busy for a few
# minutes. A process is therefore reported only once it has been busy at every
# pass for CPU_PERSIST seconds, and only if its average over that time exceeds
# the threshold too, which a process busy at the moments of measurement alone
# would not achieve.
CPU_THRESHOLD="${WATCHDOG_CPU_THRESHOLD:-150}"
CPU_MIN_AGE="${WATCHDOG_CPU_MIN_AGE:-60}"
CPU_WINDOW="${WATCHDOG_CPU_WINDOW:-15}"
CPU_PERSIST="${WATCHDOG_CPU_PERSIST:-900}"
CPU_STATE="$STATE_DIR/.watchdog-cpu"

NO_MAIL=0
CPU_ONLY=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --no-mail)  NO_MAIL=1 ;;
        --cpu-only) CPU_ONLY=1 ;;
        --verbose|-v) VERBOSE=1 ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# \?//'
            echo "Options: --no-mail  --cpu-only  --verbose"
            exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

ALERT=0
ALERTS=""
KEYS=""

# Records one finding. The first argument is what the reader sees; the second is
# a stable key naming the *kind* of finding, free of process identifiers and
# other per-run noise. The rate limiter fingerprints the keys, so a condition
# that persists across runs is recognised as one condition and mailed once an
# hour, instead of looking new every time its process identifier changes.
log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: ${1//$'\n'/ | }" >> "$LOG"
    ALERTS="${ALERTS}\n  - $1"
    KEYS="${KEYS}|$2"
    ALERT=1
}

# Processor time consumed so far by a process, in clock ticks, and the moment
# it started, in clock ticks after boot: "<ticks> <start>". Fields 14 and 15 of
# /proc/PID/stat are utime and stime, field 22 is starttime; the command name
# held in field 2 may contain spaces and parentheses, so everything up to the
# final ") " is dropped and the remainder counted from field 3.
cpu_stat() {
    local stat rest
    [ -r "/proc/$1/stat" ] || return 1
    stat=$(< "/proc/$1/stat") || return 1
    rest=${stat##*') '}
    printf '%s' "$rest" | awk '{print $12 + $13, $20}'
}

# "40 s", "17 min".
duration_phrase() {
    if [ "$1" -lt 120 ]; then printf '%s s' "$1"; else printf '%s min' $(( ($1 + 30) / 60 )); fi
}

# A busy process whose streak is still too short to report: one line in the log,
# and on the terminal with --verbose, but no alert and therefore no mail.
log_watch() {
    local line
    line="CPU watch: $(ps -o comm= -p "$1" 2>/dev/null) (pid $1) at $2% of one core over ${CPU_WINDOW}s, above ${CPU_THRESHOLD}% for $3 s of the ${CPU_PERSIST} s that raise an alert"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$LOG"
    [ "$VERBOSE" -eq 1 ] && echo "$line"
    return 0
}

# 1. Processes burning the processor, measured honestly over a window, and
# reported only when the load lasts.
#
# The streaks are kept in CPU_STATE: a first line "boot <boot id>", then one
# line "<pid> <start> <since> <since_ticks>" for each process found busy at the
# previous pass, where since is the epoch at which its streak began and
# since_ticks its processor time at that moment. The pid and the start time
# together name one process even when its number is reused, and the boot id
# voids every streak after a reboot. A pass that finds the process below the
# threshold drops its line, so that the count starts over.
check_high_cpu() {
    local clk_tck own_pgid boot pid start_t since since_t before_t after_t after_s
    local delta rate win_start now held avg key tmp
    local -A before start prev
    local -a streaks=()
    clk_tck=$(getconf CLK_TCK 2>/dev/null) || clk_tck=100
    own_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
    boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)

    if [ -r "$CPU_STATE" ] && [ "$(head -n 1 "$CPU_STATE")" = "boot $boot" ]; then
        while read -r pid start_t since since_t; do
            [ -n "$since_t" ] && prev["$pid $start_t"]="$since $since_t"
        done < <(tail -n +2 "$CPU_STATE")
    fi

    # Candidates: old enough to be real, and outside this script's own process
    # group, so that nothing can escape the check by choosing a command name.
    while read -r pid; do
        [ -n "$pid" ] || continue
        read -r before_t start_t < <(cpu_stat "$pid") || continue
        [ -n "$start_t" ] || continue
        before["$pid"]=$before_t
        start["$pid"]=$start_t
    done < <(ps -u "$WATCH_USER" -o pid=,pgid=,etimes= 2>/dev/null |
             awk -v age="$CPU_MIN_AGE" -v pg="$own_pgid" -v self="$$" \
                 '$3 >= age && $2 != pg && $1 != self {print $1}')

    if [ ${#before[@]} -gt 0 ]; then
        win_start=$(date +%s)
        sleep "$CPU_WINDOW"
        now=$(date +%s)

        for pid in "${!before[@]}"; do
            read -r after_t after_s < <(cpu_stat "$pid") || continue   # died during the window
            [ "$after_s" = "${start[$pid]}" ] || continue               # its number was reused
            delta=$(( after_t - before[$pid] ))
            [ "$delta" -gt 0 ] || continue
            rate=$(awk -v d="$delta" -v t="$clk_tck" -v w="$CPU_WINDOW" \
                       'BEGIN { printf "%.0f", (d * 100) / (t * w) }')
            [ "$rate" -gt "$CPU_THRESHOLD" ] || continue

            key="$pid ${start[$pid]}"
            if [ -n "${prev[$key]:-}" ]; then
                read -r since since_t <<< "${prev[$key]}"
            else
                since=$win_start
                since_t=${before[$pid]}
            fi
            streaks+=("$key $since $since_t")
            held=$(( now - since ))
            [ "$held" -gt 0 ] || held=1
            avg=$(awk -v d="$(( after_t - since_t ))" -v t="$clk_tck" -v s="$held" \
                      'BEGIN { printf "%.0f", (d * 100) / (t * s) }')
            if [ "$held" -ge "$CPU_PERSIST" ] && [ "$avg" -gt "$CPU_THRESHOLD" ]; then
                log_alert "$(describe_process "$pid" "$rate" "$avg" "$held")" \
                          "high-cpu:$(ps -o comm= -p "$pid" 2>/dev/null)"
            else
                log_watch "$pid" "$rate" "$held"
            fi
        done
    fi

    # --cpu-only only looks: the streaks are those of the passes made by cron,
    # and a test with other thresholds must not disturb them.
    [ "$CPU_ONLY" -eq 1 ] && return 0
    tmp=$(mktemp "$CPU_STATE.XXXXXX" 2>/dev/null) || return 0
    if {
        printf 'boot %s\n' "$boot"
        for key in "${streaks[@]}"; do printf '%s\n' "$key"; done
    } > "$tmp" && mv -f "$tmp" "$CPU_STATE"; then
        return 0
    fi
    rm -f "$tmp"
    return 0
}

# A description a reader can judge without opening a session on the server.
describe_process() {
    local pid=$1 rate=$2 avg=$3 held=$4 comm user ppid pcomm started cputime cmd
    comm=$(ps -o comm= -p "$pid" 2>/dev/null)
    user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null)
    started=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^ *//')
    cputime=$(ps -o time= -p "$pid" 2>/dev/null | tr -d ' ')
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-300)
    [ -n "$cmd" ] || cmd="[$comm]"
    printf 'High CPU: %s has stayed above %s%% of one core for %s, %s%% on average, %s%% over the last %ss\n' \
           "$comm" "$CPU_THRESHOLD" "$(duration_phrase "$held")" "$avg" "$rate" "$CPU_WINDOW"
    printf '      process %s, owner %s, started %s, CPU time so far %s\n' \
           "$pid" "$user" "$started" "$cputime"
    printf '      parent %s (%s)\n      command: %s' "$ppid" "$pcomm" "$cmd"
}

check_high_cpu

if [ "$CPU_ONLY" -eq 1 ]; then
    if [ "$ALERT" -eq 1 ]; then printf 'HIT%b\n' "$ALERTS"; else echo "clean"; fi
    exit 0
fi

# 2. Hidden executables of any size in the home directory.
SUSPICIOUS_BINS=$(find "$WATCH_HOME" -maxdepth 1 -name '.*' -type f -executable -size +100k 2>/dev/null)
if [ -n "$SUSPICIOUS_BINS" ]; then
    log_alert "Suspicious hidden executables in home: $SUSPICIOUS_BINS" "hidden-exec:$SUSPICIOUS_BINS"
fi

# 3. Random-named directories in the home directory, a common malware pattern.
RANDOM_DIRS=$(find "$WATCH_HOME" -maxdepth 1 -type d -regextype posix-extended -regex '.*/[a-z]{8}$' ! -name 'anaconda3' ! -name 'miniconda3' ! -name 'obsidian' ! -name 'products' ! -name 'Documents' ! -name 'snap' ! -name 'tools' ! -name 'utils' ! -name 'logs' 2>/dev/null)
if [ -n "$RANDOM_DIRS" ]; then
    log_alert "Suspicious random-named directories: $RANDOM_DIRS" "random-dir:$RANDOM_DIRS"
fi

# A program: an ELF binary, or a script opening with "#!". A file that cannot be
# read cannot be cleared either, so it counts as one.
is_program() {
    local magic
    [ -r "$1" ] || return 0
    magic=$(head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || [ "${magic:0:4}" = 2321 ]
}

# 4. Executables dropped in the temporary directories. The execute bit is read
# from the permissions: find -executable asks the kernel whether the file may
# run, which a noexec mount always refuses, so that nothing there would be seen.
# Chromium unpacks the components it downloads (model manifests, a speech
# engine) into folders of its own, org.chromium.Chromium.scoped_dir.XXXXXX, and
# leaves the execute bit on their data files; Node's compile cache is treated
# alike. Inside those folders only a program is reported, so that their names,
# which anyone can read here, cannot shelter one.
TMP_EXECS=$(find "${TMP_DIRS[@]}" -user "$WATCH_USER" -type f -perm -u+x 2>/dev/null |
    while IFS= read -r f; do
        case "$f" in
            */org.chromium.Chromium.scoped_dir.*/*|*/node-compile-cache/*)
                is_program "$f" || continue ;;
        esac
        printf '%s\n' "$f"
    done | head -5)
if [ -n "$TMP_EXECS" ]; then
    log_alert "Executable files in tmp: $TMP_EXECS" "tmp-exec:$TMP_EXECS"
fi

# 5. Processes carrying a known miner or backdoor name.
SUSPICIOUS_PROCS=$(ps -u "$WATCH_USER" -o pid,comm --no-headers | grep -iE '\batd\b|xmrig|miner|kworker|kthread|npm-clis|gsocket' | grep -v grep)
if [ -n "$SUSPICIOUS_PROCS" ]; then
    log_alert "Suspicious process names: $SUSPICIOUS_PROCS" "bad-procname:$(echo "$SUSPICIOUS_PROCS" | awk '{print $2}' | sort -u | tr '\n' ',')"
fi

# 6. Crontab entries that fetch or decode something.
CRON_CHECK=$(crontab -l 2>/dev/null | grep -ivE 'security-watchdog' | grep -iE 'base64|miner|xmr|guard|/tmp/|/var/tmp/|hashvault|monero|pool\.')
if [ -n "$CRON_CHECK" ]; then
    log_alert "Suspicious crontab entry: $CRON_CHECK" "bad-cron:$CRON_CHECK"
fi

# 7. Known malware signatures in the shell configuration.
if grep -qE 'npm-clis-kernel|base64 -d\s*\|\s*bash|node_monitor_agent|moneroocean|SEED PRNG' \
        "$WATCH_HOME/.bashrc" "$WATCH_HOME/.profile" 2>/dev/null; then
    log_alert "Shell config tampering detected!" "shell-tamper"
fi

# 8. Outbound connections to a mining pool.
MINING_CONNS=$(ss -tnp 2>/dev/null | grep -iE 'hashvault|moneroocean|nanopool|minexmr|supportxmr|pool\.' | head -3)
if [ -n "$MINING_CONNS" ]; then
    log_alert "Connection to mining pool detected: $MINING_CONNS" "mining-pool"
fi

# 9. The shell startup files: writable by anyone, or changed since the last run.
# These run on every login, so they are the cheapest place to plant something
# that survives a reboot.
SHELL_FILES=$(find "$WATCH_HOME" -maxdepth 1 -type f \
    \( -name '.bashrc*' -o -name '.bash_profile' -o -name '.bash_login' \
       -o -name '.profile' -o -name '.zshrc' -o -name '.zprofile' \
       -o -name '.condarc' -o -name '.bash_logout' \) 2>/dev/null | sort)

# Only "writable by others" is reported. Under a umask of 002 the group bit is set
# on almost everything, and a single-member group makes it harmless.
LOOSE_PERMS=$(printf '%s\n' "$SHELL_FILES" | while read -r f; do
    [ -n "$f" ] && find "$f" -maxdepth 0 -perm /002 2>/dev/null
done)
if [ -n "$LOOSE_PERMS" ]; then
    log_alert "Shell startup files writable by others: $(echo "$LOOSE_PERMS" | tr '\n' ' ')" "shellfile-perms"
fi

SUM_FILE="$STATE_DIR/.watchdog-shellfiles"
CURRENT_SUM=$(printf '%s\n' "$SHELL_FILES" | while read -r f; do
    [ -n "$f" ] && [ -r "$f" ] && md5sum "$f"
done)
if [ -f "$SUM_FILE" ]; then
    CHANGED=$(diff <(cat "$SUM_FILE") <(printf '%s\n' "$CURRENT_SUM") 2>/dev/null |
              grep '^[<>]' | awk '{print $3}' | sort -u | tr '\n' ' ')
    if [ -n "$CHANGED" ]; then
        log_alert "Shell startup files changed since the last check: $CHANGED" "shellfile-changed"
        printf '%s\n' "$CURRENT_SUM" > "$SUM_FILE"   # report the change once
    fi
else
    printf '%s\n' "$CURRENT_SUM" > "$SUM_FILE"
fi

if [ "$ALERT" -eq 1 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] === ALERTS FOUND ===" >> "$LOG"

    # The findings go in as an argument, never into the format: a "%" in them,
    # as in "150% of one core", would be read as a conversion and garble the file.
    printf '!!! SECURITY ALERT - %s !!!\n\nThe following issues were detected:\n%b\n\nCheck full log: %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$ALERTS" "$LOG" > "$ALERT_FILE"

    # Email through the SMTP account of vpsmonitor, so that a compromise at 03:00
    # is not discovered only at the next login. Rate-limited to one message per
    # hour per distinct set of findings.
    MONITOR="$MONITOR_DIR/venv/bin/python $MONITOR_DIR/monitor.py"
    FINGERPRINT=$(printf '%s' "$KEYS" | md5sum | cut -c1-12)
    STAMP_FILE="$STATE_DIR/.watchdog-notified-${FINGERPRINT}"
    if [ "$NO_MAIL" -eq 1 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Mail suppressed (--no-mail), fingerprint $FINGERPRINT" >> "$LOG"
    elif [ ! -f "$STAMP_FILE" ] || [ "$(find "$STAMP_FILE" -mmin +60 2>/dev/null)" ]; then
        if [ -x "$MONITOR_DIR/venv/bin/python" ]; then
            printf "Security watchdog on %s detected:\n%b\n\nFull log: %s\n" \
                "$(hostname)" "$ALERTS" "$LOG" > "$ALERT_FILE.mail"
            $MONITOR --notify "[SECURITY] Watchdog alert on $(hostname)" \
                     --body-file "$ALERT_FILE.mail" >/dev/null 2>&1 \
                && touch "$STAMP_FILE" \
                && echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alert emailed" >> "$LOG"
            rm -f "$ALERT_FILE.mail"
        fi
    fi

    # Forget stamps for conditions that have cleared.
    find "$STATE_DIR" -name '.watchdog-notified-*' -mmin +1440 -delete 2>/dev/null

    [ "$VERBOSE" -eq 1 ] && printf 'ALERTS:%b\n' "$ALERTS"
else
    rm -f "$ALERT_FILE"

    # A clean status is worth one line an hour, not one line every five minutes.
    if [ "$(date +%M)" -lt 5 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] OK: All checks passed" >> "$LOG"
    fi
    [ "$VERBOSE" -eq 1 ] && echo "OK: all checks passed"
fi

exit 0
