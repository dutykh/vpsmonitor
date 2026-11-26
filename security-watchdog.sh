#!/bin/bash
#
# Security Watchdog - detects crypto-miner and backdoor activity on a Linux
# server, and reports it by email through the alert channel of monitor.py.
#
# Runs from cron every five minutes:
#   */5 * * * * /path/to/vpsmonitor/security-watchdog.sh
#
# Author: Dr. Denys Dutykh (Khalifa University of Science and Technology,
#         Abu Dhabi, UAE)
# License: GPL-3.0
#

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
            echo "Settings: the WATCHDOG_* variables, from the environment or from the .env of the monitor"
            exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Everything this script writes (its log, its state, the alert, the lock) says
# what was found on this account, and is readable by the account alone.
umask 077

# This script by its resolved path, and the folder of the monitor it mails
# through: the folder of the script itself, unless WATCHDOG_MONITOR_DIR names
# another one.
SELF=$(readlink -f -- "$0" 2>/dev/null)
[ -n "$SELF" ] || SELF=$0
SCRIPT_DIR=${SELF%/*}
[ "$SCRIPT_DIR" != "$SELF" ] || SCRIPT_DIR=.
MONITOR_DIR="${WATCHDOG_MONITOR_DIR:-${SCRIPT_DIR:-/}}"

# Settings that the environment leaves unset may come from the .env of the
# monitor, so that a server keeps its own (the folders it ignores, say) out of
# its crontab and out of this public repository. The file is read line by line
# and never run: only WATCHDOG_* names are taken, nothing in a value is expanded
# but a leading ~/ or $HOME/, and the environment wins over the file.
load_env_file() {
    local line key value
    [ -r "$1" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(export[[:space:]]+)?(WATCHDOG_[A-Z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        key=${BASH_REMATCH[2]}
        value=${BASH_REMATCH[3]}
        [ "$key" != WATCHDOG_MONITOR_DIR ] || continue   # it has located this very file
        [ -z "${!key+set}" ] || continue                  # the environment wins
        case $value in
            \"*) value=${value#\"}; value=${value%%\"*} ;;
            \'*) value=${value#\'}; value=${value%%\'*} ;;
            *)   value=${value%%[[:space:]]#*}
                 value=${value%"${value##*[![:space:]]}"} ;;
        esac
        # shellcheck disable=SC2088,SC2016  # the text "~/" or "$HOME/" itself
        case $value in
            '~/'*|'$HOME/'*|'${HOME}/'*) value="$HOME/${value#*/}" ;;
        esac
        printf -v "$key" '%s' "$value"
    done < "$1"
}
load_env_file "$MONITOR_DIR/.env"

WATCH_USER="${WATCHDOG_USER:-$(id -un)}"
WATCH_HOME="${WATCHDOG_HOME:-$HOME}"
LOG="${WATCHDOG_LOG:-$WATCH_HOME/logs/security-watchdog.log}"
ALERT_FILE="${WATCHDOG_ALERT_FILE:-$WATCH_HOME/logs/SECURITY_ALERT}"
STATE_DIR="$(dirname "$ALERT_FILE")"
read -ra TMP_DIRS <<< "${WATCHDOG_TMP_DIRS:-/tmp /var/tmp /dev/shm}"
read -ra IGNORE_DIRS <<< "${WATCHDOG_IGNORE_DIRS:-}"
IGNORE_DIRS=("${IGNORE_DIRS[@]%/}")

# Stratum ports of the large mining pools. The ports of ordinary services (80,
# 443, 8080, 8443, 9000, 8888, a second SSH on 2222, Netdata's 19999) are left
# out, so that an ordinary server stays quiet.
read -ra POOL_PORTS <<< "${WATCHDOG_POOL_PORTS:-3333 4444 5555 7777 10128 13333 14433 14444 15555 17777 20128 45700}"

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

# Seconds the monitor may take to deliver a mail, below the five minutes
# between two passes.
MAIL_TIMEOUT=270

# The log and the state live in folders private to the account, made here when
# they are missing. Without them nothing could be recorded, compared or mailed,
# so a folder that cannot be made stops the run at once.
for dir in "$(dirname "$LOG")" "$STATE_DIR"; do
    # shellcheck disable=SC2174  # the umask makes the folders made on the way private too
    if ! (umask 077 && mkdir -p -m 700 -- "$dir") 2>/dev/null || [ ! -w "$dir" ]; then
        echo "security-watchdog: cannot create or write the folder $dir" >&2
        exit 1
    fi
done

ALERT=0
ALERTS=""
KEYS=()

log_line() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# Writes its standard input to the file $1 through a temporary file in the same
# folder, so that no reader ever meets the file half written.
write_atomic() {
    local tmp
    tmp=$(mktemp "$1.XXXXXX" 2>/dev/null) || return 1
    if cat > "$tmp" && mv -f "$tmp" "$1"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# Records one finding. The first argument is what the reader sees; the second is
# a stable key naming the *kind* of finding, free of paths, process identifiers
# and other per-run noise. The rate limiter fingerprints the sorted keys, so a
# condition that persists across runs is recognised as one condition and mailed
# once an hour, instead of looking new every time its process identifier or the
# name of a dropped file changes. The findings are kept with real line breaks
# and always printed through %s: a backslash in them, as in a file named
# "a\cb", is then text and never an escape that could cut the report short.
log_alert() {
    log_line "ALERT: ${1//$'\n'/ | }"
    ALERTS="${ALERTS}"$'\n'"  - $1"
    KEYS+=("$2")
    ALERT=1
}

# One pass at a time. A pass overlapping a slow one (a mail server that takes
# its time, a crowded temporary folder) would mail the same findings twice and
# could read a baseline while the other rewrites it, so it stops at once, and
# quietly. Status 1 is how flock says that the lock is held; any other failure
# (a file system without locks) leaves the pass to run without one rather than
# stop every pass for good. --cpu-only writes no state and is left free.
if [ "$CPU_ONLY" -eq 0 ] && have flock && exec 9>> "$STATE_DIR/.watchdog.lock"; then
    flock -n 9
    lock_status=$?
    if [ "$lock_status" -eq 1 ]; then
        [ "$VERBOSE" -eq 1 ] && echo "Another pass is running; this one stops."
        exit 0
    elif [ "$lock_status" -ne 0 ]; then
        log_line "The lock could not be taken (flock exit $lock_status); this pass runs without it"
    fi
fi

# The commands the checks need. A check runs only when what it needs is there,
# and the log names what is missing, when that changes and then once an hour.
MISSING=()
PS_OK=0
if ps -u "$(id -un)" -o pid=,pgid=,etimes= >/dev/null 2>&1; then
    PS_OK=1
else
    MISSING+=("ps from procps (busy processes, process names)")
fi
have awk     || MISSING+=("awk (busy processes, startup files)")
have find    || MISSING+=("find (files in the home and temporary folders, startup files)")
have md5sum  || MISSING+=("md5sum (changes of the startup files)")
have crontab || MISSING+=("crontab (crontab entries)")
have grep    || MISSING+=("grep (malware signatures in the shell configuration)")
have ss      || MISSING+=("ss from iproute2 (connections to mining pools)")
have flock   || MISSING+=("flock (protection against overlapping runs)")
have timeout || MISSING+=("timeout (a time limit on the mail)")
MISSING_FILE="$STATE_DIR/.watchdog-missing"
if [ ${#MISSING[@]} -gt 0 ]; then
    MISSING_LINE="Missing commands, the checks that need them are skipped: $(printf '%s; ' "${MISSING[@]}")"
    MISSING_LINE=${MISSING_LINE%; }
    [ "$VERBOSE" -eq 1 ] && echo "$MISSING_LINE"
    if [ "$CPU_ONLY" -eq 0 ] &&
       { [ "$(cat "$MISSING_FILE" 2>/dev/null)" != "$MISSING_LINE" ] || [ "$(date +%M)" -lt 5 ]; }; then
        log_line "$MISSING_LINE"
        printf '%s\n' "$MISSING_LINE" | write_atomic "$MISSING_FILE"
    fi
elif [ "$CPU_ONLY" -eq 0 ]; then
    rm -f "$MISSING_FILE"
fi

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

if [ "$PS_OK" -eq 1 ] && have awk; then
    check_high_cpu
fi

if [ "$CPU_ONLY" -eq 1 ]; then
    if [ "$ALERT" -eq 1 ]; then printf 'HIT%s\n' "$ALERTS"; else echo "clean"; fi
    exit 0
fi

# 2. Hidden executables over 100 KiB directly in the home directory: binaries,
# rather than the small executable scripts that some setups keep there.
if have find; then
    SUSPICIOUS_BINS=$(find "$WATCH_HOME" -maxdepth 1 -name '.*' -type f -executable -size +100k 2>/dev/null)
    if [ -n "$SUSPICIOUS_BINS" ]; then
        log_alert "Suspicious hidden executables in home: $SUSPICIOUS_BINS" "hidden-exec"
    fi
fi

# 3. Random-named directories in the home directory, a common malware pattern:
# eight lowercase letters. Common names of that shape are passed over, and so
# are the names listed in WATCHDOG_IGNORE_DIRS, for the folders of one's own.
COMMON_DIRS=(anaconda archives articles database datasets dotfiles download
             examples homework lectures notebook packages personal programs
             projects research software students teaching websites workshop)
if have find; then
    RANDOM_DIRS=$(find "$WATCH_HOME" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | LC_ALL=C sort |
        while IFS= read -r d; do
            name=${d##*/}
            [[ $name =~ ^[a-z]{8}$ ]] || continue
            case " ${COMMON_DIRS[*]} ${IGNORE_DIRS[*]} " in *" $name "*) continue ;; esac
            printf '%s\n' "$d"
        done)
    if [ -n "$RANDOM_DIRS" ]; then
        log_alert "Suspicious random-named directories: $RANDOM_DIRS" "random-dir"
    fi
fi

# A program: an ELF binary, or a script opening with "#!". A file that cannot be
# read cannot be cleared either, so it counts as one, and so does every file
# when od is missing.
is_program() {
    local magic
    [ -r "$1" ] || return 0
    have od || return 0
    magic=$(head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$magic" = 7f454c46 ] || [ "${magic:0:4}" = 2321 ]
}

# 4. Executables dropped in the temporary directories. The execute bit is read
# from the permissions: find -executable asks the kernel whether the file may
# run, which a noexec mount always refuses, so that nothing there would be seen.
# Chromium unpacks the components it downloads (model manifests, a speech
# engine) into folders of its own, org.chromium.Chromium.scoped_dir.XXXXXX, and
# leaves the execute bit on their data files; Node's compile cache is treated
# alike, and so is /dev/shm, where some programs (MATLAB's service host among
# them) create their shared memory with the execute bit. Inside those folders
# only a program is reported, so that their names, which anyone can read here,
# cannot shelter one.
if have find; then
    TMP_EXECS=$(find "${TMP_DIRS[@]}" -user "$WATCH_USER" -type f -perm -u+x 2>/dev/null |
        while IFS= read -r f; do
            case "$f" in
                /dev/shm/*|*/org.chromium.Chromium.scoped_dir.*/*|*/node-compile-cache/*)
                    is_program "$f" || continue ;;
            esac
            printf '%s\n' "$f"
        done | head -5)
    if [ -n "$TMP_EXECS" ]; then
        log_alert "Executable files in tmp: $TMP_EXECS" "tmp-exec"
    fi
fi

# 5. Processes carrying a known miner or backdoor name. The patterns hold the
# whole command name (in lower case), so that an indexer such as GNOME's
# tracker-miner-fs is not taken for a miner: atd, kworker or kthread posing as
# a kernel thread under this account, xmrig and its kin, and names ending in
# "miner" or "minerd", with a suffix such as "-multi" allowed.
BAD_NAME_RE='^[[]?atd[]]?$|^[[]?kworker|^[[]?kthread|^xmr|xmrig|^[[:alnum:]]*miner(d|-[[:alnum:]]+)?$|npm-clis|gsocket|kdevtmpfsi|kinsing'
is_bad_name() {
    [[ ${1,,} =~ $BAD_NAME_RE ]]
}
if [ "$PS_OK" -eq 1 ]; then
    SUSPICIOUS_PROCS=$(ps -u "$WATCH_USER" -o pid=,comm= 2>/dev/null |
        while IFS= read -r line; do
            read -r _ comm <<< "$line"
            is_bad_name "$comm" && printf '%s\n' "$line"
        done)
    if [ -n "$SUSPICIOUS_PROCS" ]; then
        log_alert "Suspicious process names: $SUSPICIOUS_PROCS" \
                  "bad-procname:$(printf '%s\n' "$SUSPICIOUS_PROCS" | awk '{print $2}' | LC_ALL=C sort -u | tr '\n' ',')"
    fi
fi

# 6. Crontab entries that fetch or decode something, or run it from a
# temporary folder. Comment lines are passed over, and so is the line that runs
# this script, recognised by its resolved path, as long as nothing is chained to
# it. A temporary folder counts only where something is run from it, not where
# output is written to it.
Q="[\"']"
CRON_NAMES_RE='base64|xmr|hashvault|monero|nanopool|c3pool|2miners|herominers|unmineable|nicehash|minergate|f2pool|stratum[+](tcp|ssl|tls)://|(^|[^[:alnum:]_])(miner|minerd|cpuminer|guard)([^[:alnum:]_]|$)'
SHELL_SINK='[|][[:space:]]*(sudo[[:space:]]+)?((/usr)?(/local)?/bin/)?(ba|da|z|k|a|c|tc)?sh([[:space:]]+-[[:alnum:]-]*)*([[:space:]]+-s([[:space:]][^;&|)]*)?)?[[:space:]]*($|[;&|)])'
FETCH_RE="(^|[^[:alnum:]_.-])(curl|wget)([[:space:]][^;&]*)?${SHELL_SINK}"
DECODE_RE="(^|[^[:alnum:]_.-])(base64|base32|xxd|openssl)([[:space:]][^;&]*)?${SHELL_SINK}"
SUBST_RE="(^|[^[:alnum:]_])((ba|da|z|k|a)?sh[[:space:]]+(-[[:alnum:]]+[[:space:]]+)*-c[[:space:]]+${Q}?|eval[[:space:]]+${Q}?)[\$][(](curl|wget)|(^|[^[:alnum:]_])((ba|da|z|k|a)?sh|source|[.])[[:space:]]+<[(](curl|wget)"
TCP_RE='/dev/(tcp|udp)/'
NET_INTERP_RE="(^|[^[:alnum:]_])(python[0-9.]*|perl)[[:space:]](.*[[:space:]])?-[[:alnum:]]*[ce]([[:space:]]|${Q}|\$)"
NET_MOD_RE='(^|[^[:alnum:]_])(socket|urllib[0-9]*|urlopen|requests|http[.]client|httplib[0-9]*|ftplib|telnetlib|paramiko)([^[:alnum:]_]|$)|io::socket|lwp::|http::tiny|net::'
TMP_PATH="${Q}?(/var/tmp|/tmp|/dev/shm)/"
CMD_START='(^|[;|&({`]|[$][(])[[:space:]]*'
CMD_PREFIX='(([[:alpha:]_][[:alnum:]_]*=[^[:space:]]*|exec|nohup|setsid|nice|ionice|sudo|env|time|timeout|command|(ba|da|z|k|a|c|tc)?sh|python[0-9.]*|perl|ruby|node|php|source|[.])([[:space:]]+-[^[:space:]]*)*([[:space:]]+[0-9]+[smhd]?)?[[:space:]]+)*'
EXEC_TMP_RE="${CMD_START}${CMD_PREFIX}${TMP_PATH}"
CD_TMP_RE="(^|[;|&({[:space:]])cd[[:space:]]+${Q}?(/var/tmp|/tmp|/dev/shm)([/\"'[:space:];&|)]|\$)"
DOT_EXEC_RE="${CMD_START}((ba|da|z|k|a|c|tc)?sh[[:space:]]+)?[.]/"
SHELL_ENV_RE="^[[:space:]]*shell[[:space:]]*=[[:space:]]*${TMP_PATH}"

# The command of a crontab line: what follows its five time fields or its
# @keyword.
cron_command() {
    local five='^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+(.*)$'
    if [[ $1 =~ ^[[:space:]]*@[[:alpha:]]+[[:space:]]+(.*)$ ]] || [[ $1 =~ $five ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

# Redirections that duplicate a descriptor ("2>&1", ">&2", "&>file"): their "&"
# chains nothing, so they are reduced to plain redirections.
plain_redirections() {
    printf '%s' "$1" | sed -E 's/[0-9]*>&[0-9-]//g; s/&>/>/g; s/>&/>/g'
}

# The line that runs this script: its command, after any VAR=value settings, is
# a path resolving to this script, followed by arguments and redirections only.
is_own_cron_line() {
    local cmd word rest path
    local assign="^[A-Za-z_][A-Za-z0-9_]*=(\"[^\"]*\"|'[^']*'|[^[:space:]]*)[[:space:]]+(.*)\$"
    cmd=$(cron_command "$1")
    while [[ $cmd =~ $assign ]]; do cmd=${BASH_REMATCH[2]}; done
    word=${cmd%%[[:space:]]*}
    rest=${cmd#"$word"}
    # shellcheck disable=SC2088,SC2016  # the text "~/" or "$HOME/" itself
    case $word in
        '~/'*|'$HOME/'*|'${HOME}/'*) word="$HOME/${word#*/}" ;;
    esac
    path=$(readlink -f -- "$word" 2>/dev/null)
    [ -n "$path" ] && [ "$path" = "$SELF" ] || return 1
    rest=$(plain_redirections "$rest")
    # shellcheck disable=SC2016  # the text "$(" itself
    case $rest in *';'*|*'|'*|*'&'*|*'`'*|*'$('*) return 1 ;; esac
    return 0
}

suspicious_cron_line() {
    local line=${1,,} cmd
    if [[ $line =~ $CRON_NAMES_RE || $line =~ $FETCH_RE || $line =~ $DECODE_RE ||
          $line =~ $SUBST_RE || $line =~ $TCP_RE || $line =~ $SHELL_ENV_RE ]]; then
        return 0
    fi
    if [[ $line =~ $NET_INTERP_RE && $line =~ $NET_MOD_RE ]]; then
        return 0
    fi
    cmd=$(plain_redirections "$(cron_command "$line")")
    [ -n "$cmd" ] || return 1
    [[ $cmd =~ $EXEC_TMP_RE ]] && return 0
    [[ $cmd =~ $CD_TMP_RE && $cmd =~ $DOT_EXEC_RE ]] && return 0
    return 1
}

if have crontab; then
    CRON_CHECK=$(crontab -l 2>/dev/null | while IFS= read -r line || [ -n "$line" ]; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        is_own_cron_line "$line" && continue
        suspicious_cron_line "$line" && printf '%s\n' "$line"
    done)
    if [ -n "$CRON_CHECK" ]; then
        log_alert "Suspicious crontab entry: $CRON_CHECK" "bad-cron"
    fi
fi

# 7. Known malware signatures in the shell configuration.
if have grep &&
   grep -qE 'npm-clis-kernel|base64 -d[[:space:]]*[|][[:space:]]*bash|node_monitor_agent|moneroocean|SEED PRNG' \
        "$WATCH_HOME/.bashrc" "$WATCH_HOME/.profile" 2>/dev/null; then
    log_alert "Shell config tampering detected!" "shell-tamper"
fi

# 8. Outbound connections to a mining pool. The addresses that ss prints are
# numeric, so a pool is recognised by its port: a connection counts when one of
# this account's processes opened it (ss names the process of a socket only for
# one's own) to a peer outside this machine on one of the ports of
# WATCHDOG_POOL_PORTS. A connection to a listening port of this machine is a
# visitor's, inbound, and its peer port is the visitor's own random one, so it
# never counts: on a busy web server some visitor would sooner or later come
# from a port of the list. A process with a miner's name counts whatever its
# peer, since a miner may reach its pool through a proxy on this machine.
USERS_NAME_RE='[(]"([^"]+)"'     # a process name in the column users:(("name",pid=...))
if have ss; then
    LISTEN_PORTS=" $(ss -tln 2>/dev/null | awk 'NR > 1 { n = split($4, a, ":"); print a[n] }' |
                     LC_ALL=C sort -u | tr '\n' ' ') "
    MINING_CONNS=$(ss -tnp state established 2>/dev/null |
        while IFS= read -r line; do
            read -r recvq _ local peer _ <<< "$line"
            [[ $recvq =~ ^[0-9]+$ ]] || continue           # the header
            port=${peer##*:}
            host=${peer%:*}; host=${host#[}; host=${host%]}
            hit=0
            case $host in
                127.*|::1|::ffff:127.*) ;;
                *) if [[ $line == *'users:(('* && $LISTEN_PORTS != *" ${local##*:} "* ]]; then
                       case " ${POOL_PORTS[*]} " in *" $port "*) hit=1 ;; esac
                   fi ;;
            esac
            rest=$line
            while [ "$hit" -eq 0 ] && [[ $rest =~ $USERS_NAME_RE ]]; do
                name=${BASH_REMATCH[1]}
                rest=${rest#*"${BASH_REMATCH[0]}"}   # before is_bad_name resets BASH_REMATCH
                is_bad_name "$name" && hit=1
            done
            [ "$hit" -eq 1 ] && printf '%s\n' "${line%"${line##*[![:space:]]}"}"
        done | head -3)
    if [ -n "$MINING_CONNS" ]; then
        log_alert "Connection to mining pool detected: $MINING_CONNS" "mining-pool"
    fi
fi

# 9. The shell startup files and the keys that open the account: writable by
# anyone, or changed since the last report. These run on every login, or let
# one in, so they are the cheapest place to plant something that survives a
# reboot. Symbolic links are followed, so that dotfiles kept in a repository
# and linked into the home directory are watched too.
STARTUP_NAMES=('.bashrc*' .bash_profile .bash_login .bash_logout .bash_aliases .profile
               .zshrc .zshenv .zprofile .condarc)
SSH_NAMES=(authorized_keys authorized_keys2)

# The watched files that exist.
startup_files() {
    local n home_args=() ssh_args=()
    for n in "${STARTUP_NAMES[@]}"; do home_args+=(-o -name "$n"); done
    for n in "${SSH_NAMES[@]}"; do ssh_args+=(-o -name "$n"); done
    find -L "$WATCH_HOME" -maxdepth 1 -type f \( "${home_args[@]:1}" \) 2>/dev/null
    find -L "$WATCH_HOME/.ssh" -maxdepth 1 -type f \( "${ssh_args[@]:1}" \) 2>/dev/null
}

if have find && have md5sum && have awk; then
    SHELL_FILES=$(startup_files | LC_ALL=C sort)

    # Only "writable by others" is reported. Under a umask of 002 the group bit is
    # set on almost everything, and a single-member group makes it harmless.
    LOOSE_PERMS=$(printf '%s\n' "$SHELL_FILES" | while IFS= read -r f; do
        [ -n "$f" ] && find -L "$f" -maxdepth 0 -perm -002 2>/dev/null
    done)
    if [ -n "$LOOSE_PERMS" ]; then
        log_alert "Shell startup files writable by others: $(printf '%s\n' "$LOOSE_PERMS" | tr '\n' ' ')" "shellfile-perms"
    fi

    # The baseline opens with a line naming the version of the watch list; a
    # baseline made for another list (or by an older version of this script) is
    # replaced silently, once, instead of reporting the files added to the watch
    # as changes. A change found is kept in PENDING_FILE and reported at every
    # pass until a mail has carried it, so that neither a failed mail, nor a
    # pass held back by the hourly limit, nor a run with --no-mail loses it.
    SUM_FILE="$STATE_DIR/.watchdog-shellfiles"
    PENDING_FILE="$STATE_DIR/.watchdog-shellfiles-pending"
    LIST_ID=$(printf '%s\n' 'symbolic links followed' "${STARTUP_NAMES[@]}" "${SSH_NAMES[@]/#/.ssh/}" |
              md5sum | cut -c1-12)
    CURRENT_SUM=$(printf '%s\n' "$SHELL_FILES" | while IFS= read -r f; do
        [ -n "$f" ] && [ -r "$f" ] && md5sum "$f"
    done)

    save_baseline() {
        { printf 'list %s\n' "$LIST_ID"; printf '%s\n' "$CURRENT_SUM"; } | write_atomic "$SUM_FILE"
    }

    # The files whose checksum line differs between the baseline and now:
    # changed, added or removed.
    changed_files() {
        printf '%s\n' "$CURRENT_SUM" |
            awk 'NR == FNR { if (FNR > 1 && $0 != "") old[$0] = 1; next }
                 $0 != "" { now[$0] = 1 }
                 END { for (l in old) if (!(l in now)) print l
                       for (l in now) if (!(l in old)) print l }' "$SUM_FILE" - |
            sed -E 's/^\\?[0-9a-f]+  //' | LC_ALL=C sort -u
    }

    if [ -f "$SUM_FILE" ] && [ "$(head -n 1 "$SUM_FILE")" = "list $LIST_ID" ]; then
        CHANGED=$(changed_files)
        if [ -n "$CHANGED" ]; then
            { cat "$PENDING_FILE" 2>/dev/null; printf '%s\n' "$CHANGED"; } |
                LC_ALL=C sort -u | write_atomic "$PENDING_FILE"
            save_baseline
        fi
    else
        save_baseline
    fi

    SHELL_CHANGE_REPORTED=0
    if [ -s "$PENDING_FILE" ]; then
        PENDING=$(cat "$PENDING_FILE")
        PENDING_NAMES=""
        while IFS= read -r f; do
            PENDING_NAMES="${PENDING_NAMES}${f#"$WATCH_HOME"/},"
        done <<< "$PENDING"
        log_alert "Shell startup files changed since the last check: $(printf '%s\n' "$PENDING" | tr '\n' ' ')" \
                  "shellfile-changed:$PENDING_NAMES"
        SHELL_CHANGE_REPORTED=1
    fi
fi

# Hands the findings to the monitor, which mails them, and records how it went.
send_mail() {
    local body out status
    local -a timer=()
    if ! body=$(mktemp "$STATE_DIR/.watchdog-mail.XXXXXX" 2>/dev/null); then
        log_line "Mail not sent: no temporary file could be made in $STATE_DIR for its text"
        return
    fi
    printf 'Security watchdog on %s detected:\n%s\n\nFull log: %s\n' "$HOST" "$ALERTS" "$LOG" > "$body"
    have timeout && timer=(timeout "$MAIL_TIMEOUT")
    out=$("${timer[@]}" "${MONITOR[@]}" --notify "[SECURITY] Watchdog alert on $HOST" \
                        --body-file "$body" 2>&1 9>&-)
    status=$?
    rm -f "$body"
    out=${out//$'\n'/ | }
    [ ${#out} -le 300 ] || out="...${out: -300}"
    case $status in
        0)   touch "$STAMP_FILE"
             log_line "Alert emailed"
             REPORTED=1 ;;
        1)   log_line "Mail not sent: the monitor could not deliver it (exit 1), next try at the next pass${out:+: $out}" ;;
        2)   log_line "Mail not sent: the configuration of the monitor is broken (exit 2)${out:+: $out}" ;;
        124) log_line "Mail not sent: the monitor did not finish within $MAIL_TIMEOUT s" ;;
        *)   log_line "Mail not sent: the monitor exited with status $status${out:+: $out}" ;;
    esac
}

if [ "$ALERT" -eq 1 ]; then
    log_line "=== ALERTS FOUND ==="

    # The findings go in as an argument, never into the format: a "%" in them,
    # as in "150% of one core", would be read as a conversion and garble the file.
    printf '!!! SECURITY ALERT - %s !!!\n\nThe following issues were detected:\n%s\n\nCheck full log: %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$ALERTS" "$LOG" | write_atomic "$ALERT_FILE"

    # Email through the SMTP account of vpsmonitor, so that a compromise at 03:00
    # is not discovered only at the next login. Rate-limited to one message per
    # hour per distinct set of findings.
    HOST=$(uname -n 2>/dev/null)
    MONITOR=("$MONITOR_DIR/venv/bin/python" "$MONITOR_DIR/monitor.py")
    FINGERPRINT=$(printf '%s\n' "${KEYS[@]}" | LC_ALL=C sort -u | md5sum | cut -c1-12)
    STAMP_FILE="$STATE_DIR/.watchdog-notified-${FINGERPRINT}"
    REPORTED=0      # 1 once the findings have gone as far as they can go
    if [ "$NO_MAIL" -eq 1 ]; then
        log_line "Mail suppressed (--no-mail), fingerprint $FINGERPRINT"
    elif [ -f "$STAMP_FILE" ] && [ -z "$(find "$STAMP_FILE" -mmin +60 2>/dev/null)" ]; then
        :   # the same findings were mailed less than an hour ago
    elif [ ! -x "${MONITOR[0]}" ] || [ ! -f "${MONITOR[1]}" ]; then
        # The log and the alert file are then all there is.
        log_line "Mail not sent: no monitor in $MONITOR_DIR (it needs venv/bin/python and monitor.py; WATCHDOG_MONITOR_DIR names another folder)"
        REPORTED=1
    else
        send_mail
    fi
    if [ "$REPORTED" -eq 1 ] && [ "${SHELL_CHANGE_REPORTED:-0}" -eq 1 ]; then
        rm -f "$PENDING_FILE"
    fi

    # Forget stamps for conditions that have cleared.
    find "$STATE_DIR" -maxdepth 1 -name '.watchdog-notified-*' -mmin +1440 -delete 2>/dev/null

    [ "$VERBOSE" -eq 1 ] && printf 'ALERTS:%s\n' "$ALERTS"
else
    rm -f "$ALERT_FILE"

    # A clean status is worth one line an hour, not one line every five minutes.
    if [ "$(date +%M)" -lt 5 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] OK: All checks passed" >> "$LOG"
    fi
    [ "$VERBOSE" -eq 1 ] && echo "OK: all checks passed"
fi

exit 0
