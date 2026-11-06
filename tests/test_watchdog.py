# Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and Technology, Abu Dhabi, UAE)
"""Security watchdog: executables in the temporary directories, and the
processor check.

Chromium and Node leave the execute bit on data files in folders of their own.
Inside those folders only a program is reported (an ELF binary, a script opening
with "#!", or a file the watchdog cannot read); anywhere else every executable
file is.

A program that keeps the processor busy is first only watched, and reported once
it has been busy at every pass for WATCHDOG_CPU_PERSIST seconds."""
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

WATCHDOG = Path(__file__).resolve().parent.parent / "security-watchdog.sh"
CHROMIUM = "org.chromium.Chromium.scoped_dir.yP64w2"
ELF = b"\x7fELF\x02\x01\x01\x00"
PROTOBUF = b"\x0a\x12\x08\x01"


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


def watchdog_output(tmp_root, **settings):
    """Run every check with the mail suppressed and return what it printed. Each
    keyword sets the variable WATCHDOG_<KEYWORD>. Unless told otherwise, no
    process is old enough for the processor check, so it does not wait."""
    scratch = tmp_root.parent
    home = scratch / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "WATCHDOG_TMP_DIRS": str(tmp_root),
        "WATCHDOG_HOME": str(home),
        "WATCHDOG_LOG": str(scratch / "watchdog.log"),
        "WATCHDOG_ALERT_FILE": str(scratch / "ALERT"),
        "WATCHDOG_CPU_MIN_AGE": "1000000000",
        **{f"WATCHDOG_{name.upper()}": str(value) for name, value in settings.items()},
    }
    done = subprocess.run(["bash", str(WATCHDOG), "--no-mail", "--verbose"], env=env,
                          capture_output=True, text=True, timeout=120, check=True)
    return done.stdout


@pytest.fixture
def busy():
    """A program that keeps one core busy, in a session of its own: the watchdog
    passes over its own process group, which it shares with the test runner."""
    proc = subprocess.Popen([sys.executable, "-c", "while True: pass"],
                            start_new_session=True)
    yield proc
    proc.kill()
    proc.wait()


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
