# Dr. Denys Dutykh (Mathematics Department, Khalifa University of Science and Technology, Abu Dhabi, UAE)
"""Security watchdog: executables in the temporary directories.

Chromium and Node leave the execute bit on data files in folders of their own.
Inside those folders only a program is reported (an ELF binary, a script opening
with "#!", or a file the watchdog cannot read); anywhere else every executable
file is."""
import os
import shutil
import subprocess
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


def watchdog_output(tmp_root):
    """Run every check with the mail suppressed and return what it printed. No
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
    }
    done = subprocess.run(["bash", str(WATCHDOG), "--no-mail", "--verbose"], env=env,
                          capture_output=True, text=True, timeout=60, check=True)
    return done.stdout


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
