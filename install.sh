#!/usr/bin/env bash
# install.sh - Installation script for Website Monitor
# Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

DEV=0
[[ "${1:-}" == "--dev" ]] && DEV=1

echo "==================================="
echo "Website Monitor Installation"
echo "==================================="

# --- Python version -------------------------------------------------------
# 3.11+ is required for tomllib (used for the optional targets.toml).
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found on PATH." >&2
    exit 1
fi
python_version="$(python3 --version 2>&1 | awk '{print $2}')"
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Error: Python 3.11+ is required. Found: ${python_version}" >&2
    exit 1
fi
echo "✓ Python ${python_version}"

# --- Virtual environment --------------------------------------------------
if [[ ! -d venv ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
./venv/bin/pip install --quiet --upgrade pip
if [[ $DEV -eq 1 ]]; then
    echo "Installing runtime + development dependencies..."
    ./venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt
else
    # Production deliberately gets ONLY requests + python-dotenv (~17 MB).
    # Installing the dev tooling here costs about 90 MB for no runtime benefit.
    echo "Installing runtime dependencies..."
    ./venv/bin/pip install --quiet -r requirements.txt
fi
echo "✓ Dependencies installed"

mkdir -p logs data
chmod 700 data

# --- Configuration --------------------------------------------------------
if [[ ! -f .env ]]; then
    echo "Creating .env from template..."
    cp .env.example .env
    echo ""
    echo "⚠️  Edit .env before running: SMTP credentials, ALERT_EMAIL, WEBSITES"
else
    echo "✓ .env already exists"
fi
# Unconditional, not only on creation: an existing .env may predate this rule.
chmod 600 .env
echo "✓ .env permissions set to 600"

# --- Safety checks --------------------------------------------------------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git check-ignore -q .env; then
        echo "✗ DANGER: .env is NOT ignored by git. Fix .gitignore before committing." >&2
        exit 1
    fi
    echo "✓ .env is git-ignored"
    if [[ -f .githooks/pre-commit ]]; then
        git config core.hooksPath .githooks
        chmod +x .githooks/pre-commit
        echo "✓ Secret-scanning pre-commit hook enabled"
    fi
fi

# --- Verify ---------------------------------------------------------------
echo ""
echo "Validating configuration..."
# stderr is NOT discarded here; the previous version hid the actual reason.
if ./venv/bin/python -c 'import monitor; monitor.Config()'; then
    echo "✓ Configuration valid"
    ./venv/bin/python monitor.py --dry-run --quiet && echo "✓ Dry run succeeded"
else
    echo "✗ Configuration error (see the message above)" >&2
fi

# --- Scheduling -----------------------------------------------------------
cat <<EOF

Installation complete.

Next steps:
  1. Verify alerting:      ./venv/bin/python monitor.py --test-email
  2. See current state:    ./venv/bin/python monitor.py --status
  3. Schedule it (crontab -e):

     # Website monitor - checks every 5 minutes (safe: runs are lock-guarded)
     */5 * * * * cd ${HERE} && ${HERE}/venv/bin/python monitor.py >> ${HERE}/logs/cron.log 2>&1

     # Daily uptime summary at 08:00
     0 8 * * * cd ${HERE} && ${HERE}/venv/bin/python monitor.py --report daily >> ${HERE}/logs/cron.log 2>&1

  A systemd timer is also provided (see systemd/ and the README).
EOF
