#!/bin/bash
# install.sh - Installation script for Website Monitor
# Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)

echo "==================================="
echo "Website Monitor Installation Script"
echo "==================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "Error: Python 3.8+ is required. Found: $python_version"
    exit 1
fi

echo "✓ Python version: $python_version"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p logs

# Set up configuration
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    chmod 600 .env
    echo ""
    echo "⚠️  Please edit .env file with your configuration:"
    echo "   - SMTP credentials"
    echo "   - Alert email address"
    echo "   - Website URLs"
else
    echo "✓ .env file already exists"
fi

# Create cron entry
echo ""
echo "To set up automatic monitoring, add this to your crontab:"
echo "(Run 'crontab -e' to edit)"
echo ""
echo "# Website Monitor - runs every 5 minutes"
echo "*/5 * * * * cd $(pwd) && $(pwd)/venv/bin/python monitor.py >> logs/cron.log 2>&1"
echo ""

# Test configuration
echo "Testing configuration..."
source venv/bin/activate
python3 -c "from monitor import Config; Config()" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ Configuration valid"
else
    echo "✗ Configuration error - please check your .env file"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Test the monitor: ./venv/bin/python monitor.py"
echo "3. Add cron job for automatic monitoring"
echo ""