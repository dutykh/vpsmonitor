# Website Monitor

A production-ready website monitoring solution for Ubuntu servers that checks website availability and sends email alerts when issues are detected.

**Author:** Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)

## Features

- 🔍 Monitors multiple websites with configurable intervals
- 📧 Email alerts with detailed error information
- 🔄 Automatic retry logic with exponential backoff
- 🛡️ SSL certificate validation
- 📊 Response time tracking
- 🚦 Rate-limited alerts to prevent spam
- 📝 Comprehensive logging
- 🔐 Secure credential management

## Requirements

- Ubuntu 22.04 (or compatible Linux distribution)
- Python 3.8+
- Email account with SMTP access (Gmail, etc.)

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd vpsmonitor
   ```

2. Run the installation script:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. Configure your settings:
   ```bash
   cp .env.example .env
   nano .env  # Edit with your values
   ```

4. Test the monitor:
   ```bash
   ./venv/bin/python monitor.py
   ```

5. Set up automated monitoring with cron:
   ```bash
   crontab -e
   # Add: */5 * * * * cd /path/to/vpsmonitor && ./venv/bin/python monitor.py
   ```

## Configuration

All configuration is managed through the `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_SERVER` | SMTP server address | smtp.gmail.com |
| `SMTP_PORT` | SMTP server port | 587 |
| `SMTP_USERNAME` | Email username | Required |
| `SMTP_PASSWORD` | Email password/app password | Required |
| `ALERT_EMAIL` | Where to send alerts | Required |
| `WEBSITES` | Comma-separated URLs to monitor | Required |
| `CHECK_INTERVAL` | Seconds between checks | 300 |
| `TIMEOUT` | Request timeout in seconds | 30 |
| `ALERT_COOLDOWN` | Seconds between repeated alerts | 3600 |

## Email Setup

### Gmail
1. Enable 2-factor authentication
2. Generate an app-specific password: https://myaccount.google.com/apppasswords
3. Use your Gmail address as `SMTP_USERNAME`
4. Use the app password as `SMTP_PASSWORD`

## Monitoring Multiple Sites

Add comma-separated URLs to the `WEBSITES` variable:
```
WEBSITES=https://site1.com,https://site2.com,https://site3.com
```

## Logs

Logs are stored in the `logs/` directory:
- `monitor_YYYYMMDD.log` - Daily application logs
- `cron.log` - Cron execution logs
- `alert_history.json` - Alert rate limiting data

## Troubleshooting

### No alerts received
1. Check SMTP credentials in `.env`
2. Verify alert email address
3. Check logs for errors: `tail -f logs/monitor_*.log`
4. Test email manually: `./venv/bin/python -c "from monitor import *; monitor = WebsiteMonitor(); monitor.run_once()"`

### False positives
1. Increase `TIMEOUT` value
2. Check if website requires specific headers
3. Verify SSL certificates are valid

### High resource usage
1. Increase `CHECK_INTERVAL`
2. Reduce `MAX_RETRIES`
3. Check for memory leaks in logs

## Security

- Store `.env` with restricted permissions: `chmod 600 .env`
- Never commit `.env` to version control
- Use app-specific passwords for email
- Regularly update dependencies: `pip install --upgrade -r requirements.txt`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code passes linting
5. Submit a pull request

## License

GPL-3.0 License - See LICENSE file for details
