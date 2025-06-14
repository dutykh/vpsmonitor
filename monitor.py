#!/usr/bin/env python3
"""
Website Monitor - Production-ready monitoring solution
Monitors multiple websites and sends email alerts on failures

Author: Dr. Denys Dutykh (Khalifa University of Science and Technology, Abu Dhabi, UAE)
"""

import os
import sys
import time
import logging
import smtplib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import requests
from requests.exceptions import RequestException, SSLError, Timeout
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output"""
    
    grey = "\x1b[38;21m"
    green = "\x1b[32m"
    yellow = "\x1b[33m"
    red = "\x1b[31m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    
    FORMATS = {
        logging.DEBUG: grey + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.INFO: green + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.WARNING: yellow + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.ERROR: red + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset,
        logging.CRITICAL: bold_red + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + reset
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Set up logging configuration"""
    logger = logging.getLogger("website_monitor")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # File handler
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(
        log_dir / f"monitor_{datetime.now().strftime('%Y%m%d')}.log"
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

class Config:
    """Configuration handler for the monitoring script"""
    
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.alert_email = os.getenv("ALERT_EMAIL")
        
        websites_str = os.getenv("WEBSITES", "")
        self.websites = [url.strip() for url in websites_str.split(",") if url.strip()]
        
        self.check_interval = int(os.getenv("CHECK_INTERVAL", "300"))
        self.timeout = int(os.getenv("TIMEOUT", "30"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.alert_cooldown = int(os.getenv("ALERT_COOLDOWN", "3600"))
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        
        self.validate()
    
    def validate(self):
        """Validate configuration values"""
        if not self.smtp_username or not self.smtp_password:
            raise ValueError("SMTP credentials not configured")
        
        if not self.alert_email:
            raise ValueError("Alert email not configured")
        
        if not self.websites:
            raise ValueError("No websites configured for monitoring")
        
        for url in self.websites:
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"Invalid URL: {url}")

class WebsiteChecker:
    """Handles website health checks"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Website-Monitor/1.0 (Ubuntu 22.04)'
        })
    
    def check_website(self, url: str) -> Tuple[bool, Dict]:
        """
        Check if a website is responding correctly
        Returns: (is_healthy, details)
        """
        attempt = 0
        last_error = None
        
        while attempt < self.config.max_retries:
            try:
                start_time = time.time()
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    verify=True,  # Verify SSL certificates
                    allow_redirects=True
                )
                response_time = round((time.time() - start_time) * 1000, 2)
                
                is_healthy = 200 <= response.status_code < 400
                
                return is_healthy, {
                    'status_code': response.status_code,
                    'response_time_ms': response_time,
                    'error': None,
                    'ssl_valid': True,
                    'timestamp': datetime.now().isoformat()
                }
                
            except SSLError as e:
                last_error = f"SSL Error: {str(e)}"
                self.logger.warning(f"SSL error for {url}: {e}")
                
            except Timeout:
                last_error = f"Timeout after {self.config.timeout} seconds"
                self.logger.warning(f"Timeout for {url}")
                
            except RequestException as e:
                last_error = f"Request failed: {str(e)}"
                self.logger.warning(f"Request error for {url}: {e}")
                
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                self.logger.error(f"Unexpected error for {url}: {e}")
            
            attempt += 1
            if attempt < self.config.max_retries:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return False, {
            'status_code': None,
            'response_time_ms': None,
            'error': last_error,
            'ssl_valid': 'SSL' not in last_error if last_error else None,
            'timestamp': datetime.now().isoformat()
        }

class EmailNotifier:
    """Handles email notifications"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.alert_history = {}
        self._load_alert_history()
    
    def _load_alert_history(self):
        """Load alert history from file"""
        history_file = Path("logs/alert_history.json")
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    self.alert_history = json.load(f)
            except Exception as e:
                self.logger.warning(f"Could not load alert history: {e}")
    
    def _save_alert_history(self):
        """Save alert history to file"""
        history_file = Path("logs/alert_history.json")
        try:
            with open(history_file, 'w') as f:
                json.dump(self.alert_history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Could not save alert history: {e}")
    
    def should_send_alert(self, url: str) -> bool:
        """Check if we should send an alert (rate limiting)"""
        if url not in self.alert_history:
            return True
        
        last_alert = datetime.fromisoformat(self.alert_history[url])
        cooldown_expires = last_alert + timedelta(seconds=self.config.alert_cooldown)
        
        return datetime.now() > cooldown_expires
    
    def send_alert(self, url: str, details: Dict) -> bool:
        """Send email alert for website issue"""
        if not self.should_send_alert(url):
            self.logger.info(f"Alert for {url} suppressed due to cooldown")
            return False
        
        try:
            msg = self._create_alert_message(url, details)
            
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                server.starttls()
                server.login(self.config.smtp_username, self.config.smtp_password)
                server.send_message(msg)
            
            self.alert_history[url] = datetime.now().isoformat()
            self._save_alert_history()
            
            self.logger.info(f"Alert sent for {url}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
            return False
    
    def _create_alert_message(self, url: str, details: Dict) -> MIMEMultipart:
        """Create formatted alert email"""
        msg = MIMEMultipart()
        msg['From'] = self.config.smtp_username
        msg['To'] = self.config.alert_email
        msg['Subject'] = f"[ALERT] Website Issue: {url}"
        
        body = f"""
Website Monitoring Alert
------------------------
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Website: {url}
Status: DOWN

Error Details:
- Error: {details.get('error', 'Unknown error')}
- HTTP Status: {details.get('status_code', 'N/A')}
- Response Time: {details.get('response_time_ms', 'N/A')} ms
- SSL Valid: {details.get('ssl_valid', 'Unknown')}

Recommended Actions:
1. Check if the website is accessible from your browser
2. Verify server status and logs
3. Check PM2 process status if applicable
4. Review recent deployments or changes

This is an automated alert from your website monitoring system.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        return msg

class WebsiteMonitor:
    """Main monitoring orchestrator"""
    
    def __init__(self):
        self.config = Config()
        self.logger = setup_logging(self.config.log_level)
        self.checker = WebsiteChecker(self.config, self.logger)
        self.notifier = EmailNotifier(self.config, self.logger)
        self.logger.info("Website Monitor initialized")
    
    def run_checks(self):
        """Run health checks for all configured websites"""
        self.logger.info(f"Running checks for {len(self.config.websites)} websites")
        
        for url in self.config.websites:
            is_healthy, details = self.checker.check_website(url)
            
            if is_healthy:
                self.logger.info(
                    f"✓ {url} - OK ({details['status_code']}, "
                    f"{details['response_time_ms']}ms)"
                )
            else:
                self.logger.error(
                    f"✗ {url} - FAILED: {details['error']}"
                )
                self.notifier.send_alert(url, details)
    
    def run_once(self):
        """Run a single check cycle"""
        try:
            self.run_checks()
        except Exception as e:
            self.logger.critical(f"Critical error during monitoring: {e}", exc_info=True)
    
    def run_continuous(self):
        """Run continuous monitoring"""
        self.logger.info(
            f"Starting continuous monitoring (interval: {self.config.check_interval}s)"
        )
        
        while True:
            try:
                self.run_checks()
                time.sleep(self.config.check_interval)
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.critical(f"Critical error: {e}", exc_info=True)
                time.sleep(60)  # Wait before retrying

def main():
    """Main entry point"""
    monitor = WebsiteMonitor()
    
    # Check if running from cron (single check) or continuous
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        monitor.run_once()
    else:
        # For cron, we typically want single execution
        monitor.run_once()

if __name__ == "__main__":
    main()