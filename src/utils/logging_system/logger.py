import logging
import logging.handlers
import os
import json
import sqlite3
from datetime import datetime, timedelta # Added timedelta here
from threading import Lock
from dataclasses import dataclass
from typing import Dict, Any, Optional
from enum import Enum

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class AlertSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class LogEntry:
    timestamp: datetime
    level: LogLevel
    component: str
    message: str
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class Alert:
    timestamp: datetime
    severity: AlertSeverity
    source_ip: str
    threat_type: str
    description: str
    confidence: float
    metadata: Optional[Dict[str, Any]] = None

class IDSLogger:
    """
    A comprehensive logging system for the IDS/IPS, supporting file, console, and database logging.
    """

    def __init__(self, config: dict = None):
        self.config = self.load_config(config)
        self.log_directory = self.config.get("log_directory", "./logs")
        self.log_level = getattr(logging, self.config.get("log_level", "INFO").upper())
        self.retention_days = self.config.get("retention_days", 30)
        self.db_path = os.path.join(self.log_directory, "ids_events.db")
        self.db_lock = Lock()

        # Ensure the log directory exists
        os.makedirs(self.log_directory, exist_ok=True)

        # Initialize self.logger here, before any handlers are added
        self.logger = logging.getLogger("IDS_IPS_Logger")
        self.logger.setLevel(self.log_level)
        # Prevent adding duplicate handlers if __init__ is called multiple times
        if not self.logger.handlers:
            self.setup_console_logging()
            self.setup_file_logging()
            self.setup_database_logging()

        self.clean_old_logs()

    def load_config(self, config: dict) -> dict:
        default_config = {
            "log_directory": "./logs",
            "log_level": "INFO",
            "retention_days": 30,
            "enable_console_logging": True,
            "enable_file_logging": True,
            "enable_database_logging": True,
            "enable_syslog": False,
            "syslog_address": ("localhost", 514)
        }
        if config:
            return {**default_config, **config}
        
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "log_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    file_config = json.load(f)
                return {**default_config, **file_config}
            except json.JSONDecodeError:
                self.log("WARNING", f"Invalid JSON in {config_path}. Using default config.")
        return default_config

    def setup_console_logging(self):
        if self.config.get("enable_console_logging", True):
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def setup_file_logging(self):
        if self.config.get("enable_file_logging", True):
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(self.log_directory, "ids_ips.log"),
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5,
            )
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            # Specific handler for alerts
            alert_handler = logging.handlers.RotatingFileHandler(
                os.path.join(self.log_directory, "alerts.log"),
                maxBytes=5*1024*1024,  # 5 MB
                backupCount=3,
            )
            alert_formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(threat_type)s - %(source_ip)s - %(message)s"
            )
            alert_handler.setFormatter(alert_formatter)
            alert_handler.setLevel(logging.WARNING) # Alerts are typically WARNING or higher
            self.logger.addHandler(alert_handler)

    def setup_database_logging(self):
        if self.config.get("enable_database_logging", True):
            # Database logging setup (ensure table exists)
            self.initialize_database()
            db_handler = DatabaseHandler(self.db_path, self.db_lock)
            db_handler.setLevel(self.log_level)
            self.logger.addHandler(db_handler)

    def initialize_database(self):
        with self.db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        name TEXT,
                        pathname TEXT,
                        lineno INTEGER,
                        funcname TEXT,
                        sinfo TEXT,
                        process INTEGER,
                        thread TEXT,
                        threat_type TEXT,
                        source_ip TEXT
                    )
                """)
                conn.commit()
            except sqlite3.Error as e:
                print(f"[ERROR] Database initialization failed: {e}")
            finally:
                if conn:
                    conn.close()

    def clean_old_logs(self):
        # Clean old file logs
        for log_file in ["ids_ips.log", "alerts.log"]:
            path = os.path.join(self.log_directory, log_file)
            if os.path.exists(path):
                # This is a simple check, RotatingFileHandler handles its own rotation
                # For older files (e.g., .log.1, .log.2), a more robust cleanup might be needed
                pass # Rely on RotatingFileHandler for now

        # Clean old database logs
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        with self.db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date.isoformat(),))
                conn.commit()
            except sqlite3.Error as e:
                self.log("ERROR", f"Failed to clean old database logs: {e}")
            finally:
                if conn:
                    conn.close()

    def log(self, level: str, message: str, **kwargs):
        extra = {
            "threat_type": kwargs.get("threat_type", "N/A"),
            "source_ip": kwargs.get("source_ip", "N/A"),
        }
        if level.upper() == "INFO":
            self.logger.info(message, extra=extra)
        elif level.upper() == "WARNING":
            self.logger.warning(message, extra=extra)
        elif level.upper() == "ERROR":
            self.logger.error(message, extra=extra)
        elif level.upper() == "CRITICAL":
            self.logger.critical(message, extra=extra)
        elif level.upper() == "DEBUG":
            self.logger.debug(message, extra=extra)

# Custom logging handler for SQLite
class DatabaseHandler(logging.Handler):
    def __init__(self, db_path, db_lock):
        super().__init__()
        self.db_path = db_path
        self.db_lock = db_lock

    def emit(self, record):
        with self.db_lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO logs (timestamp, level, message, name, pathname, lineno, funcname, sinfo, process, thread, threat_type, source_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.fromtimestamp(record.created).isoformat(),
                    record.levelname,
                    record.getMessage(),
                    record.name,  # Fixed: Added missing name field
                    record.pathname,
                    record.lineno,
                    record.funcName,
                    self.formatStack(record.stack_info) if record.stack_info else None,
                    record.process,
                    record.threadName,
                    getattr(record, "threat_type", "N/A"),
                    getattr(record, "source_ip", "N/A"),
                ),
                )
                conn.commit()
            except sqlite3.Error as e:
                # Log to console if database logging fails to avoid infinite recursion
                print(f"[ERROR] Failed to write log to database: {e}")
            finally:
                if conn:
                    conn.close()

