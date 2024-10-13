import os
import time
import json
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import psutil
from datetime import datetime
from cryptography.fernet import Fernet
import paho.mqtt.client as mqtt
from pathlib import Path


class NVRHealthMonitor(win32serviceutil.ServiceFramework):
    """Service and file system monitor for network video recorder on Windows"""

    DEFAULT_CONFIG_JSON = """
    {
        "services": {},
        "mqtt": {
            "username": "default_user",
            "password": "default_password",
            "broker": "localhost",
            "port": 1883,
            "topic": "nvr/status"
        },
        "start_services": false,
        "service_start_wait": 20,
        "file_check_path": "D:/BlueIris/New",
        "interval_seconds": 120,
        "log_file": "nvr_health_monitor.log"
    }
    """
    status_messages = {
        "unknown_error": "Uknown error",
        "check_success": "OK",
        "service_not_running": "Service not running",
        "service_does_not_exist": "Service does not exist",
        "service_failed_start": "Service failed to start",
        "folder_does_not_exist": "Folder does not exist",
        "folder_is_empty": "No files found",
        "folder_is_stale": "Last modified {seconds} ago",
    }

    def __init__(self):
        if getattr(
            sys, "frozen", False
        ):  # Check if the script is compiled with PyInstaller
            self.bundle_dir = os.path.dirname(sys.executable)
        else:
            self.bundle_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file_path = os.path.join(self.bundle_dir, "config.json")
        self.load_config()
        self.setup_logging()
        self.setup_mqtt_client()

    def recursive_update(self, default, override):
        """Recursively update default dict with override dict."""
        for key, value in override.items():
            if isinstance(value, dict) and key in default:
                self.recursive_update(default[key], value)
            else:
                default[key] = value

    def load_config(self):
        """Load the configuration defaults and then config.json."""
        self.config = json.loads(self.DEFAULT_CONFIG_JSON)
        if os.path.isfile(self.config_file_path):
            try:
                with open(self.config_file_path, "r") as f:
                    user_config = json.load(f)
                self.recursive_update(self.config, user_config)
            except Exception as e:
                print(
                    f"Error loading configuration from {self.config_file_path}: {str(e)}"
                )
        else:
            print(f"No config file found at {self.config_file_path}. Using defaults.")
        if "password_encrypted" in self.config["mqtt"]:
            self.mqtt_password = self.decrypt_password(
                self.config["mqtt"]["password_encrypted"]
            )
        else:
            self.mqtt_password = self.config["mqtt"]["password"]

    def setup_logging(self):
        """Set up logging configuration."""
        log_file = self.config.get("log_file", "nvr_health_monitor.log")
        if not os.path.isabs(log_file):
            log_file = os.path.join(self.bundle_dir, log_file)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"")

    def decrypt_password(self, encrypted_password):
        """Decrypt the MQTT password stored in the configuration."""
        key = os.getenv("ENCRYPTION_KEY")
        fernet = Fernet(key.encode())
        return fernet.decrypt(encrypted_password.encode()).decode()

    def setup_mqtt_client(self):
        """Set up the MQTT client and establish connection."""
        try:
            self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            self.mqtt_client.username_pw_set(
                self.config["mqtt"]["username"], self.mqtt_password
            )
            self.mqtt_client.connect(
                self.config["mqtt"]["broker"], self.config["mqtt"]["port"], 60
            )
            self.mqtt_client.loop_start()
            self.logger.info("MQTT client connected successfully.")
        except Exception as e:
            self.logger.error(f"Error setting up MQTT client: {str(e)}")
            self.mqtt_client = None

    def check_service_status(self, service_name):
        """Check if a service is running."""
        try:
            service = psutil.win_service_get(service_name)
            service = service.as_dict()
            if service["status"] == "running":
                return self.status_messages.get("check_success", "Unknown Status Code")
            else:
                return self.status_messages.get(
                    "service_not_running", "Unknown Status Code"
                )
        except psutil.NoSuchProcess:
            self.logger.error(f"Service {service_name} does not exist.")
            return self.status_messages.get(
                "service_does_not_exist", "Unknown Status Code"
            )
        except Exception as e:
            self.logger.error(f"Error checking service {service_name}: {str(e)}")
            return self.status_messages.get("unknown_error", "Unknown Status Code")

    def check_services(self, is_recheck=False):
        """Check all services in config."""
        self.service_statuses = {}
        self.services_to_start = []
        for service_key, service_name in self.config["services"].items():
            status = self.check_service_status(service_name)
            self.service_statuses[service_key] = status
            if status == self.status_messages.get("service_not_running"):
                if is_recheck:
                    self.service_statuses[service_key] = self.status_messages.get(
                        "service_failed_start"
                    )
                else:
                    self.services_to_start.append(service_key)

    def start_services(self):
        """Start services that were not running when checked"""
        if self.services_to_start:
            for service_key in self.services_to_start:
                service_name = self.config["services"][service_key]
                self.logger.warning(
                    f"{service_name} is not running. Attempting to start."
                )
                try:
                    win32serviceutil.StartService(service_name)
                except Exception as e:
                    self.logger.error(
                        f"Failed to start service '{service_name}': {str(e)}"
                    )
                    self.service_statuses[service_key] = self.status_messages.get(
                        "service_failed_start"
                    )

    def check_file_modified(self, path, time_interval):
        """Check if the most recent file in the directory has been modified within the specified time interval."""
        try:
            directory = Path(path)
            if not directory.exists():
                self.logger.error(f"Folder {path} does not exist.")
                return self.status_messages.get(
                    "folder_does_not_exist", "Unknown Status Code"
                )
            files = sorted(
                directory.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True
            )
            if files:
                most_recent_file = files[0]
                last_modified = most_recent_file.stat().st_mtime
                time_since_modified = time.time() - last_modified

                if time_since_modified > time_interval:
                    return self.status_messages.get(
                        "folder_is_stale", "Unknown Status Code"
                    ).format(seconds=int(time_since_modified))
                return self.status_messages.get("check_success", "Unknown Status Code")
            else:
                return self.status_messages.get(
                    "folder_is_empty", "Unknown Status Code"
                )
        except Exception as e:
            self.logger.error(f"Error checking file modification: {str(e)}")
            return self.status_messages.get("unknown_error", "Unknown Status Code")

    def create_mqtt_payload(self):
        """Create JSON string payload for MQTT message"""
        self.message_payload = {}
        for service_key, service_status in self.service_statuses.items():
            self.message_payload[service_key] = service_status
        self.message_payload["disk activity"] = self.disk_activity_status

    def send_mqtt_message(self, message_payload):
        """Send an MQTT message with the results."""
        try:
            if self.mqtt_client:
                message_json = json.dumps(message_payload)
                self.mqtt_client.publish(self.config["mqtt"]["topic"], message_json)
                self.logger.info(f"MQTT message sent: {message_json}")
            else:
                self.logger.warning("MQTT client not initialized, message not sent.")
        except Exception as e:
            self.logger.error(f"Error sending MQTT message: {str(e)}")

    def log_check_status(self):
        """Log message based on status"""
        all_checks_passed = all(
            value == self.status_messages.get("check_success")
            for value in self.message_payload.values()
        )
        if all_checks_passed:
            self.logger.info(
                f"{datetime.now()} - {self.status_messages.get("check_success")}"
            )
        else:
            self.logger.warning(f"{datetime.now()} - {self.message_payload}")

    def stop(self):
        """Service stop handler."""
        self.isrunning = False
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
            self.logger.info("MQTT client disconnected.")

    def run(self):
        """Main service loop."""
        self.isrunning = True
        while self.isrunning:
            start_time = time.time()
            try:
                self.check_services()
                if self.config.get("start_services", False):
                    self.start_services()
                    time.sleep(int(self.config["service_start_wait"]))
                    self.check_services(is_recheck=True)
                self.disk_activity_status = self.check_file_modified(
                    self.config["file_check_path"], self.config["interval_seconds"]
                )
                self.create_mqtt_payload()
                self.log_check_status()
                self.send_mqtt_message(self.message_payload)
            except Exception as e:
                self.logger.error(f"Error in service loop: {str(e)}")
            elapsed_time = time.time() - start_time
            sleep_time = max(0, self.config["interval_seconds"] - elapsed_time)
            time.sleep(sleep_time)


class NVRHealthMonitorServiceFramework(win32serviceutil.ServiceFramework):
    _svc_name_ = "NVRHealthMonitor"
    _svc_display_name_ = "NVR Health Monitor Service"
    _svc_description_ = "Monitors NVR services and system health and reports via MQTT."

    def SvcStop(self):
        """Service stop handler."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.service_impl.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """Service start handler."""
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        self.service_impl = NVRHealthMonitor()
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.service_impl.run()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NVRHealthMonitorServiceFramework)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NVRHealthMonitorServiceFramework)
