import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import time
import json
import win32service
from unittest.mock import patch, MagicMock, mock_open
import pytest
from nvr_health_monitor import NVRHealthMonitor
import psutil
from cryptography.fernet import Fernet
from datetime import datetime


@pytest.fixture
def mock_config():
    """Fixture that returns a mock config for the tests."""
    return {
        "services": {
            "blue_iris": "BlueIrisService",
            "codeprojectai": "CodeProjectAIService",
        },
        "file_check_path": "D:/BlueIris/New",
        "interval_seconds": 60,
        "mqtt": {
            "username": "test_user",
            "password": "plaintext_password",
            "broker": "localhost",
            "port": 1883,
            "topic": "nvr/health",
        },
        "start_services": True,
        "service_start_wait": 5,
    }


@pytest.fixture
@patch("win32serviceutil.ServiceFramework.__init__", return_value=None)
@patch("paho.mqtt.client.Client")
def monitor(mock_mqtt_client, mock_win32_srv, mock_config):
    """Fixture to create an NVRHealthMonitor instance."""
    monitor_instance = NVRHealthMonitor()
    monitor_instance.config = mock_config
    return monitor_instance


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data=json.dumps({"mqtt": {"username": "user", "password": "pass"}}),
)
@patch("os.path.isfile", return_value=True)
def test_load_config(mock_isfile, mock_open_file, monitor):
    """Test the loading of configuration."""
    monitor.load_config()
    assert monitor.config["mqtt"]["username"] == "user"
    assert monitor.config["mqtt"]["password"] == "pass"


@patch("os.path.isfile", return_value=False)
def test_load_config_no_file(mock_isfile, monitor):
    """Test the loading of configuration with no file."""
    monitor.load_config()
    assert monitor.config["mqtt"]["username"] == "default_user"
    assert monitor.config["mqtt"]["password"] == "default_password"


@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data='{"mqtt": {"username": "user", "password": "pass",}',
)
@patch("os.path.isfile", return_value=True)
def test_load_config_invalid_json(mock_isfile, mock_open_file, monitor):
    """Test loading configuration when JSON is invalid."""
    monitor.load_config()
    assert monitor.config["mqtt"]["username"] == "default_user"
    assert monitor.config["mqtt"]["password"] == "default_password"


def test_load_config_with_encrypted_password(monitor):
    """Test loading configuration with an encrypted password."""
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(b"plaintext_password").decode()
    mock_config_data = {
        "mqtt": {"username": "user", "password_encrypted": encrypted_password}
    }
    with patch(
        "builtins.open", new_callable=mock_open, read_data=json.dumps(mock_config_data)
    ):
        with patch("os.path.isfile", return_value=True):
            with patch.dict(os.environ, {"ENCRYPTION_KEY": key.decode()}):
                monitor.load_config()
                assert monitor.mqtt_password == "plaintext_password"


@patch("psutil.win_service_get")
def test_check_service_status_running(mock_win_service_get, monitor):
    """Test service status when the service is running."""
    mock_service = MagicMock()
    mock_service.as_dict.return_value = {"status": "running"}
    mock_win_service_get.return_value = mock_service
    result = monitor.check_service_status("BlueIrisService")
    assert result == monitor.status_messages.get("check_success")


@patch("psutil.win_service_get")
def test_check_service_status_not_running(mock_win_service_get, monitor):
    """Test service status when the service is not running."""
    mock_service = MagicMock()
    mock_service.as_dict.return_value = {"status": "stopped"}
    mock_win_service_get.return_value = mock_service
    result = monitor.check_service_status("BlueIrisService")
    assert result == monitor.status_messages.get("service_not_running")


@patch("psutil.win_service_get", side_effect=psutil.NoSuchProcess("Service not found"))
def test_check_service_status_not_exist(mock_win_service_get, monitor):
    """Test service status when the service doesn't exist."""
    result = monitor.check_service_status("NonExistentService")
    assert result == monitor.status_messages.get("service_does_not_exist")


@patch("psutil.win_service_get", side_effect=Exception("Unknown error"))
def test_check_service_status_unknown_error(mock_win_service_get, monitor):
    """Test service status when an unknown error occurs."""
    result = monitor.check_service_status("BlueIrisService")
    assert result == monitor.status_messages.get("unknown_error")


@patch.object(NVRHealthMonitor, "check_service_status")
def test_check_services_initial_check(mock_check_service_status, monitor):
    """Test check_services when is_recheck is False (initial check)."""
    mock_check_service_status.return_value = monitor.status_messages.get(
        "service_not_running"
    )
    monitor.config = {
        "services": {
            "blue_iris": "BlueIrisService",
            "codeprojectai": "CodeProjectAIService",
        }
    }
    monitor.check_services(is_recheck=False)
    mock_check_service_status.assert_any_call("BlueIrisService")
    mock_check_service_status.assert_any_call("CodeProjectAIService")
    assert mock_check_service_status.call_count == 2
    assert monitor.services_to_start == ["blue_iris", "codeprojectai"]
    assert monitor.service_statuses == {
        "blue_iris": monitor.status_messages.get("service_not_running"),
        "codeprojectai": monitor.status_messages.get("service_not_running"),
    }


@patch.object(NVRHealthMonitor, "check_service_status")
def test_check_services_recheck_failure(mock_check_service_status, monitor):
    """Test check_services when is_recheck is True and services failed to start."""
    mock_check_service_status.return_value = monitor.status_messages.get(
        "service_not_running"
    )
    monitor.config = {"services": {"blue_iris": "BlueIrisService"}}
    monitor.check_services(is_recheck=True)
    mock_check_service_status.assert_called_once_with("BlueIrisService")
    assert monitor.service_statuses == {
        "blue_iris": monitor.status_messages.get("service_failed_start")
    }
    assert monitor.services_to_start == []


@patch.object(NVRHealthMonitor, "check_service_status")
def test_check_services_service_running(mock_check_service_status, monitor):
    """Test check_services when services are running."""
    mock_check_service_status.return_value = monitor.status_messages.get(
        "check_success"
    )
    monitor.config = {
        "services": {
            "blue_iris": "BlueIrisService",
            "codeprojectai": "CodeProjectAIService",
        }
    }
    monitor.check_services(is_recheck=False)
    mock_check_service_status.assert_any_call("BlueIrisService")
    mock_check_service_status.assert_any_call("CodeProjectAIService")
    assert mock_check_service_status.call_count == 2
    assert monitor.services_to_start == []
    assert monitor.service_statuses == {
        "blue_iris": monitor.status_messages.get("check_success"),
        "codeprojectai": monitor.status_messages.get("check_success"),
    }


@patch.object(NVRHealthMonitor, "check_service_status")
def test_check_services_no_services(mock_check_service_status, monitor):
    """Test check_services when no services in config."""
    monitor.config = {"services": {}}
    monitor.check_services(is_recheck=False)
    assert mock_check_service_status.call_count == 0
    assert monitor.services_to_start == []
    assert monitor.service_statuses == {}


@patch("pathlib.Path.exists", return_value=True)
@patch("pathlib.Path.iterdir")
@patch("time.time", return_value=2000)
def test_check_file_modified_recent(mock_time, mock_iterdir, mock_exists, monitor):
    """Test file modification when file has been modified recently."""
    mock_file = MagicMock()
    mock_file.stat.return_value.st_mtime = 1990
    mock_iterdir.return_value = [mock_file]
    result = monitor.check_file_modified("D:/BlueIris/New", 60)
    assert result == monitor.status_messages.get("check_success")


@patch("pathlib.Path.exists", return_value=True)
@patch("pathlib.Path.iterdir")
@patch("time.time", return_value=3000)
def test_check_file_modified_old(mock_time, mock_iterdir, mock_exists, monitor):
    """Test file modification when the last change is too old."""
    mock_file = MagicMock()
    mock_file.stat.return_value.st_mtime = 1000
    mock_iterdir.return_value = [mock_file]
    result = monitor.check_file_modified("D:/BlueIris/New", 60)
    assert result == monitor.status_messages.get(
        "folder_is_stale", "Unknown Status Code"
    ).format(seconds=2000)


@patch("pathlib.Path.exists", return_value=False)
def test_check_file_folder_not_exist(mock_exists, monitor):
    """Test file modification when folder doesn't exist."""
    result = monitor.check_file_modified("D:/BlueIris/New", 60)
    assert result == monitor.status_messages.get("folder_does_not_exist")


@patch("pathlib.Path.iterdir", return_value=[])
@patch("pathlib.Path.exists", return_value=True)
def test_check_file_folder_empty(mock_exists, mock_iterdir, monitor):
    """Test file modification when the folder is empty."""
    result = monitor.check_file_modified("D:/BlueIris/New", 60)
    assert result == monitor.status_messages.get("folder_is_empty")


@patch("pathlib.Path.exists", side_effect=Exception("Unknown error"))
def test_check_file_modified_exception(mock_exists, monitor):
    """Test file modification when exception is thrown."""
    result = monitor.check_file_modified("D:/BlueIris/New", 60)
    assert result == monitor.status_messages.get("unknown_error")


@patch("paho.mqtt.client.Client.connect", side_effect=Exception("Connection failed"))
def test_mqtt_client_connect_failure(mock_mqtt_client_connect, monitor):
    """Test MQTT client connection failure."""
    monitor.setup_mqtt_client()
    assert monitor.mqtt_client is None


def test_send_mqtt_message_success(monitor):
    """Test sending an MQTT message successfully."""
    payload = {"blue iris service": "OK", "codeprojectai service": "OK"}
    monitor.send_mqtt_message(payload)
    monitor.mqtt_client.publish.assert_called_once_with(
        monitor.config["mqtt"]["topic"], json.dumps(payload)
    )


@patch("logging.Logger.warning")
def test_send_mqtt_message_client_not_initialized(mock_logger_warning, monitor):
    """Test sending an MQTT message when the client is not initialized."""
    monitor.mqtt_client = None
    payload = {"blue iris service": "OK", "codeprojectai service": "OK"}
    monitor.send_mqtt_message(payload)
    mock_logger_warning.assert_called_with(
        "MQTT client not initialized, message not sent."
    )


@patch("logging.Logger.error")
def test_send_mqtt_message_failure(mock_logger_error, monitor):
    """Test failure when sending an MQTT message."""
    monitor.mqtt_client.publish.side_effect = Exception("MQTT error")
    payload = {"blue iris service": "OK", "codeprojectai service": "OK"}
    monitor.send_mqtt_message(payload)
    mock_logger_error.assert_called_once_with("Error sending MQTT message: MQTT error")


def test_stop(monitor):
    """Test the stop method for stopping the service."""
    monitor.isrunning = True
    monitor.stop()
    monitor.mqtt_client.loop_stop.assert_called_once()
    monitor.mqtt_client.disconnect.assert_called_once()
    assert not monitor.isrunning


@patch("logging.Logger.info")
@patch("logging.Logger.warning")
@patch("nvr_health_monitor.datetime")
def test_log_check_status_all_checks_passed(
    mock_datetime, mock_warning, mock_info, monitor
):
    """Test log_check_status when all checks pass."""
    mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
    monitor.status_messages = {"check_success": "OK"}
    monitor.message_payload = {"check_1": "OK", "check_2": "OK"}
    monitor.log_check_status()
    mock_info.assert_called_once_with(f"2024-01-01 12:00:00 - OK")
    mock_warning.assert_not_called()


@patch("logging.Logger.info")
@patch("logging.Logger.warning")
@patch("nvr_health_monitor.datetime")
def test_log_check_status_some_checks_failed(
    mock_datetime, mock_warning, mock_info, monitor
):
    """Test log_check_status when some checks fail."""
    mock_datetime.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
    monitor.status_messages = {"check_success": "OK"}
    monitor.message_payload = {"check_1": "OK", "check_2": "Service not running"}
    monitor.log_check_status()
    mock_warning.assert_called_once_with(
        f"2024-01-01 12:00:00 - {monitor.message_payload}"
    )
    mock_info.assert_not_called()


def test_create_mqtt_payload(monitor):
    """Test that MQTT payload is correctly created based on service statuses and disk activity."""
    monitor.service_statuses = {"service_1": "running", "service_2": "stopped"}
    monitor.disk_activity_status = "active"
    monitor.create_mqtt_payload()
    expected_payload = {
        "service_1": "running",
        "service_2": "stopped",
        "disk activity": "active",
    }
    assert monitor.message_payload == expected_payload


def test_create_mqtt_payload_without_services(monitor):
    """Test that MQTT payload is correctly created when no services are defined."""
    monitor.service_statuses = {}
    monitor.disk_activity_status = "active"
    monitor.create_mqtt_payload()
    expected_payload = {"disk activity": "active"}
    assert monitor.message_payload == expected_payload


@patch("win32serviceutil.StartService")
def test_start_services_success(mock_start_service, monitor):
    """Test starting services when they are not running."""
    monitor.services_to_start = ["blue_iris", "codeprojectai"]
    monitor.config = {
        "services": {
            "blue_iris": "BlueIrisService",
            "codeprojectai": "CodeProjectAIService",
        }
    }
    monitor.start_services()
    mock_start_service.assert_any_call("BlueIrisService")
    mock_start_service.assert_any_call("CodeProjectAIService")
    assert mock_start_service.call_count == 2


@patch(
    "win32serviceutil.StartService", side_effect=Exception("Failed to start service")
)
@patch("logging.Logger.error")
def test_start_services_failure(mock_logger_error, mock_start_service, monitor):
    """Test behavior when starting a service fails."""
    monitor.services_to_start = ["blue_iris"]
    monitor.config = {"services": {"blue_iris": "BlueIrisService"}}
    monitor.service_statuses = {"blue_iris": "stopped"}
    monitor.start_services()
    mock_start_service.assert_called_once_with("BlueIrisService")
    mock_logger_error.assert_called_once_with(
        "Failed to start service 'BlueIrisService': Failed to start service"
    )
    assert monitor.service_statuses["blue_iris"] == monitor.status_messages.get(
        "service_failed_start"
    )
