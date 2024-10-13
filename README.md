# NVRHealthMonitor

## Overview

**NVRHealthMonitor** is a Windows service designed to monitor specific services and disk activity related to your Network Video Recorder (NVR) system. It checks if the specified services are running, monitors file changes in a designated directory, and reports the status via MQTT messaging.

## Features

- Monitors the status of configured services (eg. Blue Iris and CodeProject.AI services).
- Optionally attempts to start services that aren't running.
- Checks for the most recently modified file in a specified directory.
- Sends status updates as JSON payloads via MQTT.
- Logs service status and errors.
- Configurable via a JSON configuration file.

## Requirements

- Python 3.7 or higher
- Required Python packages listed in `requirements.txt`
- A valid MQTT broker for sending messages
- Windows operating system

## Installation

1. **Clone the Repository**:
    ```PowerShell
    git clone https://github.com/yourusername/nvr-health-monitor.git
    cd nvr-health-monitor
    ```

2. **Set Up a Virtual Environment** (optional but recommended):
    ```PowerShell
    python -m venv .venv
    .venv\Scripts\activate
    ```

3. **Install Dependencies**:
    ```PowerShell
    pip install -r requirements.txt
    ```

4. **Configure the Service**: create config.json
    ```json
   {
        "services": {
            "blueiris": "BlueIris",
            "codeproject_ai": "CodeProject.AI Server"
        },
        "start_services": true,
        "service_start_wait": 30,
        "file_check_path": "D:\\BlueIris\\New",
        "interval_seconds": 120,
        "log_file": "nvr_health_monitor.log",
        "mqtt": {
            "broker": "mqtt.example.com",
            "port": 1883,
            "username": "your_mqtt_username",
            "password_encrypted": "your_mqtt_password_encrypted",
            "password": "your_mqtt_password",
            "topic": "nvr/status"
        }
    }
    ```
    | config | description |
    | ----- | ----- |
    | **services** | list of services to check, see below for details |
    | **start_services** | try to start a service if it isn't running |
    | **service_start_wait** | seconds to wait for services to start |
    | **file_check_path** | path to a folder that blue iris will write to at least every **interval_seconds** |
    | **interval_seconds** | seconds between checks |
    | **password_encrypted** / **password** | use only one, see below for encrypted |
    To encrypt a password
    ```python
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    print(key.decode())
    # save this key as the environment variable ENCRYPTION_KEY
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(b'password_goes_here')
    print(encrypted_password.decode())
    # put this value for password_encrypted
    ```
    The services are in the format `key: service_name` where `key` will be the name in the JSON payload and service_name is the name of the Windows service. Note that some services have a different *display name* which cannot be used in place of the *service name*.

5. **Build the service**:
    ```PowerShell
    pip install pyinstaller
    pyinstaller --hidden-import win32timezone .\nvr_health_monitor.py
    cp config.json dist\nvr_health_monitor\
    ```
    Optionally, copy the `nvr_health_monitor` folder from `dist` to a different location.

6. **Install the Service** (run as administrator from `nvr_health_monitor` folder created during build):
    ```PowerShell
    .\nvr_health_monitor.exe install
    ```
    Configure as any other Windows service. If using encrypted password, the decryption key environment variable can be set with the following proceedure:
    * Open Registry Editor as admin
    * Create a new Multi-String value named `Environment` in Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NVRHealthMonitor
    * Modify the value to add ENCRYPTION_KEY=<key> (replacing <key> with the key generated above)

## JSON Payload

### Example
```JSON
{
    "blue iris service": "OK",
    "codeprojectai service": "Service failed to start",
    "disk activity": "Last modified 120 seconds ago"
}
```

### Service Statuses
| status | meaning |
| ----- | ----- |
| **OK** | the check passed |
| **Service not running** | service was not running and no attempt was made to start it |
| **Service failed to start** | service was not running and did not start within service_start_wait seconds |
| **Service does not exist** | service does not exist, check config against service names |
| **Unknown error** | an unexpected exception occured when trying to test service status |

### Disk Activity Statuses
| status | meaning |
| ----- | ----- |
| **OK** | the check passed |
| **Folder does not exist** | **file_check_path** does not exist, check config |
| **No files found** | no files in **file_check_path** |
| **Last modified # seconds ago** | modification is longer than interval_seconds |
| **Unknown error** | an unexpected exception occured when trying to test disk |

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
