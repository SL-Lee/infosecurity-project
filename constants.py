import getpass
import hashlib
import os

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

from crypto_functions import decrypt
from errors import InvalidEncryptionKeyError
from helper_functions import (
    get_config_value,
    restart_req,
    schedule_backup,
    set_config_value,
)
from server_models import ServerUser

VALID_SERVER_PERMISSION_NAMES = [
    "manage_backups",
    "manage_ip_whitelist",
    "view_logged_requests",
    "manage_request_behaviour",
    "manage_sensitive_fields",
    "manage_encrypted_files",
    "manage_encrypted_fields",
    "manage_alerts",
    "manage_api_keys",
    "manage_users",
    "view_api_documentation",
    "manage_encryption_key",
]

_ENCRYPTION_KEY_CONFIG = get_config_value(
    "encryption-key-config",
    config_db_name="encryption-config",
)

if _ENCRYPTION_KEY_CONFIG is not None:
    kek_passphrase = getpass.getpass("Encryption passphrase: ")
    kek = hashlib.scrypt(
        kek_passphrase.encode("UTF-8"),
        salt=bytes.fromhex(_ENCRYPTION_KEY_CONFIG["kek-salt"]),
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    if hashlib.sha3_512(kek).hexdigest() == _ENCRYPTION_KEY_CONFIG["kek-hash"]:
        ENCRYPTION_KEY = decrypt(
            bytes.fromhex(_ENCRYPTION_KEY_CONFIG["encrypted-dek"]),
            kek,
        )
    else:
        raise InvalidEncryptionKeyError
else:
    ENCRYPTION_KEY = None

_DIRNAME = os.path.dirname(__file__)

# only if backup folder does not exist, then make a backup folder
if not os.path.exists(os.path.join(_DIRNAME, "backup")):
    os.mkdir(os.path.join(_DIRNAME, "backup"))

BACKUP_PATH = os.path.join(_DIRNAME, "backup")
SCHEDULER = BackgroundScheduler(
    jobstores={"default": SQLAlchemyJobStore(url="sqlite:///jobs.sqlite3")},
    daemon=True,
)
SCHEDULER.start()

if os.path.exists(os.path.join(_DIRNAME, "client_secrets.json")):
    _GAUTH = GoogleAuth()

    DRIVE = GoogleDrive(_GAUTH)

    _file_list = DRIVE.ListFile(
        {"q": "'root' in parents and trashed=false"}
    ).GetList()
    _FOLDER_NAMES = []

    for file in _file_list:
        _FOLDER_NAMES.append(file["title"])

    # if backup folder not created
    if "backup" not in _FOLDER_NAMES:
        _FOLDER = DRIVE.CreateFile(
            {
                "title": "backup",
                "mimeType": "application/vnd.google-apps.folder",
            }
        )
        _FOLDER.Upload()

    _file_list = DRIVE.ListFile(
        {"q": "'root' in parents and trashed=false"}
    ).GetList()

    # set drive id for backup
    for file in _file_list:
        if file["title"] == "backup":
            DRIVE_BACKUP_ID = file["id"]


# check if the scheduler is empty
from app import app  # pylint: disable=wrong-import-position

with app.app_context():
    server_users = ServerUser.query.all()

    if len(SCHEDULER.get_jobs()) == 0 and len(server_users) != 0:
        _backup_config = get_config_value("backup")

        # if the config is empty
        if _backup_config is None:
            _PATH = ".\\client_db.sqlite3"
            _KEYNAME = os.path.basename(_PATH)
            _INTERVAL = 1
            _INTERVAL_TYPE = "wk"
            _CLIENT_DB_CONFIG = {
                _KEYNAME: {
                    "path": _PATH,
                    "interval": _INTERVAL,
                    "interval_type": _INTERVAL_TYPE,
                }
            }
            set_config_value("backup", _CLIENT_DB_CONFIG)
            _backup_config = get_config_value("backup")
            print("backup files:", _backup_config)
            print(_backup_config[_KEYNAME]["path"])
            print(os.path.isfile(_backup_config[_KEYNAME]["path"]))

        for filename in _backup_config.keys():
            _FILE_SETTINGS = _backup_config[filename]

            if _FILE_SETTINGS["interval_type"] == "min":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    minutes=_FILE_SETTINGS["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif _FILE_SETTINGS["interval_type"] == "hr":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    hours=_FILE_SETTINGS["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif _FILE_SETTINGS["interval_type"] == "d":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    days=_FILE_SETTINGS["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif _FILE_SETTINGS["interval_type"] == "wk":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    weeks=_FILE_SETTINGS["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif _FILE_SETTINGS["interval_type"] == "mth":
                months = 31 * _FILE_SETTINGS["interval"]
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    days=months,
                    id=filename,
                    replace_existing=True,
                )
