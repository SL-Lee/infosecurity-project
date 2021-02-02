import getpass
import hashlib
import os

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

from crypto_functions import decrypt
from errors import InvalidEncryptionKeyError
from helper_functions import get_config_value, schedule_backup, set_config_value
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

_encryption_config = get_config_value("encryption-config")

if _encryption_config is not None:
    kek_passphrase = getpass.getpass("Encryption passphrase: ")
    kek = hashlib.scrypt(
        kek_passphrase.encode("UTF-8"),
        salt=bytes.fromhex(_encryption_config["kek-salt"]),
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    if hashlib.sha3_512(kek).hexdigest() == _encryption_config["kek-hash"]:
        ENCRYPTION_KEY = decrypt(
            bytes.fromhex(_encryption_config["encrypted-dek"]),
            kek,
        )
    else:
        raise InvalidEncryptionKeyError
else:
    ENCRYPTION_KEY = None

_dirname = os.path.dirname(__file__)

# only if backup folder does not exist, then make a backup folder
if not os.path.exists(os.path.join(_dirname, "backup")):
    os.mkdir(os.path.join(_dirname, "backup"))

BACKUP_PATH = os.path.join(_dirname, "backup")
SCHEDULER = BackgroundScheduler(
    jobstores={"default": SQLAlchemyJobStore(url="sqlite:///jobs.sqlite3")},
    daemon=True,
)
SCHEDULER.start()

if os.path.exists(os.path.join(_dirname, "client_secrets.json")):
    gauth = GoogleAuth()

    DRIVE = GoogleDrive(gauth)

    file_list = DRIVE.ListFile(
        {"q": "'root' in parents and trashed=false"}
    ).GetList()
    folder_names = []

    for file in file_list:
        folder_names.append(file["title"])

    # if backup folder not created
    if "backup" not in folder_names:
        folder = DRIVE.CreateFile(
            {
                "title": "backup",
                "mimeType": "application/vnd.google-apps.folder",
            }
        )
        folder.Upload()

    file_list = DRIVE.ListFile(
        {"q": "'root' in parents and trashed=false"}
    ).GetList()

    # set drive id for backup
    for file in file_list:
        if file["title"] == "backup":
            DRIVE_BACKUP_ID = file["id"]


# check if the scheduler is empty
from app import app

with app.app_context():
    server_users = ServerUser.query.all()
    if len(SCHEDULER.get_jobs()) == 0 and len(server_users) != 0:
        backup_config = get_config_value("backup")
        # if the config is empty
        if backup_config is None:
            path = ".\\client_db.sqlite3"
            keyname = os.path.basename(path)
            interval = 1
            interval_type = "wk"
            client_db_config = {
                keyname: {
                    "path": path,
                    "interval": interval,
                    "interval_type": interval_type,
                }
            }
            set_config_value("backup", client_db_config)
            backup_config = get_config_value("backup")
            print("backup files:", backup_config)
            print(backup_config[keyname]["path"])
            print(os.path.isfile(backup_config[keyname]["path"]))

        for filename in backup_config.keys():
            file_settings = backup_config[filename]

            if file_settings["interval_type"] == "min":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    minutes=file_settings["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif file_settings["interval_type"] == "hr":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    hours=file_settings["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif file_settings["interval_type"] == "d":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    days=file_settings["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif file_settings["interval_type"] == "wk":
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    weeks=file_settings["interval"],
                    id=filename,
                    replace_existing=True,
                )
            elif file_settings["interval_type"] == "mth":
                months = 31 * file_settings["interval"]
                SCHEDULER.add_job(
                    schedule_backup,
                    args=[filename],
                    trigger="interval",
                    days=months,
                    id=filename,
                    replace_existing=True,
                )
