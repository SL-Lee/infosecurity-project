import datetime
import getpass
import hashlib
import os
import shutil

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from werkzeug.utils import secure_filename

from crypto import decrypt, encrypt_file
from errors import InvalidEncryptionKeyError
from helper_functions import get_config_value
from server_models import BackupLog, server_db

VALID_SERVER_PERMISSION_NAMES = [
    "manage_backups",
    "manage_ip_whitelist",
    "view_logged_requests",
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
        print("Title: %s, ID: %s" % (file["title"], file["id"]))
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
        print("Title: %s, ID: %s" % (file["title"], file["id"]))

        if file["title"] == "backup":
            DRIVE_BACKUP_ID = file["id"]


# backup function to run at interval
def schedule_backup(filename):
    # pylint: disable=import-outside-toplevel

    from app import app

    with app.app_context():
        # get the config of the file
        SCHEDULER.print_jobs()
        backup_config = get_config_value("backup")
        print("backup files:", backup_config)
        file_settings = backup_config[filename]
        backup_datetime = datetime.datetime.now()
        backup_folder = os.path.join(BACKUP_PATH, filename)

        # if the file does not have a backup folder
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % DRIVE_BACKUP_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])

        # if backup folder not created
        if filename not in folder_names:
            folder = DRIVE.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {"kind": "drive#fileLink", "id": DRIVE_BACKUP_ID}
                    ],
                }
            )
            folder.Upload()

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % DRIVE_BACKUP_ID}
        ).GetList()

        # set drive id for backup
        filename_id = None

        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))

            if file["title"] == filename:
                filename_id = file["id"]

        timestamp = secure_filename(
            backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
        )
        timestamp_folder = os.path.join(
            backup_folder,
            timestamp,
        )
        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])

        # if backup folder not created
        if timestamp not in folder_names:
            folder = DRIVE.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_id}],
                }
            )
            folder.Upload()

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()

        # set drive id for backup
        timestamp_id = None

        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))

            if file["title"] == timestamp:
                timestamp_id = file["id"]

        # if no timestamp folder
        if not os.path.exists(timestamp_folder):
            os.mkdir(timestamp_folder)

        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"])
        )

        shutil.copy2(file_settings["path"], file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, ENCRYPTION_KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"]) + ".enc"
        )
        # upload to drive
        file_upload = DRIVE.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        # set content is get file from filepath
        file_upload.SetContentFile(file_backup_path)
        file_upload.Upload()  # Upload the file.

        file_hash = hashlib.md5(
            open(file_settings["path"], "rb").read()
        ).hexdigest()

        backup_log = BackupLog(
            filename=os.path.splitext(os.path.basename(file_settings["path"]))[
                0
            ],
            date_created=backup_datetime,
            method="Automatic Backup",
            source_path=file_settings["path"],
            backup_path=file_backup_path,
            md5=file_hash,
        )
        server_db.session.add(backup_log)
        server_db.session.commit()


# check if the scheduler is empty
if len(SCHEDULER.get_jobs()) == 0:
    backup_config = get_config_value("backup")

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
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "d":
            SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "wk":
            SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
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
