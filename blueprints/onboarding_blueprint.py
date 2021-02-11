import atexit
import datetime
import hashlib
import os
import shutil

import yaml
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import login_user
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from werkzeug.utils import secure_filename

import constants
import forms
from crypto_functions import encrypt, encrypt_file
from helper_functions import (
    get_config_value,
    required_permissions,
    schedule_backup,
    set_config_value,
)
from server_models import BackupLog, ServerPermission, ServerUser, server_db

onboarding_blueprint = Blueprint("onboarding", __name__)


@onboarding_blueprint.route("/onboarding")
def onboarding():
    return redirect(url_for(".onboarding_admin_user_creation"))


@onboarding_blueprint.route(
    "/onboarding/admin-user-creation", methods=["GET", "POST"]
)
def onboarding_admin_user_creation():
    if any(
        ServerPermission.query.get("manage_users") in server_user.permissions
        for server_user in ServerUser.query.all()
    ):
        return redirect(url_for(".onboarding_database_config"))

    create_admin_user_form = forms.CreateAdminUserForm(request.form)

    if request.method == "POST" and create_admin_user_form.validate():
        new_admin_user_password_salt = os.urandom(32)
        new_admin_user_password_hash = hashlib.scrypt(
            password=create_admin_user_form.password.data.encode("UTF-8"),
            salt=new_admin_user_password_salt,
            n=32768,
            r=8,
            p=1,
            maxmem=33816576,
        )
        new_admin_user = ServerUser(
            username=create_admin_user_form.username.data,
            password_salt=new_admin_user_password_salt,
            password_hash=new_admin_user_password_hash,
            date_created=datetime.datetime.now(),
        )

        for server_permission in ServerPermission.query.all():
            new_admin_user.permissions.append(server_permission)

        server_db.session.add(new_admin_user)
        server_db.session.commit()

        login_user(ServerUser.query.get(new_admin_user.id))
        return redirect(url_for(".onboarding_database_config"))

    return render_template(
        "onboarding-admin-user-creation.html", form=create_admin_user_form
    )


@onboarding_blueprint.route(
    "/onboarding/database-config", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def onboarding_database_config():
    if request.method == "POST":
        db_file = request.files.get("db-file")

        if db_file is not None and db_file.filename.endswith(".sqlite3"):
            db_file.save(secure_filename("client_db.sqlite3.tmp"))
            atexit.register(
                lambda: os.replace(
                    "client_db.sqlite3.tmp", "client_db.sqlite3"
                ),
            )
        else:
            flash(
                "The database file seems to be of an incorrect format. Please "
                "try again.",
                "danger",
            )
            return redirect(url_for(".onboarding_database_config"))

        db_models = request.files.get("db-models")

        if db_models is not None and db_models.filename.endswith(".py"):
            db_models.save(secure_filename("client_models.py.tmp"))
            atexit.register(
                lambda: os.replace("client_models.py.tmp", "client_models.py"),
            )
        else:
            flash(
                "The database models file seems to be of an incorrect format. "
                "Please try again.",
                "danger",
            )
            return redirect(url_for(".onboarding_database_config"))

        return redirect(url_for(".onboarding_encryption_key_config"))

    return render_template("onboarding-database-config.html")


@onboarding_blueprint.route(
    "/onboarding/encryption-key-config", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def onboarding_encryption_key_config():
    if (
        get_config_value(
            "encryption-key-config", config_db_name="encryption-config"
        )
        is not None
    ):
        return redirect(url_for(".onboarding_api_config"))

    if request.method == "POST":
        encryption_passphrase = request.form.get("encryption-passphrase")

        if encryption_passphrase is None:
            flash(
                "An error occurred while generating the encryption key. Please "
                "try again.",
                "danger",
            )
            return redirect(url_for(".onboarding_encryption_config"))

        encryption_key_config = {}

        dek = os.urandom(32)

        kek_salt = os.urandom(32)
        kek = hashlib.scrypt(
            encryption_passphrase.encode("UTF-8"),
            salt=kek_salt,
            n=32768,
            r=8,
            p=1,
            maxmem=33816576,
            dklen=32,
        )

        encryption_key_config["timestamp"] = datetime.datetime.now().strftime(
            "%Y-%m-%dT%H:%M:%S+08:00"
        )
        encryption_key_config["kek-salt"] = kek_salt.hex()
        encryption_key_config["kek-hash"] = hashlib.sha3_512(kek).hexdigest()
        encryption_key_config["encrypted-dek"] = encrypt(dek, kek).hex()

        set_config_value(
            "encryption-key-config",
            encryption_key_config,
            config_db_name="encryption-config",
        )
        return redirect(url_for(".onboarding_api_config"))

    return render_template("onboarding-encryption-key-config.html")


@onboarding_blueprint.route("/onboarding/api-config")
@required_permissions("manage_users")
def onboarding_api_config():
    if get_config_value("api-keys") is not None:
        return redirect(url_for(".onboarding_drive_upload_config"))

    return render_template("onboarding-api-config.html")


@onboarding_blueprint.route(
    "/onboarding/drive-upload-config", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def onboarding_drive_upload_config():
    form = forms.OnboardingDriveUpload(request.form)

    if request.method == "POST" and form.validate():
        json_file = request.files.get("json-file")

        if json_file is not None and json_file.filename.endswith(".json"):
            json_file.save(secure_filename("client_secrets.json"))

        setting = {
            "client_config_backend": "file",
            "client_config": {
                "client_id": form.client_id.data,
                "client_secret": form.client_secret.data,
            },
            "save_credentials": True,
            "save_credentials_backend": "file",
            "save_credentials_file": "credentials.json",
            "get_refresh_token": True,
            "oauth_scope": [
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/drive.install",
            ],
        }

        with open("settings.yaml", "w") as file:
            _documents = yaml.dump(setting, file)

        gauth = GoogleAuth()

        drive = GoogleDrive(gauth)

        file_list = drive.ListFile(
            {"q": "'root' in parents and trashed=false"}
        ).GetList()
        folder_names = []

        for file in file_list:
            folder_names.append(file["title"])

        # if backup folder not created
        if "backup" not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": "backup",
                    "mimeType": "application/vnd.google-apps.folder",
                }
            )
            folder.Upload()

        file_list = drive.ListFile(
            {"q": "'root' in parents and trashed=false"}
        ).GetList()

        # set drive id for backup
        for file in file_list:
            if file["title"] == "backup":
                _drive_backup_id = file["id"]

        return redirect(url_for(".onboarding_backup_config"))

    return render_template("onboarding-drive-upload-config.html", form=form)


@onboarding_blueprint.route(
    "/onboarding/drive-upload-pdf", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def onboarding_drive_upload():
    return send_from_directory("static/docs", "drive-how-to.pdf")


@onboarding_blueprint.route(
    "/onboarding/backup-config", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def onboarding_backup_config():
    # onboarding backup form, when there are no settings for the file
    form = forms.OnboardingBackupForm(request.form)

    if request.method == "POST" and form.validate():
        client_db_config = {
            os.path.basename(form.source.data): {
                "path": form.source.data,
                "interval": form.interval.data,
                "interval_type": form.interval_type.data,
            }
        }
        # set backup information for database
        set_config_value("backup", client_db_config)

        location = form.source.data
        backup_datetime = datetime.datetime.now()

        filename = os.path.basename(location)
        filename_folder = os.path.join(constants.BACKUP_PATH, filename)
        # check if the folder with the name exists,
        # else make a folder for it

        if not os.path.exists(filename_folder):
            os.mkdir(filename_folder)

        file_list = constants.DRIVE.ListFile(
            {
                "q": "'%s' in parents and trashed=false"
                % constants.DRIVE_BACKUP_ID
            }
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            folder_names.append(file["title"])

        # if backup folder not created
        if filename not in folder_names:
            folder = constants.DRIVE.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {
                            "kind": "drive#fileLink",
                            "id": constants.DRIVE_BACKUP_ID,
                        }
                    ],
                }
            )
            folder.Upload()

        file_list = constants.DRIVE.ListFile(
            {
                "q": "'%s' in parents and trashed=false"
                % constants.DRIVE_BACKUP_ID
            }
        ).GetList()

        # set drive id for backup
        filename_id = None

        for file in file_list:
            if file["title"] == filename:
                filename_id = file["id"]

        timestamp = secure_filename(
            backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
        )
        # backup folder is timestamp of backup
        backup_folder = os.path.join(
            filename_folder,
            timestamp,
        )

        # check if there is a timestamp for the backup
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        file_list = constants.DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            folder_names.append(file["title"])

        # if backup folder not created
        if timestamp not in folder_names:
            folder = constants.DRIVE.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_id}],
                }
            )
            folder.Upload()

        file_list = constants.DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()

        # set drive id for backup
        timestamp_id = None

        for file in file_list:
            if file["title"] == timestamp:
                timestamp_id = file["id"]

        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location)
        )

        # copy from original location to timestamp
        shutil.copy2(location, file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, constants.ENCRYPTION_KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location) + ".enc"
        )
        # upload to drive
        file_upload = constants.DRIVE.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        # set content is get file from filepath
        file_upload.SetContentFile(file_backup_path)
        file_upload.Upload()  # Upload the file.

        # then add the encryption config for future restore
        shutil.copy2(
            "encryption-config.bak",
            os.path.join(backup_folder, "encryption-config.bak"),
        )
        shutil.copy2(
            "encryption-config.dat",
            os.path.join(backup_folder, "encryption-config.dat"),
        )
        shutil.copy2(
            "encryption-config.dir",
            os.path.join(backup_folder, "encryption-config.dir"),
        )

        file_upload = constants.DRIVE.CreateFile(
            {
                "title": "encryption-config.bak",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.bak")
        file_upload.Upload()  # Upload the file.

        file_upload = constants.DRIVE.CreateFile(
            {
                "title": "encryption-config.dat",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.dat")
        file_upload.Upload()  # Upload the file.

        file_upload = constants.DRIVE.CreateFile(
            {
                "title": "encryption-config.dir",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.dir")
        file_upload.Upload()  # Upload the file.

        file_hash = hashlib.md5(open(location, "rb").read()).hexdigest()

        backup_log = BackupLog(
            filename=filename,
            date_created=backup_datetime,
            method="Manual Backup",
            source_path=location,
            backup_path=file_backup_path,
            md5=file_hash,
        )
        update_log = BackupLog(
            filename=filename,
            date_created=backup_datetime,
            method="Update Settings",
            source_path=location,
            backup_path=file_backup_path,
            md5=file_hash,
        )
        server_db.session.add(update_log)
        server_db.session.add(backup_log)
        server_db.session.commit()

        if form.interval_type.data == "min":
            constants.SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "hr":
            constants.SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                hours=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "d":
            constants.SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "wk":
            constants.SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                weeks=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "mth":
            months = 31 * form.interval.data
            constants.SCHEDULER.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=months,
                id=filename,
                replace_existing=True,
            )

        constants.SCHEDULER.print_jobs()
        return redirect(url_for(".onboarding_complete"))

    return render_template("onboarding-backup-config.html", form=form)


@onboarding_blueprint.route("/onboarding/onboarding-complete")
@required_permissions("manage_users")
def onboarding_complete():
    return render_template("onboarding-complete.html")
