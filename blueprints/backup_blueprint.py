import datetime
import hashlib
import os
import shutil

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import constants
import forms
from crypto_functions import decrypt_file, encrypt_file
from helper_functions import (
    get_config_value,
    required_permissions,
    schedule_backup,
    set_config_value,
)
from server_models import BackupLog, server_db

backup_blueprint = Blueprint("backup", __name__)


@backup_blueprint.route("/backup")
@required_permissions("manage_backups")
def backup():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    files = list(backup_config.keys())
    return render_template("backup.html", files=files)


@backup_blueprint.route("/backup/add", methods=["GET", "POST"])
@required_permissions("manage_backups")
def backup_add():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)

    # first form, when there are no settings for the file
    form = forms.BackupFirstForm(request.form)

    if request.method == "POST" and form.validate():
        if os.path.isfile(form.source.data):
            if os.path.basename(form.source.data) not in backup_config:
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
                            "parents": [
                                {"kind": "drive#fileLink", "id": filename_id}
                            ],
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

                backup_config[filename] = {
                    "path": location,
                    "interval": form.interval.data,
                    "interval_type": form.interval_type.data,
                }
                print(backup_config)
                set_config_value("backup", backup_config)
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

                # upload to drive
                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": os.path.basename(file_backup_path),
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                # set content is get file from filepath
                file_upload.SetContentFile(file_backup_path)
                file_upload.Upload()  # Upload the file.

                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": "encryption-config.bak",
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                file_upload.SetContentFile("encryption-config.bak")
                file_upload.Upload()  # Upload the file.

                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": "encryption-config.dat",
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                file_upload.SetContentFile("encryption-config.dat")
                file_upload.Upload()  # Upload the file.

                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": "encryption-config.dir",
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                file_upload.SetContentFile("encryption-config.dir")
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
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                file_upload.SetContentFile("encryption-config.bak")
                file_upload.Upload()  # Upload the file.

                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": "encryption-config.dat",
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
                    }
                )
                file_upload.SetContentFile("encryption-config.dat")
                file_upload.Upload()  # Upload the file.

                file_upload = constants.DRIVE.CreateFile(
                    {
                        "title": "encryption-config.dir",
                        "parents": [
                            {"kind": "drive#fileLink", "id": timestamp_id}
                        ],
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

                return redirect(url_for("index"))
            else:
                flash(
                    "There is already a backup for the filename, please rename "
                    "the file or update the settings for the filename.",
                    "danger",
                )
                return redirect(url_for(".backup_add"))
        else:
            flash(
                "The file path entered is invalid, please try again with a "
                "valid file path.",
                "danger",
            )
            return redirect(url_for(".backup_add"))

    return render_template("backup-form.html", form1=form)


@backup_blueprint.route("/backup/<file>", methods=["GET", "POST"])
@required_permissions("manage_backups")
def backup_history(file):
    path = os.path.join(constants.BACKUP_PATH, file)

    # get all entries in the directory
    entries = []

    for file_name in os.listdir(path):
        entries.append(os.path.join(path, file_name))

    entries.sort(key=os.path.getctime, reverse=True)
    timestamp = []

    for i in entries:
        timestamp.append(os.path.basename(i))

    print(timestamp)

    return render_template(
        "backup-history.html", file=file, timestamp=timestamp
    )


@backup_blueprint.route("/backup/<file>/update", methods=["GET", "POST"])
@required_permissions("manage_backups")
def backup_update(file):
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    file_settings = backup_config[file]

    form = forms.BackupForm(request.form)

    if request.method == "POST" and form.validate():
        # only backup, nothing else happens, including changes to settings
        if form.manual.data:
            print("manual backup")

            backup_datetime = datetime.datetime.now()

            filename = os.path.join(constants.BACKUP_PATH, file)

            if not os.path.exists(filename):
                os.mkdir(filename)

            file_list = constants.DRIVE.ListFile(
                {
                    "q": "'%s' in parents and trashed=false"
                    % constants.DRIVE_BACKUP_ID
                }
            ).GetList()  # to list the files in the folder id
            folder_names = []

            for files in file_list:
                folder_names.append(files["title"])

            # if backup folder not created
            if file not in folder_names:
                folder = constants.DRIVE.CreateFile(
                    {
                        "title": file,
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

            for files in file_list:
                if files["title"] == file:
                    filename_id = files["id"]

            timestamp = secure_filename(
                backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
            )
            backup_folder = os.path.join(
                filename,
                timestamp,
            )

            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_list = constants.DRIVE.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_id}
            ).GetList()  # to list the files in the folder id
            folder_names = []

            for files in file_list:
                folder_names.append(files["title"])

            # if backup folder not created
            if timestamp not in folder_names:
                folder = constants.DRIVE.CreateFile(
                    {
                        "title": timestamp,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": filename_id}
                        ],
                    }
                )
                folder.Upload()

            file_list = constants.DRIVE.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_id}
            ).GetList()

            # set drive id for backup
            timestamp_id = None

            for files in file_list:
                if files["title"] == timestamp:
                    timestamp_id = files["id"]

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)
            # encrypt the backed up file
            encrypt_file(file_backup_path, constants.ENCRYPTION_KEY)
            # after encrypting the copied file,
            # remove the copied file
            os.remove(file_backup_path)
            # set new path name for encrypted file
            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"]) + ".enc"
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

            file_hash = hashlib.md5(
                open(file_settings["path"], "rb").read()
            ).hexdigest()

            backup_log = BackupLog(
                filename=os.path.basename(file_settings["path"]),
                date_created=backup_datetime,
                method="Manual Backup",
                source_path=file_settings["path"],
                backup_path=file_backup_path,
                md5=file_hash,
            )
            server_db.session.add(backup_log)
            server_db.session.commit()
        # will perform a update, and update the settings
        elif form.update.data:
            print("update settings")

            # if field different from settings and the file is valid and not
            # empty
            if form.source.data is not None:
                if (
                    form.source.data != file_settings["path"]
                    and form.source.data != ""
                ):
                    if os.path.isfile(form.source.data):
                        file_settings["path"] = form.source.data
                    else:
                        flash(
                            "The file path entered is invalid, please try again "
                            "with a valid file path.",
                            "danger",
                        )
                        return redirect(url_for(".backup_update", file=file))

            # if field different from settings and not empty
            if form.interval_type.data is not None:
                if (
                    form.interval_type.data != file_settings["interval_type"]
                    and form.interval_type.data != ""
                ):
                    file_settings["interval_type"] = form.interval_type.data

            # if field different from settings and not empty
            if form.interval.data is not None:
                if (
                    form.interval.data != file_settings["interval"]
                    and form.interval.data != ""
                ):
                    file_settings["interval"] = form.interval.data

            # update settings for file
            backup_config[file] = file_settings
            # cannot put file settings directly, else it would override the
            # whole backup settings
            set_config_value("backup", backup_config)
            backup_config = get_config_value("backup")
            print("backup files:", backup_config)
            file_settings = backup_config[file]

            # create folders to be used for saving
            backup_datetime = datetime.datetime.now()
            filename = os.path.join(constants.BACKUP_PATH, file)

            if not os.path.exists(filename):
                os.mkdir(filename)

            file_list = constants.DRIVE.ListFile(
                {
                    "q": "'%s' in parents and trashed=false"
                    % constants.DRIVE_BACKUP_ID
                }
            ).GetList()  # to list the files in the folder id
            folder_names = []

            for files in file_list:
                folder_names.append(files["title"])

            # if backup folder not created
            if file not in folder_names:
                folder = constants.DRIVE.CreateFile(
                    {
                        "title": file,
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

            for files in file_list:
                if files["title"] == file:
                    filename_id = files["id"]

            timestamp = secure_filename(
                backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
            )
            backup_folder = os.path.join(
                filename,
                timestamp,
            )

            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_list = constants.DRIVE.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_id}
            ).GetList()  # to list the files in the folder id
            folder_names = []

            for files in file_list:
                folder_names.append(files["title"])

            # if backup folder not created
            if timestamp not in folder_names:
                folder = constants.DRIVE.CreateFile(
                    {
                        "title": timestamp,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": filename_id}
                        ],
                    }
                )
                folder.Upload()

            file_list = constants.DRIVE.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_id}
            ).GetList()

            # set drive id for backup
            timestamp_id = None

            for files in file_list:
                if files["title"] == timestamp:
                    timestamp_id = files["id"]

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)
            # encrypt the backed up file
            encrypt_file(file_backup_path, constants.ENCRYPTION_KEY)
            # after encrypting the copied file,
            # remove the copied file
            os.remove(file_backup_path)
            # set new path name for encrypted file
            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"]) + ".enc"
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

            file_hash = hashlib.md5(
                open(file_settings["path"], "rb").read()
            ).hexdigest()

            backup_log = BackupLog(
                filename=os.path.basename(file_settings["path"]),
                date_created=backup_datetime,
                method="Manual Backup",
                source_path=file_settings["path"],
                backup_path=file_backup_path,
                md5=file_hash,
            )
            update_log = BackupLog(
                filename=os.path.basename(file_settings["path"]),
                date_created=backup_datetime,
                method="Update Settings",
                source_path=file_settings["path"],
                backup_path=file_backup_path,
                md5=file_hash,
            )
            server_db.session.add(update_log)
            server_db.session.add(backup_log)
            server_db.session.commit()

            if form.interval_type.data == "min":
                constants.SCHEDULER.reschedule_job(
                    file,
                    trigger="interval",
                    minutes=file_settings["interval"],
                )
            elif form.interval_type.data == "hr":
                constants.SCHEDULER.reschedule_job(
                    file,
                    trigger="interval",
                    hours=file_settings["interval"],
                )
            elif form.interval_type.data == "d":
                constants.SCHEDULER.reschedule_job(
                    file,
                    trigger="interval",
                    days=file_settings["interval"],
                )
            elif form.interval_type.data == "wk":
                constants.SCHEDULER.reschedule_job(
                    file,
                    trigger="interval",
                    weeks=file_settings["interval"],
                )
            elif form.interval_type.data == "mth":
                months = 31 * file_settings["interval"]
                constants.SCHEDULER.reschedule_job(
                    file,
                    trigger="interval",
                    days=months,
                )

            constants.SCHEDULER.print_jobs()

        return redirect(url_for(".backup"))

    return render_template("backup-form.html", form2=form)


@backup_blueprint.route("/backup/<file>/<timestamp>/restore")
@required_permissions("manage_backups")
def backup_restore(file, timestamp):
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    file_settings = backup_config[file]

    # backup before restoring
    backup_datetime = datetime.datetime.now()

    filename = os.path.join(constants.BACKUP_PATH, file)

    if not os.path.exists(filename):
        os.mkdir(filename)

    file_list = constants.DRIVE.ListFile(
        {"q": "'%s' in parents and trashed=false" % constants.DRIVE_BACKUP_ID}
    ).GetList()  # to list the files in the folder id
    folder_names = []

    for files in file_list:
        folder_names.append(files["title"])

    # if backup folder not created
    if file not in folder_names:
        folder = constants.DRIVE.CreateFile(
            {
                "title": file,
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
        {"q": "'%s' in parents and trashed=false" % constants.DRIVE_BACKUP_ID}
    ).GetList()

    # set drive id for backup
    filename_id = None

    for files in file_list:
        if files["title"] == file:
            filename_id = files["id"]

    backup_timestamp = secure_filename(
        backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
    )
    backup_folder = os.path.join(
        filename,
        backup_timestamp,
    )

    if not os.path.exists(backup_folder):
        os.mkdir(backup_folder)

    file_list = constants.DRIVE.ListFile(
        {"q": "'%s' in parents and trashed=false" % filename_id}
    ).GetList()  # to list the files in the folder id
    folder_names = []

    for files in file_list:
        folder_names.append(files["title"])

    # if backup folder not created
    if backup_timestamp not in folder_names:
        folder = constants.DRIVE.CreateFile(
            {
                "title": backup_timestamp,
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

    for files in file_list:
        if files["title"] == backup_timestamp:
            timestamp_id = files["id"]

    file_backup_path = os.path.join(
        backup_folder, os.path.basename(file_settings["path"])
    )

    shutil.copy2(file_settings["path"], file_backup_path)
    # encrypt the backed up file
    encrypt_file(file_backup_path, constants.ENCRYPTION_KEY)
    # after encrypting the copied file,
    # remove the copied file
    os.remove(file_backup_path)
    # set new path name for encrypted file
    file_backup_path = os.path.join(
        backup_folder, os.path.basename(file_settings["path"]) + ".enc"
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

    file_hash = hashlib.md5(
        open(file_settings["path"], "rb").read()
    ).hexdigest()

    backup_log = BackupLog(
        filename=os.path.basename(file_settings["path"]),
        date_created=backup_datetime,
        method="Backup before Restore",
        source_path=file_settings["path"],
        backup_path=file_backup_path,
        md5=file_hash,
    )
    server_db.session.add(backup_log)
    server_db.session.commit()

    # path to file dir
    file_folder = os.path.join(constants.BACKUP_PATH, file)

    # path to timestamp dir
    timestamp_folder = os.path.join(file_folder, timestamp)

    # path to encrypted file
    encrypted = os.path.join(
        timestamp_folder, os.path.basename(file_settings["path"] + ".enc")
    )
    # restore encryption config before decrypting
    shutil.copy2(
        os.path.join(timestamp_folder, "encryption-config.bak"),
        "encryption-config.bak",
    )
    shutil.copy2(
        os.path.join(timestamp_folder, "encryption-config.dat"),
        "encryption-config.dat",
    )
    shutil.copy2(
        os.path.join(timestamp_folder, "encryption-config.dir"),
        "encryption-config.dir",
    )

    # decrypt the encrypted file
    decrypt_file(encrypted, constants.ENCRYPTION_KEY)

    # path to decrypted file
    decrypted = os.path.join(
        timestamp_folder, os.path.basename(file_settings["path"] + ".dec")
    )

    # name the decrypted file
    os.rename(
        decrypted,
        os.path.join(timestamp_folder, os.path.basename(file_settings["path"])),
    )
    restore = os.path.join(
        timestamp_folder, os.path.basename(file_settings["path"])
    )

    # copy from timestamp to source path
    shutil.copy2(restore, file_settings["path"])

    file_hash = hashlib.md5(open(restore, "rb").read()).hexdigest()

    # remove decrypted file
    os.remove(restore)

    restore_log = BackupLog(
        filename=os.path.splitext(os.path.basename(restore))[0],
        date_created=datetime.datetime.now(),
        method="Restore",
        source_path=encrypted,
        backup_path=file_settings["path"],
        md5=file_hash,
    )
    server_db.session.add(restore_log)
    server_db.session.commit()

    return redirect(url_for(".backup"))
