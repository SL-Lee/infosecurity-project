import datetime
import hashlib
import json
import os
import re
import shutil
import uuid

import marshmallow
import sqlalchemy
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask import (
    Blueprint,
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_restx import Api, Resource, apidoc, inputs, reqparse
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

import constants
import forms
import yaml
from client_models import *
from crypto import decrypt, decrypt_file, encrypt, encrypt_file
from helper_functions import (
    get_config_value,
    is_safe_url,
    log_request,
    request_filter,
    required_permissions,
    set_config_value,
    validate_api_key,
)
from server_models import (
    Alert,
    BackupLog,
    Rule,
    ServerPermission,
    ServerUser,
    server_db,
)
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    "server": "sqlite:///server_db.sqlite3",
}
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"
login_manager.login_message_category = "danger"

blueprint = Blueprint("api", __name__, url_prefix="/api")
authorizations = {
    "api-key": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
}
api = Api(
    blueprint,
    title="SecureDB API",
    description="Documentation for the SecureDB API",
    authorizations=authorizations,
    security="api-key",
    doc="/doc/",
)
app.register_blueprint(blueprint)
csrf.exempt(blueprint)

client_db.init_app(app)
server_db.init_app(app)

with app.app_context():
    client_db.create_all()
    client_db.session.commit()

    server_db.create_all(bind="server")
    server_permission_names = [
        server_permission.name
        for server_permission in ServerPermission.query.all()
    ]

    # Create missing server permission(s)
    for server_permission_name in [
        valid_server_permission
        for valid_server_permission in constants.VALID_SERVER_PERMISSION_NAMES
        if valid_server_permission not in server_permission_names
    ]:
        server_db.session.add(ServerPermission(name=server_permission_name))

    # Remove any invalid server permission(s)
    for server_permission_name in [
        server_permission_name
        for server_permission_name in server_permission_names
        if server_permission_name not in constants.VALID_SERVER_PERMISSION_NAMES
    ]:
        server_db.session.delete(
            ServerPermission.query.get(server_permission_name)
        )

    server_db.session.commit()

dirname = os.path.dirname(__file__)

# only if backup folder does not exist,
# then make a backup folder
if not os.path.exists(os.path.join(dirname, "backup")):
    os.mkdir(os.path.join(dirname, "backup"))

backup_path = os.path.join(dirname, "backup")
schedule = BackgroundScheduler(
    jobstores={"default": SQLAlchemyJobStore(url="sqlite:///jobs.sqlite3")},
    daemon=True,
)
schedule.start()
drive_backup_ID = ""
if os.path.exists(os.path.join(dirname, "client_secrets.json")):
    gauth = GoogleAuth()

    drive = GoogleDrive(gauth)

    file_list = drive.ListFile(
        {"q": "'root' in parents and trashed=false"}
    ).GetList()
    folder_names = []
    for file in file_list:
        print("Title: %s, ID: %s" % (file["title"], file["id"]))
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
        print("Title: %s, ID: %s" % (file["title"], file["id"]))
        if file["title"] == "backup":
            drive_backup_ID = file["id"]


# backup function to run at interval
def schedule_backup(filename):
    with app.app_context():
        # get the config of the file
        schedule.print_jobs()
        backup_config = get_config_value("backup")
        print("backup files:", backup_config)
        file_settings = backup_config[filename]
        backup_datetime = datetime.datetime.now()
        backup_folder = os.path.join(backup_path, filename)
        # if the file does not have a backup folder
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if filename not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {"kind": "drive#fileLink", "id": drive_backup_ID}
                    ],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == filename:
                filename_ID = file["id"]

        timestamp = secure_filename(
            backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
        )
        timestamp_folder = os.path.join(
            backup_folder,
            timestamp,
        )
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if timestamp not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_ID}],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == timestamp:
                timestamp_ID = file["id"]

        # if no timestamp folder
        if not os.path.exists(timestamp_folder):
            os.mkdir(timestamp_folder)

        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"])
        )

        shutil.copy2(file_settings["path"], file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, constants.ENCRYPTION_KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"]) + ".enc"
        )
        # upload to drive
        file_upload = drive.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_ID}],
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
if len(schedule.get_jobs()) == 0:
    backup_config = get_config_value("backup")
    for filename in backup_config.keys():
        file_settings = backup_config[filename]
        if file_settings["interval_type"] == "min":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "hr":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "d":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "wk":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=file_settings["interval"],
                id=filename,
                replace_existing=True,
            )
        elif file_settings["interval_type"] == "mth":
            months = 31 * file_settings["interval"]
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=months,
                id=filename,
                replace_existing=True,
            )


@app.template_filter()
def contains_any(items, *required_items):
    return any(item in required_items for item in items)


@app.context_processor
def inject_current_user_permissions():
    current_user_permissions = (
        [user_permission.name for user_permission in current_user.permissions]
        if current_user.is_authenticated
        else None
    )
    return dict(current_user_permissions=current_user_permissions)


@login_manager.user_loader
def load_user(user_id):
    return server_db.session.query(ServerUser).get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def index():
    server_users = ServerUser.query.all()

    if not any(
        ServerPermission.query.get("manage_users") in server_user.permissions
        for server_user in server_users
    ):
        return redirect(url_for("onboarding"))

    login_form = forms.LoginForm(request.form)

    if request.method == "POST" and login_form.validate():
        server_user = ServerUser.query.filter_by(
            username=login_form.username.data
        ).first()

        if server_user is None:
            flash("Invalid username and/or password.", "danger")
            return render_template("index.html", form=login_form)

        if (
            hashlib.scrypt(
                password=login_form.password.data.encode("UTF-8"),
                salt=server_user.password_salt,
                n=16384,
                r=8,
                p=1,
            )
            == server_user.password_hash
        ):
            login_user(server_user)
            flash("Logged in successfully.", "success")

            next_url = request.args.get("next")

            if next_url is not None and is_safe_url(next_url):
                return redirect(next_url)
        else:
            flash("Invalid username and/or password.", "danger")

    return render_template(
        "index.html", form=login_form, next=request.args.get("next")
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# User management routes
@app.route("/user-management")
@required_permissions("manage_users")
def user_management():
    server_users = ServerUser.query.all()
    return render_template("user-management.html", server_users=server_users)


@app.route("/user-management/create", methods=["GET", "POST"])
@required_permissions("manage_users")
def user_management_create():
    create_user_form = forms.CreateUserForm(request.form)
    create_user_form.permissions.choices = [
        (server_permission.name, server_permission.name)
        for server_permission in ServerPermission.query.all()
    ]

    if request.method == "POST" and create_user_form.validate():
        new_server_user_password_salt = os.urandom(32)
        new_server_user_password_hash = hashlib.scrypt(
            password=create_user_form.password.data.encode("UTF-8"),
            salt=new_server_user_password_salt,
            n=16384,
            r=8,
            p=1,
        )
        new_server_user = ServerUser(
            username=create_user_form.username.data,
            password_salt=new_server_user_password_salt,
            password_hash=new_server_user_password_hash,
            date_created=datetime.datetime.now(),
        )

        for server_permission in create_user_form.permissions.data:
            new_server_user_permission = ServerPermission.query.get(
                server_permission
            )

            if new_server_user_permission is not None:
                new_server_user.permissions.append(new_server_user_permission)

        try:
            server_db.session.add(new_server_user)
            server_db.session.commit()
            flash("New user created successfully.", "success")
        except sqlalchemy.exc.IntegrityError:
            flash(
                "Another user account already has the username of '"
                f"{create_user_form.username.data}'. Please try again with a "
                "unique username.",
                "danger",
            )
            return redirect(url_for("user_management_create"))

        return redirect(url_for("user_management"))

    return render_template(
        "user-management-form.html",
        title="User Management — Create User",
        form=create_user_form,
        form_action_route=url_for("user_management_create"),
        action_name="Create",
    )


@app.route(
    "/user-management/edit/<int:server_user_id>", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def user_management_edit(server_user_id):
    edit_user_form = forms.CreateUserForm(request.form)
    edit_user_form.permissions.choices = [
        (server_permission.name, server_permission.name)
        for server_permission in ServerPermission.query.all()
    ]
    server_user = ServerUser.query.get(server_user_id)

    if request.method == "POST" and edit_user_form.validate():
        server_user.username = edit_user_form.username.data
        password_salt = os.urandom(32)
        password_hash = hashlib.scrypt(
            password=edit_user_form.password.data.encode("UTF-8"),
            salt=password_salt,
            n=16384,
            r=8,
            p=1,
        )
        server_user.password_salt = password_salt
        server_user.password_hash = password_hash

        if (
            ServerUser.query.count() == 1
            and "manage_users" not in edit_user_form.permissions.data
        ):
            flash(
                "You cannot unassign the 'manage_users' permission from the "
                "only user that has this permission.",
                "danger",
            )
            return redirect(
                url_for("user_management_edit", server_user_id=server_user_id)
            )

        if (
            server_user_id == current_user.id
            and "manage_users" not in edit_user_form.permissions.data
        ):
            flash(
                "You cannot unassign the 'manage_users' permission from the "
                "current user.",
                "danger",
            )
            return redirect(
                url_for("user_management_edit", server_user_id=server_user_id)
            )

        server_user.permissions = []

        for server_permission in edit_user_form.permissions.data:
            server_user_permission = ServerPermission.query.get(
                server_permission
            )

            if server_user_permission is not None:
                server_user.permissions.append(server_user_permission)

        try:
            server_db.session.commit()
            flash("User edited successfully.", "success")
        except sqlalchemy.exc.IntegrityError:
            flash(
                "Another user account already has the username of '"
                f"{edit_user_form.username.data}'. Please try again with a "
                "unique username.",
                "danger",
            )
            return redirect(
                url_for("user_management_edit", server_user_id=server_user_id)
            )

        return redirect(url_for("user_management"))

    edit_user_form.username.data = server_user.username
    edit_user_form.permissions.data = [
        server_permission.name for server_permission in server_user.permissions
    ]

    return render_template(
        "user-management-form.html",
        title="User Management — Edit User",
        form=edit_user_form,
        form_action_route=url_for(
            "user_management_edit", server_user_id=server_user_id
        ),
        action_name="Edit",
    )


@app.route("/user-management/delete", methods=["POST"])
@required_permissions("manage_users")
def user_management_delete():
    if ServerUser.query.count() == 1:
        flash("You cannot delete the only remaining user.", "danger")
        return redirect(url_for("user_management"))

    try:
        server_user_id = int(request.form["server-user-id"])

        if server_user_id == current_user.id:
            flash("You cannot delete the current user.", "danger")
            return redirect(url_for("user_management"))

        server_user = ServerUser.query.get(server_user_id)
        server_db.session.delete(server_user)
        server_db.session.commit()
        flash("User deleted successfully.", "success")
    except:
        flash("There was an error while deleting the user.", "danger")

    return redirect(url_for("user_management"))


# Backup functions
@app.route("/backup")
@required_permissions("manage_backups")
def backup():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    files = list(backup_config.keys())
    return render_template("backup.html", files=files)


@app.route("/temp-backup-set-default")
@required_permissions("manage_backups")
def backup_set_default():
    path = ".\\client_db.sqlite3"
    keyname = os.path.basename(path)
    interval = 1
    interval_type = "min"
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
    return redirect(url_for("backup"))


@app.route("/backup/add", methods=["GET", "POST"])
@required_permissions("manage_backups")
def backup_add():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)

    # first form, when there are no settings for the file
    form = forms.BackupFirstForm(request.form)

    if request.method == "POST" and form.validate():
        location = form.source.data
        backup_datetime = datetime.datetime.now()

        filename = os.path.basename(location)
        filename_folder = os.path.join(backup_path, filename)
        # check if the folder with the name exists,
        # else make a folder for it
        if not os.path.exists(filename_folder):
            os.mkdir(filename_folder)
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if filename not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {"kind": "drive#fileLink", "id": drive_backup_ID}
                    ],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == filename:
                filename_ID = file["id"]

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
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if timestamp not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_ID}],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == timestamp:
                timestamp_ID = file["id"]

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
        # upload to drive
        file_upload = drive.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_ID}],
            }
        )
        # set content is get file from filepath
        file_upload.SetContentFile(file_backup_path)
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
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "hr":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                hours=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "d":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "wk":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                weeks=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "mth":
            months = 31 * form.interval.data
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=months,
                id=filename,
                replace_existing=True,
            )
        schedule.print_jobs()

        return redirect(url_for("index"))

    return render_template("backup-form.html", form1=form)


@app.route("/backup/<file>", methods=["GET", "POST"])
@required_permissions("manage_backups")
def backup_history(file):
    path = os.path.join(backup_path, file)
    timestamp = os.listdir(path)
    timestamp.reverse()
    print(timestamp)

    return render_template(
        "backup-history.html", file=file, timestamp=timestamp
    )


@app.route("/backup/<file>/update", methods=["GET", "POST"])
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

            filename = os.path.join(backup_path, file)
            if not os.path.exists(filename):
                os.mkdir(filename)
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
            ).GetList()  # to list the files in the folder id
            folder_names = []
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                folder_names.append(files["title"])
            # if backup folder not created
            if file not in folder_names:
                folder = drive.CreateFile(
                    {
                        "title": file,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": drive_backup_ID}
                        ],
                    }
                )
                folder.Upload()
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
            ).GetList()
            # set drive id for backup
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                if files["title"] == file:
                    filename_ID = files["id"]

            timestamp = secure_filename(
                backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
            )
            backup_folder = os.path.join(
                filename,
                timestamp,
            )
            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_ID}
            ).GetList()  # to list the files in the folder id
            folder_names = []
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                folder_names.append(files["title"])
            # if backup folder not created
            if timestamp not in folder_names:
                folder = drive.CreateFile(
                    {
                        "title": timestamp,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": filename_ID}
                        ],
                    }
                )
                folder.Upload()
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_ID}
            ).GetList()
            # set drive id for backup
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                if files["title"] == timestamp:
                    timestamp_ID = files["id"]

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
            file_upload = drive.CreateFile(
                {
                    "title": os.path.basename(file_backup_path),
                    "parents": [{"kind": "drive#fileLink", "id": timestamp_ID}],
                }
            )
            # set content is get file from filepath
            file_upload.SetContentFile(file_backup_path)
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
            if (
                form.source.data != file_settings["path"]
                and os.path.isfile(form.source.data)
                and form.source.data != ""
            ):
                file_settings["path"] = form.source.data

            # if field different from settings and not empty
            if (
                form.interval_type.data != file_settings["interval_type"]
                and form.interval_type.data != ""
            ):
                file_settings["interval_type"] = form.interval_type.data

            # if field different from settings and not empty
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

            # create folders to be used for saving
            backup_datetime = datetime.datetime.now()
            filename = os.path.join(backup_path, file)

            if not os.path.exists(filename):
                os.mkdir(filename)
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
            ).GetList()  # to list the files in the folder id
            folder_names = []
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                folder_names.append(files["title"])
            # if backup folder not created
            if file not in folder_names:
                folder = drive.CreateFile(
                    {
                        "title": file,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": drive_backup_ID}
                        ],
                    }
                )
                folder.Upload()
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
            ).GetList()
            # set drive id for backup
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                if files["title"] == file:
                    filename_ID = files["id"]

            timestamp = secure_filename(
                backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
            )
            backup_folder = os.path.join(
                filename,
                timestamp,
            )
            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_ID}
            ).GetList()  # to list the files in the folder id
            folder_names = []
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                folder_names.append(files["title"])
            # if backup folder not created
            if timestamp not in folder_names:
                folder = drive.CreateFile(
                    {
                        "title": timestamp,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [
                            {"kind": "drive#fileLink", "id": filename_ID}
                        ],
                    }
                )
                folder.Upload()
            file_list = drive.ListFile(
                {"q": "'%s' in parents and trashed=false" % filename_ID}
            ).GetList()
            # set drive id for backup
            for files in file_list:
                print("Title: %s, ID: %s" % (files["title"], files["id"]))
                if files["title"] == timestamp:
                    timestamp_ID = files["id"]

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
            file_upload = drive.CreateFile(
                {
                    "title": os.path.basename(file_backup_path),
                    "parents": [{"kind": "drive#fileLink", "id": timestamp_ID}],
                }
            )
            # set content is get file from filepath
            file_upload.SetContentFile(file_backup_path)
            file_upload.Upload()  # Upload the file.

            file_hash = hashlib.md5(
                open(file_settings["path"], "rb").read()
            ).hexdigest()

            backup_log = BackupLog(
                filename=os.path.splitext(
                    os.path.basename(file_settings["path"])
                )[0],
                date_created=backup_datetime,
                method="Manual Backup",
                source_path=file_settings["path"],
                backup_path=file_backup_path,
                md5=file_hash,
            )
            update_log = BackupLog(
                filename=os.path.splitext(
                    os.path.basename(file_settings["path"])
                )[0],
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
                schedule.reschedule_job(
                    file,
                    trigger="interval",
                    minutes=form.interval.data,
                )
            elif form.interval_type.data == "hr":
                schedule.reschedule_job(
                    file,
                    trigger="interval",
                    hours=form.interval.data,
                )
            elif form.interval_type.data == "d":
                schedule.reschedule_job(
                    file,
                    trigger="interval",
                    days=form.interval.data,
                )
            elif form.interval_type.data == "wk":
                schedule.reschedule_job(
                    file,
                    trigger="interval",
                    weeks=form.interval.data,
                )
            elif form.interval_type.data == "mth":
                months = 31 * form.interval.data
                schedule.reschedule_job(
                    file,
                    trigger="interval",
                    days=months,
                )
            schedule.print_jobs()

        return redirect(url_for("backup"))

    return render_template("backup-form.html", form2=form)


@app.route("/backup/<file>/<timestamp>/restore")
@required_permissions("manage_backups")
def backup_restore(file, timestamp):
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    file_settings = backup_config[file]

    # path to file dir
    file_folder = os.path.join(backup_path, file)

    # path to timestamp dir
    timestamp_folder = os.path.join(file_folder, timestamp)

    # path to encrypted file
    encrypted = os.path.join(
        timestamp_folder, os.path.basename(file_settings["path"] + ".enc")
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

    return redirect(url_for("backup"))


# Whitelist
@app.route("/whitelist", methods=["GET"])
@required_permissions("manage_ip_whitelist")
def get_whitelist():
    try:
        whitelist = get_config_value("whitelist")
    except:
        whitelist = list()
    return render_template("whitelist.html", whitelist=whitelist)


@app.route("/whitelist/add", methods=["GET", "POST"])
@required_permissions("manage_ip_whitelist")
def whitelist():
    form = forms.WhitelistForm(request.form)

    if request.method == "POST" and form.validate():
        try:
            whitelist = get_config_value("whitelist")
            whitelist.append(form.ip_address.data)
        except:
            whitelist = list()
            whitelist.append(form.ip_address.data)
        set_config_value("whitelist", whitelist)

        return redirect(url_for("get_whitelist"))

    return render_template("whitelist-add.html", form=form)


@app.route("/whitelist/delete/<field>", methods=["GET", "POST"])
@required_permissions("manage_ip_whitelist")
def delete_whitelist(field):
    whitelist = get_config_value("whitelist")
    whitelist.remove(field)
    set_config_value("whitelist", whitelist)

    return redirect(url_for("get_whitelist"))


# Requests
@app.route("/requests/<alert_level>/<date>/<query>", methods=["GET", "POST"])
@required_permissions("view_logged_requests")
def get_requests(query, alert_level, date):
    form = forms.RequestFilter(request.form)

    if request.method == "POST" and form.validate():
        if form.query.data == "":
            form.query.data = "<query>"
        return redirect(
            "/requests/{}/{}/{}".format(
                form.alert_level.data, form.date.data, form.query.data
            )
        )

    # Filter alert list according to alert_level
    if alert_level == "None":
        alerts = Alert.query.all()
    else:
        alerts = Alert.query.filter_by(alert_level=alert_level).all()
    alert_list = request_filter(alerts, date, query)

    form.alert_level.data = alert_level

    # if query is empty, display in form empty string
    if query == "<query>":
        form.query.data = ""
    else:
        form.query.data = query

    return render_template(
        "requests.html", alerts=alert_list, filter=alert_level, form=form
    )


# Configure Sensitive Fields
@app.route("/sensitive-fields", methods=["GET"])
@required_permissions("manage_sensitive_fields")
def get_sensitive_fields():
    sensitive_fields = Rule.query.all()
    return render_template(
        "sensitive-fields.html", sensitive_fields=sensitive_fields
    )


@app.route("/sensitive-fields/add", methods=["GET", "POST"])
@required_permissions("manage_sensitive_fields")
def add_sensitive_fields():
    form = forms.SensitiveFieldForm(request.form)

    if request.method == "POST" and form.validate():
        rule = Rule(
            contents=form.sensitive_field.data,
            action=form.action.data,
            alert_level=form.alert_level.data,
            occurrence_threshold=form.occurrence_threshold.data,
        )
        server_db.session.add(rule)
        server_db.session.commit()

        return redirect(url_for("get_sensitive_fields"))

    return render_template("sensitive-fields-add.html", form=form)


@app.route("/sensitive-fields/update/<field>", methods=["GET", "POST"])
@required_permissions("manage_sensitive_fields")
def update_sensitive_fields(field):
    form = forms.SensitiveFieldForm(request.form)
    rule = Rule.query.filter_by(id=field).first_or_404()

    if request.method == "POST" and form.validate():
        rule.contents = form.sensitive_field.data
        rule.action = form.action.data
        rule.alert_level = form.alert_level.data
        rule.occurrence_threshold = form.occurrence_threshold.data
        server_db.session.commit()

        return redirect(url_for("get_sensitive_fields"))

    form.sensitive_field.data = rule.contents
    form.action.data = rule.action
    form.occurrence_threshold.data = rule.occurrence_threshold

    return render_template("sensitive-fields-update.html", form=form, rule=rule)


@app.route("/sensitive-fields/delete/<field>", methods=["GET", "POST"])
@required_permissions("manage_sensitive_fields")
def delete_sensitive_fields(field):
    rule = Rule.query.filter_by(id=field).first_or_404()
    server_db.session.delete(rule)
    server_db.session.commit()

    return redirect(url_for("get_sensitive_fields"))


# Encryption key management
@app.route("/encryption/key-management")
@required_permissions("manage_encryption_key")
def encryption_key_management():
    encryption_key_timestamp = get_config_value("encryption-config").get(
        "timestamp", None
    )
    return render_template(
        "encryption-key-management.html",
        encryption_key_timestamp=encryption_key_timestamp,
    )


@app.route("/encryption/key-management/generate", methods=["POST"])
def encryption_key_management_generate():
    # if get_config_value("encryption-config") is not None:
    #     return redirect(url_for("encryption_key_management"))

    encryption_passphrase = request.form.get("encryption-passphrase")

    if encryption_passphrase is None:
        flash(
            "An error occurred while generating the encryption key. Please "
            "try again.",
            "danger",
        )
        return redirect(url_for("encryption_key_management_generate"))

    encryption_config = {}

    dek = os.urandom(32)

    kek_salt = os.urandom(32)
    kek = hashlib.scrypt(
        encryption_passphrase.encode("UTF-8"),
        salt=kek_salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

    encryption_config["timestamp"] = datetime.datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S+08:00"
    )
    encryption_config["kek-salt"] = kek_salt.hex()
    encryption_config["kek-hash"] = hashlib.sha3_512(kek).hexdigest()
    encryption_config["encrypted-dek"] = encrypt(dek, kek).hex()

    set_config_value("encryption-config", encryption_config)
    return redirect(url_for("encryption_key_management"))


@app.route("/encryption/key-management/reset-passphrase", methods=["POST"])
def encryption_reset_passphrase():
    encryption_config = get_config_value("encryption-config")

    if encryption_config is None:
        return redirect(url_for("onboarding_encryption_config"))

    old_encryption_passphrase = request.form.get("old-encryption-passphrase")
    new_encryption_passphrase = request.form.get("new-encryption-passphrase")
    confirm_new_encryption_passphrase = request.form.get(
        "confirm-new-encryption-passphrase"
    )

    # Return an error if any of the required fields are somehow empty
    if any(
        field is None
        for field in [
            old_encryption_passphrase,
            new_encryption_passphrase,
            confirm_new_encryption_passphrase,
        ]
    ):
        flash(
            "There was an error while resetting the encryption passphase. "
            "Please try again.",
            "danger",
        )
        return redirect(url_for("encryption_key_management"))

    old_kek = hashlib.scrypt(
        old_encryption_passphrase.encode("UTF-8"),
        salt=bytes.fromhex(encryption_config["kek-salt"]),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

    # Return an error if the old kek is wrong
    if hashlib.sha3_512(old_kek).hexdigest() != encryption_config["kek-hash"]:
        flash(
            "There was an error while resetting the encryption passphase. "
            "Please try again.",
            "danger",
        )
        return redirect(url_for("encryption_key_management"))

    # Return an error if new encryption passphrases do not match
    if new_encryption_passphrase != confirm_new_encryption_passphrase:
        flash(
            "New encryption passphrases do not match. Please try again.",
            "danger",
        )
        return redirect(url_for("encryption_key_management"))

    new_kek_salt = os.urandom(32)
    new_kek = hashlib.scrypt(
        new_encryption_passphrase.encode("UTF-8"),
        salt=new_kek_salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )

    dek = decrypt(bytes.fromhex(encryption_config["encrypted-dek"]), old_kek)

    encryption_config["timestamp"] = datetime.datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S+08:00"
    )
    encryption_config["kek-salt"] = new_kek_salt.hex()
    encryption_config["kek-hash"] = hashlib.sha3_512(new_kek).hexdigest()
    encryption_config["encrypted-dek"] = encrypt(dek, new_kek).hex()

    set_config_value("encryption-config", encryption_config)
    flash("Encryption passphrase resetted successfully.", "success")
    return redirect(url_for("encryption_key_management"))


# Upload API
@app.route("/upload-file", methods=["GET", "POST"])
@required_permissions("manage_encrypted_files")
def upload_file():
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            print("no file")
            return redirect(request.url)

        file = request.files["file"]

        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == "":
            flash("No file", "danger")
            print("no filename")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file.save(os.path.join("uploads/", filename))

        if "encrypt" in request.form:
            encrypt_file(
                os.path.join("uploads/", filename), constants.ENCRYPTION_KEY
            )
            print("saved file successfully")
            # delete uploaded file
            os.remove(os.path.join("uploads/", filename))
            # send file name as parameter to download
            return redirect("/download-file/" + filename + ".enc")

        if "decrypt" in request.form:
            decrypt_file(
                os.path.join("uploads/", filename), constants.ENCRYPTION_KEY
            )
            print("saved file2 successfully")
            os.remove(os.path.join("uploads/", filename))
            # send file name as parameter to download
            return redirect("/download-file2/" + filename[:-4] + ".dec")

    return render_template("upload-file.html")


# Download API
@app.route("/download-file/<filename>", methods=["GET"])
@required_permissions("manage_encrypted_files")
def download_file(filename):
    return render_template("download-file.html", value=filename)


@app.route("/return-files/<filename>")
@required_permissions("manage_encrypted_files")
def return_files_tut(filename):
    file_path = "uploads/" + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Download API
@app.route("/download-file2/<filename>", methods=["GET"])
@required_permissions("manage_encrypted_files")
def download_file2(filename):
    file_path = "uploads/" + filename

    def generate():
        with open(file_path) as file:
            yield from file

        os.remove(file_path)

    download_request = app.response_class(generate())
    download_request.headers.set(
        "Content-Disposition", "attachment", filename=filename
    )
    return download_request


@app.route("/return-files2/<filename>")
@required_permissions("manage_encrypted_files")
def return_files_tut2(filename):
    file_path = "uploads/" + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Individual data fields encryption
@app.route("/upload-field", methods=["GET", "POST"])
@required_permissions("manage_encrypted_fields")
def upload_field():
    # pylint: disable=pointless-string-statement
    # pylint: disable=unused-variable

    form = forms.ChoiceForm()
    form.user.choices = [
        None,
        User.username,
        User.email,
        User.password,
    ]
    form.role.choices = [None, Role.name, Role.description]
    form.credit_card.choices = [
        None,
        CreditCard.card_number,
        CreditCard.iv,
    ]
    form.address.choices = [
        None,
        Address.address,
        Address.zip_code,
        Address.city,
        Address.state,
    ]
    form.product.choices = [
        None,
        Product.product_name,
        Product.description,
        Product.image,
        Product.quantity,
    ]
    form.review.choices = [None, Review.rating, Review.contents]
    form.order.choices = [None, OrderProduct.quantity]

    if request.method == "POST":
        encrypted_fields = get_config_value(
            "encrypted-fields",
            {
                "User": [],
                "Role": [],
                "CreditCard": [],
                "Address": [],
                "Product": [],
                "Review": [],
                "OrderProduct": [],
            },
        )

        # User class
        for user in User.query.all():
            if form.user.data == "User.username":
                user.username = encrypt(
                    str(user.username), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "username" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("username")

                # print(encrypted_fields)
            elif form.user.data == "User.email":
                user.email = encrypt(
                    str(user.email), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "email" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("email")

                # print(encrypted_fields)
            elif form.user.data == "User.password":
                user.password = encrypt(
                    str(user.password), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "password" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("password")

                # print(encrypted_fields)
            else:
                print("not found")

        # Role class
        for role in Role.query.all():
            if form.role.data == "Role.name":
                role.name = encrypt(
                    str(role.name), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "name" not in encrypted_fields["Role"]:
                    encrypted_fields["Role"].append("name")

                # print(encrypted_fields)
            elif form.role.data == "Role.description":
                role.description = encrypt(
                    str(role.description), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "description" not in encrypted_fields["Role"]:
                    encrypted_fields["Role"].append("description")

                # print(encrypted_fields)
            else:
                print("not found")

        # Credit Card Class
        for credit_card in CreditCard.query.all():
            if form.credit_card.data == "CreditCard.card_number":
                credit_card.card_number = encrypt(
                    str(credit_card.card_number), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "card_number" not in encrypted_fields["CreditCard"]:
                    encrypted_fields["CreditCard"].append("card_number")

                # print(encrypted_fields)
            elif form.credit_card.data == "CreditCard.iv":
                credit_card.iv = encrypt(
                    str(credit_card.iv), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "iv" not in encrypted_fields["CreditCard"]:
                    encrypted_fields["CreditCard"].append("iv")

                # print(encrypted_fields)
            else:
                print("not found")

        # Address Class
        for address in Address.query.all():
            if form.address.data == "Address.address":
                address.address = encrypt(
                    str(address.address), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "address" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("address")

                # print(encrypted_fields)
            elif form.address.data == "Address.zip_code":
                address.zip_code = encrypt(
                    str(address.zip_code), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "zip_code" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("zip_code")

                # print(encrypted_fields)
            elif form.address.data == "Address.city":
                address.city = encrypt(
                    str(address.city), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "city" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("city")

                # print(encrypted_fields)
            elif form.address.data == "Address.state":
                address.state = encrypt(
                    str(address.state), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "state" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("state")

                # print(encrypted_fields)
            else:
                print("not found")

        # Product Class
        for product in Product.query.all():
            if form.product.data == "Product.product_name":
                product.product_name = encrypt(
                    str(product.product_name), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "product_name" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("product_name")

                # print(encrypted_fields)
            elif form.product.data == "Product.description":
                product.description = encrypt(
                    str(product.description), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "description" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("description")

                # print(encrypted_fields)
            elif form.product.data == "Product.image":
                product.image = encrypt(
                    str(product.image), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "image" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("image")

                # print(encrypted_fields)
            elif form.product.data == "Product.quantity":
                product.quantity = encrypt(
                    str(product.quantity), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "quantity" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("quantity")

                # print(encrypted_fields)
            else:
                print("not found")

        # Review Class
        for review in Review.query.all():
            if form.review.data == "Review.rating":
                review.rating = encrypt(
                    str(review.rating), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "rating" not in encrypted_fields["Review"]:
                    encrypted_fields["Review"].append("rating")

                # print(encrypted_fields)
            elif form.review.data == "Review.contents":
                review.contents = encrypt(
                    str(review.contents), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "contents" not in encrypted_fields["Review"]:
                    encrypted_fields["Review"].append("contents")

                # print(encrypted_fields)
            else:
                print("not found")

        # Order Product Class
        for order in OrderProduct.query.all():
            if form.order.data == "OrderProduct.quantity":
                order.quantity = encrypt(
                    str(order.quantity), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "quantity" not in encrypted_fields["OrderProduct"]:
                    encrypted_fields["OrderProduct"].append("quantity")

                # print(encrypted_fields)
            else:
                print("not found")

        set_config_value("encrypted-fields", encrypted_fields)
        return redirect(url_for("index"))

    return render_template("upload-field.html", form=form)


# Alert Function
@app.route("/alert")
@required_permissions("manage_alerts")
def alert():
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    files = list(alert_config.keys())
    return render_template("alert.html", files=files)


@app.route("/temp-alert-set-default")
@required_permissions("manage_alerts")
def alert_set_default():
    path = ".\\server_db.sqlite3"
    interval = 1
    interval_type = "min"
    server_db_config = {
        "server_db": {
            "path": path,
            "interval": interval,
            "interval_type": interval_type,
        }
    }
    set_config_value("alert", server_db_config)
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    print(alert_config["server_db"]["path"])
    print(os.path.isfile(alert_config["server_db"]["path"]))
    return redirect(url_for("alert"))


# Onboarding routes
@app.route("/onboarding")
def onboarding():
    return redirect(url_for("onboarding_admin_user_creation"))


@app.route("/onboarding/admin-user-creation", methods=["GET", "POST"])
def onboarding_admin_user_creation():
    create_admin_user_form = forms.CreateAdminUserForm(request.form)

    if request.method == "POST" and create_admin_user_form.validate():
        new_admin_user_password_salt = os.urandom(32)
        new_admin_user_password_hash = hashlib.scrypt(
            password=create_admin_user_form.password.data.encode("UTF-8"),
            salt=new_admin_user_password_salt,
            n=16384,
            r=8,
            p=1,
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
        return redirect(url_for("onboarding_database_config"))

    return render_template(
        "onboarding-admin-user-creation.html", form=create_admin_user_form
    )


@app.route("/onboarding/database-config", methods=["GET", "POST"])
@required_permissions("manage_users")
def onboarding_database_config():
    if request.method == "POST":
        db_file = request.files.get("db-file")

        if db_file is not None and db_file.filename.endswith(".sqlite3"):
            db_file.save(secure_filename("client_db.sqlite3"))
        else:
            flash(
                "The database file seems to be of an incorrect format. Please "
                "try again.",
                "danger",
            )
            return redirect(url_for("onboarding_database_config"))

        db_models = request.files.get("db-models")

        if db_models is not None and db_models.filename.endswith(".py"):
            db_models.save(secure_filename("client_models.py"))
        else:
            flash(
                "The database models file seems to be of an incorrect format. "
                "Please try again.",
                "danger",
            )
            return redirect(url_for("onboarding_database_config"))

        return redirect(url_for("onboarding_api_config"))

    return render_template("onboarding-database-config.html")


@app.route("/onboarding/encryption-config", methods=["GET", "POST"])
# @required_permissions("manage_users")
def onboarding_encryption_config():
    if request.method == "POST":
        encryption_passphrase = request.form.get("encryption-passphrase")

        if encryption_passphrase is None:
            flash(
                "An error occurred while generating the encryption key. Please "
                "try again.",
                "danger",
            )
            return redirect(url_for("onboarding_encryption_config"))

        encryption_config = {}

        dek = os.urandom(32)

        kek_salt = os.urandom(32)
        kek = hashlib.scrypt(
            encryption_passphrase.encode("UTF-8"),
            salt=kek_salt,
            n=16384,
            r=8,
            p=1,
            dklen=32,
        )

        encryption_config["timestamp"] = datetime.datetime.now().strftime(
            "%Y-%m-%dT%H:%M:%S+08:00"
        )
        encryption_config["kek-salt"] = kek_salt.hex()
        encryption_config["kek-hash"] = hashlib.sha3_512(kek).hexdigest()
        encryption_config["encrypted-dek"] = encrypt(dek, kek).hex()

        set_config_value("encryption-config", encryption_config)
        return redirect(url_for("onboarding_api_config"))

    return render_template("onboarding-encryption-config.html")


@app.route("/onboarding/api-config")
@required_permissions("manage_users")
def onboarding_api_config():
    return render_template("onboarding-api-config.html")


@app.route("/onboarding/drive-upload-config", methods=["GET", "POST"])
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
            documents = yaml.dump(setting, file)

        gauth = GoogleAuth()

        drive = GoogleDrive(gauth)

        file_list = drive.ListFile(
            {"q": "'root' in parents and trashed=false"}
        ).GetList()
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
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
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == "backup":
                drive_backup_ID = file["id"]

        return redirect(url_for("onboarding_backup_config"))

    return render_template("onboarding-drive-upload-config.html", form=form)


@app.route("/onboarding/backup-config", methods=["GET", "POST"])
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
        filename_folder = os.path.join(backup_path, filename)
        # check if the folder with the name exists,
        # else make a folder for it
        if not os.path.exists(filename_folder):
            os.mkdir(filename_folder)
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if filename not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {"kind": "drive#fileLink", "id": drive_backup_ID}
                    ],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % drive_backup_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == filename:
                filename_ID = file["id"]

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
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            folder_names.append(file["title"])
        # if backup folder not created
        if timestamp not in folder_names:
            folder = drive.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_ID}],
                }
            )
            folder.Upload()
        file_list = drive.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_ID}
        ).GetList()
        # set drive id for backup
        for file in file_list:
            print("Title: %s, ID: %s" % (file["title"], file["id"]))
            if file["title"] == timestamp:
                timestamp_ID = file["id"]

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
        file_upload = drive.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_ID}],
            }
        )
        # set content is get file from filepath
        file_upload.SetContentFile(file_backup_path)
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
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                minutes=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "hr":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                hours=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "d":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "wk":
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                weeks=form.interval.data,
                id=filename,
                replace_existing=True,
            )
        elif form.interval_type.data == "mth":
            months = 31 * form.interval.data
            schedule.add_job(
                schedule_backup,
                args=[filename],
                trigger="interval",
                days=months,
                id=filename,
                replace_existing=True,
            )
        schedule.print_jobs()
        return redirect(url_for("onboarding_review_settings"))
    return render_template("onboarding-backup-config.html", form=form)


@app.route("/onboarding/review-settings")
@required_permissions("manage_users")
def onboarding_review_settings():
    return render_template("onboarding-review-settings.html")


# API key management routes
@app.route("/api/key-management")
@required_permissions("manage_api_keys")
def api_key_management():
    api_keys = get_config_value("api-keys", [])
    current_datetime = datetime.datetime.now()

    for api_key in api_keys:
        if current_datetime - datetime.datetime.strptime(
            api_key["timestamp"], "%Y-%m-%dT%H:%M:%S+08:00"
        ) > datetime.timedelta(days=60):
            flash(
                f"The API key named '{api_key['name']}' was generated over 60 "
                "days ago. Consider revoking the key and generating a new one "
                "for increased security.",
                "warning",
            )

    return render_template(
        "api-key-management.html",
        api_keys=get_config_value("api-keys"),
    )


@app.route("/api/key-management/rename", methods=["POST"])
@required_permissions("manage_api_keys")
def api_key_rename():
    api_keys = get_config_value("api-keys", [])

    try:
        api_key_index = int(request.form["rename-api-key-index"])
        new_api_key_name = request.form.get("new-api-key-name", "New API Key")
        api_keys[api_key_index]["name"] = new_api_key_name
        set_config_value("api-keys", api_keys)
    except:
        flash("There was an error while renaming the API key.", "danger")
        return redirect(url_for("api_key_management"))

    flash("The API key was renamed successfully.", "success")
    return redirect(url_for("api_key_management"))


@app.route("/api/key-management/revoke", methods=["POST"])
@required_permissions("manage_api_keys")
def api_key_revoke():
    api_keys = get_config_value("api-keys", [])

    try:
        api_key_index = int(request.form["revoke-api-key-index"])
        del api_keys[api_key_index]
        set_config_value("api-keys", api_keys)
    except:
        flash("There was an error while revoking the API key.", "danger")
        return redirect(url_for("api_key_management"))

    flash("The API key was revoked successfully.", "success")
    return redirect(url_for("api_key_management"))


@app.route("/api/key-management/generate", methods=["POST"])
@required_permissions("manage_api_keys")
def api_key_generate():
    api_key = uuid.uuid4()
    api_keys = get_config_value("api-keys", [])
    api_keys.append(
        {
            "name": request.form.get("api-key-name", "New API Key"),
            "hash": hashlib.sha3_512(api_key.bytes).hexdigest(),
            "timestamp": datetime.datetime.now().strftime(
                "%Y-%m-%dT%H:%M:%S+08:00"
            ),
        }
    )
    set_config_value("api-keys", api_keys)
    return jsonify(
        {
            "status": "OK",
            "new-api-key-name": request.form.get("api-key-name", "New API Key"),
            "new-api-key": api_key.hex,
        }
    )


# API documentation route
@api.documentation
@required_permissions("view_api_documentation")
def api_documentation():
    return apidoc.ui_for(api)


# API routes
@api.route("/database")
class Database(Resource):
    base_parser = reqparse.RequestParser(bundle_errors=True)
    base_parser.add_argument(
        "X-API-KEY",
        required=True,
        type=validate_api_key,
        location="headers",
    )
    base_parser.add_argument("model", required=True, type=str, location="form")
    base_parser.add_argument("filter", required=True, type=str, location="form")

    # Parser for POST requests
    post_parser = base_parser.copy()
    post_parser.remove_argument("filter")
    post_parser.add_argument(
        "object",
        required=True,
        type=json.loads,
        location="form",
    )

    # Parser for GET requests
    get_parser = base_parser.copy()
    get_parser.replace_argument(
        "model",
        required=True,
        type=str,
        location="args",
    )
    get_parser.replace_argument(
        "filter",
        required=True,
        type=str,
        location="args",
    )
    get_parser.add_argument(
        "ip",
        required=True,
        type=inputs.ipv4,
        location="args",
    )

    # Parser for PATCH requests
    patch_parser = base_parser.copy()
    patch_parser.add_argument(
        "values",
        required=True,
        type=json.loads,
        location="form",
    )

    # Parser for DELETE requests
    delete_parser = base_parser.copy()

    @api.expect(post_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    def post(self):
        args = self.post_parser.parse_args()

        # Attempt to validate the received API key. If the API key is not found
        # or found to be invalid, then return a 401 UNAUTHORIZED response.
        try:
            validate_api_key(request.headers.get("X-API-KEY"))
        except:
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
                ip_address=args["ip"],
            )
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

        try:
            schema = eval(f"{args['model']}Schema()")
            created_object = schema.load(args["object"])

            encrypted_fields = get_config_value(
                "encrypted-fields",
                {
                    "User": [],
                    "Role": [],
                    "CreditCard": [],
                    "Address": [],
                    "Product": [],
                    "Review": [],
                    "OrderProduct": [],
                },
            )

            if args["model"] in encrypted_fields:
                for encrypted_field_name in encrypted_fields[args["model"]]:
                    setattr(
                        created_object,
                        encrypted_field_name,
                        encrypt(
                            getattr(created_object, encrypted_field_name),
                            constants.ENCRYPTION_KEY,
                        ).hex(),
                    )

            client_db.session.add(created_object)
            client_db.session.commit()

            if args["model"] in encrypted_fields:
                for encrypted_field_name in encrypted_fields[args["model"]]:
                    setattr(
                        created_object,
                        encrypted_field_name,
                        decrypt(
                            getattr(created_object, encrypted_field_name),
                            constants.ENCRYPTION_KEY,
                        ),
                    )

            serialized_created_object = schema.dump(created_object)
            status, status_msg, status_code = "OK", "OK", 200
            logged_request, logged_alert = log_request(
                alert_level="Low",
                status=status,
                status_msg=status_msg,
                request_params=f"Model: {args['model']}",
                response=str(args["object"]),
                ip_address=args["ip"],
            )
        except marshmallow.exceptions.ValidationError:
            serialized_created_object = None
            status, status_msg, status_code = (
                "ERROR",
                "error while deserializing object",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=f"Model: {args['model']}",
                response=str(args["object"]),
                ip_address=args["ip"],
            )
        except (NameError, SyntaxError):
            serialized_created_object = None
            status, status_msg, status_code = (
                "ERROR",
                "invalid request",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=f"Model: {args['model']}",
                response=str(args["object"]),
                ip_address=args["ip"],
            )
        except sqlalchemy.exc.IntegrityError:
            serialized_created_object = None
            status, status_msg, status_code = (
                "ERROR",
                "database integrity error",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=f"Model: {args['model']}",
                response=str(args["object"]),
                ip_address=args["ip"],
            )
        except:
            serialized_created_object = None
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=f"Model: {args['model']}",
                response=str(args["object"]),
                ip_address=args["ip"],
            )
        finally:
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()

        return {
            "status": status,
            "status_msg": status_msg,
            "created_object": serialized_created_object,
        }, status_code

    @api.expect(get_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    @api.response(403, "Forbidden")
    def get(self):
        args = self.get_parser.parse_args()

        # Attempt to validate the received API key. If the API key is not found
        # or found to be invalid, then return a 401 UNAUTHORIZED response.
        try:
            validate_api_key(request.headers.get("X-API-KEY"))
        except:
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
                ip_address=args["ip"],
            )
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

        try:
            schema = eval(f"{args['model']}Schema(many=True)")
            query_results = (
                client_db.session.query(eval(args["model"]))
                .filter(eval(args["filter"]))
                .all()
            )
            encrypted_fields = get_config_value(
                "encrypted-fields",
                {
                    "User": [],
                    "Role": [],
                    "CreditCard": [],
                    "Address": [],
                    "Product": [],
                    "Review": [],
                    "OrderProduct": [],
                },
            )

            if args["model"] in encrypted_fields:
                for obj in query_results:
                    for encrypted_field_name in encrypted_fields[args["model"]]:
                        setattr(
                            obj,
                            encrypted_field_name,
                            decrypt(
                                bytes.fromhex(
                                    getattr(obj, encrypted_field_name)
                                ),
                                constants.ENCRYPTION_KEY,
                            ),
                        )

            query_results = schema.dump(query_results)

            sensitive_fields = Rule.query.all()
            whitelist = get_config_value("whitelist")
            if args.get("ip") not in whitelist:
                for i in sensitive_fields:
                    pattern = f"'{i.contents}',"
                    pattern_occurrence_count = re.findall(
                        pattern, str(query_results)
                    )
                    print(i.action)
                    # If pattern occurs more than once, that means there is
                    # more than 1 occurrence of sensitive data, so deny this
                    # request and log it as a high alert
                    if len(pattern_occurrence_count) > i.occurrence_threshold:
                        print("exceed")

                        if i.action == "deny_and_alert":
                            status, status_msg, status_code = (
                                "ERROR",
                                "Denied",
                                403,
                            )
                            logged_request, logged_alert = log_request(
                                alert_level=i.alert_level,
                                status=status,
                                status_msg=status_msg,
                                request_params=(
                                    f"Model: {args['model']}, Filter: "
                                    f"{args['filter']}"
                                ),
                                response=str(query_results),
                                ip_address=args["ip"],
                            )
                            return {
                                "status": status,
                                "status_msg": status_msg,
                            }, status_code

                        status, status_msg, status_code = (
                            "OK",
                            "Sensitive Field Triggered - " + i.contents,
                            200,
                        )
                        logged_request, logged_alert = log_request(
                            alert_level=i.alert_level,
                            status=status,
                            status_msg=status_msg,
                            request_params=(
                                f"Model: {args['model']}, Filter: "
                                f"{args['filter']}"
                            ),
                            response=str(query_results),
                            ip_address=args["ip"],
                        )
                        # need a diff return statement as this is alert only,
                        # so request should still be allowed
                        return {
                            "status": status,
                            "status_msg": status_msg,
                            "query_results": query_results,
                        }, status_code

            status, status_msg, status_code = "OK", "OK", 200
            logged_request, logged_alert = log_request(
                alert_level="Low",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(query_results),
                ip_address=args["ip"],
            )
        except (
            sqlalchemy.exc.InvalidRequestError,
            AttributeError,
            NameError,
            SyntaxError,
        ):
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "invalid request",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(query_results),
                ip_address=args["ip"],
            )
        except:
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(query_results),
                ip_address=args["ip"],
            )
        finally:
            server_db.session.add(logged_request)
            server_db.session.add(logged_alert)
            server_db.session.commit()

        return {
            "status": status,
            "status_msg": status_msg,
            "query_results": query_results,
        }, status_code

    @api.expect(patch_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    def patch(self):
        args = self.patch_parser.parse_args()

        # Attempt to validate the received API key. If the API key is not found
        # or found to be invalid, then return a 401 UNAUTHORIZED response.
        try:
            validate_api_key(request.headers.get("X-API-KEY"))
        except:
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
                ip_address=args["ip"],
            )
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

        try:
            if args["model"] == "CreditCard":
                for field, value in args["values"].items():
                    if field in ["card_number", "iv"]:
                        binary = bytes.fromhex(value)
                        args["values"][field] = binary

                    if field == "expiry":
                        date = datetime.datetime.strptime(value, "%Y-%m-%d")
                        args["values"][field] = date

            encrypted_fields = get_config_value(
                "encrypted-fields",
                {
                    "User": [],
                    "Role": [],
                    "CreditCard": [],
                    "Address": [],
                    "Product": [],
                    "Review": [],
                    "OrderProduct": [],
                },
            )

            if args["model"] in encrypted_fields:
                for field_name in args["values"]:
                    if field_name in encrypted_fields[args["model"]]:
                        args["values"][field_name] = encrypt(
                            args["values"][field_name], constants.ENCRYPTION_KEY
                        ).hex()

            client_db.session.query(eval(args["model"])).filter(
                eval(args["filter"])
            ).update(args["values"])
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
            logged_request, logged_alert = log_request(
                alert_level="Low",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(args["values"]),
                ip_address=args["ip"],
            )
        except (
            NameError,
            sqlalchemy.exc.InvalidRequestError,
            sqlalchemy.exc.StatementError,
            SyntaxError,
        ):
            status, status_msg, status_code = (
                "ERROR",
                "invalid request",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(args["values"]),
                ip_address=args["ip"],
            )
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(args["values"]),
                ip_address=args["ip"],
            )

        server_db.session.add(logged_alert)
        server_db.session.add(logged_request)
        server_db.session.commit()
        return {"status": status, "status_msg": status_msg}, status_code

    @api.expect(delete_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    def delete(self):
        args = self.delete_parser.parse_args()

        # Attempt to validate the received API key. If the API key is not found
        # or found to be invalid, then return a 401 UNAUTHORIZED response.
        try:
            validate_api_key(request.headers.get("X-API-KEY"))
        except:
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
                ip_address=args["ip"],
            )
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

        try:
            client_db.session.query(eval(args["model"])).filter(
                eval(args["filter"])
            ).delete()
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
            logged_request, logged_alert = log_request(
                alert_level="Low",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response="",
                ip_address=args["ip"],
            )
        except (NameError, sqlalchemy.exc.InvalidRequestError, SyntaxError):
            status, status_msg, status_code = (
                "ERROR",
                "invalid request",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response="",
                ip_address=args["ip"],
            )
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            logged_request, logged_alert = log_request(
                alert_level="Medium",
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response="",
                ip_address=args["ip"],
            )

        server_db.session.add(logged_alert)
        server_db.session.add(logged_request)
        server_db.session.commit()
        return {"status": status, "status_msg": status_msg}, status_code


if __name__ == "__main__":
    app.run(debug=True, port=4999)
