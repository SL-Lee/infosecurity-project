import datetime
import hashlib
import json
import os
import re
import shutil
import uuid
from functools import wraps
from urllib.parse import urljoin, urlparse

import marshmallow
import sqlalchemy
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from Crypto import Random
from Crypto.Cipher import AES
from flask import (
    Blueprint,
    Flask,
    abort,
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

import forms
from client_models import *
from crypto import KEY, decrypt_file, encrypt_file
from helper_functions import (
    get_config_value,
    set_config_value,
    validate_api_key,
)
from server_models import (
    Alert,
    BackupLog,
    Request,
    Rule,
    ServerPermission,
    ServerUser,
    server_db,
)

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    "server": "sqlite:///server_db.sqlite3",
}
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
csrf = CSRFProtect(app)
UPLOAD_FOLDER = "uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

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

VALID_SERVER_PERMISSION_NAMES = [
    "manage_backups",
    "manage_ip_whitelist",
    "view_logged_requests",
    "manage_sensitive_fields",
    "manage_encrypted_files",
    "manage_alerts",
    "manage_api_keys",
    "manage_users",
    "view_api_documentation",
]

with app.app_context():
    client_db.create_all()
    client_db.session.commit()

    server_db.create_all(bind="server")
    server_permissions = ServerPermission.query.all()
    server_permission_names = [
        server_permission.name for server_permission in server_permissions
    ]

    # Create missing server permission(s)
    for server_permission_name in [
        valid_server_permission_name
        for valid_server_permission_name in VALID_SERVER_PERMISSION_NAMES
        if valid_server_permission_name not in server_permission_names
    ]:
        server_db.session.add(ServerPermission(name=server_permission_name))

    # Remove any invalid server permission(s)
    for server_permission_name in [
        server_permission_name
        for server_permission_name in server_permission_names
        if server_permission_name not in VALID_SERVER_PERMISSION_NAMES
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

        timestamp_folder = os.path.join(
            backup_folder,
            secure_filename(backup_datetime.strftime("%d-%m-%Y %H:%M:%S")),
        )

        # if no timestamp folder
        if not os.path.exists(timestamp_folder):
            os.mkdir(timestamp_folder)

        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"])
        )

        shutil.copy2(file_settings["path"], file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            backup_folder, os.path.basename(file_settings["path"]) + ".enc"
        )

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


def required_permissions(*required_permission_names):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Abort with a 404 error code if current user is not authenticated
            if not current_user.is_authenticated:
                abort(404)

            # Abort with a 500 error code if not all required permissions are
            # valid
            if not all(
                permission in VALID_SERVER_PERMISSION_NAMES
                for permission in required_permission_names
            ):
                abort(500)

            # Abort with a 403 error code if not all required permissions are
            # found in the current user's list of permissions
            if not all(
                required_permission
                in [
                    user_permission.name
                    for user_permission in current_user.permissions
                ]
                for required_permission in required_permission_names
            ):
                abort(403)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ("http", "https")
        and ref_url.netloc == test_url.netloc
    )


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

        # backup folder is timestamp of backup
        backup_folder = os.path.join(
            filename_folder,
            secure_filename(backup_datetime.strftime("%d-%m-%Y %H:%M:%S")),
        )
        # check if there is a timestamp for the backup
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

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
        encrypt_file(file_backup_path, KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location) + ".enc"
        )

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

            backup_folder = os.path.join(
                filename,
                secure_filename(backup_datetime.strftime("%d-%m-%Y %H:%M:%S")),
            )
            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)
            # encrypt the backed up file
            encrypt_file(file_backup_path, KEY)
            # after encrypting the copied file,
            # remove the copied file
            os.remove(file_backup_path)
            # set new path name for encrypted file
            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"]) + ".enc"
            )

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

            backup_folder = os.path.join(
                filename,
                secure_filename(backup_datetime.strftime("%d-%m-%Y %H:%M:%S")),
            )

            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)
            # encrypt the backed up file
            encrypt_file(file_backup_path, KEY)
            # after encrypting the copied file,
            # remove the copied file
            os.remove(file_backup_path)
            # set new path name for encrypted file
            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"]) + ".enc"
            )

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
    decrypt_file(encrypted, KEY)

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
@app.route("/requests/filter=<field>", methods=["GET"])
@required_permissions("view_logged_requests")
def get_requests(field):
    alerts = Alert.query.all()
    request_filter = field
    return render_template(
        "requests.html", alerts=alerts, filter=request_filter
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
        rule = Rule(contents=form.sensitive_field.data)
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
        server_db.session.commit()

        return redirect(url_for("get_sensitive_fields"))

    return render_template("sensitive-fields-update.html", form=form, rule=rule)


@app.route("/sensitive-fields/delete/<field>", methods=["GET", "POST"])
@required_permissions("manage_sensitive_fields")
def delete_sensitive_fields(field):
    rule = Rule.query.filter_by(id=field).first_or_404()
    server_db.session.delete(rule)
    server_db.session.commit()

    return redirect(url_for("get_sensitive_fields"))


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
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        def pad(string):
            return string + b"\0" * (
                AES.block_size - len(string) % AES.block_size
            )

        def encrypt(message, key):
            message = pad(message)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(message)

        def decrypt(ciphertext, key):
            iv = ciphertext[: AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[AES.block_size :])
            return plaintext.rstrip(b"\0")

        def encrypt_file(file_name, key):
            with open(file_name, "rb") as file:
                plaintext = file.read()

            enc = encrypt(plaintext, key)

            with open(file_name + ".enc", "wb") as file:
                file.write(enc)

        def decrypt_file(file_name, key):
            with open(file_name, "rb") as file:
                ciphertext = file.read()

            dec = decrypt(ciphertext, key)

            with open(file_name[:-4] + ".dec", "wb") as file:
                file.write(dec)

        key = (
            b"\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e"
            b"[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18"
        )
        if "encrypt" in request.form:
            encrypt_file(
                os.path.join(app.config["UPLOAD_FOLDER"], filename), key
            )
            print("saved file successfully")
            # send file name as parameter to download
            return redirect("/download-file/" + filename + ".enc")

        if "decrypt" in request.form:
            decrypt_file(
                os.path.join(app.config["UPLOAD_FOLDER"], filename), key
            )
            print("saved file2 successfully")
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
    file_path = UPLOAD_FOLDER + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Download API
@app.route("/download-file2/<filename>", methods=["GET"])
@required_permissions("manage_encrypted_files")
def download_file2(filename):
    return render_template("download-file2.html", value=filename)


@app.route("/return-files2/<filename>")
@required_permissions("manage_encrypted_files")
def return_files_tut2(filename):
    file_path = UPLOAD_FOLDER + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Individual data fields encryption
@app.route("/upload-field", methods=["GET", "POST"])
def upload_field():
    form = forms.ChoiceForm()
    form.user.choices = [
        User.id,
        User.username,
        User.email,
        User.password,
        User.date_created,
        User.status,
        User.roles,
        User.reviews,
        User.orders,
        User.credit_cards,
        User.addresses,
    ]
    form.role.choices = [Role.id, Role.name, Role.description]
    form.credit_card.choices = [
        CreditCard.id,
        CreditCard.card_number,
        CreditCard.expiry,
        CreditCard.user_id,
        CreditCard.iv,
    ]
    form.address.choices = [
        Address.id,
        Address.address,
        Address.zip_code,
        Address.city,
        Address.state,
        Address.user_id,
    ]
    form.product.choices = [
        Product.product_id,
        Product.product_name,
        Product.description,
        Product.image,
        Product.price,
        Product.quantity,
        Product.deleted,
    ]
    form.review.choices = [
        Review.user_id,
        Review.product_id,
        Review.rating,
        Review.contents,
        Review.product,
    ]
    form.order.choices = [
        OrderProduct.order_id,
        OrderProduct.product_id,
        OrderProduct.quantity,
        OrderProduct.product,
    ]

    if request.method == "POST":
        # User class
        user_id = User.query.with_entities(User.id).all()
        username = User.query.with_entities(User.username).all()
        email = User.query.with_entities(User.email).all()
        password = User.query.with_entities(User.password).all()
        date_created = User.query.with_entities(User.date_created).all()
        status = User.query.with_entities(User.status).all()
        roles = User.query.with_entities(User.roles).all()
        reviews = User.query.with_entities(User.reviews).all()
        orders = User.query.with_entities(User.orders).all()
        credit_cards = User.query.with_entities(User.credit_cards).all()
        addresses = User.query.with_entities(User.addresses).all()

        # Role class
        role_id = Role.query.with_entities(Role.id).all()
        role_name = Role.query.with_entities(Role.name).all()
        role_description = Role.query.with_entities(Role.description).all()
        # role = Role.query.filter_by(id=form.role.data).first()

        # Credit Card Class
        cc_id = CreditCard.query.with_entities(CreditCard.id).all()
        card_number = CreditCard.query.with_entities(
            CreditCard.card_number
        ).all()
        expiry = CreditCard.query.with_entities(CreditCard.expiry).all()
        cc_user_id = CreditCard.query.with_entities(CreditCard.user_id).all()
        iv = CreditCard.query.with_entities(CreditCard.iv).all()
        """
        credit_card = CreditCard.query.filter_by(
           id=form.credit_card.data
        ).first()
        """

        # Address Class
        addr_id = Address.query.with_entities(Address.id).all()
        address = Address.query.with_entities(Address.address).all()
        zip_code = Address.query.with_entities(Address.zip_code).all()
        city = Address.query.with_entities(Address.city).all()
        state = Address.query.with_entities(Address.state).all()
        addr_user_id = Address.query.with_entities(Address.user_id).all()

        # Product Class
        product_id = Product.query.with_entities(Product.product_id).all()
        product_name = Product.query.with_entities(Product.product_name).all()
        product_description = Product.query.with_entities(
            Product.description
        ).all()
        image = Product.query.with_entities(Product.image).all()
        price = Product.query.with_entities(Product.price).all()
        product_quantity = Product.query.with_entities(Product.quantity).all()
        deleted = Product.query.with_entities(Product.deleted).all()

        # Review Class
        review_user_id = Review.query.with_entities(Review.user_id).all()
        review_product_id = Review.query.with_entities(Review.product_id).all()
        rating = Review.query.with_entities(Review.rating).all()
        contents = Review.query.with_entities(Review.contents).all()
        review_product = Review.query.with_entities(Review.product).all()

        # Order Product Class
        order_id = OrderProduct.query.with_entities(OrderProduct.order_id).all()
        order_product_id = OrderProduct.query.with_entities(
            OrderProduct.product_id
        ).all()
        order_quantity = OrderProduct.query.with_entities(
            OrderProduct.quantity
        ).all()
        order_product = OrderProduct.query.with_entities(
            OrderProduct.product
        ).all()

        return (
            f"<h1>User: {user_id}, Email: {email}, Status: "
            f"{status}, <br> User Role: {role_name}, Role ID: "
            f"{role_id}</h1>"
        )

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
        return redirect(url_for("onboarding_database_config"))

    return render_template(
        "onboarding-admin-user-creation.html", form=create_admin_user_form
    )


@app.route("/onboarding/database-config", methods=["GET", "POST"])
@login_required
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


@app.route("/onboarding/api-config")
@login_required
@required_permissions("manage_users")
def onboarding_api_config():
    return render_template("onboarding-api-config.html")


@app.route("/onboarding/backup-config", methods=["GET", "POST"])
@login_required
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

        # backup folder is timestamp of backup
        backup_folder = os.path.join(
            filename_folder,
            secure_filename(backup_datetime.strftime("%d-%m-%Y %H:%M:%S")),
        )
        # check if there is a timestamp for the backup
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location)
        )

        # copy from original location to timestamp
        shutil.copy2(location, file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location) + ".enc"
        )

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
@login_required
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
        def log_request(alert_level, status, status_msg):
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status=status,
                status_msg=status_msg,
                request_params="Model: {}".format(args["model"]),
                response=str(args["object"]),
            )
            logged_alert = Alert(
                request=logged_request, alert_level=alert_level
            )
            return logged_request, logged_alert

        try:
            validate_api_key(request.headers.get("X-API-KEY"))

            args = self.post_parser.parse_args()

            try:
                schema = eval(f"{args['model']}Schema()")
                created_object = schema.load(args["object"])
                client_db.session.add(created_object)
                client_db.session.commit()
                serialized_created_object = schema.dump(created_object)
                status, status_msg, status_code = "OK", "OK", 200
                logged_request, logged_alert = log_request(
                    "low", status, status_msg
                )
            except marshmallow.exceptions.ValidationError:
                serialized_created_object = None
                status, status_msg, status_code = (
                    "ERROR",
                    "error while deserializing object",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )
            except (NameError, SyntaxError):
                serialized_created_object = None
                status, status_msg, status_code = (
                    "ERROR",
                    "invalid request",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )
            except sqlalchemy.exc.IntegrityError:
                serialized_created_object = None
                status, status_msg, status_code = (
                    "ERROR",
                    "database integrity error",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )
            except:
                serialized_created_object = None
                status, status_msg, status_code = (
                    "ERROR",
                    "an unknown error occurred",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
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

        except:
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
            )
            logged_alert = Alert(request=logged_request, alert_level="medium")
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

    @api.expect(get_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    @api.response(403, "Forbidden")
    def get(self):
        def log_request(alert_level, status, status_msg):
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status=status,
                status_msg=status_msg,
                request_params=(
                    f"Model: {args['model']}, Filter: {args['filter']}"
                ),
                response=str(query_results),
            )
            logged_alert = Alert(
                request=logged_request, alert_level=alert_level
            )
            return logged_request, logged_alert

        try:
            validate_api_key(request.headers.get("X-API-KEY"))
            args = self.get_parser.parse_args()

            try:
                schema = eval(f"{args['model']}Schema(many=True)")
                query_results = schema.dump(
                    client_db.session.query(eval(args["model"]))
                    .filter(eval(args["filter"]))
                    .all()
                )
                sensitive_fields = Rule.query.all()
                try:
                    whitelist = get_config_value("whitelist")
                    if args["ip"] in whitelist:
                        status, status_msg, status_code = "OK", "OK", 200
                        logged_request, logged_alert = log_request(
                            "low", status, status_msg
                        )
                    else:
                        for i in sensitive_fields:
                            pattern = "'" + i.contents + "',"
                            pattern_occurrence_count = re.findall(
                                pattern, str(query_results)
                            )

                            # if pattern occurs more than once, that means there
                            # are more than 10 sensitive data, so deny this
                            # request and log it as a high alert
                            if len(pattern_occurrence_count) > 1:
                                status, status_msg, status_code = (
                                    "ERROR",
                                    "Denied",
                                    403,
                                )
                                logged_request, logged_alert = log_request(
                                    "high", status, status_msg
                                )
                                query_results = None
                                break

                            status, status_msg, status_code = "OK", "OK", 200
                            logged_request, logged_alert = log_request(
                                "low", status, status_msg
                            )
                except:
                    status, status_msg, status_code = "OK", "OK", 200
                    logged_request, logged_alert = log_request(
                        "low", status, status_msg
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
                    "medium", status, status_msg
                )

            except:
                query_results = None
                status, status_msg, status_code = (
                    "ERROR",
                    "an unknown error occurred",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )

            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()

            return {
                "status": status,
                "status_msg": status_msg,
                "query_results": query_results,
            }, status_code
        except:
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
            )
            logged_alert = Alert(request=logged_request, alert_level="medium")
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

    @api.expect(patch_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    def patch(self):
        def log_request(alert_level, status, status_msg):
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status=status,
                status_msg=status_msg,
                request_params="Model: {}, Filter: {}".format(
                    args["model"], args["filter"]
                ),
                response=str(args["values"]),
            )
            logged_alert = Alert(
                request=logged_request, alert_level=alert_level
            )
            return logged_request, logged_alert

        try:
            validate_api_key(request.headers.get("X-API-KEY"))

            args = self.patch_parser.parse_args()

            try:
                if args["model"] == "CreditCard":
                    for field, value in args["values"].items():
                        if field in ["card_number", "iv"]:
                            binary = bytes.fromhex(value)
                            args["values"][field] = binary

                        if field == "expiry":
                            date = datetime.datetime.strptime(value, "%Y-%m-%d")
                            args["values"][field] = date

                client_db.session.query(eval(args["model"])).filter(
                    eval(args["filter"])
                ).update(args["values"])
                client_db.session.commit()
                status, status_msg, status_code = "OK", "OK", 200
                logged_request, logged_alert = log_request(
                    "low", status, status_msg
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
                    "medium", status, status_msg
                )
            except:
                status, status_msg, status_code = (
                    "ERROR",
                    "an unknown error occurred",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )

            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {"status": status, "status_msg": status_msg}, status_code
        except:
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
            )
            logged_alert = Alert(request=logged_request, alert_level="medium")
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401

    @api.expect(delete_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    @api.response(401, "Authentication failed")
    def delete(self):
        def log_request(alert_level, status, status_msg):
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status=status,
                status_msg=status_msg,
                request_params="Model: {}, Filter: {}".format(
                    args["model"], args["filter"]
                ),
                response="",
            )
            logged_alert = Alert(
                request=logged_request, alert_level=alert_level
            )
            return logged_request, logged_alert

        try:
            validate_api_key(request.headers.get("X-API-KEY"))

            args = self.delete_parser.parse_args()

            try:
                client_db.session.query(eval(args["model"])).filter(
                    eval(args["filter"])
                ).delete()
                client_db.session.commit()
                status, status_msg, status_code = "OK", "OK", 200
                logged_request, logged_alert = log_request(
                    "low", status, status_msg
                )
            except (NameError, sqlalchemy.exc.InvalidRequestError, SyntaxError):
                status, status_msg, status_code = (
                    "ERROR",
                    "invalid request",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )
            except:
                status, status_msg, status_code = (
                    "ERROR",
                    "an unknown error occurred",
                    400,
                )
                logged_request, logged_alert = log_request(
                    "medium", status, status_msg
                )

            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {"status": status, "status_msg": status_msg}, status_code

        except:
            logged_request = Request(
                datetime=datetime.datetime.now(),
                status="ERROR",
                status_msg="Authentication Failed",
                request_params="",
                response="",
            )
            logged_alert = Alert(request=logged_request, alert_level="medium")
            server_db.session.add(logged_alert)
            server_db.session.add(logged_request)
            server_db.session.commit()
            return {
                "status": "ERROR",
                "status_msg": "Authentication failed",
            }, 401


if __name__ == "__main__":
    app.run(debug=True, port=4999)
