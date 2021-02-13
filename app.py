import datetime
import hashlib
import os

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

import constants
import forms
from blueprints import (
    alert_blueprint,
    api_blueprint,
    api_key_management_blueprint,
    backup_blueprint,
    dashboard_blueprint,
    documentation_blueprint,
    encryption_blueprint,
    encryption_key_management_blueprint,
    onboarding_blueprint,
    requests_blueprint,
    sensitive_fields_blueprint,
    user_management_blueprint,
    whitelist_blueprint,
)
from client_models import client_db
from helper_functions import is_safe_url
from server_models import (
    Alert,
    BackupLog,
    Request,
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
app.config.update(
    dict(
        DEBUG=True,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_DEFAULT_SENDER="asecuredb@gmail.com",
        MAIL_USERNAME="asecuredb@gmail.com",
        MAIL_PASSWORD="securedb123",
    )
)

app.register_blueprint(alert_blueprint.alert_blueprint)
app.register_blueprint(api_blueprint.api_blueprint)
app.register_blueprint(
    api_key_management_blueprint.api_key_management_blueprint
)
app.register_blueprint(backup_blueprint.backup_blueprint)
app.register_blueprint(dashboard_blueprint.dashboard_blueprint)
app.register_blueprint(documentation_blueprint.documentation_blueprint)
app.register_blueprint(encryption_blueprint.encryption_blueprint)
app.register_blueprint(
    encryption_key_management_blueprint.encryption_key_management_blueprint
)
app.register_blueprint(onboarding_blueprint.onboarding_blueprint)
app.register_blueprint(requests_blueprint.requests_blueprint)
app.register_blueprint(sensitive_fields_blueprint.sensitive_fields_blueprint)
app.register_blueprint(user_management_blueprint.user_management_blueprint)
app.register_blueprint(whitelist_blueprint.whitelist_blueprint)

csrf = CSRFProtect(app)
csrf.exempt(api_blueprint.api_blueprint)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"
login_manager.login_message_category = "danger"

client_db.init_app(app)
server_db.init_app(app)
alert_blueprint.mail.init_app(app)

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
        return redirect(url_for("onboarding.onboarding"))

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
                n=32768,
                r=8,
                p=1,
                maxmem=33816576,
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

    today = datetime.datetime.now()
    today = datetime.datetime(today.year, today.month, today.day)
    last_time = datetime.datetime(
        today.year, today.month, today.day, 23, 59, 59, 999999
    )

    # Get requests based on time
    requests = Request.query.filter(
        Request.datetime.between(today, last_time)
    ).all()

    alerts = list()

    for client_request in requests:
        alert = Alert.query.filter_by(request_id=client_request.id).first()
        alerts.append(alert)

    alert_list = [0, 0, 0]

    for i in alerts:
        if i.alert_level == "Low":
            alert_list[0] += 1
        elif i.alert_level == "Medium":
            alert_list[1] += 1
        else:
            alert_list[2] += 1

    try:
        backup_log = (
            BackupLog.query.filter_by(filename="client_db.sqlite3")
            .order_by(BackupLog.id.desc())
            .first()
        )

        date = backup_log.date_created.strftime("%d %b %Y %H:%M:%S")
    except:
        date = "None"

    try:
        backup_job = constants.SCHEDULER.get_job(job_id="client_db.sqlite3")
        next_backup = backup_job.next_run_time.strftime("%d %b %Y %H:%M:%S")
    except:
        next_backup = "None"

    return render_template(
        "index.html",
        form=login_form,
        next=request.args.get("next"),
        alert_list=alert_list,
        recent_backup=date,
        next_backup=next_backup,
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, port=4999)
