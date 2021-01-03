import datetime
import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime

import marshmallow
import sqlalchemy
from sqlalchemy import create_engine
engine = create_engine('sqlite:///monitoring_db.sqlite3')
from flask import (
    Blueprint,
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    login_required,
    logout_user,
)
from flask_restx import Api, Resource, reqparse
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

import forms
from client_models import (
    client_db,
)
from helper_functions import (
    get_config_value,
    set_config_value,
    validate_api_key,
)
from monitoring_models import Alert, BackupLog, Request, Rule, monitoring_db

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    "monitoring": "sqlite:///monitoring_db.sqlite3"
}
csrf = CSRFProtect(app)
UPLOAD_FOLDER = "uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

blueprint = Blueprint("api", __name__, url_prefix="/api")
authorizations = {
    "api-key": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
}
api = Api(
    blueprint,
    authorizations=authorizations,
    security="api-key",
    doc="/doc/",
)
app.register_blueprint(blueprint)
csrf.exempt(blueprint)

client_db.init_app(app)
monitoring_db.init_app(app)

with app.app_context():
    client_db.create_all()
    monitoring_db.create_all(bind="monitoring")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"

dirname = os.path.dirname(__file__)

# only if backup folder does not exist
if not os.path.isdir(os.path.join(dirname, "backup")):
    os.mkdir(os.path.join(dirname, "backup"))

backup_path = os.path.join(dirname, "backup")

if not os.path.isdir(os.path.join(backup_path, "client_db")):
    os.mkdir(os.path.join(backup_path, "client_db"))


@login_manager.user_loader
def load_user(user_id):
    return redirect(url_for("index"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(url_for("index"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# Backup functions
@app.route("/backup")
def backup():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    files = list(backup_config.keys())
    return render_template("backup.html", files=files)


@app.route("/tempBackupSetDefault")
def backupSetDefault():
    path = ".\client_db.sqlite3"
    interval = 1
    interval_type = "min"
    client_db = {
        "client_db": {
            "path": path,
            "interval": interval,
            "interval_type": interval_type,
        }
    }
    set_config_value("backup", client_db)
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    print(backup_config["client_db"]["path"])
    print(os.path.isfile(backup_config["client_db"]["path"]))
    return redirect(url_for("backup"))


@app.route("/backup/add", methods=["GET", "POST"])
def backupAdd():
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)

    # first form, when there are no settings for the file
    form = forms.BackupFirstForm(request.form)

    if request.method == "POST" and form.validate():
        location = form.source.data
        backup_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        filename = os.path.join(
            backup_path, os.path.splitext(os.path.basename(location))[0]
        )

        if not os.path.exists(filename):
            os.mkdir(filename)

        backup_folder = os.path.join(filename, secure_filename(backup_datetime))

        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        file_backup_path = os.path.join(
            backup_folder, os.path.basename(location)
        )

        backup_config = {
            os.path.splitext(os.path.basename(location))[0]: {
                "path": location,
                "interval": form.interval.data,
                "interval_type": form.interval_type.data,
            }
        }
        print(backup_config)
        set_config_value("backup", backup_config)

        shutil.copy2(location, file_backup_path)

        return redirect(url_for("index"))

    return render_template("backupForm.html", form1=form)


@app.route("/backup/<file>", methods=["GET", "POST"])
def backupHistory(file):
    path = os.path.join(backup_path, file)
    timestamp = os.listdir(path)
    print(timestamp)

    return render_template("backupHistory.html", file=file, timestamp=timestamp)


@app.route("/backup/<file>/update", methods=["GET", "POST"])
def backupUpdate(file):
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    file_settings = backup_config[file]

    form = forms.BackupForm(request.form)
    if request.method == "POST" and form.validate():
        # only update, nothing else happens, including changes to settings
        if form.manual.data:
            print("manual backup")

            backup_datetime = datetime.datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            )
            filename = os.path.join(backup_path, file)
            if not os.path.exists(filename):
                os.mkdir(filename)

            backup_folder = os.path.join(
                filename, secure_filename(backup_datetime)
            )
            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)

        # will perform a update, and update the settings
        elif form.update.data:
            print("update settings")

            # if field different from settings and the file is valid and not empty
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
            # cannot put file settings directly, else it would override the whole backup settings
            set_config_value("backup", backup_config)

            # create folders to be used for saving
            backup_datetime = datetime.datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            )
            filename = os.path.join(backup_path, file)

            if not os.path.exists(filename):
                os.mkdir(filename)

            backup_folder = os.path.join(
                filename, secure_filename(backup_datetime)
            )

            if not os.path.exists(backup_folder):
                os.mkdir(backup_folder)

            file_backup_path = os.path.join(
                backup_folder, os.path.basename(file_settings["path"])
            )

            shutil.copy2(file_settings["path"], file_backup_path)

        return redirect(url_for("backup"))

    return render_template("backupForm.html", form2=form)


@app.route("/backup/<file>/<timestamp>/restore")
def backupRestore(file, timestamp):
    backup_config = get_config_value("backup")
    print("backup files:", backup_config)
    file_settings = backup_config[file]

    # path to file dir
    file_folder = os.path.join(backup_path, file)

    # path to timestamp dir
    timestamp_folder = os.path.join(file_folder, timestamp)

    # path to backup file
    restore = os.path.join(
        timestamp_folder, os.path.basename(file_settings["path"])
    )

    # copy from timestamp to source path
    shutil.copy2(restore, file_settings["path"])

    return redirect(url_for("backup"))


# Configure Sensitive Fields
@app.route("/sensitive-fields", methods=["GET"])
def get_sensitive_fields():
    sensitive_fields = Rule.query.all()

    for i in sensitive_fields:
        print(i.contents)

    return render_template(
        "sensitive-fields.html", sensitive_fields=sensitive_fields
    )


@app.route("/sensitive-fields/add", methods=["GET", "POST"])
def add_sensitive_fields():
    form = forms.SensitiveFieldForm(request.form)

    if request.method == "POST" and form.validate():
        rule = Rule(contents=form.sensitive_field.data)
        monitoring_db.session.add(rule)
        monitoring_db.session.commit()

        return redirect(url_for("get_sensitive_fields"))

    return render_template("sensitive-fields-add.html", form=form)


@app.route("/sensitive-fields/update/<field>", methods=["GET", "POST"])
def update_sensitive_fields(field):
    form = forms.SensitiveFieldForm(request.form)
    rule = Rule.query.filter_by(id=field).first_or_404()

    if request.method == "POST" and form.validate():
        rule.contents = form.sensitive_field.data
        monitoring_db.session.commit()

        return redirect(url_for("get_sensitive_fields"))

    return render_template("sensitive-fields-update.html", form=form, rule=rule)


@app.route("/sensitive-fields/delete/<field>", methods=["GET", "POST"])
def delete_sensitive_fields(field):
    rule = Rule.query.filter_by(id=field).first_or_404()
    monitoring_db.session.delete(rule)
    monitoring_db.session.commit()

    return redirect(url_for("get_sensitive_fields"))


# Upload API
@app.route("/upload-file", methods=["GET", "POST"])
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
            print("no filename")
            return redirect(request.url)
        else:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            print("saved file successfully")
            # send file name as parameter to download
            return redirect("/download-file/" + filename + ".encrypted")

    return render_template("upload-file.html")


# Download API
@app.route("/download-file/<filename>", methods=["GET"])
def download_file(filename):
    return render_template("download-file.html", value=filename)


@app.route("/return-files/<filename>")
def return_files_tut(filename):
    file_path = UPLOAD_FOLDER + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")



# Alert Function
@app.route("/alert")
def alert():
    alert_config = get_config_value("alert")
    files = list(alert_config.keys())
    print("alert files:", alert_config)
    return render_template("alert.html", files=files)

@app.route("/temp-alert-set-default")
def alert_set_default():
    path = ".\\monitoring_db.sqlite3"
    interval = 1
    interval_type = "min"
    monitoring_db_config = {
        "monitoring_db": {
            "path": path,
            "interval": interval,
            "interval_type": interval_type,
        }
    }
    set_config_value("alert", monitoring_db_config)
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    print(alert_config["monitoring_db"]["path"])
    print(os.path.isfile(alert_config["monitoring_db"]["path"]))
    return redirect(url_for("alert"))

@app.route("/alert/view", methods=['GET'])
def alertview():
    alert_config = get_config_value("alert")
    files = list(alert_config.keys())
    print("alert files:", alert_config)
    with engine.connect() as con:
        rs = con.execute('SELECT * FROM alert, request')
        for col in rs:
            print(col)
    return render_template("alert-view.html", files=rs)


# Onboarding routes
@app.route("/onboarding")
def onboarding():
    return redirect(url_for("onboarding_database_config"))


@app.route("/onboarding/database-config", methods=["GET", "POST"])
def onboarding_database_config():
    if request.method == "POST":
        db_file = request.files.get("db-file")

        if db_file is not None and db_file.filename.endswith(".sqlite3"):
            db_file.save(secure_filename("client_db.sqlite3"))
        else:
            flash(
                (
                    "The database file seems to be of an incorrect format. "
                    "Please try again."
                ),
                "danger",
            )
            return render_template("onboarding-database-config.html")

        db_models = request.files.get("db-models")

        if db_models is not None and db_models.filename.endswith(".py"):
            db_models.save(secure_filename("client_models.py"))
        else:
            flash(
                (
                    "The database models file seems to be of an incorrect "
                    "format. Please try again."
                ),
                "danger",
            )
            return render_template("onboarding-database-config.html")

        return redirect(url_for("onboarding_api_config"))

    return render_template("onboarding-database-config.html")


@app.route("/onboarding/api-config")
def onboarding_api_config():
    return render_template("onboarding-api-config.html")


@app.route("/onboarding/backup-config")
def onboarding_backup_config():
    return render_template("onboarding-backup-config.html")


@app.route("/onboarding/review-settings")
def onboarding_review_settings():
    return render_template("onboarding-review-settings.html")


# API key management routes
@app.route("/api/key-management")
def api_key_management():
    return render_template(
        "api-key-management.html",
        api_key=get_config_value("api-key"),
    )


@app.route("/api/key-management/revoke", methods=["POST"])
def api_key_revoke():
    set_config_value("api-key", None)
    return jsonify({"status": "OK"})


@app.route("/api/key-management/generate", methods=["POST"])
def api_key_generate():
    api_key = uuid.uuid4()
    set_config_value(
        "api-key",
        {
            "hash": hashlib.sha3_512(api_key.bytes).hexdigest(),
            "timestamp": datetime.datetime.now().strftime(
                "%Y-%m-%dT%H:%M:%S+08:00"
            ),
        },
    )
    return jsonify(
        {
            "status": "OK",
            "new_api_key": api_key.hex,
        }
    )


# API routes
def log_request(param, status, status_msg):
    pass


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
    def post(self):
        args = self.post_parser.parse_args()

        try:
            schema = eval(f"{args['model']}Schema()")
            client_db.session.add(schema.load(args["object"]))
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
        except marshmallow.exceptions.ValidationError:
            status, status_msg, status_code = (
                "ERROR",
                "error while deserializing object",
                400,
            )
        except (NameError, SyntaxError):
            status, status_msg, status_code = "ERROR", "invalid request", 400
        except sqlalchemy.exc.IntegrityError:
            status, status_msg, status_code = (
                "ERROR",
                "database integrity error",
                400,
            )
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {"status": status, "status_msg": status_msg}, status_code

    @api.expect(get_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def get(self, request=None):
        args = self.get_parser.parse_args()

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

                pattern = "'password'"
                pattern_occurrence_count = re.findall(
                    pattern, str(query_results)
                )

                # if pattern occurs more than once, that means there are more
                # than 1 sensitive data, so deny this request and log it as a
                # high alert
                if len(pattern_occurrence_count) > 1:
                    status, status_msg, status_code = "ERROR", "Denied", 403
                    logged_request, logged_alert = log_request(
                        "high", status, status_msg
                    )
                    query_results = None
                else:
                    status, status_msg, status_code = "OK", "OK", 200
                    logged_request, logged_alert = log_request(
                        "low", status, status_msg
                    )

            except (sqlalchemy.exc.InvalidRequestError, NameError, SyntaxError):
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

            monitoring_db.session.add(logged_alert)
            monitoring_db.session.add(logged_request)
            monitoring_db.session.commit()

            return {
                "status": status,
                "status_msg": status_msg,
                "query_results": query_results,
            }, status_code
        except:
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            request = Request(datetime=datetime.now(), request_params="Model: {}, Filter: {}".format(args["model"], args["filter"]), response=str(query_results))
            alert = Alert(request=request, alertLevel="medium")
            monitoring_db.session.add(alert)

        monitoring_db.session.add(request)
        monitoring_db.session.commit()

        return {
            "status": status,
            "status_msg": status_msg,
            "query_results": query_results,
        }, status_code

    @api.expect(patch_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def patch(self):
        args = self.patch_parser.parse_args()

        try:
            client_db.session.query(eval(args["model"])).filter(
                eval(args["filter"])
            ).update(args["values"])
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
        except (
            NameError,
            sqlalchemy.exc.InvalidRequestError,
            sqlalchemy.exc.StatementError,
            SyntaxError,
        ):
            status, status_msg, status_code = "ERROR", "invalid request", 400
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {"status": status, "status_msg": status_msg}, status_code

    @api.expect(delete_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def delete(self):
        args = self.delete_parser.parse_args()

        try:
            client_db.session.query(eval(args["model"])).filter(
                eval(args["filter"])
            ).delete()
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
        except (NameError, sqlalchemy.exc.InvalidRequestError, SyntaxError):
            status, status_msg, status_code = "ERROR", "invalid request", 400
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {"status": status, "status_msg": status_msg}, status_code

#Alert Function
@app.route("/alert")
def alert():
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    files = list(alert_config.keys())
    return render_template("alert.html", files = files)

@app.route("/tempalertSetDefault")
def alertSetDefault():
    path = ".\monitoring_db.sqlite3"
    interval = 1
    interval_type = "min"
    monitoring_db = {
        "monitoring_db": {
            "path": path,
            "interval": interval,
            "interval_type": interval_type,
        }
    }
    set_config_value("alert", monitoring_db)
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    print(alert_config["monitoring_db"]["path"])
    print(os.path.isfile(alert_config["monitoring_db"]["path"]))
    return redirect(url_for("alert"))



if __name__ == "__main__":
    app.run(debug=True, port=4999)
