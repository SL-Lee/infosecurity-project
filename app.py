import datetime
import hashlib
import json
import os
import re
import shutil
import uuid

import marshmallow
import sqlalchemy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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
from flask_restx import Api, Resource, reqparse
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

import forms
from client_models import *
from helper_functions import (
    get_config_value,
    set_config_value,
    validate_api_key,
)
from monitoring_models import Alert, Request, monitoring_db

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    "monitoring": "sqlite:///monitoring_db.sqlite3"
}
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
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


@app.route("/temp-backup-set-default")
def backup_set_default():
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
def backup_add():
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

    return render_template("backup-form.html", form1=form)


@app.route("/backup/<file>", methods=["GET", "POST"])
def backup_history(file):
    path = os.path.join(backup_path, file)
    timestamp = os.listdir(path)
    print(timestamp)

    return render_template("backup-history.html", file=file, timestamp=timestamp)


@app.route("/backup/<file>/update", methods=["GET", "POST"])
def backup_update(file):
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

    return render_template("backup-form.html", form2=form)


@app.route("/backup/<file>/<timestamp>/restore")
def backup_restore(file, timestamp):
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


# Upload API
@app.route("/uploadfile", methods=["GET", "POST"])
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
            flash("No file", "error")
            print("no filename")
            return redirect(request.url)
        else:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            key = get_random_bytes(32)  # Use a stored / generated key
            buffer_size = 65536  # 64kb

            # === Encrypt ===

            # Open the input and output files
            input_file = open(
                os.path.join(app.config["UPLOAD_FOLDER"], filename), "rb"
            )
            output_file = open(
                os.path.join(app.config["UPLOAD_FOLDER"], filename)
                + ".encrypted",
                "wb",
            )

            # Create the cipher object and encrypt the data
            cipher_encrypt = AES.new(key, AES.MODE_CFB)

            # Initially write the iv to the output file
            output_file.write(cipher_encrypt.iv)

            # Keep reading the file into the buffer, encrypting then writing to the new file
            buffer = input_file.read(buffer_size)

            while len(buffer) > 0:
                ciphered_bytes = cipher_encrypt.encrypt(buffer)
                output_file.write(ciphered_bytes)
                buffer = input_file.read(buffer_size)

            # Close the input and output files
            input_file.close()
            output_file.close()
            print("saved file successfully")
            # send file name as parameter to download
            return redirect("/downloadfile/" + filename + ".encrypted")

    return render_template("upload_file.html")


# Download API
@app.route("/downloadfile/<filename>", methods=["GET"])
def download_file(filename):
    return render_template("download.html", value=filename)


@app.route("/return-files/<filename>")
def return_files_tut(filename):
    file_path = UPLOAD_FOLDER + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Alert Function
@app.route("/alert")
def alert():
    alert_config = get_config_value("alert")
    print("alert files:", alert_config)
    return render_template("alert.html")


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
    print(alert_config["client_db"]["path"])
    print(os.path.isfile(alert_config["client_db"]["path"]))
    return redirect(url_for("alert"))


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
            return jsonify({"status": "ERROR"}), 400

        db_models = request.files.get("db-models")

        if db_models is not None and db_models.filename.endswith(".py"):
            db_models.save(secure_filename("client_models.py"))
        else:
            return jsonify({"status": "ERROR"}), 400

        return jsonify({"status": "OK"}), 200

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
        api_keys=get_config_value("api-keys"),
    )


@app.route("/api/key-management/rename", methods=["POST"])
def api_key_rename():
    api_keys = get_config_value("api-keys", [])
    api_key_index = request.json.get("api-key-index")
    new_api_key_name = request.json.get("new-api-key-name", "New API Key")

    try:
        api_keys[api_key_index]["name"] = new_api_key_name
        set_config_value("api-keys", api_keys)
    except:
        return jsonify({"status": "ERROR"}), 400

    return jsonify({"status": "OK"})


@app.route("/api/key-management/revoke", methods=["POST"])
def api_key_revoke():
    api_keys = get_config_value("api-keys", [])
    api_key_index = request.json.get("api-key-index")

    try:
        del api_keys[api_key_index]
        set_config_value("api-keys", api_keys)
    except:
        return jsonify({"status": "ERROR"}), 400

    return jsonify({"status": "OK"})


@app.route("/api/key-management/generate", methods=["POST"])
def api_key_generate():
    api_key = uuid.uuid4()
    api_keys = get_config_value("api-keys", [])
    api_keys.append(
        {
            "name": request.json.get("api-key-name", "New API Key"),
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
            "new-api-key": api_key.hex,
        }
    )


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
    def get(self):
        args = self.get_parser.parse_args()

        try:
            schema = eval(f"{args['model']}Schema(many=True)")
            query_results = schema.dump(
                client_db.session.query(eval(args["model"]))
                .filter(eval(args["filter"]))
                .all()
            )
            status, status_msg, status_code = "OK", "OK", 200

            request = Request(
                datetime=datetime.now(),
                request_params="Model: {}, Filter: {}".format(
                    args["model"], args["filter"]
                ),
                response=str(query_results),
            )
            pattern = "'password'"
            x = re.findall(pattern, str(query_results))
            if len(x) > 1:  # if more than 1 sensitive data
                try:
                    alert = Alert(request=request, alert_level="high")
                    monitoring_db.session.add(alert)
                except:
                    print("error")
            else:
                alert = Alert(request=request, alert_level="low")
                monitoring_db.session.add(alert)
        except (sqlalchemy.exc.InvalidRequestError, NameError, SyntaxError):
            query_results = None
            status, status_msg, status_code = "ERROR", "invalid request", 400
            request = Request(
                datetime=datetime.now(),
                request_params="Model: {}, Filter: {}".format(
                    args["model"], args["filter"]
                ),
                response=str(query_results),
            )
            alert = Alert(request=request, alertLevel="medium")
            monitoring_db.session.add(alert)
        except:
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )
            request = Request(
                datetime=datetime.now(),
                request_params="Model: {}, Filter: {}".format(
                    args["model"], args["filter"]
                ),
                response=str(query_results),
            )
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


if __name__ == "__main__":
    app.run(debug=True, port=4999)
