from client_models import (
    client_db,
    Product,
    ProductSchema,
    Review,
    ReviewSchema,
    User,
    UserSchema,
)
from flask import (
    abort,
    Blueprint,
    flash,
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    current_user,
    login_required,
    login_user,
    LoginManager,
    logout_user,
)
from flask_restx import Api, reqparse, Resource
from flask_wtf.csrf import CSRFProtect
from helper_functions import (
    get_config_value,
    set_config_value,
    validate_api_key,
)
import datetime
import forms
import hashlib
import json
import marshmallow
import os
import shutil
import sqlalchemy
import uuid
import configparser


app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
csrf = CSRFProtect(app)

blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/doc/")
app.register_blueprint(blueprint)

csrf.exempt(blueprint)

client_db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"

dirname = os.path.dirname(__file__)
db_location = ""

# only if backup folder does not exist
if not os.path.isdir(os.path.join(dirname, "backup")):
    os.mkdir(os.path.join(dirname, "backup"))

backup_path = os.path.join(dirname, "backup")
if not os.path.isdir(os.path.join(backup_path, "client_db")):
    os.mkdir(os.path.join(backup_path, "client_db"))
backup_interval = ""


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


@app.route("/backup", methods=["GET", "POST"])
def backup():
    config = configparser.ConfigParser()
    config.read("backup.ini")
    return render_template("backup.html", files=config.sections())


@app.route("/backup/<file>", methods=["GET", "POST"])
def backupHistory(file):
    config = configparser.ConfigParser()
    config.read("backup.ini")

    path = os.path.join(backup_path, file)
    files = os.listdir(path)

    return render_template("backupHistory.html", files=files)


@app.route("/backupForm", methods=["GET", "POST"])
def backupForm():
    config = configparser.ConfigParser()
    config.read("backup.ini")
    global db_location, backup_interval

    if not config["client_db"]["path"]:
        form = forms.BackupFirstForm(request.form)

        if request.method == "POST" and form.validate():
            db_location = form.source.data
            backup_datetime = datetime.datetime.now().strftime("Backup %d-%m-%Y %H-%M-%S")
            os.mkdir(os.path.join(backup_path, backup_datetime))
            file_backup_path = os.path.join(os.path.join(backup_path, backup_datetime), os.path.basename(db_location))

            backup_interval = {"type": form.interval_type.data, "interval": form.interval.data}
            shutil.copy2(db_location, file_backup_path)

            return redirect(url_for("index"))
        return render_template("backupForm.html", form1=form)
    else:
        form = forms.BackupForm(request.form)

        if request.method == "POST" and form.validate():
            if form.manual.data:
                # only update, nothing else happens, including changes to settings
                print("manual backup")

                backup_datetime = datetime.datetime.now().strftime("Backup %d-%m-%Y %H-%M-%S")
                print(backup_datetime)
                os.mkdir(os.path.join(backup_path, backup_datetime))
                file_backup_path = os.path.join(os.path.join(backup_path, backup_datetime), os.path.basename(db_location))

                shutil.copy2(db_location, file_backup_path)
            elif form.update.data:
                # will perform a update, and update the settings
                print("update settings")

                if form.source.data != "" and os.path.isfile(form.source.data):     # if field is not empty and the file is valid
                    db_location = form.source.data
                if form.interval.data != "":                                        # if field is not empty
                    backup_interval = {"type": form.interval_type.data, "interval": form.interval.data}

                backup_datetime = datetime.datetime.now().strftime("Backup %d-%m-%Y %H-%M-%S")
                os.mkdir(os.path.join(backup_path, backup_datetime))
                file_backup_path = os.path.join(os.path.join(backup_path, backup_datetime), os.path.basename(db_location))

                shutil.copy2(db_location, file_backup_path)
            else:
                # still dk wat to do if this gets executed
                print("something else happened")

            return redirect(url_for("index"))
        return render_template("backupForm.html", form2=form)


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
    api_key_hash = hashlib.sha3_512(api_key.bytes).hexdigest()
    api_key_timestamp = datetime\
        .datetime\
        .now()\
        .strftime("%Y-%m-%dT%H:%M:%S+08:00")
    set_config_value(
        "api-key",
        {
            "hash": api_key_hash,
            "timestamp": api_key_timestamp,
        },
    )
    return jsonify({
        "status": "OK",
        "new_api_key_hash": api_key.hex,
        "new_api_key_timestamp": api_key_timestamp,
    })


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
                client_db.session.query(eval(args["model"]))\
                    .filter(eval(args["filter"]))\
                    .all()
            )
            status, status_msg, status_code = "OK", "OK", 200
        except (sqlalchemy.exc.InvalidRequestError, NameError, SyntaxError):
            query_results = None
            status, status_msg, status_code = "ERROR", "invalid request", 400
        except:
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {
            "status": status,
            "status_msg": status_msg,
            "query_results": query_results,
        },\
        status_code

    @api.expect(patch_parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def patch(self):
        args = self.patch_parser.parse_args()

        try:
            query_result = client_db.session.query(eval(args["model"]))\
                .filter(eval(args["filter"]))\
                .update(args["values"])
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
            query_result = client_db.session.query(eval(args["model"]))\
                .filter(eval(args["filter"]))\
                .delete()
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
