from client_models import (
    client_db,
    Product,
    Review,
    User,
)
from flask import (
    abort,
    Blueprint,
    flash,
    Flask,
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
from helper_functions import deserialize, serialize
import binascii
import datetime
import forms
import json
import os
import pickle
import shutil
import sqlalchemy

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"

blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/doc/")
app.register_blueprint(blueprint)

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
    global db_location, backup_interval

    if db_location == "":
        form = forms.BackupFirstForm(request.form)

        if request.method == "POST" and form.validate():
            db_location = form.source.data
            backup_datetime = datetime.datetime.now().strftime("Backup %d-%m-%Y %H-%M-%S")
            os.mkdir(os.path.join(backup_path, backup_datetime))
            file_backup_path = os.path.join(os.path.join(backup_path, backup_datetime), os.path.basename(db_location))

            backup_interval = {"type": form.interval_type.data, "interval": form.interval.data}
            shutil.copy2(db_location, file_backup_path)

            return redirect(url_for("index"))
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

    return render_template("backup.html", form=form)


# API routes
@api.route("/add")
class Add(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("object", required=True, type=str, location="form")

    @api.expect(parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def post(self):
        args = self.parser.parse_args()

        try:
            obj = deserialize(args["object"])
            client_db.session.add(obj)
            client_db.session.commit()
            status, status_msg, status_code = "OK", "OK", 200
        except (binascii.Error, pickle.UnpicklingError):
            status, status_msg, status_code = (
                "ERROR",
                "error while deserializing object",
                400,
            )
        except sqlalchemy.orm.exc.UnmappedInstanceError:
            status, status_msg, status_code = "ERROR", "unmapped object", 400
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {"status": status, "status_msg": status_msg}, status_code


@api.route("/query")
class Query(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("model", required=True, type=str, location="form")
    parser.add_argument("filter", required=True, type=str, location="form")

    @api.expect(parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def post(self):
        args = self.parser.parse_args()

        try:
            args["filter"] = json.loads(args["filter"])
            query_results = client_db.session.query(eval(args["model"]))\
                .filter_by(**args["filter"])\
                .all()
            status, status_msg, status_code = "OK", "OK", 200
        except json.decoder.JSONDecodeError:
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "error while parsing filter object",
                400,
            )
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
            "query_results": serialize(query_results),
        },\
        status_code


@api.route("/update")
class Update(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("model", required=True, type=str, location="form")
    parser.add_argument("filter", required=True, type=str, location="form")
    parser.add_argument("field", required=True, type=str, location="form")
    parser.add_argument("value", required=True, location="form")

    @api.expect(parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def post(self):
        args = self.parser.parse_args()

        try:
            args["filter"] = json.loads(args["filter"])
            query_result = client_db.session.query(eval(args["model"]))\
                .filter_by(**args["filter"])\
                .first()

            if query_result is not None:
                setattr(query_result, args["field"], args["value"])
                client_db.session.commit()
                status, status_msg, status_code = "OK", "OK", 200
            else:
                status, status_msg, status_code = "ERROR", "no match found", 400
        except json.decoder.JSONDecodeError:
            status, status_msg, status_code = (
                "ERROR",
                "error while parsing filter object",
                400,
            )
        except (
            sqlalchemy.exc.InvalidRequestError,
            sqlalchemy.exc.StatementError,
            NameError,
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


@api.route("/delete")
class Delete(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("model", required=True, type=str, location="form")
    parser.add_argument("filter", required=True, type=str, location="form")

    @api.expect(parser)
    @api.response(200, "Success")
    @api.response(400, "Invalid Request")
    def post(self):
        args = self.parser.parse_args()

        try:
            args["filter"] = json.loads(args["filter"])
            query_result = client_db.session.query(eval(args["model"]))\
                .filter_by(**args["filter"])\
                .first()

            if query_result is not None:
                client_db.session.delete(query_result)
                client_db.session.commit()
                status, status_msg, status_code = "OK", "OK", 200
            else:
                status, status_msg, status_code = "ERROR", "no match found", 400
        except json.decoder.JSONDecodeError:
            status, status_msg, status_code = (
                "ERROR",
                "error while parsing filter object",
                400,
            )
        except (sqlalchemy.exc.InvalidRequestError, NameError, SyntaxError):
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
