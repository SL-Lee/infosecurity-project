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
from client_models import (
    client_db,
    Product,
    Review,
    User,
)
from sqlalchemy import exc
import base64
import json
import pickle
import os
import shutil
import datetime
import forms

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
        except:
            abort(400, "Filter must be a valid Python dict")

        try:
            query_results = serialize(
                client_db.session.query(eval(args["model"]))
                    .filter_by(**args["filter"])
                    .all(),
            )
            status_msg, status_code = "OK", 200
        except (exc.InvalidRequestError, SyntaxError):
            query_results = None
            status_msg, status_code = "ERROR", 400

        return {
            "status": status_msg,
            "query_results": query_results,
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
        except:
            abort(400, "Filter must be a valid Python dict")

        try:
            query_result = client_db.session.query(eval(args["model"]))\
                .filter_by(**args["filter"])\
                .first()

            if query_result is not None:
                setattr(query_result, args["field"], args["value"])
                client_db.session.commit()
                status_msg, status_code = "OK", 200
            else:
                status_msg, status_code = "ERROR", 400
        except (exc.InvalidRequestError, exc.StatementError, SyntaxError):
            status_msg, status_code = "ERROR", 400

        return {"status": status_msg}, status_code


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
        except:
            abort(400, "Filter must be a valid Python dict")

        try:
            query_result = client_db.session.query(eval(args["model"]))\
                .filter_by(**args["filter"])\
                .first()

            if query_result is not None:
                client_db.session.delete(query_result)
                client_db.session.commit()
                status_msg, status_code = "OK", 200
            else:
                status_msg, status_code = "ERROR", 400
        except (exc.InvalidRequestError, SyntaxError):
            status_msg, status_code = "ERROR", 400

        return {"status": status_msg}, status_code


# Functions
def serialize(obj):
    return base64.b64encode(pickle.dumps(obj)).decode("UTF-8")


def deserialize(string):
    return pickle.loads(base64.b64decode(string.encode("UTF-8")))


if __name__ == "__main__":
    app.run(debug=True, port=4999)
