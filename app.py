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
        except (exc.InvalidRequestError, SyntaxError):
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
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "error while parsing filter object",
                400,
            )
        except (exc.InvalidRequestError, exc.StatementError, SyntaxError):
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
            query_results = None
            status, status_msg, status_code = (
                "ERROR",
                "error while parsing filter object",
                400,
            )
        except (exc.InvalidRequestError, SyntaxError):
            status, status_msg, status_code = "ERROR", "invalid request", 400
        except:
            status, status_msg, status_code = (
                "ERROR",
                "an unknown error occurred",
                400,
            )

        return {"status": status, "status_msg": status_msg}, status_code


# Functions
def serialize(obj):
    return base64.b64encode(pickle.dumps(obj)).decode("UTF-8")


def deserialize(string):
    return pickle.loads(base64.b64decode(string.encode("UTF-8")))


if __name__ == "__main__":
    app.run(debug=True, port=4999)
