import datetime
import json
import re

import marshmallow
import sqlalchemy
from flask import Blueprint, request
from flask_restx import Api, Resource, apidoc, inputs, reqparse

import constants
from client_models import *
from crypto_functions import decrypt, encrypt
from helper_functions import (
    get_config_value,
    log_request,
    required_permissions,
    validate_api_key,
)
from server_models import Rule, server_db

api_blueprint = Blueprint("api", __name__, url_prefix="/api")
api_authorizations = {
    "api-key": {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
}
api = Api(
    api_blueprint,
    title="SecureDB API",
    description="Documentation for the SecureDB API",
    authorizations=api_authorizations,
    security="api-key",
    doc="/doc/",
)


@api.documentation
@required_permissions("view_api_documentation")
def api_documentation():
    return apidoc.ui_for(api)


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