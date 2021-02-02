import datetime
import hashlib
import uuid

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from helper_functions import (
    get_config_value,
    required_permissions,
    set_config_value,
)

api_key_management_blueprint = Blueprint("api_key_management", __name__)


@api_key_management_blueprint.route("/api/key-management")
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


@api_key_management_blueprint.route(
    "/api/key-management/rename", methods=["POST"]
)
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
        return redirect(url_for(".api_key_management"))

    flash("The API key was renamed successfully.", "success")
    return redirect(url_for(".api_key_management"))


@api_key_management_blueprint.route(
    "/api/key-management/revoke", methods=["POST"]
)
@required_permissions("manage_api_keys")
def api_key_revoke():
    api_keys = get_config_value("api-keys", [])

    try:
        api_key_index = int(request.form["revoke-api-key-index"])
        del api_keys[api_key_index]
        set_config_value("api-keys", api_keys)
    except:
        flash("There was an error while revoking the API key.", "danger")
        return redirect(url_for(".api_key_management"))

    flash("The API key was revoked successfully.", "success")
    return redirect(url_for(".api_key_management"))


@api_key_management_blueprint.route(
    "/api/key-management/generate", methods=["POST"]
)
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
