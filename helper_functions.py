import datetime
import hashlib
import shelve
import re
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import abort, request
from flask_login import current_user

import constants
from errors import InvalidAPIKeyError
from server_models import Alert, Request


def get_config_value(key, default_value=None):
    config_db = shelve.open("config")

    try:
        return config_db["config"][key]
    except:
        return default_value
    finally:
        config_db.close()


def set_config_value(key, value):
    config_db = shelve.open("config")
    config = config_db.get("config", {})
    config[key] = value
    config_db["config"] = config
    config_db.close()


def validate_api_key(given_api_key):
    api_keys = get_config_value("api-keys")

    for api_key in api_keys:
        if (
            hashlib.sha3_512(bytes.fromhex(given_api_key)).hexdigest()
            == api_key["hash"]
        ):
            return given_api_key

    raise InvalidAPIKeyError


def log_request(alert_level, status, status_msg, request_params, response, ip_address):
    logged_request = Request(
        datetime=datetime.datetime.now(),
        status=status,
        status_msg=status_msg,
        request_params=request_params,
        response=response,
        ip_address=ip_address,
    )
    logged_alert = Alert(request=logged_request, alert_level=alert_level)
    return logged_request, logged_alert


def request_filter(alerts, date, query):
    alert_list = list()
    for i in alerts:
        if date == str(i.request.datetime.date()) or date == "<date>" or date == "None":
            if query != "<query>":
                search_list = i.alert_level, i.request.id, str(i.request.datetime), i.request.ip_address, i.request.status, i.request.status_msg, i.request.request_params, i.request.response
                query_count = re.findall(query, str(search_list))
                if len(query_count) >= 1:
                    alert_list.append(i)
            else:
                alert_list.append(i)
    return alert_list


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
                permission in constants.VALID_SERVER_PERMISSION_NAMES
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
