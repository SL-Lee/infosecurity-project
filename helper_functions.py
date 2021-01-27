import datetime
import hashlib
import shelve

from server_models import Alert, Request
from errors import InvalidAPIKeyError


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


def log_request(alert_level, status, status_msg, request_params, response):
    logged_request = Request(
        datetime=datetime.datetime.now(),
        status=status,
        status_msg=status_msg,
        request_params=request_params,
        response=response,
    )
    logged_alert = Alert(request=logged_request, alert_level=alert_level)
    return logged_request, logged_alert
