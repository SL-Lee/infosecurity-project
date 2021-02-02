import datetime
import hashlib
import re
import shelve
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import abort, request
from flask_login import current_user

import constants
from errors import InvalidAPIKeyError
from server_models import Alert, Request, server_db


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


def log_request(
    alert_level, status, status_msg, request_params, response, ip_address
):
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


def request_filter(alerts, date, query, sort):
    alert_list = list()
    for i in alerts:
        if (
            date == str(i.request.datetime.date())
            or date == "<date>"
            or date == "None"
        ):
            if query != "<query>":
                search_list = (
                    i.alert_level,
                    i.request.id,
                    str(i.request.datetime),
                    i.request.ip_address,
                    i.request.status,
                    i.request.status_msg,
                    i.request.request_params,
                    i.request.response,
                )
                query_count = re.findall(query, str(search_list))
                if len(query_count) >= 1:
                    alert_list.append(i)
            else:
                alert_list.append(i)

    if sort == "Latest" or sort == "<sort>":
        alert_list.reverse()

    return alert_list


def req_behaviour(url, ip):
    url_dict = get_config_value("url_dict")
    if url_dict is None:
        url_dict = dict()
        set_config_value("url_dict", url_dict)
    url_dict_count = get_config_value("url_dict_count")
    if url_dict_count is None:
        url_dict_count = dict()
    ip_access_url_count = dict()
    # Go through url dict to find any url matching inside the dictionary
    for i in url_dict:
        url_found = re.findall(i, url)
        if i == url:
            # If url first accessed
            if url not in url_dict_count:
                ip_access_url_count[ip] = 1
                url_dict_count[url] = ip_access_url_count
            else:
                # If a new ip access the url
                if ip not in url_dict_count[url]:
                    # Retrieve existing ip address : count
                    ip_access_url_count = url_dict_count[url]
                    ip_access_url_count[ip] = 1
                    url_dict_count[url] = ip_access_url_count
                # Existing ip access the url
                else:
                    url_dict_count[url][ip] += 1
            # When ip address count reaches stated url count, trigger alert
            if url_dict_count[url][ip] >= url_dict[i][0]:
                logged_request, logged_alert = log_request(alert_level=url_dict[i][1], status="", status_msg="Request Behaviour conditions met", request_params="", response="URL Path - {}, has been accessed {} time(s) from ip address {}".format(url, url_dict_count[url][ip], ip),  ip_address=ip,)
                server_db.session.add(logged_request)
                server_db.session.add(logged_alert)
                server_db.session.commit()
    set_config_value("url_dict_count", url_dict_count)
    print(url_dict_count)


def restart_req():
    url_dict_count = dict()
    set_config_value("url_dict_count", url_dict_count)


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
