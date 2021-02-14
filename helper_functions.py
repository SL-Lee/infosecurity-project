import datetime
import hashlib
import os
import re
import shelve
import shutil
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import abort, request
from flask_login import current_user
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

from crypto_functions import encrypt_file
from errors import InvalidAPIKeyError
from server_models import Alert, BackupLog, Request, server_db


def get_config_value(key, default_value=None, config_db_name="config"):
    config_db = shelve.open(config_db_name)

    try:
        return config_db["config"][key]
    except:
        return default_value
    finally:
        config_db.close()


def set_config_value(key, value, config_db_name="config"):
    config_db = shelve.open(config_db_name)
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
    server_db.session.add(logged_alert)
    server_db.session.add(logged_request)
    server_db.session.commit()

    # if alert level is high, send email
    if logged_alert.alert_level == "High":
        alertemail(logged_alert.request_id)


def month_calculator(month):
    month_list = {
        1: "Jan",
        2: "Feb",
        3: "Mar",
        4: "Apr",
        5: "May",
        6: "Jun",
        7: "Jul",
        8: "Aug",
        9: "Sep",
        10: "Oct",
        11: "Nov",
        12: "Dec",
    }
    months = list()
    months_num = list()

    if month - 4 <= 0:
        # extra month is the number of months before Jan
        # start is the month that starts from the months before Jan
        extra_month = 1 - (month - 4)
        start = 13 - extra_month

        for i in range(start, 13):
            months.append(month_list[i])
            months_num.append(i)

        for i in range(1, month + 1):
            months.append(month_list[i])
            months_num.append(i)
        year = "previous"
    else:
        # Append the previous 4 months
        for i in range(month - 4, month + 1):
            months.append(month_list[i])
            months_num.append(i)

        year = "current"

    return months, months_num, year


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

    if sort in ("Latest", "<sort>"):
        alert_list.sort(key=lambda r: r.request.datetime, reverse=True)
    else:
        alert_list.sort(key=lambda r: r.request.datetime, reverse=False)

    return alert_list


def req_behaviour(url, ip):
    # url_dict is dictionary of urls configured in Requests Behaviour
    # url_dict_count is the current number of url being accessed
    # url_dict_count[url][ip] gives number of time url accessed by ip
    url_dict = get_config_value("url_dict", {})
    url_dict_count = get_config_value("url_dict_count", {})
    ip_access_url_count = dict()

    # Go through url dict to find any url matching inside the dictionary
    for i in url_dict:
        if i == url:
            # If url first accessed
            if url not in url_dict_count:
                ip_access_url_count[ip] = 1
                url_dict_count[url] = ip_access_url_count
            # Existing url
            else:
                # If a new ip access the url
                if ip not in url_dict_count[url]:
                    # Add new ip address: count
                    ip_access_url_count = url_dict_count[url]
                    ip_access_url_count[ip] = 1
                    url_dict_count[url] = ip_access_url_count
                # Retrieve existing ip access the url
                else:
                    url_dict_count[url][ip] += 1

            # When ip address count reaches stated url count, trigger alert
            if url_dict_count[url][ip] >= url_dict[i][0]:
                log_request(
                    alert_level=url_dict[i][1],
                    status="",
                    status_msg="Request Behaviour conditions met",
                    request_params="",
                    response=(
                        f"URL Path - {url}, has been accessed "
                        f"{url_dict_count[url][ip]} time(s) from ip address "
                        f"{ip}"
                    ),
                    ip_address=ip,
                )

    set_config_value("url_dict_count", url_dict_count)
    print(url_dict_count)


def restart_req(url):
    url_dict_count = get_config_value("url_dict_count", {})

    if url in url_dict_count:
        url_dict_count.pop(url)
        print(url, "dict reset")
        set_config_value("url_dict_count", url_dict_count)


def required_permissions(*required_permission_names):
    # pylint: disable=import-outside-toplevel

    from constants import VALID_SERVER_PERMISSION_NAMES

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Abort with a 404 error code if current user is not authenticated
            if not current_user.is_authenticated:
                abort(404)

            # Abort with a 500 error code if not all required permissions are
            # valid
            if not all(
                permission in VALID_SERVER_PERMISSION_NAMES
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


def schedule_backup(filename):
    # pylint: disable=import-outside-toplevel

    from app import app
    from constants import (
        BACKUP_PATH,
        DRIVE,
        DRIVE_BACKUP_ID,
        ENCRYPTION_KEY,
        SCHEDULER,
    )

    with app.app_context():
        # get the config of the file
        SCHEDULER.print_jobs()
        backup_config = get_config_value("backup")
        print("backup files:", backup_config)
        file_settings = backup_config[filename]
        backup_datetime = datetime.datetime.now()
        backup_folder = os.path.join(BACKUP_PATH, filename)

        # if the file does not have a backup folder
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % DRIVE_BACKUP_ID}
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            folder_names.append(file["title"])

        # if backup folder not created
        if filename not in folder_names:
            folder = DRIVE.CreateFile(
                {
                    "title": filename,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [
                        {"kind": "drive#fileLink", "id": DRIVE_BACKUP_ID}
                    ],
                }
            )
            folder.Upload()

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % DRIVE_BACKUP_ID}
        ).GetList()

        # set drive id for backup
        filename_id = None

        for file in file_list:
            if file["title"] == filename:
                filename_id = file["id"]

        timestamp = secure_filename(
            backup_datetime.strftime("%d-%m-%Y %H:%M:%S")
        )
        timestamp_folder = os.path.join(
            backup_folder,
            timestamp,
        )
        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()  # to list the files in the folder id
        folder_names = []

        for file in file_list:
            folder_names.append(file["title"])

        # if backup folder not created
        if timestamp not in folder_names:
            folder = DRIVE.CreateFile(
                {
                    "title": timestamp,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [{"kind": "drive#fileLink", "id": filename_id}],
                }
            )
            folder.Upload()

        file_list = DRIVE.ListFile(
            {"q": "'%s' in parents and trashed=false" % filename_id}
        ).GetList()

        # set drive id for backup
        timestamp_id = None

        for file in file_list:
            if file["title"] == timestamp:
                timestamp_id = file["id"]

        # if no timestamp folder
        if not os.path.exists(timestamp_folder):
            os.mkdir(timestamp_folder)

        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"])
        )

        shutil.copy2(file_settings["path"], file_backup_path)
        # encrypt the backed up file
        encrypt_file(file_backup_path, ENCRYPTION_KEY)
        # after encrypting the copied file,
        # remove the copied file
        os.remove(file_backup_path)
        # set new path name for encrypted file
        file_backup_path = os.path.join(
            timestamp_folder, os.path.basename(file_settings["path"]) + ".enc"
        )
        # upload to drive
        file_upload = DRIVE.CreateFile(
            {
                "title": os.path.basename(file_backup_path),
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        # set content is get file from filepath
        file_upload.SetContentFile(file_backup_path)
        file_upload.Upload()  # Upload the file.

        # then add the encryption config for future restore
        shutil.copy2(
            "encryption-config.bak",
            os.path.join(timestamp_folder, "encryption-config.bak"),
        )
        shutil.copy2(
            "encryption-config.dat",
            os.path.join(timestamp_folder, "encryption-config.dat"),
        )
        shutil.copy2(
            "encryption-config.dir",
            os.path.join(timestamp_folder, "encryption-config.dir"),
        )

        file_upload = DRIVE.CreateFile(
            {
                "title": "encryption-config.bak",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.bak")
        file_upload.Upload()  # Upload the file.

        file_upload = DRIVE.CreateFile(
            {
                "title": "encryption-config.dat",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.dat")
        file_upload.Upload()  # Upload the file.

        file_upload = DRIVE.CreateFile(
            {
                "title": "encryption-config.dir",
                "parents": [{"kind": "drive#fileLink", "id": timestamp_id}],
            }
        )
        file_upload.SetContentFile("encryption-config.dir")
        file_upload.Upload()  # Upload the file.

        file_hash = hashlib.md5(
            open(file_settings["path"], "rb").read()
        ).hexdigest()

        backup_log = BackupLog(
            filename=os.path.splitext(os.path.basename(file_settings["path"]))[
                0
            ],
            date_created=backup_datetime,
            method="Automatic Backup",
            source_path=file_settings["path"],
            backup_path=file_backup_path,
            md5=file_hash,
        )
        server_db.session.add(backup_log)
        server_db.session.commit()


def alertemail(request_id):
    mail = Mail()
    alerts = Alert.query.filter_by(request_id=request_id).all()
    msg = Message(
        "SecureDB Report on Suspicious Requests.",
        sender="asecured@gmail.com",
        recipients=["aecommerce7@gmail.com"],
        html=(
            "<h2><b>Request ID :</h2> {}"
            "\n<h2>Alert Level :</h2> {}"
            "\n<h2>Time of Request :</h2> {}"
            "\n<h2>IP Address :</h2> {}"
            "\n<h2>Request Parameters :</h2> {}"
            "\n<h2>Status :</h2> {}"
            "\n<h2>Message :</h2> {}"
            "\n<h2>Response :</h2> {}</"
            "b>".format(
                alerts[0].request_id,
                alerts[0].alert_level,
                str(alerts[0].request.datetime)[:19],
                alerts[0].request.ip_address,
                alerts[0].request.request_params,
                alerts[0].request.status,
                alerts[0].request.status_msg,
                alerts[0].request.response,
            )
        ),
    )
    mail.send(msg)
