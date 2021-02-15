import calendar
import datetime

from flask import Blueprint, jsonify

from helper_functions import month_calculator
from server_models import Alert, Request

dashboard_blueprint = Blueprint("dashboard", __name__)


@dashboard_blueprint.route("/day")
def data():
    today = datetime.datetime.now()
    day_no = datetime.datetime.weekday(today)
    mon_date = today

    # When today is not monday, get monday date
    if day_no != 0:
        mon_date = today - datetime.timedelta(days=today.weekday())
    if day_no != 6:
        sun_date = today + datetime.timedelta(days=(6 - today.weekday()))
    else:
        sun_date = today

    # Get requests based on time
    requests = Request.query.filter(
        Request.datetime.between(mon_date, sun_date)
    ).all()
    alerts = list()

    for request in requests:
        alert = Alert.query.filter_by(request_id=request.id).first()
        alerts.append(alert)

    low_date_list = [0, 0, 0, 0, 0, 0, 0]
    medium_date_list = [0, 0, 0, 0, 0, 0, 0]
    high_date_list = [0, 0, 0, 0, 0, 0, 0]

    for i in alerts:
        num = i.request.datetime.weekday()

        if i.alert_level == "Low":
            low_date_list[num] += 1
        elif i.alert_level == "Medium":
            medium_date_list[num] += 1
        else:
            high_date_list[num] += 1

    return jsonify(
        {
            "low": low_date_list,
            "medium": medium_date_list,
            "high": high_date_list,
        }
    )


@dashboard_blueprint.route("/month")
def month():
    today = datetime.datetime.now()
    current_year = today.year
    month_list, month_num_list, year = month_calculator(today.month)
    low_date_list = [0, 0, 0, 0, 0]
    medium_date_list = [0, 0, 0, 0, 0]
    high_date_list = [0, 0, 0, 0, 0]
    index = 0

    if year == "previous":
        for i in month_num_list:
            alerts = list()

            if i > 8:
                last_day = calendar.monthrange(current_year - 1, i)[1]
                start = datetime.datetime(current_year - 1, i, 1)
                end = datetime.datetime(current_year - 1, i, last_day)
                requests = Request.query.filter(
                    Request.datetime.between(start, end)
                ).all()

                for request in requests:
                    alert = Alert.query.filter_by(request_id=request.id).first()
                    alerts.append(alert)

                for i in alerts:
                    if i.alert_level == "Low":
                        low_date_list[index] += 1
                    elif i.alert_level == "Medium":
                        medium_date_list[index] += 1
                    else:
                        high_date_list[index] += 1
            else:
                last_day = calendar.monthrange(current_year, i)[1]
                start = datetime.datetime(current_year, i, 1)
                end = datetime.datetime(current_year, i, last_day)
                requests = Request.query.filter(
                    Request.datetime.between(start, end)
                ).all()

                for request in requests:
                    alert = Alert.query.filter_by(request_id=request.id).first()
                    alerts.append(alert)

                for i in alerts:
                    if i.alert_level == "Low":
                        low_date_list[index] += 1
                    elif i.alert_level == "Medium":
                        medium_date_list[index] += 1
                    else:
                        high_date_list[index] += 1

            index += 1
    else:
        for i in month_num_list:
            alerts = list()
            last_day = calendar.monthrange(current_year, i)[1]
            start = datetime.datetime(current_year, i, 1)
            end = datetime.datetime(current_year, i, last_day)
            requests = Request.query.filter(
                Request.datetime.between(start, end)
            ).all()

            for request in requests:
                alert = Alert.query.filter_by(request_id=request.id).first()
                alerts.append(alert)

            for i in alerts:
                if i.alert_level == "Low":
                    low_date_list[index] += 1
                elif i.alert_level == "Medium":
                    medium_date_list[index] += 1
                else:
                    high_date_list[index] += 1

            index += 1

    return jsonify(
        {
            "low": low_date_list,
            "medium": medium_date_list,
            "high": high_date_list,
            "month": month_list,
        }
    )


@dashboard_blueprint.route("/year")
def year():
    today = datetime.datetime.now()
    today = datetime.datetime(today.year, today.month, today.day)
    current_year = today.year
    year = [current_year - 2, current_year - 1, current_year]
    low_date_list = [0, 0, 0]
    medium_date_list = [0, 0, 0]
    high_date_list = [0, 0, 0]
    index = 0

    for i in year:
        start = datetime.datetime(i, 1, 1)
        end = datetime.datetime(i, 12, 31)
        requests = Request.query.filter(
            Request.datetime.between(start, end)
        ).all()
        alerts = list()

        for request in requests:
            alert = Alert.query.filter_by(request_id=request.id).first()
            alerts.append(alert)

        for i in alerts:
            if i.alert_level == "Low":
                low_date_list[index] += 1
            elif i.alert_level == "Medium":
                medium_date_list[index] += 1
            else:
                high_date_list[index] += 1

        index += 1

    return jsonify(
        {
            "low": low_date_list,
            "medium": medium_date_list,
            "high": high_date_list,
            "year": year,
        }
    )
