from flask import Blueprint, redirect, render_template, request, url_for

import constants
import forms
from helper_functions import (
    get_config_value,
    request_filter,
    required_permissions,
    restart_req,
    set_config_value,
)
from server_models import Alert

requests_blueprint = Blueprint("requests", __name__)


@requests_blueprint.route(
    "/requests/<alert_level>/<date>/<query>/<sort>", methods=["GET", "POST"]
)
@required_permissions("view_logged_requests")
def get_requests(query, alert_level, date, sort):
    form = forms.RequestFilter(request.form)

    if request.method == "POST" and form.validate():
        if form.query.data == "":
            form.query.data = "<query>"

        return redirect(
            "/requests/{}/{}/{}/{}".format(
                form.alert_level.data,
                form.date.data,
                form.query.data,
                form.sort.data,
            )
        )

    # Filter alert list according to alert_level
    if alert_level == "None":
        alerts = Alert.query.all()
    else:
        alerts = Alert.query.filter_by(alert_level=alert_level).all()

    alert_list = request_filter(alerts, date, query, sort)
    form.alert_level.data = alert_level

    # if query is empty, display in form empty string
    if query == "<query>":
        form.query.data = ""
    else:
        form.query.data = query

    return render_template(
        "requests.html", alerts=alert_list, filter=alert_level, form=form
    )


@requests_blueprint.route("/requests/behaviour", methods=["GET"])
@required_permissions("manage_request_behaviour")
def request_behaviour():
    url_dict = get_config_value("url_dict", {})
    url_dict_count = get_config_value("url_dict_count", {})
    print(url_dict_count)
    url_converted_dict = {}

    for i in url_dict:
        converted_url = i.replace("/", "|")
        url_converted_dict[i] = converted_url

    return render_template(
        "request-behaviour.html",
        urls=url_dict,
        url_converted_dict=url_converted_dict,
    )


@requests_blueprint.route("/requests/behaviour/add", methods=["GET", "POST"])
@required_permissions("manage_request_behaviour")
def request_behaviour_add():
    form = forms.RequestBehaviourForm(request.form)
    if request.method == "POST" and form.validate():
        url_dict = get_config_value("url_dict", {})

        url_dict[form.url.data] = [
            form.count.data,
            form.alert_level.data,
            form.refresh_time.data,
            form.refresh_unit.data,
        ]
        set_config_value("url_dict", url_dict)
        if form.refresh_unit.data == "Sec":
            constants.SCHEDULER.add_job(
                restart_req,
                args=[form.url.data],
                trigger="interval",
                seconds=form.refresh_time.data,
                id=form.url.data,
                name=form.url.data,
            )
        elif form.refresh_unit.data == "Min":
            constants.SCHEDULER.add_job(
                restart_req,
                args=[form.url.data],
                trigger="interval",
                minutes=form.refresh_time.data,
                id=form.url.data,
                name=form.url.data,
            )
        elif form.refresh_unit.data == "Hour":
            constants.SCHEDULER.add_job(
                restart_req,
                args=[form.url.data],
                trigger="interval",
                hours=form.refresh_time.data,
                id=form.url.data,
                name=form.url.data,
            )
        elif form.refresh_unit.data == "Day":
            constants.SCHEDULER.add_job(
                restart_req,
                args=[form.url.data],
                trigger="interval",
                days=form.refresh_time.data,
                id=form.url.data,
                name=form.url.data,
            )
        print(constants.SCHEDULER.get_job(job_id=form.url.data))
        return redirect(url_for(".request_behaviour"))

    return render_template(
        "request-behaviour-add.html", form=form, title="Add Request Behaviour"
    )


@requests_blueprint.route(
    "/requests/behaviour/update/<url>", methods=["GET", "POST"]
)
@required_permissions("manage_request_behaviour")
def request_behaviour_update(url):
    form = forms.RequestBehaviourForm(request.form)
    url_dict = get_config_value("url_dict", {})

    if request.method == "POST" and form.validate():

        form_data = [
            form.count.data,
            form.alert_level.data,
            form.refresh_time.data,
            form.refresh_unit.data,
        ]
        url_dict[form.url.data] = form_data
        set_config_value("url_dict", url_dict)

        if form.refresh_unit.data == "Sec":
            constants.SCHEDULER.reschedule_job(
                form.url.data,
                trigger="interval",
                seconds=form.refresh_time.data,
            )
        elif form.refresh_unit.data == "Min":
            constants.SCHEDULER.reschedule_job(
                form.url.data,
                trigger="interval",
                minutes=form.refresh_time.data,
            )
        elif form.refresh_unit.data == "Hour":
            constants.SCHEDULER.reschedule_job(
                form.url.data,
                trigger="interval",
                hours=form.refresh_time.data,
            )
        elif form.refresh_unit.data == "Day":
            constants.SCHEDULER.reschedule_job(
                form.url.data,
                trigger="interval",
                days=form.refresh_time.data,
            )

        print(constants.SCHEDULER.get_job(job_id=form.url.data))
        return redirect(url_for(".request_behaviour"))

    url = url.replace("|", "/")
    form.url.data = url
    form.count.data = url_dict[url][0]
    form.alert_level.data = url_dict[url][1]
    form.refresh_time.data = url_dict[url][2]
    form.refresh_unit.data = url_dict[url][3]

    return render_template(
        "request-behaviour-add.html",
        form=form,
        title="Update Request Behaviour",
    )


@requests_blueprint.route(
    "/requests/behaviour/delete/<url>", methods=["GET", "POST"]
)
@required_permissions("manage_sensitive_fields")
def delete_request_behaviour(url):
    url = url.replace("|", "/")
    url_dict = get_config_value("url_dict", {})

    try:
        url_dict.pop(url)
        set_config_value("url_dict", url_dict)
        constants.SCHEDULER.remove_job(job_id=url)
        print(constants.SCHEDULER.get_jobs())
    except:
        print("URL does not exist")

    return redirect(url_for(".request_behaviour"))
