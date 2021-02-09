from flask import Blueprint, redirect, render_template, request, url_for

import forms
from helper_functions import (
    get_config_value,
    request_filter,
    required_permissions,
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
    url_dict = get_config_value("url_dict")
    url_dict_count = get_config_value("url_dict_count")
    print(url_dict_count)

    if url_dict is None:
        url_dict = dict()
        set_config_value("url_dict", url_dict)

    url_converted_dict = dict()

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
        url_dict = get_config_value("url_dict")

        if url_dict is None:
            url_dict = dict()

        url_dict[form.url.data] = (form.count.data, form.alert_level.data)
        set_config_value("url_dict", url_dict)

        return redirect(url_for(".request_behaviour"))

    return render_template("request-behaviour-add.html", form=form)


@requests_blueprint.route(
    "/requests/behaviour/delete/<url>", methods=["GET", "POST"]
)
@required_permissions("manage_sensitive_fields")
def delete_request_behaviour(url):
    url = url.replace("|", "/")
    url_dict = get_config_value("url_dict")
    url_dict.pop(url)
    set_config_value("url_dict", url_dict)

    return redirect(url_for(".request_behaviour"))
