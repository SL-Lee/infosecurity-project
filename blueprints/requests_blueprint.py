from flask import Blueprint, redirect, render_template, request

import forms
from helper_functions import request_filter, required_permissions
from server_models import Alert

requests_blueprint = Blueprint("requests", __name__)


@requests_blueprint.route(
    "/requests/<alert_level>/<date>/<query>", methods=["GET", "POST"]
)
@required_permissions("view_logged_requests")
def get_requests(query, alert_level, date):
    form = forms.RequestFilter(request.form)

    if request.method == "POST" and form.validate():
        if form.query.data == "":
            form.query.data = "<query>"

        return redirect(
            "/requests/{}/{}/{}".format(
                form.alert_level.data, form.date.data, form.query.data
            )
        )

    # Filter alert list according to alert_level
    if alert_level == "None":
        alerts = Alert.query.all()
    else:
        alerts = Alert.query.filter_by(alert_level=alert_level).all()

    alert_list = request_filter(alerts, date, query)

    form.alert_level.data = alert_level

    # if query is empty, display in form empty string
    if query == "<query>":
        form.query.data = ""
    else:
        form.query.data = query

    return render_template(
        "requests.html", alerts=alert_list, filter=alert_level, form=form
    )
