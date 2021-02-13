from flask import Blueprint, redirect, render_template, request, url_for

import forms
from helper_functions import required_permissions
from server_models import Rule, server_db

sensitive_fields_blueprint = Blueprint("sensitive_fields", __name__)


@sensitive_fields_blueprint.route("/sensitive-fields", methods=["GET"])
@required_permissions("manage_sensitive_fields")
def get_sensitive_fields():
    sensitive_fields = Rule.query.all()
    return render_template(
        "sensitive-fields.html", sensitive_fields=sensitive_fields
    )


@sensitive_fields_blueprint.route(
    "/sensitive-fields/add", methods=["GET", "POST"]
)
@required_permissions("manage_sensitive_fields")
def add_sensitive_fields():
    form = forms.SensitiveFieldForm(request.form)

    if request.method == "POST" and form.validate():
        rule = Rule(
            contents=form.sensitive_field.data,
            action=form.action.data,
            alert_level=form.alert_level.data,
            occurrence_threshold=form.occurrence_threshold.data,
        )
        server_db.session.add(rule)
        server_db.session.commit()

        return redirect(url_for(".get_sensitive_fields"))

    return render_template("sensitive-fields-add.html", form=form)


@sensitive_fields_blueprint.route(
    "/sensitive-fields/update/<field>", methods=["GET", "POST"]
)
@required_permissions("manage_sensitive_fields")
def update_sensitive_fields(field):
    form = forms.SensitiveFieldForm(request.form)
    rule = Rule.query.filter_by(id=field).first_or_404()

    if request.method == "POST" and form.validate():
        rule.contents = form.sensitive_field.data
        rule.action = form.action.data
        rule.alert_level = form.alert_level.data
        rule.occurrence_threshold = form.occurrence_threshold.data
        server_db.session.commit()

        return redirect(url_for(".get_sensitive_fields"))

    form.sensitive_field.data = rule.contents
    form.action.data = rule.action
    form.occurrence_threshold.data = rule.occurrence_threshold
    form.alert_level.data = rule.alert_level
    return render_template("sensitive-fields-update.html", form=form, rule=rule)


@sensitive_fields_blueprint.route(
    "/sensitive-fields/delete/<field>", methods=["GET", "POST"]
)
@required_permissions("manage_sensitive_fields")
def delete_sensitive_fields(field):
    rule = Rule.query.filter_by(id=field).first_or_404()
    server_db.session.delete(rule)
    server_db.session.commit()

    return redirect(url_for(".get_sensitive_fields"))
