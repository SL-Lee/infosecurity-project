from flask import Blueprint, redirect, render_template, request, url_for

import forms
from helper_functions import (
    get_config_value,
    required_permissions,
    set_config_value,
)

whitelist_blueprint = Blueprint("whitelist", __name__)


@whitelist_blueprint.route("/whitelist", methods=["GET"])
@required_permissions("manage_ip_whitelist")
def get_whitelist():
    whitelist = get_config_value("whitelist", [])
    return render_template("whitelist.html", whitelist=whitelist)


@whitelist_blueprint.route("/whitelist/add", methods=["GET", "POST"])
@required_permissions("manage_ip_whitelist")
def whitelist():
    form = forms.WhitelistForm(request.form)

    if request.method == "POST" and form.validate():
        whitelist = get_config_value("whitelist", [])
        whitelist.append(form.ip_address.data)
        set_config_value("whitelist", whitelist)

        return redirect(url_for(".get_whitelist"))

    return render_template("whitelist-add.html", form=form)


@whitelist_blueprint.route("/whitelist/delete/<field>", methods=["GET", "POST"])
@required_permissions("manage_ip_whitelist")
def delete_whitelist(field):
    whitelist = get_config_value("whitelist", [])

    try:
        whitelist.remove(field)
        set_config_value("whitelist", whitelist)
    except:
        print("No such whitelist")

    return redirect(url_for(".get_whitelist"))
