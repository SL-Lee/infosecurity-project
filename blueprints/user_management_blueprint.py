import datetime
import hashlib
import os

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

import forms
from helper_functions import required_permissions
from server_models import ServerPermission, ServerUser, server_db

user_management_blueprint = Blueprint("user_management", __name__)


@user_management_blueprint.route("/user-management")
@required_permissions("manage_users")
def user_management():
    server_users = ServerUser.query.all()
    return render_template("user-management.html", server_users=server_users)


@user_management_blueprint.route(
    "/user-management/create", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def user_management_create():
    create_user_form = forms.CreateUserForm(request.form)
    create_user_form.permissions.choices = [
        (server_permission.name, server_permission.name)
        for server_permission in ServerPermission.query.all()
    ]

    if request.method == "POST" and create_user_form.validate():
        if (
            ServerUser.query.filter_by(
                username=create_user_form.username.data
            ).first()
            is not None
        ):
            flash(
                "Another user account already has the username of '"
                f"{create_user_form.username.data}'. Please try again with a "
                "unique username.",
                "danger",
            )
            return redirect(url_for(".user_management_create"))

        new_server_user_password_salt = os.urandom(32)
        new_server_user_password_hash = hashlib.scrypt(
            password=create_user_form.password.data.encode("UTF-8"),
            salt=new_server_user_password_salt,
            n=32768,
            r=8,
            p=1,
            maxmem=33816576,
        )
        new_server_user = ServerUser(
            username=create_user_form.username.data,
            password_salt=new_server_user_password_salt,
            password_hash=new_server_user_password_hash,
            date_created=datetime.datetime.now(),
        )

        for server_permission in create_user_form.permissions.data:
            new_server_user_permission = ServerPermission.query.get(
                server_permission
            )

            if new_server_user_permission is not None:
                new_server_user.permissions.append(new_server_user_permission)

        server_db.session.add(new_server_user)
        server_db.session.commit()
        flash("New user created successfully.", "success")

        return redirect(url_for(".user_management"))

    return render_template(
        "user-management-form.html",
        title="User Management — Create User",
        form=create_user_form,
        form_action_route=url_for(".user_management_create"),
        action_name="Create",
    )


@user_management_blueprint.route(
    "/user-management/edit/<int:server_user_id>", methods=["GET", "POST"]
)
@required_permissions("manage_users")
def user_management_edit(server_user_id):
    edit_user_form = forms.CreateUserForm(request.form)
    edit_user_form.permissions.choices = [
        (server_permission.name, server_permission.name)
        for server_permission in ServerPermission.query.all()
    ]
    server_user = ServerUser.query.get(server_user_id)

    if request.method == "POST" and edit_user_form.validate():
        # If the user supplies a new username but that username already exists,
        # return an error
        if (
            server_user.username != edit_user_form.username.data
            and ServerUser.query.filter_by(
                username=edit_user_form.username.data
            ).first()
            is not None
        ):
            flash(
                "Another user account already has the username of '"
                f"{edit_user_form.username.data}'. Please try again with a "
                "unique username.",
                "danger",
            )
            return redirect(
                url_for(".user_management_edit", server_user_id=server_user_id)
            )

        server_user.username = edit_user_form.username.data
        password_salt = os.urandom(32)
        password_hash = hashlib.scrypt(
            password=edit_user_form.password.data.encode("UTF-8"),
            salt=password_salt,
            n=32768,
            r=8,
            p=1,
            maxmem=33816576,
        )
        server_user.password_salt = password_salt
        server_user.password_hash = password_hash

        if (
            ServerUser.query.count() == 1
            and "manage_users" not in edit_user_form.permissions.data
        ):
            flash(
                "You cannot unassign the 'manage_users' permission from the "
                "only user that has this permission.",
                "danger",
            )
            return redirect(
                url_for(".user_management_edit", server_user_id=server_user_id)
            )

        if (
            server_user_id == current_user.id
            and "manage_users" not in edit_user_form.permissions.data
        ):
            flash(
                "You cannot unassign the 'manage_users' permission from the "
                "current user.",
                "danger",
            )
            return redirect(
                url_for(".user_management_edit", server_user_id=server_user_id)
            )

        server_user.permissions = []

        for server_permission in edit_user_form.permissions.data:
            server_user_permission = ServerPermission.query.get(
                server_permission
            )

            if server_user_permission is not None:
                server_user.permissions.append(server_user_permission)

        server_db.session.commit()
        flash("User edited successfully.", "success")

        return redirect(url_for(".user_management"))

    edit_user_form.username.data = server_user.username
    edit_user_form.permissions.data = [
        server_permission.name for server_permission in server_user.permissions
    ]

    return render_template(
        "user-management-form.html",
        title="User Management — Edit User",
        form=edit_user_form,
        form_action_route=url_for(
            ".user_management_edit", server_user_id=server_user_id
        ),
        action_name="Edit",
    )


@user_management_blueprint.route("/user-management/delete", methods=["POST"])
@required_permissions("manage_users")
def user_management_delete():
    if ServerUser.query.count() == 1:
        flash("You cannot delete the only remaining user.", "danger")
        return redirect(url_for(".user_management"))

    try:
        server_user_id = int(request.form["server-user-id"])

        if server_user_id == current_user.id:
            flash("You cannot delete the current user.", "danger")
            return redirect(url_for(".user_management"))

        server_user = ServerUser.query.get(server_user_id)
        server_db.session.delete(server_user)
        server_db.session.commit()
        flash("User deleted successfully.", "success")
    except:
        flash("There was an error while deleting the user.", "danger")

    return redirect(url_for(".user_management"))
