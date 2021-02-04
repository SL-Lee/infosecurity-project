import os

from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
)
from werkzeug.utils import secure_filename

import constants
import forms
from client_models import *
from crypto_functions import decrypt_file, encrypt, encrypt_file
from helper_functions import (
    get_config_value,
    required_permissions,
    set_config_value,
)

encryption_blueprint = Blueprint("encryption_blueprint", __name__)


# Upload API
@encryption_blueprint.route("/encrypt-file", methods=["GET", "POST"])
@required_permissions("manage_encrypted_files")
def upload_file():
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            print("no file")
            return redirect(request.url)

        file = request.files["file"]

        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == "":
            flash("No file", "danger")
            print("no filename")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file.save(os.path.join("uploads/", filename))

        if "encrypt" in request.form:
            encrypt_file(
                os.path.join("uploads/", filename), constants.ENCRYPTION_KEY
            )
            print("saved file successfully")
            # delete uploaded file
            os.remove(os.path.join("uploads/", filename))
            # send file name as parameter to download
            return redirect("/download-file/" + filename + ".enc")

        if "decrypt" in request.form:
            decrypt_file(
                os.path.join("uploads/", filename), constants.ENCRYPTION_KEY
            )
            print("saved file2 successfully")
            os.remove(os.path.join("uploads/", filename))
            # send file name as parameter to download
            return redirect("/download-file2/" + filename[:-4] + ".dec")

    return render_template("encrypt-file.html")


# Download API
@encryption_blueprint.route("/download-file/<filename>", methods=["GET"])
@required_permissions("manage_encrypted_files")
def download_file(filename):
    return render_template("download-file.html", value=filename)


@encryption_blueprint.route("/return-files/<filename>")
@required_permissions("manage_encrypted_files")
def return_files_tut(filename):
    file_path = "uploads/" + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Download API
@encryption_blueprint.route("/download-file2/<filename>", methods=["GET"])
@required_permissions("manage_encrypted_files")
def download_file2(filename):
    file_path = "uploads/" + filename

    def generate():
        with open(file_path, "rb") as file:
            yield from file

        os.remove(file_path)

    download_request = Response(generate())
    download_request.headers.set(
        "Content-Disposition", "attachment", filename=filename
    )
    return download_request


@encryption_blueprint.route("/return-files2/<filename>")
@required_permissions("manage_encrypted_files")
def return_files_tut2(filename):
    file_path = "uploads/" + filename
    return send_file(file_path, as_attachment=True, attachment_filename="")


# Individual data fields encryption
@encryption_blueprint.route("/encrypt-field", methods=["GET", "POST"])
@required_permissions("manage_encrypted_fields")
def upload_field():
    # pylint: disable=pointless-string-statement
    # pylint: disable=unused-variable

    form = forms.ChoiceForm()
    model = form.model.data
    field = form.field.data

    if request.method == "POST":
        encrypted_fields = get_config_value(
            "encrypted-fields",
            {
                "User": [],
                "Role": [],
                "CreditCard": [],
                "Address": [],
                "Product": [],
                "Review": [],
                "OrderProduct": [],
            },
        )
        # User Class
        if model == "User":
            for user in User.query.all():
                setattr(
                    user,
                    field,
                    encrypt(
                        str(getattr(user, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["User"]:
                    encrypted_fields["User"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Role Class
        elif model == "Role":
            for role in Role.query.all():
                setattr(
                    role,
                    field,
                    encrypt(
                        str(getattr(role, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["Role"]:
                    encrypted_fields["Role"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Credit Card Class
        elif model == "Credit Card":
            for credit_card in CreditCard.query.all():
                setattr(
                    credit_card,
                    field,
                    encrypt(
                        str(getattr(credit_card, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["CreditCard"]:
                    encrypted_fields["CreditCard"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Address Class
        elif model == "Address":
            for address in Address.query.all():
                setattr(
                    address,
                    field,
                    encrypt(
                        str(getattr(address, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Product Class
        elif model == "Product":
            for product in Product.query.all():
                setattr(
                    product,
                    field,
                    encrypt(
                        str(getattr(product, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Review Class
        elif model == "Review":
            for review in Review.query.all():
                setattr(
                    review,
                    field,
                    encrypt(
                        str(getattr(review, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["Review"]:
                    encrypted_fields["Review"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        # Order Class
        elif model == "Order Product":
            for order in OrderProduct.query.all():
                setattr(
                    order,
                    field,
                    encrypt(
                        str(getattr(order, field)), constants.ENCRYPTION_KEY
                    ).hex(),
                )
                client_db.session.commit()

                if field not in encrypted_fields["OrderProduct"]:
                    encrypted_fields["OrderProduct"].append(field)
                # print(encrypted_fields)

            flash("Encrypted!", "success")
        else:
            flash("Not Found!", "danger")

        set_config_value("encrypted-fields", encrypted_fields)
        return redirect(url_for("index"))

    return render_template("encrypt-field.html", form=form)
