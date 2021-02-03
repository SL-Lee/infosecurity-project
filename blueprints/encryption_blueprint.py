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
        for user in User.query.all():
            if model == "User" and field == "username":
                user.username = encrypt(
                    str(user.username), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "username" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("username")

                # print(encrypted_fields)
            elif model == "User" and field == "email":
                user.email = encrypt(
                    str(user.email), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "email" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("email")

                # print(encrypted_fields)
            elif model == "User" and field == "password":
                user.password = encrypt(
                    str(user.password), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "password" not in encrypted_fields["User"]:
                    encrypted_fields["User"].append("password")

                # print(encrypted_fields)
            else:
                print("not found")

        # Role Class
        for role in Role.query.all():
            if model == "Role" and field == "name":
                role.name = encrypt(
                    str(role.name), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "name" not in encrypted_fields["Role"]:
                    encrypted_fields["Role"].append("name")

                # print(encrypted_fields)
            elif model == "Role" and field == "description":
                role.description = encrypt(
                    str(role.description), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "description" not in encrypted_fields["Role"]:
                    encrypted_fields["Role"].append("description")

                # print(encrypted_fields)

        # Credit Card Class
        for credit_card in CreditCard.query.all():
            if model == "Credit Card" and field == "card number":
                credit_card.card_number = encrypt(
                    str(credit_card.card_number), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "card_number" not in encrypted_fields["CreditCard"]:
                    encrypted_fields["CreditCard"].append("card_number")

                # print(encrypted_fields)
            elif model == "Credit Card" and field == "iv":
                credit_card.iv = encrypt(
                    str(credit_card.iv), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "iv" not in encrypted_fields["CreditCard"]:
                    encrypted_fields["CreditCard"].append("iv")

                # print(encrypted_fields)
            else:
                print("not found")

        # Address Class
        for address in Address.query.all():
            if model == "Address" and field == "address":
                address.address = encrypt(
                    str(address.address), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "address" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("address")

                # print(encrypted_fields)
            elif model == "Address" and field == "zip code":
                address.zip_code = encrypt(
                    str(address.zip_code), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "zip_code" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("zip_code")

                # print(encrypted_fields)
            elif model == "Address" and field == "city":
                address.city = encrypt(
                    str(address.city), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "city" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("city")

                # print(encrypted_fields)
            elif model == "Address" and field == "state":
                address.state = encrypt(
                    str(address.state), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "state" not in encrypted_fields["Address"]:
                    encrypted_fields["Address"].append("state")

                # print(encrypted_fields)
            else:
                print("not found")

        # Product Class
        for product in Product.query.all():
            if model == "Product" and field == "product name":
                product.product_name = encrypt(
                    str(product.product_name), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "product_name" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("product_name")

                # print(encrypted_fields)
            elif model == "Product" and field == "description":
                product.description = encrypt(
                    str(product.description), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "description" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("description")

                # print(encrypted_fields)
            elif model == "Product" and field == "image":
                product.image = encrypt(
                    str(product.image), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "image" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("image")

                # print(encrypted_fields)
            elif model == "Product" and field == "quantity":
                product.quantity = encrypt(
                    str(product.quantity), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "quantity" not in encrypted_fields["Product"]:
                    encrypted_fields["Product"].append("quantity")

                # print(encrypted_fields)
            else:
                print("not found")

        # Review Class
        for review in Review.query.all():
            if model == "Review" and field == "rating":
                review.rating = encrypt(
                    str(review.rating), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "rating" not in encrypted_fields["Review"]:
                    encrypted_fields["Review"].append("rating")

                # print(encrypted_fields)
            elif model == "Review" and field == "contents":
                review.contents = encrypt(
                    str(review.contents), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "contents" not in encrypted_fields["Review"]:
                    encrypted_fields["Review"].append("contents")

                # print(encrypted_fields)
            else:
                print("not found")

        # Order Class
        for order in OrderProduct.query.all():
            if model == "Order Product" and field == "quantity":
                order.quantity = encrypt(
                    str(order.quantity), constants.ENCRYPTION_KEY
                ).hex()
                client_db.session.commit()

                if "quantity" not in encrypted_fields["OrderProduct"]:
                    encrypted_fields["OrderProduct"].append("quantity")

                # print(encrypted_fields)
            else:
                print("not found")

        set_config_value("encrypted-fields", encrypted_fields)
        return redirect(url_for("index"))

    return render_template("encrypt-field.html", form=form)
