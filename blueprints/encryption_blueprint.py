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
    form = forms.ChoiceForm()
    model = form.model.data
    field = form.field.data

    if request.method == "POST":
        encrypted_fields = get_config_value(
            "encrypted-fields", {}, config_db_name="encryption-config"
        )

        try:
            client_class = client_db.session.query(eval(f"{model}"))
            try:
                for client in client_class:
                    setattr(
                        client,
                        field,
                        encrypt(
                            str(getattr(client, field)),
                            constants.ENCRYPTION_KEY,
                        ).hex(),
                    )
                    client_db.session.commit()

                    if field in encrypted_fields:
                        if model in encrypted_fields[model]:
                            encrypted_fields[model].append(field)
                            print(encrypted_fields[model])
                        else:
                            encrypted_fields[model] = [field]
                            print(encrypted_fields)
                    else:
                        encrypted_fields[model] = [field]
                        print(encrypted_fields)
                flash("Encrypted!", "success")
            except AttributeError:
                flash("Not found!", "danger")
            except IntegrityError:
                flash("Not found!", "danger")

        except NameError:
            flash("Not found!", "danger")

        set_config_value(
            "encrypted-fields",
            encrypted_fields,
            config_db_name="encryption-config",
        )
        # return redirect(url_for("index"))

    return render_template("encrypt-field.html", form=form)
