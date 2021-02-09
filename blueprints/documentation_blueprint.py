from flask import Blueprint, abort, render_template
from markdown import markdown

from helper_functions import required_permissions

documentation_blueprint = Blueprint("doc", __name__)


@documentation_blueprint.route("/doc/")
@required_permissions("view_api_documentation")
def doc_index():
    return render_template("documentation-index.html")


@documentation_blueprint.route("/doc/secure-db-client-side-program")
@required_permissions("view_api_documentation")
def secure_db_client_side_program_doc():
    try:
        file = open("SecureDB Client Side Program Reference.md")
    except FileNotFoundError:
        abort(404)

    file_contents = file.read()
    file.close()
    return render_template(
        "documentation-template.html",
        title="SecureDB Client Side Program Documentation",
        content=markdown(file_contents),
    )
