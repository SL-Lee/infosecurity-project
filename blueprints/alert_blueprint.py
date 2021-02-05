from flask import Blueprint, redirect, render_template, url_for
from flask_mail import Mail

from helper_functions import alertemail
from server_models import Alert

alert_blueprint = Blueprint("alert", __name__)
mail = Mail()


@alert_blueprint.route("/alert/view", methods=["GET"])
def alertview():
    alerts = Alert.query.filter_by(alert_level="High").all()
    print(alerts)
    return render_template("alert-view.html", alerts=alerts)


# def alertemail():
#     msg = Message(
#         "SecureDB Report on Suspicious Requests",
#         sender="asecured@gmail.com",
#         recipients=["aecommerce7@gmail.com"],
#     )
#     msg.body = (
#         "This is a report on High Alert Level Requests we have received. "
#         "Please look through and respond accordingly. Thank you for using "
#         "SecureDB."
#     )
#     return "Sent"


@alert_blueprint.route("/alert/email/<request_id>", methods=["GET", "POST"])
def sendalertemail(request_id):
    alertemail(request_id)
    return redirect(url_for(".alertview"))
