from flask import Blueprint, redirect, render_template, url_for
from flask_mail import Mail, Message

from server_models import Alert

alert_blueprint = Blueprint("alert", __name__)
mail = Mail()


@alert_blueprint.route("/alert/view", methods=["GET"])
def alertview():
    alerts = Alert.query.filter_by(alert_level="high").all()
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
    print("sent")
    alerts = Alert.query.filter_by(request_id=request_id).all()
    print("Sent", alerts[0].__dict__)
    msg = Message(
        "SecureDB Report on Suspicious Requests.",
        sender="asecured@gmail.com",
        recipients=["aecommerce7@gmail.com"],
        html=(
            "<h1><b>Request ID : {}\nAlert Level : {}\nDatetime : {}\nRequest "
            "Parameters : {}\nStatus : {}\nMessage : {}\nResponse : {}</h1></"
            "b>".format(
                alerts[0].request_id,
                alerts[0].alert_level,
                alerts[0].request.datetime,
                alerts[0].request.request_params,
                alerts[0].request.status,
                alerts[0].request.status_msg,
                alerts[0].request.response,
            )
        ),
    )
    mail.send(msg)
    return redirect(url_for(".alertview"))
