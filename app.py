import hashlib
import os

from flask import Flask, flash, redirect, render_template, request, url_for, jsonify
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

import constants
import forms
from blueprints import (
    alert_blueprint,
    api_blueprint,
    api_key_management_blueprint,
    backup_blueprint,
    encryption_blueprint,
    encryption_key_management_blueprint,
    requests_blueprint,
    sensitive_fields_blueprint,
    user_management_blueprint,
    whitelist_blueprint,
)
from client_models import client_db
from helper_functions import is_safe_url
from server_models import ServerPermission, ServerUser, server_db, Alert, Request

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///client_db.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    "server": "sqlite:///server_db.sqlite3",
}
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config.update(
    dict(
        DEBUG=True,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_DEFAULT_SENDER="asecuredb@gmail.com",
        MAIL_USERNAME="asecuredb@gmail.com",
        MAIL_PASSWORD="securedb123",
    )
)

app.register_blueprint(alert_blueprint.alert_blueprint)
app.register_blueprint(api_blueprint.api_blueprint)
app.register_blueprint(
    api_key_management_blueprint.api_key_management_blueprint
)
app.register_blueprint(backup_blueprint.backup_blueprint)
app.register_blueprint(encryption_blueprint.encryption_blueprint)
app.register_blueprint(
    encryption_key_management_blueprint.encryption_key_management_blueprint
)
app.register_blueprint(requests_blueprint.requests_blueprint)
app.register_blueprint(sensitive_fields_blueprint.sensitive_fields_blueprint)
app.register_blueprint(user_management_blueprint.user_management_blueprint)
app.register_blueprint(whitelist_blueprint.whitelist_blueprint)

csrf = CSRFProtect(app)
csrf.exempt(api_blueprint.api_blueprint)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"
login_manager.login_message_category = "danger"

client_db.init_app(app)
server_db.init_app(app)
alert_blueprint.mail.init_app(app)

with app.app_context():
    client_db.create_all()
    client_db.session.commit()

    server_db.create_all(bind="server")
    server_permission_names = [
        server_permission.name
        for server_permission in ServerPermission.query.all()
    ]

    # Create missing server permission(s)
    for server_permission_name in [
        valid_server_permission
        for valid_server_permission in constants.VALID_SERVER_PERMISSION_NAMES
        if valid_server_permission not in server_permission_names
    ]:
        server_db.session.add(ServerPermission(name=server_permission_name))

    # Remove any invalid server permission(s)
    for server_permission_name in [
        server_permission_name
        for server_permission_name in server_permission_names
        if server_permission_name not in constants.VALID_SERVER_PERMISSION_NAMES
    ]:
        server_db.session.delete(
            ServerPermission.query.get(server_permission_name)
        )

    server_db.session.commit()


@app.template_filter()
def contains_any(items, *required_items):
    return any(item in required_items for item in items)


@app.context_processor
def inject_current_user_permissions():
    current_user_permissions = (
        [user_permission.name for user_permission in current_user.permissions]
        if current_user.is_authenticated
        else None
    )
    return dict(current_user_permissions=current_user_permissions)


@login_manager.user_loader
def load_user(user_id):
    return server_db.session.query(ServerUser).get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def index():
    server_users = ServerUser.query.all()

    if not any(
        ServerPermission.query.get("manage_users") in server_user.permissions
        for server_user in server_users
    ):
        return redirect(url_for("onboarding.onboarding"))

    login_form = forms.LoginForm(request.form)

    if request.method == "POST" and login_form.validate():
        server_user = ServerUser.query.filter_by(
            username=login_form.username.data
        ).first()

        if server_user is None:
            flash("Invalid username and/or password.", "danger")
            return render_template("index.html", form=login_form)

        if (
            hashlib.scrypt(
                password=login_form.password.data.encode("UTF-8"),
                salt=server_user.password_salt,
                n=32768,
                r=8,
                p=1,
                maxmem=33816576,
            )
            == server_user.password_hash
        ):
            login_user(server_user)
            flash("Logged in successfully.", "success")

            next_url = request.args.get("next")

            if next_url is not None and is_safe_url(next_url):
                return redirect(next_url)
        else:
            flash("Invalid username and/or password.", "danger")

    return render_template(
        "index.html", form=login_form, next=request.args.get("next")
    )


@app.route("/day")
def data():
    import datetime
    today = datetime.datetime.now()
    day_no = datetime.datetime.weekday(today)
    mon_date = today
    # When today is not monday, get monday date
    if day_no != 0:
        mon_date = today - datetime.timedelta(days=today.weekday())
    if day_no != 6:
        sun_date = today + datetime.timedelta(days=(6-today.weekday()))
    else:
        sun_date = today

    # Get requests based on time
    requests = Request.query.filter(Request.datetime.between(mon_date, sun_date)).all()
    alerts = list()
    for request in requests:
        alert = Alert.query.filter_by(request_id=request.id).first()
        alerts.append(alert)
    low_date_list = [0, 0, 0, 0, 0, 0, 0]
    medium_date_list = [0, 0, 0, 0, 0, 0, 0]
    high_date_list = [0, 0, 0, 0, 0, 0, 0]
    for i in alerts:
        num = i.request.datetime.weekday()
        if i.alert_level == "Low":
            low_date_list[num] += 1
        elif i.alert_level == "Medium":
            medium_date_list[num] += 1
        else:
            high_date_list[num] += 1
    print(low_date_list)
    print(medium_date_list)
    print(high_date_list)

    return jsonify({"low": low_date_list, "medium": medium_date_list, "high": high_date_list})

@app.route("/month")
def month():
    import datetime, calendar
    from helper_functions import month_calculator

    today = datetime.datetime.now()
    current_year = today.year
    month_list, month_num_list, year = month_calculator(today.month)
    low_date_list = [0, 0, 0, 0, 0]
    medium_date_list = [0, 0, 0, 0, 0]
    high_date_list = [0, 0, 0, 0, 0]
    index = 0
    if year == "previous":
        for i in month_num_list:
            alerts = list()
            if i > 8:
                last_day = calendar.monthrange(current_year-1, i)[1]
                start = datetime.datetime(current_year-1, i, 1)
                end = datetime.datetime(current_year-1, i, last_day)
                requests = Request.query.filter(Request.datetime.between(start, end)).all()
                for request in requests:
                    alert = Alert.query.filter_by(request_id=request.id).first()
                    alerts.append(alert)
                for i in alerts:
                    if i.alert_level == "Low":
                        low_date_list[index] += 1
                    elif i.alert_level == "Medium":
                        medium_date_list[index] += 1
                    else:
                        high_date_list[index] += 1
            else:
                last_day = calendar.monthrange(current_year, i)[1]
                start = datetime.datetime(current_year, i, 1)
                end = datetime.datetime(current_year, i, last_day)
                requests = Request.query.filter(Request.datetime.between(start, end)).all()
                for request in requests:
                    alert = Alert.query.filter_by(request_id=request.id).first()
                    alerts.append(alert)
                for i in alerts:
                    if i.alert_level == "Low":
                        low_date_list[index] += 1
                    elif i.alert_level == "Medium":
                        medium_date_list[index] += 1
                    else:
                        high_date_list[index] += 1
            index += 1
    else:
        for i in month_num_list:
            alerts = list()
            last_day = calendar.monthrange(current_year, i)[1]
            start = datetime.datetime(current_year, i, 1)
            end = datetime.datetime(current_year, i, last_day)
            requests = Request.query.filter(Request.datetime.between(start, end)).all()
            for request in requests:
                alert = Alert.query.filter_by(request_id=request.id).first()
                alerts.append(alert)
            for i in alerts:
                if i.alert_level == "Low":
                    low_date_list[index] += 1
                elif i.alert_level == "Medium":
                    medium_date_list[index] += 1
                else:
                    high_date_list[index] += 1
            index += 1


    print(month_list)
    print(low_date_list)
    print(medium_date_list)
    print(high_date_list)
    print("/month is being sent")
    return jsonify({"low": low_date_list, "medium": medium_date_list, "high": high_date_list, "month": month_list})


@app.route("/year")
def year():
    import datetime
    today = datetime.datetime.now()
    current_year = today.year
    year = [current_year-2, current_year-1, current_year]
    low_date_list = [0, 0, 0]
    medium_date_list = [0, 0, 0]
    high_date_list = [0, 0, 0]
    index = 0
    for i in year:
        start = datetime.datetime(i, 1, 1)
        end = datetime.datetime(i, 12, 31)
        requests = Request.query.filter(Request.datetime.between(start, end)).all()
        alerts = list()
        for request in requests:
            alert = Alert.query.filter_by(request_id=request.id).first()
            alerts.append(alert)

        for i in alerts:
            if i.alert_level == "Low":
                low_date_list[index] += 1
            elif i.alert_level == "Medium":
                medium_date_list[index] += 1
            else:
                high_date_list[index] += 1
        index += 1
    print(low_date_list)
    print(medium_date_list)
    print(high_date_list)
    print("/year is being sent")
    return jsonify({"low": low_date_list, "medium": medium_date_list, "high": high_date_list, "year": year})

@app.route("/random")
def random():
    import random
    import datetime
    from server_models import Alert, BackupLog, Request, server_db

    for i in range(100):
        day = random.randrange(1, 28)
        month = random.randrange(1, 12)
        year = random.randrange(2019, 2021)
        logged_request = Request(
            datetime=datetime.datetime(year, month, day),
            status="OK",
            status_msg="OK",
            request_params="Model: Product, Filter: Product.product_id > 0",
            response="[OrderedDict([('product_id', 1), ('product_name', 'Carmen Shopper'), ('description', '1 Adjustable & Detachable Crossbody Strap, 2 Handles'), ('image', 'images/ZB7938001_main.jpg'), ('price', 218.0), ('quantity', 120), ('deleted', False)]), OrderedDict([('product_id', 2), ('product_name', 'Rachel Tote'), ('description', '2 Handles'), ('image', 'images/ZB7507200_main.jpg'), ('price', 198.0), ('quantity', 250), ('deleted', False)]), OrderedDict([('product_id', 3), ('product_name', 'Fiona Crossbody'), ('description', '1 Adjustable & Detachable Crossbody Strap'), ('image', 'images/ZB7669200_main.jpg'), ('price', 148.0), ('quantity', 150), ('deleted', False)]), OrderedDict([('product_id', 4), ('product_name', 'Maya Hobo'), ('description', '1 Adjustable & Detachable Crossbody Strap, 1 Short Shoulder Strap'), ('image', 'images/ZB6979200_main.jpg'), ('price', 238.0), ('quantity', 200), ('deleted', False)])]",
            ip_address="127.0.0.1",
        )
        logged_alert = Alert(request=logged_request, alert_level="Low")
        server_db.session.add(logged_alert)
        server_db.session.add(logged_request)
        server_db.session.commit()

    for i in range(25):
        day = random.randrange(1, 28)
        month = random.randrange(1, 12)
        year = random.randrange(2019, 2021)
        logged_request = Request(
            datetime=datetime.datetime(year, month, day),
            status="ERROR",
            status_msg="Denied",
            request_params="Model: User, Filter: User.id > 0",
            response="[OrderedDict([('id', 1), ('username', 'admin'), ('email', 'admin@example.com'), ('password', 'sha256$nKpGQSFE$73d2c4089dd30ebbbd893dce8011f00256cf29ca56579ac98214cd0d3a43d2584MzkJ0'), ('date_created', '2021-01-11T16:13:56.189315'), ('status', True), ('roles', [OrderedDict([('user_id', 1), ('role_id', 1), ('role', OrderedDict([('id', 1), ('name', 'Admin'), ('description', 'This is the master admin account')]))]), OrderedDict([('user_id', 1), ('role_id', 2), ('role', OrderedDict([('id', 2), ('name', 'Seller'), ('description', 'This is a seller account, it manages all product listings')]))]), OrderedDict([('user_id', 1), ('role_id', 3), ('role', OrderedDict([('id', 3), ('name', 'Staff'), ('description', 'This is the staff account, it manages the reviews of the products')]))]), OrderedDict([('user_id', 1), ('role_id', 4), ('role', OrderedDict([('id', 4), ('name', 'Customer'), ('description', 'This is a customer account')]))])]), ('reviews', [OrderedDict([('user_id', 1), ('product_id', 1), ('rating', 5), ('contents', 'I love this product!'), ('product', OrderedDict([('product_id', 1), ('product_name', 'Carmen Shopper'), ('description', '1 Adjustable & Detachable Crossbody Strap, 2 Handles'), ('image', 'images/ZB7938001_main.jpg'), ('price', 218.0), ('quantity', 120), ('deleted', False)]))])]), ('orders', [OrderedDict([('order_id', 1), ('user_id', 1), ('order_product', [OrderedDict([('order_id', 1), ('product_id', 1), ('quantity', 2), ('product', OrderedDict([('product_id', 1), ('product_name', 'Carmen Shopper'), ('description', '1 Adjustable & Detachable Crossbody Strap, 2 Handles'), ('image', 'images/ZB7938001_main.jpg'), ('price', 218.0), ('quantity', 120), ('deleted', False)]))]), OrderedDict([('order_id', 1), ('product_id', 3), ('quantity', 1), ('product', OrderedDict([('product_id', 3), ('product_name', 'Fiona Crossbody'), ('description', '1 Adjustable & Detachable Crossbody Strap'), ('image', 'images/ZB7669200_main.jpg'), ('price', 148.0), ('quantity', 150), ('deleted', False)]))])])])]), ('credit_cards', [OrderedDict([('id', 1), ('card_number', '847e072481a8a4ecf716d7abce1a77ce1168a6b92ddc7fd86c7e77bd127b6eda'), ('expiry', '2023-02-28'), ('user_id', 1), ('iv', 'd99f14fb3cf01cc18a5bbe13bd61a780')]), OrderedDict([('id', 2), ('card_number', '668439bf00675bc58e68142d31ddf509399eae22a06618bc9bf6b12f557d4614'), ('expiry', '2022-07-31'), ('user_id', 1), ('iv', '0d4dc70da93591f935684a29c77f6a8c')]), OrderedDict([('id', 6), ('card_number', 'db6e298a5fe459b80c7051fdec257b045e70b0b1fca7f631172bacfffe6ea2b4'), ('expiry', '2020-07-21'), ('user_id', 1), ('iv', '4e71cbf0ec19abd6dd6f1499e347de32')])]), ('addresses', [OrderedDict([('id', 2), ('address', '2337 Millbrook Road'), ('zip_code', 60607), ('city', 'Chicago'), ('state', 'Illinois'), ('user_id', 1)])])]), OrderedDict([('id', 2), ('username', 'seller'), ('email', 'seller@example.com'), ('password', 'sha256$npaQhDyd$16815f550fd0f3453a43b9672c6abb7a4f1520696a1586e589de6f414ebb3d86Cn7Sc1'), ('date_created', '2021-01-11T16:13:56.190314'), ('status', True), ('roles', [OrderedDict([('user_id', 2), ('role_id', 2), ('role', OrderedDict([('id', 2), ('name', 'Seller'), ('description', 'This is a seller account, it manages all product listings')]))]), OrderedDict([('user_id', 2), ('role_id', 4), ('role', OrderedDict([('id', 4), ('name', 'Customer'), ('description', 'This is a customer account')]))])]), ('reviews', []), ('orders', [OrderedDict([('order_id', 4), ('user_id', 2), ('order_product', [OrderedDict([('order_id', 4), ('product_id', 1), ('quantity', 1), ('product', OrderedDict([('product_id', 1), ('product_name', 'Carmen Shopper'), ('description', '1 Adjustable & Detachable Crossbody Strap, 2 Handles'), ('image', 'images/ZB7938001_main.jpg'), ('price', 218.0), ('quantity', 120), ('deleted', False)]))]), OrderedDict([('order_id', 4), ('product_id', 4), ('quantity', 1), ('product', OrderedDict([('product_id', 4), ('product_name', 'Maya Hobo'), ('description', '1 Adjustable & Detachable Crossbody Strap, 1 Short Shoulder Strap'), ('image', 'images/ZB6979200_main.jpg'), ('price', 238.0), ('quantity', 200), ('deleted', False)]))])])])]), ('credit_cards', [OrderedDict([('id', 3), ('card_number', '905b5e0a4ea95ed0fa82b06919010eadbd145398632d0f8324416c2f54139107'), ('expiry', '2024-01-31'), ('user_id', 2), ('iv', 'ea3dbc5c3ccbf3c76c571696d785a95a')])]), ('addresses', [OrderedDict([('id', 3), ('address', '4530 Freedom Lane'), ('zip_code', 95202), ('city', 'Stockton'), ('state', 'California'), ('user_id', 2)])])]), OrderedDict([('id', 3), ('username', 'staff'), ('email', 'staff@example.com'), ('password', 'sha256$nr0OS0BY$24691c872c85097a77f860705ccca75d7d7f5d1ab39f4569ec0e37fa86a310bfN7Nzev'), ('date_created', '2021-01-11T16:13:56.190314'), ('status', True), ('roles', [OrderedDict([('user_id', 3), ('role_id', 3), ('role', OrderedDict([('id', 3), ('name', 'Staff'), ('description', 'This is the staff account, it manages the reviews of the products')]))]), OrderedDict([('user_id', 3), ('role_id', 4), ('role', OrderedDict([('id', 4), ('name', 'Customer'), ('description', 'This is a customer account')]))])]), ('reviews', []), ('orders', [OrderedDict([('order_id', 2), ('user_id', 3), ('order_product', [OrderedDict([('order_id', 2), ('product_id', 1), ('quantity', 4), ('product', OrderedDict([('product_id', 1), ('product_name', 'Carmen Shopper'), ('description', '1 Adjustable & Detachable Crossbody Strap, 2 Handles'), ('image', 'images/ZB7938001_main.jpg'), ('price', 218.0), ('quantity', 120), ('deleted', False)]))]), OrderedDict([('order_id', 2), ('product_id', 3), ('quantity', 2), ('product', OrderedDict([('product_id', 3), ('product_name', 'Fiona Crossbody'), ('description', '1 Adjustable & Detachable Crossbody Strap'), ('image', 'images/ZB7669200_main.jpg'), ('price', 148.0), ('quantity', 150), ('deleted', False)]))])])]), OrderedDict([('order_id', 3), ('user_id', 3), ('order_product', [OrderedDict([('order_id', 3), ('product_id', 2), ('quantity', 1), ('product', OrderedDict([('product_id', 2), ('product_name', 'Rachel Tote'), ('description', '2 Handles'), ('image', 'images/ZB7507200_main.jpg'), ('price', 198.0), ('quantity', 250), ('deleted', False)]))])])])]), ('credit_cards', [OrderedDict([('id', 4), ('card_number', '838d5b550be6ad391e124db4a250943aa79f9f77dc03c9d2ce29569cf09ff4f0'), ('expiry', '2020-09-30'), ('user_id', 3), ('iv', 'd33094e5d2d7e9346603b45b14b4a0ae')])]), ('addresses', [OrderedDict([('id', 1), ('address', '1377 Ridge Road'), ('zip_code', 67065), ('city', 'Isabel'), ('state', 'Kansas'), ('user_id', 3)])])]), OrderedDict([('id', 4), ('username', 'customer'), ('email', 'customer@example.com'), ('password', 'sha256$nq40aYY9$996c052ee9458095f7a83a58133099e2063d7a96692f7a0a997d2d6f71672967RAza9y'), ('date_created', '2021-01-11T16:13:56.190314'), ('status', True), ('roles', [OrderedDict([('user_id', 4), ('role_id', 4), ('role', OrderedDict([('id', 4), ('name', 'Customer'), ('description', 'This is a customer account')]))])]), ('reviews', []), ('orders', []), ('credit_cards', [OrderedDict([('id', 5), ('card_number', '87e2bc52453d208fdd0d9aee6eb1762a86321bcc9fdf338e6594656bf4e7a3c0'), ('expiry', '2024-05-31'), ('user_id', 4), ('iv', '580676a728dd9d3f8affdb771663b3d5')])]), ('addresses', [OrderedDict([('id', 4), ('address', '1053 Evergreen Lane'), ('zip_code', 92614), ('city', 'Irvine'), ('state', 'California'), ('user_id', 4)])])])]",
            ip_address="192.168.1.2",
        )
        logged_alert = Alert(request=logged_request, alert_level="High")
        server_db.session.add(logged_alert)
        server_db.session.add(logged_request)
        server_db.session.commit()

    for i in range(50):
        day = random.randrange(1, 28)
        month = random.randrange(1, 12)
        year = random.randrange(2019, 2021)
        logged_request = Request(
            datetime=datetime.datetime(year, month, day),
            status="ERROR",
            status_msg="invalid request",
            request_params="Model: User, Filter: User.id == eeddv",
            response="None",
            ip_address="127.0.0.1",
        )
    logged_alert = Alert(request=logged_request, alert_level="Medium")
    server_db.session.add(logged_alert)
    server_db.session.add(logged_request)
    server_db.session.commit()




    print("done")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, port=4999)
