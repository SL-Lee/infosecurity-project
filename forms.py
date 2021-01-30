from flask_wtf import FlaskForm
from wtforms import (
    IntegerField,
    PasswordField,
    RadioField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    DateField,
    validators,
)
from wtforms.validators import InputRequired, Length, Optional


class OnboardingBackupForm(FlaskForm):
    source = StringField(
        "Database Source",
        [Length(max=260), InputRequired()],
        render_kw={"value": ".\client_db.sqlite3", "readonly": True},
    )
    interval = IntegerField(
        "Interval",
        [InputRequired()],
        render_kw={
            "placeholder": (
                "Please select the interval type and enter the duration"
            )
        },
    )
    interval_type = RadioField(
        "Interval Type",
        choices=[
            ("min", "Minute"),
            ("hr", "Hour"),
            ("d", "Day"),
            ("wk", "Week"),
            ("mth", "Month"),
        ],
        default="wk",
    )


class BackupFirstForm(FlaskForm):
    source = StringField(
        "Database Source",
        [Length(max=260), InputRequired()],
        render_kw={
            "placeholder": (
                "Please enter your database file location (including file "
                "extension)"
            )
        },
    )
    interval = IntegerField(
        "Interval",
        [InputRequired()],
        render_kw={
            "placeholder": (
                "Please select the interval type and enter the duration"
            )
        },
    )
    interval_type = RadioField(
        "Interval Type",
        choices=[
            ("min", "Minute"),
            ("hr", "Hour"),
            ("d", "Day"),
            ("wk", "Week"),
            ("mth", "Month"),
        ],
        default="wk",
    )
    submit = SubmitField("Backup & Save Settings")


class BackupForm(FlaskForm):
    source = StringField(
        "Database Source",
        [Length(max=260), Optional()],
        render_kw={"placeholder": "Leave empty if no changes"},
    )
    interval = IntegerField(
        "Interval",
        [Optional()],
        render_kw={"placeholder": "Leave empty if no changes"},
    )
    interval_type = RadioField(
        "Interval Type",
        choices=[
            ("min", "Minute"),
            ("hr", "Hour"),
            ("d", "Day"),
            ("wk", "Week"),
            ("mth", "Month"),
        ],
        default="wk",
    )
    manual = SubmitField("Manual Backup")
    update = SubmitField("Backup & Update Settings")


# Leave the comma after Optional, else it will not work
class RequestFilter(FlaskForm):
    query = StringField("Search", [Length(min=1, max=100), Optional()])
    alert_level = SelectField("Alert Level", [InputRequired()], choices=[("None", "None"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low")])
    date = DateField("Date", format='%Y-%m-%d', validators=(validators.Optional(),))


class SensitiveFieldForm(FlaskForm):
    sensitive_field = StringField(
        "Sensitive Field", [InputRequired(), Length(min=1, max=100)]
    )
    action = SelectField("Action taken when conditions meet", [InputRequired()], choices=[("deny_and_alert", "Deny and Alert"), ("alert_only", "Alert Only")])
    occurrence_threshold = IntegerField("Occurrence Threshold", [InputRequired()])
    alert_level = SelectField("Alert Level", [InputRequired()], choices=[("High", "High"), ("Medium", "Medium"), ("Low", "Low")])


class WhitelistForm(FlaskForm):
    ip_address = StringField(
        "IP address", [InputRequired(), Length(min=7, max=15)]
    )


class LoginForm(FlaskForm):
    username = StringField("Username", [InputRequired(), Length(max=32)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=32)]
    )


class CreateUserForm(FlaskForm):
    username = StringField("Username", [InputRequired(), Length(max=32)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=32)]
    )
    permissions = SelectMultipleField("Permissions", [InputRequired()])


class CreateAdminUserForm(FlaskForm):
    username = StringField("Username", [InputRequired(), Length(max=32)])
    password = PasswordField(
        "Password", [InputRequired(), Length(min=8, max=32)]
    )


class ChoiceForm(FlaskForm):
    user = SelectField("user", choices=[], default="None")
    role = SelectField("role", choices=[], default="None")
    credit_card = SelectField("credit_card", choices=[], default="None")
    address = SelectField("address", choices=[], default="None")
    product = SelectField("product", choices=[], default="None")
    review = SelectField("review", choices=[], default="None")
    order = SelectField("order", choices=[], default="None")
