from flask_wtf import FlaskForm
from wtforms import (
    DateField,
    FloatField,
    IntegerField,
    PasswordField,
    RadioField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    validators,
)
from wtforms.validators import InputRequired, Length, Optional


class OnboardingDriveUpload(FlaskForm):
    client_id = PasswordField("Client ID", [InputRequired()])
    client_secret = PasswordField("Client secret", [InputRequired()])


class OnboardingBackupForm(FlaskForm):
    source = StringField(
        "Database Source",
        [Length(max=260), InputRequired()],
        render_kw={"value": ".\\client_db.sqlite3", "readonly": True},
    )
    interval = FloatField(
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
                "Please enter file location (including file extension)"
            )
        },
    )
    interval = FloatField(
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
    interval = FloatField(
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
    alert_level = SelectField(
        "Alert Level",
        [InputRequired()],
        choices=[
            ("None", "None"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
        ],
    )
    date = DateField(
        "Date", format="%Y-%m-%d", validators=(validators.Optional(),)
    )
    sort = SelectField(
        "Sort By", choices=[("Latest", "Latest"), ("Oldest", "Oldest")]
    )


class RequestBehaviourForm(FlaskForm):
    url = StringField("URL", [InputRequired(), Length(min=1, max=100)])
    count = IntegerField("URL Accessed Count", [InputRequired()])
    alert_level = SelectField(
        "Alert Level",
        [InputRequired()],
        choices=[("High", "High"), ("Medium", "Medium"), ("Low", "Low")],
    )
    refresh_time = IntegerField("URL Count refresh time", [InputRequired()])
    refresh_unit = SelectField(
        "Unit Interval",
        [InputRequired()],
        choices=[
            ("Sec", "Sec"),
            ("Min", "Min"),
            ("Hour", "Hour"),
            ("Day", "Day"),
        ],
    )


class SensitiveFieldForm(FlaskForm):
    sensitive_field = StringField(
        "Sensitive Field", [InputRequired(), Length(min=1, max=100)]
    )
    action = SelectField(
        "Action taken when conditions meet",
        [InputRequired()],
        choices=[
            ("deny_and_alert", "Deny and Alert"),
            ("alert_only", "Alert Only"),
        ],
    )
    occurrence_threshold = IntegerField(
        "Occurrence Threshold", [InputRequired()]
    )
    alert_level = SelectField(
        "Alert Level",
        [InputRequired()],
        choices=[("High", "High"), ("Medium", "Medium"), ("Low", "Low")],
    )


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
    model = StringField("Model", validators=[InputRequired()])
    field = StringField("Field", validators=[InputRequired()])
