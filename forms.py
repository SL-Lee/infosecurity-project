from flask_wtf import FlaskForm
from wtforms import IntegerField, RadioField, StringField, SubmitField
from wtforms.validators import InputRequired, Length, Optional


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


class SensitiveFieldForm(FlaskForm):
    sensitive_field = StringField(
        "Sensitive Field", [InputRequired(), Length(min=1, max=100)]
    )


class WhitelistForm(FlaskForm):
    ip_address = StringField(
        "IP address", [InputRequired(), Length(min=7, max=15)]
    )
