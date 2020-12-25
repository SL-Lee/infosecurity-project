from flask_sqlalchemy import SQLAlchemy

monitoring_db = SQLAlchemy()


class Request(monitoring_db.Model):
    __bind_key__ = "monitoring"
    id = monitoring_db.Column(monitoring_db.Integer, primary_key=True)
    datetime = monitoring_db.Column(monitoring_db.DateTime, nullable=False)
    request_params = monitoring_db.Column(
        monitoring_db.String(255),
        nullable=False,
    )
    response = monitoring_db.Column(monitoring_db.String(65535), nullable=False)


class Rule(monitoring_db.Model):
    __bind_key__ = "monitoring"
    id = monitoring_db.Column(monitoring_db.Integer, primary_key=True)
    contents = monitoring_db.Column(monitoring_db.String(100), nullable=False)
    alerts = monitoring_db.relationship(
        "Alert",
        backref=monitoring_db.backref("rule"),
    )


class Alert(monitoring_db.Model):
    __bind_key__ = "monitoring"
    request_id = monitoring_db.Column(
        monitoring_db.Integer,
        monitoring_db.ForeignKey("request.id"),
        primary_key=True,
    )
    rule_id = monitoring_db.Column(
        monitoring_db.Integer,
        monitoring_db.ForeignKey("rule.id"),
        primary_key=True,
    )
    request = monitoring_db.relationship("Request")
