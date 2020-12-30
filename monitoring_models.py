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


class Alert(monitoring_db.Model):
    __bind_key__ = "monitoring"
    request_id = monitoring_db.Column(
        monitoring_db.Integer,
        monitoring_db.ForeignKey("request.id"),
        primary_key=True,
    )
    alert_level = monitoring_db.Column(monitoring_db.String(10), nullable=False)
    request = monitoring_db.relationship("Request")


class BackupLog(monitoring_db.Model):
    __bind_key__ = "monitoring"
    id = monitoring_db.Column(monitoring_db.Integer, primary_key=True)
    filename = monitoring_db.Column(monitoring_db.String(128), nullable=False)
    method = monitoring_db.Column(monitoring_db.String(128), nullable=False)
    source_path = monitoring_db.Column(
        monitoring_db.String(255), nullable=False
    )
    backup_path = monitoring_db.Column(
        monitoring_db.String(255), nullable=False
    )
    md5 = monitoring_db.Column(monitoring_db.String(32), nullable=False)
    date_created = monitoring_db.Column(monitoring_db.DateTime, nullable=False)
