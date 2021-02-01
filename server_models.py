import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

server_db = SQLAlchemy()

server_user_permissions = server_db.Table(
    "server_user_permissions",
    server_db.Column(
        "server_user_id",
        server_db.Integer,
        server_db.ForeignKey("server_user.id"),
    ),
    server_db.Column(
        "server_permission_name",
        server_db.String(128),
        server_db.ForeignKey("server_permission.name"),
    ),
    info={"bind_key": "server"},
)


class ServerUser(UserMixin, server_db.Model):
    __bind_key__ = "server"
    id = server_db.Column(server_db.Integer, primary_key=True)
    username = server_db.Column(
        server_db.String(32), unique=True, nullable=False
    )
    password_salt = server_db.Column(server_db.LargeBinary(32), nullable=False)
    password_hash = server_db.Column(server_db.LargeBinary(64), nullable=False)
    date_created = server_db.Column(
        server_db.DateTime, default=datetime.datetime.now
    )
    permissions = server_db.relationship(
        "ServerPermission",
        secondary=server_user_permissions,
        backref=server_db.backref("users", lazy="dynamic"),
    )


class ServerPermission(server_db.Model):
    __bind_key__ = "server"
    name = server_db.Column(server_db.String(128), primary_key=True)


class Request(server_db.Model):
    __bind_key__ = "server"
    id = server_db.Column(server_db.Integer, primary_key=True)
    datetime = server_db.Column(server_db.DateTime, nullable=False)
    ip_address = server_db.Column(server_db.String(15), nullable=False)
    status = server_db.Column(server_db.String(10), nullable=False)
    status_msg = server_db.Column(server_db.String(100), nullable=False)
    request_params = server_db.Column(
        server_db.String(255),
        nullable=False,
    )
    response = server_db.Column(server_db.String(65535), nullable=False)


class Rule(server_db.Model):
    __bind_key__ = "server"
    id = server_db.Column(server_db.Integer, primary_key=True)
    contents = server_db.Column(server_db.String(100), nullable=False)
    action = server_db.Column(server_db.String(100), nullable=False)
    alert_level = server_db.Column(server_db.String(6), nullable=False)
    occurrence_threshold = server_db.Column(server_db.Integer, nullable=False)


class Alert(server_db.Model):
    __bind_key__ = "server"
    request_id = server_db.Column(
        server_db.Integer,
        server_db.ForeignKey("request.id"),
        primary_key=True,
    )
    alert_level = server_db.Column(server_db.String(10), nullable=False)
    request = server_db.relationship("Request")


class BackupLog(server_db.Model):
    __bind_key__ = "server"
    id = server_db.Column(server_db.Integer, primary_key=True)
    filename = server_db.Column(server_db.String(128), nullable=False)
    method = server_db.Column(server_db.String(128), nullable=False)
    source_path = server_db.Column(server_db.String(255), nullable=False)
    backup_path = server_db.Column(server_db.String(255), nullable=False)
    md5 = server_db.Column(server_db.String(32), nullable=False)
    date_created = server_db.Column(server_db.DateTime, nullable=False)
