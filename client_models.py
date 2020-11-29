from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


client_db = SQLAlchemy()


class User(UserMixin, client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    username = client_db.Column(client_db.String(100), nullable=False)
    password = client_db.Column(client_db.String(100), nullable=False)
    reviews = client_db.relationship(
        "Review",
        backref=client_db.backref("user"),
    )


class Product(client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    name = client_db.Column(client_db.String(100), nullable=False)
    description = client_db.Column(client_db.String(100), nullable=False)
    price = client_db.Column(client_db.Numeric(10, 2), nullable=False)
    quantity = client_db.Column(client_db.Integer, nullable=False)


class Review(client_db.Model):
    user_id = client_db.Column(
        client_db.Integer,
        client_db.ForeignKey("user.id"),
        primary_key=True,
    )
    product_id = client_db.Column(
        client_db.Integer,
        client_db.ForeignKey("product.id"),
        primary_key=True,
    )
    rating = client_db.Column(client_db.Integer, nullable=False)
    product = client_db.relationship("Product")
