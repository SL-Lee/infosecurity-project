from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields, post_load, Schema


client_db = SQLAlchemy()


# Models
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


# Schemas
class ProductSchema(Schema):
    id = fields.Integer()
    name = fields.Str(required=True)
    description = fields.Str(required=True)
    price = fields.Float(required=True)
    quantity = fields.Str(required=True)

    @post_load
    def make_product(self, data, **kwargs):
        return Product(**data)


class ReviewSchema(Schema):
    user_id = fields.Integer(required=True)
    product_id = fields.Integer(required=True)
    rating = fields.Integer(required=True)
    product = fields.Nested(ProductSchema())

    @post_load
    def make_review(self, data, **kwargs):
        return Review(**data)


class UserSchema(Schema):
    id = fields.Integer()
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    reviews = fields.List(fields.Nested(ReviewSchema()))

    @post_load
    def make_user(self, data, **kwargs):
        return User(**data)
