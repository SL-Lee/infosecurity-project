from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, post_load, pre_load

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
class BaseSchema(Schema):
    __fields_to_skip_none__ = ()
    __model__ = None

    @pre_load
    def remove_null_fields(self, data, **kwargs):
        # pylint: disable=unused-argument
        if isinstance(data, dict):
            for i in self.__fields_to_skip_none__:
                if i in data and data[i] is None:
                    del data[i]

        return data

    @post_load
    def make_model(self, data, **kwargs):
        # pylint: disable=not-callable
        # pylint: disable=unused-argument
        return self.__model__(**data) if self.__model__ is not None else None

    class Meta:
        ordered = True


class ProductSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = Product
    id = fields.Integer()
    name = fields.Str(required=True)
    description = fields.Str(required=True)
    price = fields.Float(required=True)
    quantity = fields.Str(required=True)


class ReviewSchema(BaseSchema):
    __model__ = Review
    user_id = fields.Integer(required=True)
    product_id = fields.Integer(required=True)
    rating = fields.Integer(required=True)
    product = fields.Nested(ProductSchema())


class UserSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = User
    id = fields.Integer()
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    reviews = fields.List(fields.Nested(ReviewSchema()))
