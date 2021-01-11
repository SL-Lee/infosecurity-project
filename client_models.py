import datetime

from flask import url_for
from flask_login import UserMixin
from flask_sqlalchemy import BaseQuery, SQLAlchemy
from marshmallow import Schema, ValidationError, fields, post_load, pre_load

client_db = SQLAlchemy()


# Models
class User(UserMixin, client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    username = client_db.Column(
        client_db.String(25), unique=True, nullable=False
    )
    email = client_db.Column(client_db.String(120), unique=True, nullable=False)
    password = client_db.Column(client_db.String(80), nullable=False)
    date_created = client_db.Column(
        client_db.DateTime, default=datetime.datetime.now
    )
    status = client_db.Column(client_db.Boolean(), nullable=False, default=True)
    roles = client_db.relationship("UserRole")
    reviews = client_db.relationship(
        "Review", backref=client_db.backref("user")
    )
    orders = client_db.relationship("Orders", backref=client_db.backref("user"))
    credit_cards = client_db.relationship(
        "CreditCard",
        backref=client_db.backref("user"),
        cascade="all, delete, delete-orphan",
    )
    addresses = client_db.relationship(
        "Address",
        backref=client_db.backref("user"),
        cascade="all, delete, delete-orphan",
    )


class UserRole(client_db.Model):
    user_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("user.id"), primary_key=True
    )
    role_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("role.id"), primary_key=True
    )
    role = client_db.relationship("Role")


class CreditCard(client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    card_number = client_db.Column(client_db.String, nullable=False)
    expiry = client_db.Column(client_db.Date, nullable=False)
    user_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("user.id"), nullable=False
    )
    iv = client_db.Column(client_db.String, nullable=False)


class Address(client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    address = client_db.Column(client_db.String(120), nullable=False)
    zip_code = client_db.Column(client_db.Integer, nullable=False)
    city = client_db.Column(client_db.String(120), nullable=False)
    state = client_db.Column(client_db.String(120), nullable=False)
    user_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("user.id"), nullable=False
    )


class Role(client_db.Model):
    id = client_db.Column(client_db.Integer, primary_key=True)
    name = client_db.Column(client_db.String(80), unique=True)
    description = client_db.Column(client_db.String(255))


class QueryWithSoftDelete(BaseQuery):
    _with_deleted = False

    def __new__(cls, *args, **kwargs):
        obj = super(QueryWithSoftDelete, cls).__new__(cls)
        obj._with_deleted = kwargs.pop("_with_deleted", False)
        if len(args) > 0:
            super(QueryWithSoftDelete, obj).__init__(*args, **kwargs)
            return (
                obj.filter_by(deleted=False) if not obj._with_deleted else obj
            )
        return obj

    def __init__(self, *args, **kwargs):
        # pylint: disable=super-init-not-called
        pass

    def with_deleted(self):
        return self.__class__(
            client_db.class_mapper(self._mapper_zero().class_),
            session=client_db.session(),
            _with_deleted=True,
        )

    def _get(self, *args, **kwargs):
        # this calls the original query.get function from the base class
        return super().get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # pylint: disable=protected-access

        # the query.get method does not like it if there is a filter clause
        # pre-loaded, so we need to implement it using a workaround
        obj = self.with_deleted()._get(*args, **kwargs)
        return (
            obj
            if obj is None or self._with_deleted or not obj.deleted
            else None
        )


class Product(client_db.Model):
    __tablename__ = "product"
    __table_args__ = {"extend_existing": True}
    product_id = client_db.Column(client_db.Integer, primary_key=True)
    product_name = client_db.Column(client_db.String(100), nullable=False)
    description = client_db.Column(client_db.String(100), nullable=False)
    image = client_db.Column(client_db.String(50), nullable=False)
    price = client_db.Column(client_db.Numeric(10, 2), nullable=False)
    quantity = client_db.Column(client_db.Integer, nullable=False)
    deleted = client_db.Column(client_db.Boolean(), default=False)

    query_class = QueryWithSoftDelete

    def __repr__(self):
        product_id = self.product_id
        product_name = self.product_name
        description = self.description
        image = self.image
        price = self.price
        quantity = self.quantity
        url = url_for(
            "get_products", id=self.product_id if not self.deleted else None
        )
        return (
            f"Product('{product_id}', '{product_name}', '{description}', "
            f"'{image}', '{price}', '{quantity}', '{url}'"
        )


class Review(client_db.Model):
    user_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("user.id"), primary_key=True
    )
    product_id = client_db.Column(
        client_db.Integer,
        client_db.ForeignKey("product.product_id"),
        primary_key=True,
    )
    rating = client_db.Column(client_db.Integer, nullable=False)
    contents = client_db.Column(client_db.String(255), nullable=False)
    product = client_db.relationship("Product")


class Orders(client_db.Model):
    order_id = client_db.Column(client_db.Integer, primary_key=True)
    user_id = client_db.Column(
        client_db.Integer, client_db.ForeignKey("user.id")
    )
    order_product = client_db.relationship(
        "OrderProduct", backref=client_db.backref("orders")
    )


class OrderProduct(client_db.Model):
    order_id = client_db.Column(
        "order_id",
        client_db.Integer(),
        client_db.ForeignKey("orders.order_id"),
        primary_key=True,
    )
    product_id = client_db.Column(
        client_db.Integer,
        client_db.ForeignKey("product.product_id"),
        primary_key=True,
    )
    quantity = client_db.Column(client_db.Integer, nullable=False)
    product = client_db.relationship("Product")


# Custom fields
class BinaryField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return None

        return value.hex()

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return bytes.fromhex(value)
        except Exception as exception:
            raise ValidationError("Invalid byte string") from exception

    def _validate(self, value):
        if not isinstance(value, bytes):
            raise ValidationError("Input type must be bytes")

        if value is None or not value:
            raise ValidationError("Input must not be empty")


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


class RoleSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = Role
    id = fields.Integer()
    name = fields.Str(required=True)
    description = fields.Str(required=True)


class UserRoleSchema(BaseSchema):
    __model__ = UserRole
    user_id = fields.Integer(required=True)
    role_id = fields.Integer(required=True)
    role = fields.Nested(RoleSchema())

    @post_load
    def make_model(self, data, **kwargs):
        # pylint: disable=unused-argument

        data["role"] = Role.query.filter_by(id=data["role"].id).first()
        return UserRole(**data)


class CreditCardSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = CreditCard
    id = fields.Integer()
    card_number = BinaryField(required=True)
    expiry = fields.Date(required=True)
    user_id = fields.Integer(required=True)
    iv = BinaryField(required=True)


class AddressSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = Address
    id = fields.Integer()
    address = fields.Str(required=True)
    zip_code = fields.Integer(required=True)
    city = fields.Str(required=True)
    state = fields.Str(required=True)
    user_id = fields.Integer(required=True)


class ProductSchema(BaseSchema):
    __fields_to_skip_none__ = ("product_id",)
    __model__ = Product
    product_id = fields.Integer()
    product_name = fields.Str(required=True)
    description = fields.Str(required=True)
    image = fields.Str(required=True)
    price = fields.Float(required=True)
    quantity = fields.Integer(required=True)
    deleted = fields.Boolean(required=True)


class ReviewSchema(BaseSchema):
    __model__ = Review
    user_id = fields.Integer(required=True)
    product_id = fields.Integer(required=True)
    rating = fields.Integer(required=True)
    contents = fields.Str(required=True)
    product = fields.Nested(ProductSchema())

    @post_load
    def make_model(self, data, **kwargs):
        # pylint: disable=unused-argument

        data["product"] = Product.query.filter_by(
            product_id=data["product"].product_id
        ).first()
        return Review(**data)


class OrderProductSchema(BaseSchema):
    __model__ = OrderProduct
    order_id = fields.Integer(required=True)
    product_id = fields.Integer(required=True)
    quantity = fields.Integer(required=True)
    product = fields.Nested(ProductSchema())

    @post_load
    def make_model(self, data, **kwargs):
        # pylint: disable=unused-argument

        data["product"] = Product.query.filter_by(
            product_id=data["product"].product_id
        ).first()
        return OrderProduct(**data)


class OrdersSchema(BaseSchema):
    __fields_to_skip_none__ = ("order_id",)
    __model__ = Orders
    order_id = fields.Integer()
    user_id = fields.Integer(required=True)
    order_product = fields.List(fields.Nested(OrderProductSchema()))


class UserSchema(BaseSchema):
    __fields_to_skip_none__ = ("id",)
    __model__ = User
    id = fields.Integer()
    username = fields.Str(required=True)
    email = fields.Str(required=True)
    password = fields.Str(required=True)
    date_created = fields.DateTime(required=True)
    status = fields.Boolean(required=True)
    roles = fields.List(fields.Nested(UserRoleSchema()))
    reviews = fields.List(fields.Nested(ReviewSchema()))
    orders = fields.List(fields.Nested(OrdersSchema()))
    credit_cards = fields.List(fields.Nested(CreditCardSchema()))
    addresses = fields.List(fields.Nested(AddressSchema()))
