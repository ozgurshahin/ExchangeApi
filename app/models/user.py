from .. import db
from app.models.base import Base

from werkzeug.security import generate_password_hash, check_password_hash


class Users(Base):
    __tablename__ = "user"

    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    password_hash = db.Column(db.String(192))

    @property
    def password(self):
        return ''

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password=password, method='pbkdf2:sha512')

    def verify_password(self, password):
        return check_password_hash(pwhash=self.password_hash, password=password)

    def __init__(self, name, password):
        self.name = name
        self.password = password

    def __repr__(self):
        return '<Users %r>' % self.id
