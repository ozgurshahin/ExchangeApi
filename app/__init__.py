from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

from config import configuration

app = Flask(__name__)
db = SQLAlchemy(app=app)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = configuration.SECRET_KEY
API_KEY = configuration.API_KEY
BASE_URL = configuration.BASE_URL
url = BASE_URL + API_KEY


@app.route('/')
def index():
    return jsonify({"message": "ExChangeApi"})


app.config['SQLALCHEMY_DATABASE_URI'] = configuration.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = configuration.SQLALCHEMY_TRACK_MODIFICATIONS

from .routes.auth import module as auth_route
from .routes.exchange import module as exchange_route

app.register_blueprint(auth_route)
app.register_blueprint(exchange_route)

from app.models import *

db.create_all()
