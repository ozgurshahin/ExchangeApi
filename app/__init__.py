from dataclasses import asdict
from datetime import datetime, timedelta
from functools import wraps

import jwt
import requests
from flask import Flask, jsonify, request, session, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.utils import redirect

from app.dto.get_exchange_rate_response import GetExchangeRateResponse
from app.models.user import Users
from app.utils.check_currencies import check_currencies
from config import configuration

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = configuration.SECRET_KEY
API_KEY = configuration.API_KEY
BASE_URL = configuration.BASE_URL
url = BASE_URL + API_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = configuration.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = configuration.SQLALCHEMY_TRACK_MODIFICATIONS
db = SQLAlchemy(app)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registeration successfully'})


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config.get('SECRET_KEY'))
        except:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '123456':
        session['logged_in'] = True
        token = jwt.encode({
            'user': request.form['username'],
            'expiration': str(datetime.utcnow() + timedelta(seconds=60000))
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('utf-8')})
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})


# @app.route('/login', methods=['POST'])
# def login():
#     auth = request.authorization
#
#     if not auth or not auth.username or not auth.password:
#         return make_response('could not verify auth', 401, {'Authentication': 'login required"'})
#
#     user = Users.query.filter_by(name=auth.username).first()
#
#     if check_password_hash(user.password, auth.password):
#         token = jwt.encode(
#             {'public_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
#             app.config['SECRET_KEY'], "HS256")
#         return jsonify({'token': token})
#
#     return make_response('could not verify', 401, {'Authentication': '"login required"'})


@app.route('/logout')
def logout():
    if session.get('logged_in'):
        del session['logged_in']
    flash('You have successfully logged yourself out.')
    return redirect('/login')


@app.route('/pair', methods=['POST', 'GET'])
@token_required
def get_exchange_rate():
    from_currency = request.json['from']
    to_currency = request.json['to']
    if check_currencies(from_currency, to_currency):
        pair_url = url + "/pair/" + from_currency + "/" + to_currency
        print("pair_url " + pair_url)
        print("pair_url " + pair_url)
        response = requests.get(pair_url)
        conversion_rate = response.json()['conversion_rate']
        base_code = response.json()['base_code']
        target_code = response.json()['target_code']
        return asdict(
            GetExchangeRateResponse(conversion_rate=conversion_rate,
                                    base_code=base_code,
                                    target_code=target_code))
    else:
        return jsonify({"conversion_rate": "The Currency is not correct!!!"})


db.create_all()
db.session.commit()
