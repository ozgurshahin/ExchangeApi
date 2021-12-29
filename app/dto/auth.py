from datetime import datetime, timedelta
from app import db
import jwt
from flask import make_response, session, request, jsonify, flash, redirect

from app.helpers.generator import generate_password
from app.models.user import Users
from config import configuration


class Auth:
    def login(self, email, password):
        user = Users.query.filter(Users.name == email).first()
        if not user:
            return make_response("The user for the given e-mail address could not be found.", 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

        if not user.verify_password(password):
            return make_response('Wrong password.', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

        session['logged_in'] = True

        token = jwt.encode({
            'user': request.form['username'],
            'expiration': str(datetime.utcnow() + timedelta(seconds=60000))
        }, configuration.config['SECRET_KEY'])

        return jsonify({'token': token.decode('utf-8')})

    def logout(self):
        if session.get('logged_in'):
            del session['logged_in']

        flash('You have successfully logged yourself out.')
        return redirect('/login')

    def register(self, name):
        user = Users.query.filter(Users.name).first()
        if user:
            return make_response("The user is already exists.", 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

        try:
            password = generate_password()

            user = Users(name=name, password=password)

            db.session.add(user)
            db.commit()
        except Exception as e:
            return make_response("Something happened unexpected.", 500, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})

        return jsonify({'user': user.name, 'password_hash': password})
