from flask import Blueprint, request, session, jsonify, make_response, flash, redirect
from app.dto.auth import Auth

module = Blueprint("auth", __name__, url_prefix="/auth")


@module.route('/login', methods=['POST'])
def login():
    res = Auth().login(email=request.form['username'], password=request.form['password'])

    return res


@module.route('/logout', methods=['POST'])
def logout():
    res = Auth().logout()

    return res


@module.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registeration successfully'})
