from flask import request, jsonify
from werkzeug.security import generate_password_hash

from app import db, app
from app.models.user import Users


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registeration successfully'})
