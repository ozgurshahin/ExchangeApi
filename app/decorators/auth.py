from functools import wraps

import jwt
from flask import request, jsonify

from config import configuration


def token_required():
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.args.get('token')
            if not token:
                return jsonify({'Alert!': 'Token is missing!'}), 401

            try:
                data = jwt.decode(token, configuration.SECRET_KEY)
            except:
                return jsonify({'Message': 'Invalid token'}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator
