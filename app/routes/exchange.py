from dataclasses import asdict

import requests
from flask import request, jsonify, Blueprint
from config import configuration
from app.dto.get_exchange_rate_response import GetExchangeRateResponse
from app.helpers.check_currencies import check_currencies
from app.decorators.auth import token_required

module = Blueprint("exchange", __name__, url_prefix="/exchange")


@module.route('/pair', methods=['POST', 'GET'])
@token_required()
def get_exchange_rate():
    from_currency = request.json['from']
    to_currency = request.json['to']
    url = configuration.BASE_URL + configuration.SECRET_KEY
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
