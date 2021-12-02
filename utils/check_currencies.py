from enums.supported_currencies import Currencies


def check_currencies(from_currency, to_currency):
    if from_currency not in [x.name for x in Currencies] or to_currency not in [x.name for x in Currencies]:
        return False
    else:
        return True
