class Config(object):
    def __init__(self):
        self.BASE_URL = 'https://v6.exchangerate-api.com/v6/'
        self.API_KEY = '604025c31666eb39c0f864bb'
        self.SECRET_KEY = 'nwECTEUmc1JYWqBt7Bg'
        self.SQLALCHEMY_DATABASE_URI = 'sqlite:///ExchangeRateApi.db'
        self.SQLALCHEMY_TRACK_MODIFICATIONS = True


configuration = Config()
