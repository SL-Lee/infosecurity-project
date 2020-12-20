class InvalidAPIKeyError(Exception):
    def __init__(self):
        super().__init__("API key is invalid")
