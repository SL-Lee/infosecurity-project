import base64
import pickle


def serialize(obj):
    return base64.b64encode(pickle.dumps(obj)).decode("UTF-8")


def deserialize(string):
    return pickle.loads(base64.b64decode(string.encode("UTF-8")))
