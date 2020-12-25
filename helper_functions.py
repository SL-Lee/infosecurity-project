from errors import InvalidAPIKeyError
import hashlib
import shelve


def get_config_value(key):
    config_db = shelve.open("config")

    try:
        return config_db["config"][key]
    except:
        return None
    finally:
        config_db.close()


def set_config_value(key, value):
    config_db = shelve.open("config")
    config = config_db.get("config", {})
    config[key] = value
    config_db["config"] = config
    config_db.close()


def validate_api_key(api_key):
    if (
        hashlib.sha3_512(bytes.fromhex(api_key)).hexdigest()
        == get_config_value("api-key")["hash"]
    ):
        return api_key
    else:
        raise InvalidAPIKeyError
