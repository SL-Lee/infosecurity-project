import datetime
import hashlib
import os

from flask import Blueprint, flash, redirect, render_template, request, url_for

from crypto_functions import decrypt, encrypt
from helper_functions import (
    get_config_value,
    required_permissions,
    set_config_value,
)

encryption_key_management_blueprint = Blueprint(
    "encryption_key_management", __name__
)


@encryption_key_management_blueprint.route("/encryption/key-management")
@required_permissions("manage_encryption_key")
def encryption_key_management():
    try:
        encryption_key_timestamp = get_config_value(
            "encryption-key-config",
            config_db_name="encryption-config",
        ).get("timestamp", None)
    except:
        encryption_key_timestamp = None

    return render_template(
        "encryption-key-management.html",
        encryption_key_timestamp=encryption_key_timestamp,
    )


@encryption_key_management_blueprint.route(
    "/encryption/key-management/generate", methods=["POST"]
)
def encryption_key_management_generate():
    if (
        get_config_value(
            "encryption-key-config", config_db_name="encryption-config"
        )
        is not None
    ):
        return redirect(url_for(".encryption_key_management"))

    encryption_passphrase = request.form.get("encryption-passphrase")

    if encryption_passphrase is None:
        flash(
            "An error occurred while generating the encryption key. Please "
            "try again.",
            "danger",
        )
        return redirect(url_for(".encryption_key_management_generate"))

    encryption_key_config = {}

    dek = os.urandom(32)

    kek_salt = os.urandom(32)
    kek = hashlib.scrypt(
        encryption_passphrase.encode("UTF-8"),
        salt=kek_salt,
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    encryption_key_config["timestamp"] = datetime.datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S+08:00"
    )
    encryption_key_config["kek-salt"] = kek_salt.hex()
    encryption_key_config["kek-hash"] = hashlib.sha3_512(kek).hexdigest()
    encryption_key_config["encrypted-dek"] = encrypt(dek, kek).hex()

    set_config_value(
        "encryption-key-config",
        encryption_key_config,
        config_db_name="encryption-config",
    )
    return redirect(url_for(".encryption_key_management"))


@encryption_key_management_blueprint.route(
    "/encryption/key-management/reset-passphrase", methods=["POST"]
)
def encryption_reset_passphrase():
    encryption_key_config = get_config_value(
        "encryption-key-config", config_db_name="encryption-config"
    )

    if encryption_key_config is None:
        return redirect(url_for("onboarding.onboarding_encryption_key_config"))

    old_encryption_passphrase = request.form.get("old-encryption-passphrase")
    new_encryption_passphrase = request.form.get("new-encryption-passphrase")
    confirm_new_encryption_passphrase = request.form.get(
        "confirm-new-encryption-passphrase"
    )

    # Return an error if any of the required fields are somehow empty
    if any(
        field is None
        for field in [
            old_encryption_passphrase,
            new_encryption_passphrase,
            confirm_new_encryption_passphrase,
        ]
    ):
        flash(
            "There was an error while resetting the encryption passphase. "
            "Please try again.",
            "danger",
        )
        return redirect(url_for(".encryption_key_management"))

    old_kek = hashlib.scrypt(
        old_encryption_passphrase.encode("UTF-8"),
        salt=bytes.fromhex(encryption_key_config["kek-salt"]),
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    # Return an error if the old kek is wrong
    if (
        hashlib.sha3_512(old_kek).hexdigest()
        != encryption_key_config["kek-hash"]
    ):
        flash(
            "There was an error while resetting the encryption passphase. "
            "Please try again.",
            "danger",
        )
        return redirect(url_for(".encryption_key_management"))

    # Return an error if new encryption passphrases do not match
    if new_encryption_passphrase != confirm_new_encryption_passphrase:
        flash(
            "New encryption passphrases do not match. Please try again.",
            "danger",
        )
        return redirect(url_for(".encryption_key_management"))

    new_kek_salt = os.urandom(32)
    new_kek = hashlib.scrypt(
        new_encryption_passphrase.encode("UTF-8"),
        salt=new_kek_salt,
        n=32768,
        r=8,
        p=1,
        maxmem=33816576,
        dklen=32,
    )

    dek = decrypt(
        bytes.fromhex(encryption_key_config["encrypted-dek"]), old_kek
    )

    encryption_key_config["timestamp"] = datetime.datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S+08:00"
    )
    encryption_key_config["kek-salt"] = new_kek_salt.hex()
    encryption_key_config["kek-hash"] = hashlib.sha3_512(new_kek).hexdigest()
    encryption_key_config["encrypted-dek"] = encrypt(dek, new_kek).hex()

    set_config_value(
        "encryption-key-config",
        encryption_key_config,
        config_db_name="encryption-config",
    )
    flash("Encryption passphrase resetted successfully.", "success")
    return redirect(url_for(".encryption_key_management"))
