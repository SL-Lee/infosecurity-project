import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# key = get_random_bytes(32)  # Use a stored / generated key
# file_to_encrypt = "client_db.sqlite3"
# buffer_size = 65536  # 64kb


def encrypt(file_to_encrypt):
    key = get_random_bytes(32)  # Use a stored / generated key
    buffer_size = 65536  # 64kb
    # === Encrypt ===

    # Open the input and output files
    input_file = open(file_to_encrypt, "rb")
    output_file = open(file_to_encrypt + ".encrypted", "wb")

    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_CFB)

    # Initially write the iv to the output file
    output_file.write(cipher_encrypt.iv)

    # Keep reading the file into the buffer, encrypting then writing to the new file
    buffer = input_file.read(buffer_size)

    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)

    # Close the input and output files
    input_file.close()
    output_file.close()


def decrypt(file_to_encrypt):
    key = get_random_bytes(32)  # Use a stored / generated key
    buffer_size = 65536  # 64kb
    # === Decrypt ===

    # Open the input and output files
    input_file = open(file_to_encrypt + ".encrypted", "rb")
    output_file = open(file_to_encrypt + ".decrypted", "wb")

    # Read in the iv
    iv = input_file.read(16)

    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)

    # Keep reading the file into the buffer, decrypting then writing to the new file
    buffer = input_file.read(buffer_size)

    while len(buffer) > 0:
        decrypted_bytes = cipher_encrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)

    # Close the input and output files
    input_file.close()
    output_file.close()


file = input("Enter file to upload: ")
encrypt(file)
decrypt(file)
"""
# === Proving the data matches (hash the files and compare the hashes) ===


def get_file_hash(file_path):
    block_size = 65536
    file_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        fb = f.read(block_size)

        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(block_size)

    return file_hash.hexdigest()


assert get_file_hash(file_to_encrypt) == get_file_hash(
    file_to_encrypt + ".decrypted"
), "Files are not identical"
"""
