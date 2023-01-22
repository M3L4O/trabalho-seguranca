import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

_hash_dict = {
    'sha256' : { 
        'hasher' : hashlib.sha256,
        'prehashed' : utils.Prehashed(hashes.SHA256())
    },
    'sha512' : {
        'hasher' : hashlib.sha512,
        'prehashed' : utils.Prehashed(hashes.SHA512())
    },
}


def load_key(filename, is_private):
    with open(filename, "rb") as pem_in:
        pemlines = pem_in.read()
    if is_private:
        key = serialization.load_pem_private_key(base64.b64decode(pemlines), None)
    else:
        key = serialization.load_pem_public_key(base64.b64decode(pemlines))
    return key


def save_key(pk, filename, is_private=False):
    if is_private:
        pem = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        pem = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    with open(filename, "ab") as pem_out:
        pem_out.write(base64.b64encode(pem))

