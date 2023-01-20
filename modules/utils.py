from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path as ph


def load_key(filename, is_private):
    with open(filename, "rb") as pem_in:
        pemlines = pem_in.read()
    if is_private:
        key = serialization.load_pem_private_key(pemlines, None)
    else:
        key = serialization.load_pem_public_key(pemlines)
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
        pem_out.write(pem)


def generate_keys(filepath):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    save_key(private_key, ph.join(filepath, "private.pem"), True)
    save_key(public_key, ph.join(filepath, "public.pem"))
