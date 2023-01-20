import hashlib
import base64
from utils import load_key, save_key
from os import path as ph
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature


def sign_file(file, key_file, hash_algorithm):
    with open(file, "rb") as f:
        data = f.read()
    if hash_algorithm == "sha256":
        hasher = hashlib.sha256()
        prehashed = utils.Prehashed(hashes.SHA256())
    elif hash_algorithm == "sha512":
        hasher = hashlib.sha512()
        prehashed = utils.Prehashed(hashes.SHA512())
    else:
        raise ValueError("Algoritmo de hash inválido")
    hasher.update(data)
    hash_digest = hasher.digest()

    private_key = load_key(key_file, True)
    signature = private_key.sign(hash_digest, padding.PKCS1v15(), prehashed)

    signature_file = ph.basename(file).split(".")[0] + ".sig"
    with open(signature_file, "wb") as f:
        f.write(base64.b64encode(signature))

    return signature_file


def verify_signature(file, signature_file, key_file, hash_algorithm):
    with open(file, "rb") as f:
        data = f.read()

    if hash_algorithm == "sha256":
        hasher = hashlib.sha256()
        prehashed = utils.Prehashed(hashes.SHA256())
    elif hash_algorithm == "sha512":
        hasher = hashlib.sha512()
        prehashed = utils.Prehashed(hashes.SHA512())
    else:
        raise ValueError("Algoritmo de hash inválido")

    hasher.update(data)
    hash_digest = hasher.digest()

    with open(signature_file, "rb") as f:
        signature = base64.b64decode(f.read())

    public_key = load_key(key_file, False)

    try:
        public_key.verify(signature, hash_digest, padding.PKCS1v15(), prehashed)
        return True
    except InvalidSignature:
        return False


# Exemplo de uso
def main():
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys_file = ph.abspath("./keys.pem")
    # save_key(private_key, keys_file, True)
    # save_key(private_key.public_key(), keys_file)
    file = ph.abspath("./message")
    signature_file = ph.abspath("./message.sig")
    sign_file(file, keys_file, "sha512")
    if verify_signature(file, signature_file, keys_file, "sha512"):
        print("É  o mesmo arquivo")
    else:
        print("Não é o mesmo arquivo.")


if __name__ == "__main__":
    main()
