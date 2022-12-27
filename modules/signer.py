from Crypto.PublicKey import RSA
from Crypto.Hash import SHA224
from OpenSSL.crypto import (
    TYPE_RSA,
    FILETYPE_PEM,
    PKey,
    dump_privatekey,
    dump_publickey,
    load_privatekey,
)


class Signer:
    def __init__(self, hash_fn, key_bits):
        self.hash_fn = hash_fn
        self.key_bits = key_bits

    def generate_keys(self):
        keys = PKey()
        keys.generate_key(TYPE_RSA, self.key_bits)
        with open("keys.pem", "wb") as keys_file:
            private_key = dump_privatekey(FILETYPE_PEM, keys)
            keys_file.write(private_key)
            public_key = dump_publickey(FILETYPE_PEM, keys)
            keys_file.write(public_key)

    def sign(self, text):
        self.generate_keys()
        private_key = load_privatekey(FILETYPE_PEM, open("keys.pem", "rb").read())
        print(private_key.to_cryptography_key())
        self.hash_fn(bytes(text, "utf-8")).hexdigest()


if __name__ == "__main__":
    signer = Signer(SHA224.new, 1024)
    signer.sign("ssdljdmaskldnasl")
