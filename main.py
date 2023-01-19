import hashlib
import base64
from os import path as ph
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes


def load_key(filename, private):
    with open(filename, "rb") as pem_in:
        pemlines = pem_in.read()
    if private:
        key = serialization.load_pem_private_key(pemlines, None)
    else:
        key = serialization.load_pem_public_key(pemlines)
    return key


def save_key(pk, filename, private=False):
    if private:
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


def sign_file(file, key_file, hash_algorithm):
    # Gerar o hash do arquivo
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
    print(hasher.hexdigest())
    # Cifrar o hash
    private_key = load_key(key_file, True)
    signature = private_key.sign(hash_digest, padding.PKCS1v15(), prehashed)

    # Gravar a assinatura em um arquivo
    signature_file = file + ".sig"
    with open(signature_file, "wb") as f:
        f.write(base64.b64encode(signature))

    return signature_file


def verify_signature(file, signature_file, key_file, hash_algorithm):
    # Gerar o hash do arquivo
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

    print(hasher.hexdigest())
    # Ler a assinatura do arquivo
    with open(signature_file, "rb") as f:
        signature = base64.b64decode(f.read())

    # Carregar a chave pública
    public_key = load_key(key_file, False)

    # Verificar a assinatura
    try:
        public_key.verify(signature, hash_digest, padding.PKCS1v15(), prehashed)
        return True
    except:
        return False


# Exemplo de uso
def main():
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys_file = ph.abspath("keys.pem")
    # save_key(private_key, keys_file, True)
    # save_key(private_key.public_key(), keys_file)
    file = ph.abspath("message")
    signature_file = ph.abspath("message.sig")
    # sign_file(file, keys_file, "sha512")
    if verify_signature(file, signature_file, keys_file, "sha512"):
        print("É  o mesmo arquivo")
    else:
        print("Não é o mesmo arquivo.")


# Gerar chave privada e pública
if __name__ == "__main__":
    main()
