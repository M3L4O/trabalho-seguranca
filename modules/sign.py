from os import path as ph
import argparse
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes

if __name__ == '__main__':
    from utils import load_key
else:
    from modules.utils import load_key

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


def get_args():
    agp = argparse.ArgumentParser(prog='AssinarDocumento', 
                                  description='Gera um documento com assinatura digital.')
    
    agp.add_argument('file_path', help='Caminho para o arquivo a ser assinado.')
    agp.add_argument('private_key_path', help='Caminho para o arquivo .pem com a chave privada.')
    agp.add_argument('hash', choices=_hash_dict.keys(), default='sha512', help='Algoritmo de hash a ser usado.')
    agp.add_argument('-o', '--out_file', default='message', help='Arquivo de saída da assinatura.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    args = agp.parse_args()
    
    return args


def sign_file(file, signature_file, key_file, hash_algorithm, verbose=False):
    hash_algorithm = _hash_dict[hash_algorithm]
    
    with open(file, "rb") as f:
        data = f.read()
    
    msg_hasher = hash_algorithm['hasher']()
    hex_hasher = hash_algorithm['hasher']()
    _prehashed = hash_algorithm['prehashed']
    
    msg_hasher.update(data)
    hex_hasher.update(msg_hasher.hexdigest().encode())
    
    private_key = load_key(key_file, True)
    signature = private_key.sign(hex_hasher.digest(), padding.PKCS1v15(), _prehashed)

    signature_file = file.split(".")[0] + ".sig"
    with open(signature_file, "wb") as f:
        f.write(base64.b64encode(signature))
    
    if verbose:
        print(
            f'----- Parâmetros de assinatura -----\n'
            f'Arquivo Assinado: {file}'
            f'\nAssinatura: {signature_file}'
            f'\nChave: {key_file}'
            f'\nHash: {hex_hasher.name}'
        )
    
    return signature_file


def main():
    args = get_args()
    
    sign_file(ph.abspath(args.file_path), 
              args.out_file, 
              ph.abspath(args.private_key_path),
              args.hash,
              verbose=args.verbose)
    

if __name__ == "__main__":
    main()