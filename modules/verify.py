from os import path as ph
import argparse
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

if __name__ == '__main__':
    from utils import _hash_dict, load_key
else:
    from modules.utils import _hash_dict, load_key


def get_args():
    agp = argparse.ArgumentParser(prog='AssinarDocumento', 
                                  description='Gera um documento com assinatura digital.')
    
    agp.add_argument('file_path', help='Caminho para o arquivo a ser verificado.')
    agp.add_argument('signature_path', help='Caminho para o arquivo com a assinatura.')
    agp.add_argument('public_key_path', help='Caminho para o arquivo .pem com a chave pública.')
    agp.add_argument('hash', choices=_hash_dict.keys(), default='sha512', help='Algoritmo de hash a ser usado.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    args = agp.parse_args()
    
    return args


def verify_signature(file, signature_file, key_file, hash_algorithm, verbose=False):
    hash_algorithm = _hash_dict[hash_algorithm]
    
    with open(file, "rb") as f:
        data = f.read()
    
    msg_hasher = hash_algorithm['hasher']()
    hex_hasher = hash_algorithm['hasher']()
    _prehashed = hash_algorithm['prehashed']

    msg_hasher.update(data)
    hex_hasher.update(msg_hasher.hexdigest().encode())
    
    with open(signature_file, "rb") as f:
        signature = base64.b64decode(f.read())
    
    public_key = load_key(key_file, False)
    
    print(
        f'----- Parâmetros de verificação -----\n'
        f'Arquivo Assinado: {file}\n'
        f'Assinatura: {signature_file}\n'
        f'Chave: {key_file}\n'
        f'Hash: {hex_hasher.name}'
    )
    
    try:
        public_key.verify(signature, hex_hasher.digest(), padding.PKCS1v15(), _prehashed)
        return True
    except InvalidSignature:
        return False
    

def main():
    args = get_args()
    
    if verify_signature(ph.abspath(args.file_path), 
                        ph.abspath(args.signature_path), 
                        ph.abspath(args.public_key_path),
                        args.hash,
                        verbose=args.verbose):
        print('Assinatura válida.')
    else:
        print('Assinatura inválida.')
    

if __name__ == "__main__":
    main()