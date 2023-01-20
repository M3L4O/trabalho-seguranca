import argparse
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.PublicKey.RSA import import_key
from Cryptodome.Cipher import PKCS1_OAEP
import base64
from os import path as ph

def get_args():
    hash_dict = {
        'sha256' : SHA256,
        'sha512' : SHA512,
    }
    
    agp = argparse.ArgumentParser(prog='AssinarDocumento', 
                                  description='Gera um documento com assinatura digital.')
    
    agp.add_argument('file_path', help='Caminho para o arquivo a ser assinado.')
    agp.add_argument('private_key_path', help='Caminho para o arquivo .pem com a chave privada.')
    agp.add_argument('hash', choices=hash_dict.keys(), default='sha512', help='Algoritmo de hash a ser usado.')
    agp.add_argument('-o', '--out_file', default='message', help='Algoritmo de hash a ser usado.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    args = agp.parse_args()
    
    args.hash = hash_dict[args.hash]
    
    return args


def get_msg(msg_path : str):
    with open(msg_path, 'rb') as f:
        msg = f.read()
    
    return msg


def get_private_key(private_path : str):
    with open(private_path, 'rb') as f:
        private_key = import_key(f.read())
    
    return private_key


def sign_file(msg : str, key, hash_algo, out_file : str):
    # Get hashed message
    msg_hasher = hash_algo.new(msg)
    
    encrypted_msg = PKCS1_OAEP.new(key).encrypt(msg_hasher.hexdigest().encode())
    
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    
    with open(f'{out_file}.sig', 'wb') as f:
        f.write(encoded_encrypted_msg)

def main():
    args = get_args()
    
    msg = get_msg(ph.abspath(ph.abspath(args.file_path)))
    private_key = get_private_key(ph.abspath(args.private_key_path))
    
    sign_file(msg, private_key, args.hash, args.out_file)


if __name__ == "__main__":
    main()