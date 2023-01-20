import argparse
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
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
    agp.add_argument('-o', '--output_file', default='message.sig', help='Algoritmo de hash a ser usado.')
    agp.add_argument('-v', '--verbose', type=bool, default=False, help='Escreve no console os passos.')
    
    args = agp.parse_args()
    
    args.hash = hash_dict[args.hash]
    
    print(args)
    return args


def sign_file(msg_file : str, key_file : str, hash_algo):
    # Get message
    with open(msg_file, 'rb') as f:
        msg = f.read()
    
    # Get keys
    key = RSA.import_key()
    with open(key_file, 'rb') as f:
        key = RSA.import_key(key_file)
    
    # Get hashed message
    hasher = hash_algo.new(msg)
    
    print(key.export_key('PEM'))


def main():
    args = get_args()
    
    keys_file = ph.abspath(args.private_key_path)
    file = ph.abspath(args.file_path)
    sign_file(file, keys_file, args.hash)


if __name__ == "__main__":
    main()