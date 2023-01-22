import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
import os, os.path as ph
from utils import save_key

def get_args():
    key_size_choice = [ 1024 * _ for _ in range(1, 4) ]
    
    agp = argparse.ArgumentParser(prog='rsa_gen_keys.py', 
                                  description='Gera um documento padrão PEM com chaves RSA.')
    
    agp.add_argument('-o', '--out_folder', default='', help='Diretório em que as chaves serão salvas.')
    agp.add_argument('-s', '--size', choices=key_size_choice, type=int, default=1024*2, help='Tamanho em bytes da chave.')
    agp.add_argument('-o-', '--private_out', default='private', help='Nome do arquivo de saída das chaves.')
    agp.add_argument('-o+', '--public_out', default='public', help='Nome do arquivo de saída das chaves.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    return agp.parse_args()


def generate_keys(filepath, private_out = 'private', public_out='public', key_size=2048, verbose=False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    if not ph.exists(filepath):
        os.mkdir(filepath)
    
    private_path = ph.join(filepath, f'{private_out}.pem')
    public_path = ph.join(filepath, f'{public_out}.pem')
    
    save_key(private_key, private_path, True)
    save_key(public_key, public_path)
    
    if verbose:
        print(
            f'----- Configurações de geração de chaves RSA -----\n'
            f'Tamanho da chave: {key_size}\n'
            f'Arquivos salvos:'
            f'\n\tChave pública: {public_path}'
            f'\n\tChave privada: {private_path}'
        )


def main():
    args = get_args()
    
    generate_keys(
        ph.abspath(args.out_folder),
        args.private_out,
        args.public_out,
        args.size,
        args.verbose)

if __name__ == '__main__':
    main()
