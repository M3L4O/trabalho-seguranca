import argparse
from Cryptodome.PublicKey import RSA

def get_args():
    key_size_choice = [ 1024 * _ for _ in range(1, 4) ]
    
    agp = argparse.ArgumentParser(prog='rsa_gen_keys.py', 
                                  description='Gera um documento padrão PEM com chaves RSA.')
    
    agp.add_argument('-s', '--size', choices=key_size_choice, type=int, default=1024*2, help='Tamanho em bytes da chave.')
    agp.add_argument('-o-', '--private_out', default='private', help='Nome do arquivo de saída das chaves.')
    agp.add_argument('-o+', '--public_out', default='public', help='Nome do arquivo de saída das chaves.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    return agp.parse_args()


def gen_keys(key_size : int, private_out : str, public_out : str, verbose: bool = False ):
    key = RSA.generate(key_size)
    private_key = key.export_key('PEM')
    public_key = key.public_key().export_key('PEM')
    
    with open(f"./{public_out}.pem", "wb") as f:
        f.write(public_key)
    
    with open(f'./{private_out}.pem', 'wb') as f:
        f.write(private_key)
    
    if verbose:
        print(
            f'----- Configurações -----\n'
            f'Tamanho da chave: {key_size}\n'
            f'Arquivos salvos: {public_out}.pem e {private_out}.pem\n'
            f'Chave pública gerada:\n{ public_key.decode("utf-8") }'
        )


def main():
    args = get_args()
    gen_keys(args.size, args.private_out, args.public_out, args.verbose)

if __name__ == '__main__':
    main()