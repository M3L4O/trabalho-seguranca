import argparse
from Crypto.PublicKey import RSA

def get_args():
    key_size_choice = [ 1024 * _ for _ in range(1, 4) ]
    
    agp = argparse.ArgumentParser(prog='rsa_gen_keys.py', 
                                  description='Gera um documento padrão PEM com chaves RSA.')
    
    agp.add_argument('-s', '--size', choices=key_size_choice, type=int, default=1024*2, help='Tamanho em bytes da chave.')
    agp.add_argument('-o', '--output_file', default='keys', help='Nome do arquivo de saída das chaves.')
    agp.add_argument('-v', '--verbose', action='store_true', help='Escreve no console os passos.')
    
    args = agp.parse_args()
    
    return args


def gen_keys(key_size : int, out_file : str, verbose: bool = False ):
    key = RSA.generate(key_size)
    private_key = key.export_key('PEM')
    public_key = key.public_key().export_key('PEM')
    
    with open(f"./{out_file}.pem", "wb") as f:
        f.write(public_key)
        f.write('\n'.encode('utf-8'))
        f.write(private_key)
    
    if verbose:
        print(
            f'----- Configurações -----\n'
            f'Tamanho da chave: {key_size}\n'
            f'Arquivo salvo: {out_file}.pem\n'
            f'Chave pública gerada:\n{ public_key.decode("utf-8") }'
        )


def main():
    args = get_args()
    gen_keys(args.size, args.output_file, args.verbose)

if __name__ == '__main__':
    main()