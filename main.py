from modules.core import sign_file, verify_signature
from modules.utils import generate_keys


def main():
    menu = """
1 - Gerar par de chaves;
2 - Assinar um arquivo;
3 - Verificar assinatura;
0 - Sair
    """
    while True:
        choice = input(menu)
        match choice:
            case "1":
                filepath = input("Informe em que pasta ficaram as chaves.")
                generate_keys(filepath)
            case "2":
                file = input("Qual arquivo deseja assinar? ")
                key_file = input("Caminho até a chave privada: ")
                hash_algorithm = input(
                    "Qual algoritmo de hash deseja usar: [sha512, sha256]: "
                )
                sign_file(file, key_file, hash_algorithm)
            case "3":
                file = input("Qual arquivo que foi assinado? ")
                signature_file = input("Caminho até o arquivo de assinatura: ")
                key_file = input("Caminho até a chave privada: ")
                hash_algorithm = input(
                    "Qual algoritmo de hash deseja usar: [sha512, sha256]: "
                )

                is_valid = verify_signature(
                    file, signature_file, key_file, hash_algorithm
                )
                if is_valid:
                    print("Assinatura é válida.")
                else:
                    print("Assinatura não é válida.")
            case "0":
                return


if __name__ == "__main__":
    main()
