from os import path as ph

from modules.rsa_gen_keys import generate_keys
from modules.sign import sign_file
from modules.verify import verify_signature


def main():
    menu = """
1 - Gerar par de chaves;
2 - Assinar um arquivo;
3 - Verificar assinatura;
0 - Sair
    """
    title = "Selecione uma opção:"
    options = [
        "[0] - Gerar um par de chaves",
        "[1] - Assinar um arquivo",
        "[2] - Verificar Assinatura",
        "[3] - Sair",
    ]
    while True:

        index = input("Selecione uma opção:\n" + "\n".join(options) + "\n")
        match index:

            case "0":
                filepath = input("Informe em que pasta ficarão as chaves:\n~ ")
                generate_keys(ph.abspath(filepath), verbose=True)

                input("Tecle enter para voltar ao menu.")
            case "1":
                file = input("Informe o caminho até o arquivo a ser assinado:\n~ ")
                key_file = input(
                    "Informe o caminho até a chave privada que deseja utilizar:\n~ "
                )
                signature_file = input(
                    "Informe o arquivo de saída para a assinatura.\n~ "
                )
                hash_algorithm = input(
                    "Qual algoritmo de hash deseja usar: [sha512, sha256]:\n> "
                )
                sign_file(
                    ph.abspath(file),
                    ph.abspath(signature_file),
                    ph.abspath(key_file),
                    hash_algorithm,
                    verbose=True
                )

                input("Tecle enter para voltar ao menu.")
            case "2":
                file = input(
                    "Informe o caminho até o arquivo original que foi assinado:\n~ "
                )
                signature_file = input("Informe o caminho até a assinatura:\n~ ")
                key_file = input("Informe o caminho até a chave pública:\n~ ")
                hash_algorithm = input(
                    "Qual algoritmo de hash deseja usar: [sha512, sha256]:\n> "
                )

                is_valid = verify_signature(
                    ph.abspath(file),
                    ph.abspath(signature_file),
                    ph.abspath(key_file),
                    hash_algorithm,
                    verbose=True
                )
                if is_valid:
                    print("Assinatura é válida.")
                else:
                    print("Assinatura não é válida.")

                input("Tecle enter para voltar ao menu.")
            case "3":
                return


if __name__ == "__main__":
    main()
