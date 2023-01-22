## Trabalho
Implementação de um programa de assinatura digital

### Grupo:
- Ingrid Miranda dos Santos
- João Victor Melo da Silva
- Vítor Melo Lopes

## Execução
### Preparação do ambiente
```sh
python -m venv .venv

# Ativação do ambinte virtual
# Windows >
.venv/Scripts/activate
# Linux >
source .venv/bin/activate

python -m pip install --upgrade pip

pip install -r requirements.txt
```

### Executando pelo menu
- No cmd configurado, `python main.py`
- Selecione a operação desejada.
- Indique o nome do arquivo pedido a partir da pasta de execução.

### Executando separadamente
- No cmd configurado, `python modules/rsa_gen_keys.py -v` para gerar as chaves.
  - É possível indicar tamanho, pasta e arquivo de saída das chaves.
  - Use `-h` para mais informações.

- Com chaves geradas, `python modules/sign.py path/to/message private.pem hash -v`.
  - Possivelmente, `python modules/sign.py message private.pem sha512 -v`
  - Use `-h` para mais informações.

- Com o arquivo de assinatura gerado, `python modules/verify.py path/to/message message.sig public.pem hash -v`.
  - Possivelmente, `python modules/verify.py message message.sig public.pem sha512 -v`
  - Use `-h` para mais informações.