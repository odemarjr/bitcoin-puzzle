import os
import subprocess

while True:
    print("Diretório atual:", os.getcwd())  # Exibe o diretório atual

    # Lista de opções com descrições
    programas = {
        "1": "Gerar chave decimal",
        "2": "Gerar chave hexadecimal",
        "3": "Gerar chave de criptomoedas decimal",
        "4": "Gerar chave de criptomoedas hexadecimal",
        "5": "Sair"
    }

    # Exibir as opções para o usuário
    print("\nEscolha:")
    for key, value in programas.items():
        print(f"{key}. {value}")

    # Obter a escolha do usuário
    opcao = input("Digite a opção desejada: ").strip()

    # Verificar se a opção é válida
    if opcao == "5":
        print("Saindo do programa. Até mais!")
        break  # Interrompe o loop para sair

    if opcao in programas:
        if opcao in {"1", "2", "3", "4"}:  # Apenas os programas executáveis
            # Mapear opção para o nome do programa real
            arquivos_programas = {
                "1": "gerar_chave_decimal.py",
                "2": "gerar_chave_hexadecimal.py",
                "3": "gerar_chave_criptomoedas_decimal.py",
                "4": "gerar_chave_criptomoedas_hexadecimal.py"
            }
            programa_escolhido = arquivos_programas[opcao]
            print(f"Você escolheu: {programas[opcao]}")

            # Verificar se o arquivo existe antes de executá-lo
            if os.path.exists(programa_escolhido):
                subprocess.run(["python", programa_escolhido])
            else:
                print(f"Arquivo {programa_escolhido} não encontrado.")
        else:
            print("Opção inválida. Por favor, tente novamente.")
    else:
        print("Opção inválida. Por favor, tente novamente.")
