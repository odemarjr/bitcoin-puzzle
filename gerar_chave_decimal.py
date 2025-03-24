#py -m pip install base58 ecdsa

import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def decimal_to_wif(private_key_decimal, is_compressed=True):
    # Converter chave privada decimal
    private_key_bytes = int(private_key_decimal).to_bytes(32, byteorder='big')
    prefix = b'\x80'
    key_with_prefix = prefix + private_key_bytes

    # Adicionar byte de compressão (opcional)
    if is_compressed:
        key_with_prefix += b'\x01'

    # Calcular o checksum (SHA-256 duplo hash dos bytes com prefixo)
    checksum = hashlib.sha256(hashlib.sha256(key_with_prefix).digest()).digest()[:4]

    # Adicionar checksum e codificar em base58 para obter a chave WIF
    wif_bytes = key_with_prefix + checksum
    wif = base58.b58encode(wif_bytes).decode('utf-8')
    return wif

def private_key_to_address(private_key_decimal, is_compressed=True):
    # Gerar a chave privada
    private_key_bytes = int(private_key_decimal).to_bytes(32, byteorder='big')
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Derivar a chave pública
    public_key = private_key.verifying_key
    public_key_bytes = b'\x04' + public_key.to_string()  # Prefixo 0x04 para chave não compactada

    # Se for compactada, ajustar a chave pública (opcional)
    if is_compressed:
        x = public_key.to_string()[:32]
        y = public_key.to_string()[32:]
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        public_key_bytes = prefix + x

    # Fazer SHA-256 seguido de RIPEMD-160 na chave pública
    sha256 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()

    # Adicionar prefixo para endereço Bitcoin (0x00 para mainnet)
    network_prefix = b'\x00'
    hashed_pubkey = network_prefix + ripemd160

    # Calcular o checksum
    checksum = hashlib.sha256(hashlib.sha256(hashed_pubkey).digest()).digest()[:4]

    # Adicionar o checksum e codificar em Base58
    address_bytes = hashed_pubkey + checksum
    bitcoin_address = base58.b58encode(address_bytes).decode('utf-8')

    # Retornar endereço e chave pública
    return bitcoin_address, public_key_bytes

# Exemplo de chave privada em decimal
# private_key_decimal = "1103873984953507439627945351144005829577"

print("=== Gerador de Chaves decimal ===")
while True:
    private_key_decimal = input("Digite a chave privada em decimal: ")
    
    # Verificar se a entrada contém apenas dígitos e se tem comprimento válido
    if private_key_decimal.isdigit() and len(private_key_decimal) <= 78:
        break  # Entrada válida, sair do loop
    else:
        print("Erro: A chave privada deve ser um número decimal válido de no máximo 78 caracteres.")

# Gerar as chaves WIF
wif_key_compressed = decimal_to_wif(private_key_decimal, is_compressed=True)
wif_key_uncompressed = decimal_to_wif(private_key_decimal, is_compressed=False)

# Gerar os endereços Bitcoin e chaves públicas
address_compressed, public_key_compressed = private_key_to_address(private_key_decimal, is_compressed=True)
address_uncompressed, public_key_uncompressed = private_key_to_address(private_key_decimal, is_compressed=False)

# Converter chave privada decimal para hexadecimal e garantir 64 caracteres
private_key_hex = hex(int(private_key_decimal))[2:].zfill(64)

# Imprimir resultados
# print("Chave WIF (compactada):", wif_key_compressed)
# print("Chave WIF (não compactada):", wif_key_uncompressed)
# print("Endereço (compactado):", address_compressed)
# print("Endereço (não compactado):", address_uncompressed)
# print("Chave Pública (compactada):", public_key_compressed.hex())
# print("Chave Pública (não compactada):", public_key_uncompressed.hex())
# print("Chave Privada (Hex):", private_key_hex)
# print("Chave Privada (Decimal):", private_key_decimal)

# Salvar os dados em um arquivo TXT sem sobrescrever (append mode)
with open("resultado_bitcoin.txt", "a", encoding="utf-8") as file:
    file.write("Chave WIF (compactada): " + wif_key_compressed + "\n")
    file.write("Chave WIF (não compactada): " + wif_key_uncompressed + "\n")
    file.write("Endereço (compactado): " + address_compressed + "\n")
    file.write("Endereço (não compactado): " + address_uncompressed + "\n")
    file.write("Chave Pública (compactada): " + public_key_compressed.hex() + "\n")
    file.write("Chave Pública (não compactada): " + public_key_uncompressed.hex() + "\n")
    file.write("Chave Privada (Hex): " + private_key_hex + "\n")
    file.write("Chave Privada (Decimal): " + private_key_decimal + "\n")
    file.write("---------------\n")  # Divisor para separar pesquisas

print("Resultados salvos com sucesso! Processamento concluído em resultado_bitcoin.txt")
print("---------------\n")
