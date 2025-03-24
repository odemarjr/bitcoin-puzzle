#py -m pip install base58 ecdsa

import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def hex_to_wif(private_key_hex, is_compressed=True):
    # Converter chave privada hexadecimal
    private_key_bytes = bytes.fromhex(private_key_hex)
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

def private_key_to_address(private_key_hex, is_compressed=True):
    # Gerar a chave privada
    private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)

    # Derivar a chave pública
    public_key = private_key.verifying_key
    public_key_bytes = b'\x04' + public_key.to_string()  # Prefixo 0x04 para chave não compactada

    # Se for compactada, ajustar a chave pública
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

# Exemplo de chave privada em hexadecimal
# private_key_hex = "000000000000000000000000000000033e7665705359f04f28b88cf897c603c9"

print("=== Gerador de Chaves hexadecimal ===")
private_key_hex = input("Digite a chave privada em hexadecimal: ")

while len(private_key_hex) != 64:
    print("Erro: A chave privada deve ter 64 caracteres hexadecimais.")
    private_key_hex = input("Digite novamente a chave privada em hexadecimal: ")

# Gerar as chaves WIF
wif_key_compressed = hex_to_wif(private_key_hex, is_compressed=True)
wif_key_uncompressed = hex_to_wif(private_key_hex, is_compressed=False)

# Gerar os endereços Bitcoin e chaves públicas
address_compressed, public_key_compressed = private_key_to_address(private_key_hex, is_compressed=True)
address_uncompressed, public_key_uncompressed = private_key_to_address(private_key_hex, is_compressed=False)

# Imprimir resultados
# print("Chave WIF (compactada):", wif_key_compressed)
# print("Chave WIF (não compactada):", wif_key_uncompressed)
# print("Endereço (compactado):", address_compressed)
# print("Endereço (não compactado):", address_uncompressed)
# print("Chave Pública (compactada):", public_key_compressed.hex())
# print("Chave Pública (não compactada):", public_key_uncompressed.hex())
# print("Chave Privada (Hex):", private_key_hex)
# print("Chave Privada (Decimal):", int(private_key_hex, 16))

# Salvar os dados em um arquivo TXT sem sobrescrever (append mode)
with open("resultado_bitcoin.txt", "a", encoding="utf-8") as file:
    file.write("Chave WIF (compactada): " + wif_key_compressed + "\n")
    file.write("Chave WIF (não compactada): " + wif_key_uncompressed + "\n")
    file.write("Endereço (compactado): " + address_compressed + "\n")
    file.write("Endereço (não compactado): " + address_uncompressed + "\n")
    file.write("Chave Pública (compactada): " + public_key_compressed.hex() + "\n")
    file.write("Chave Pública (não compactada): " + public_key_uncompressed.hex() + "\n")
    file.write("Chave Privada (Hex): " + private_key_hex + "\n")
    file.write("Chave Privada (Decimal): " + str(int(private_key_hex, 16)) + "\n")
    file.write("---------------\n")  # Divisor para separar pesquisas

print("Resultados salvos com sucesso! Processamento concluído resultado_bitcoin.txt")
print("---------------\n")
