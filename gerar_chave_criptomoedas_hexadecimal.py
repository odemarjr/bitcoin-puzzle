#py -m pip install base58 ecdsa

import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

# Prefixos específicos para cada criptomoeda
CRYPTO_PREFIXES = {
    "Bitcoin": {"private_key": b'\x80', "address": b'\x00'},
    "Litecoin": {"private_key": b'\xB0', "address": b'\x30'},
    "Dogecoin": {"private_key": b'\x9E', "address": b'\x1E'},
    "Dash": {"private_key": b'\xCC', "address": b'\x4C'},
    "Bitcoin SV": {"private_key": b'\x80', "address": b'\x00'},
}

def hex_to_wif(private_key_hex, crypto_name, is_compressed=True):
    # Obter prefixo para chave privada
    prefix = CRYPTO_PREFIXES[crypto_name]["private_key"]
    private_key_bytes = bytes.fromhex(private_key_hex)
    key_with_prefix = prefix + private_key_bytes

    # Adicionar byte de compressão (opcional)
    if is_compressed:
        key_with_prefix += b'\x01'

    # Calcular checksum
    checksum = hashlib.sha256(hashlib.sha256(key_with_prefix).digest()).digest()[:4]

    # Gerar chave WIF
    wif_bytes = key_with_prefix + checksum
    return base58.b58encode(wif_bytes).decode('utf-8')

def private_key_to_address(private_key_hex, crypto_name, is_compressed=True):
    # Gerar chave privada
    private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    public_key = private_key.verifying_key
    public_key_bytes = b'\x04' + public_key.to_string()

    # Compactar chave pública se necessário
    if is_compressed:
        x = public_key.to_string()[:32]
        y = public_key.to_string()[32:]
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        public_key_bytes = prefix + x

    # Hash da chave pública
    sha256 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()

    # Adicionar prefixo de rede
    network_prefix = CRYPTO_PREFIXES[crypto_name]["address"]
    hashed_pubkey = network_prefix + ripemd160

    # Calcular checksum
    checksum = hashlib.sha256(hashlib.sha256(hashed_pubkey).digest()).digest()[:4]

    # Gerar endereço em Base58
    address_bytes = hashed_pubkey + checksum
    return base58.b58encode(address_bytes).decode('utf-8'), public_key_bytes.hex()

def save_to_file(filename, results):
    # Salvar resultados no arquivo TXT com codificação UTF-8
    with open(filename, "a", encoding="utf-8") as file:
        for key, value in results.items():
            file.write(f"{key}: {value}\n")
        file.write("---------------\n")

# # Exemplo de chave privada em hexadecimal
# private_key_hex = "000000000000000000000000000000033e7665705359f04f28b88cf897c603c9"

print("=== Gerador de Chaves criptomoedas ===")
private_key_hex = input("Digite a chave privada em hexadecimal: ")

while len(private_key_hex) != 64:
    print("Erro: A chave privada deve ter 64 caracteres hexadecimais.")
    private_key_hex = input("Digite novamente a chave privada em hexadecimal: ")

cryptos = ["Bitcoin", "Bitcoin SV", "Dash", "Dogecoin", "Litecoin"]

for crypto in cryptos:
    results = {}
    is_compressed = True  # Modo compactado
    is_uncompressed = False # Modo não compactado

    # Gerar chave WIF, endereço e chave pública compactada
    wif_key = hex_to_wif(private_key_hex, crypto, is_compressed=is_compressed)
    wif_key_un = hex_to_wif(private_key_hex, crypto, is_compressed=is_uncompressed)
    address, public_key = private_key_to_address(private_key_hex, crypto, is_compressed=is_compressed)
    address_un, public_key_un = private_key_to_address(private_key_hex, crypto, is_compressed=is_uncompressed)

    # Salvar resultados
    results["Moeda"] = crypto
    results["Chave WIF (compactada)"] = wif_key
    results["Chave WIF (não compactada)"] = wif_key_un
    results["Endereço (compactado)"] = address
    results["Endereço (não compactado)"] = address_un
    results["Chave Pública (compactada)"] = public_key
    results["Chave Pública (não compactada)"] = public_key_un    
    results["Chave Privada (Hex)"] = private_key_hex
    results["Chave Privada (Decimal)"] = str(int(private_key_hex, 16))

    save_to_file("resultado_criptomoedas.txt", results)
    print(f"Resultados para {crypto} salvos com sucesso!")
    print("---------------")
