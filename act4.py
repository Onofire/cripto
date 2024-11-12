from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
import base64
import sys


def ajustar_clave(key, tamano_necesario):
    if len(key) < tamano_necesario:
        key += get_random_bytes(tamano_necesario - len(key))
    return key[:tamano_necesario]

# Función de padding PKCS5
def pkcs5_pad(text, block_size):
    padding = block_size - len(text) % block_size
    return text + bytes([padding]) * padding

# Función de eliminación de padding PKCS5
def pkcs5_unpad(text):
    padding = text[-1]
    return text[:-padding]

# Función de cifrado que devuelve el texto cifrado en base64
def cifrar(algoritmo, key, iv, text):
    cipher = algoritmo.new(key, algoritmo.MODE_CBC, iv)
    text = pkcs5_pad(text, algoritmo.block_size)  # Aplicar padding PKCS5
    texto_cifrado = cipher.encrypt(text)
    return base64.b64encode(texto_cifrado).decode()

# Función de descifrado que recibe texto cifrado en base64
def descifrar(algoritmo, key, iv, texto_cifrado_b64):
    texto_cifrado = base64.b64decode(texto_cifrado_b64)
    cipher = algoritmo.new(key, algoritmo.MODE_CBC, iv)
    text = cipher.decrypt(texto_cifrado)
    return pkcs5_unpad(text)  # Eliminar padding PKCS5

# Solicitar al usuario el algoritmo
print("Seleccione el algoritmo de cifrado (DES, 3DES o AES-256): ")
algoritmo_nombre = input().upper()

if algoritmo_nombre == 'DES':
    tamano_clave = 8
    tamano_iv = 8
    algoritmo = DES
elif algoritmo_nombre == '3DES':
    tamano_clave = 24
    tamano_iv = 8
    algoritmo = DES3
elif algoritmo_nombre == 'AES-256':
    tamano_clave = 32
    tamano_iv = 16
    algoritmo = AES
else:
    print("Algoritmo no reconocido.")
    sys.exit()

# Solicitar los datos de entrada
key = input("Ingresa la clave (key): ").encode()
iv = input("Ingresa el vector de inicialización (IV de 8 bytes): ").encode()
text = input("Ingresa el texto a cifrar: ").encode()

# Ajustar la clave y el IV
key = ajustar_clave(key, tamano_clave)
iv = ajustar_clave(iv, tamano_iv)

# Convertir la clave ajustada y el IV a base64 para mostrar en formato de texto legible
key_base64 = base64.b64encode(key).decode()
iv_base64 = base64.b64encode(iv).decode()

print(f"Clave ajustada (base64): {key_base64}")
print(f"IV ajustado (base64): {iv_base64}")

# Cifrar el texto y mostrar en base64
texto_cifrado_b64 = cifrar(algoritmo, key, iv, text)
print(f"Texto cifrado ({algoritmo_nombre}) en base64:", texto_cifrado_b64)

# Descifrar el texto cifrado en base64
texto_descifrado = descifrar(algoritmo, key, iv, texto_cifrado_b64)
print(f"Texto descifrado ({algoritmo_nombre}):", texto_descifrado.decode())
