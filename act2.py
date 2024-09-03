from scapy.all import ICMP, IP, sr1
import time
import struct
import random

def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isupper():
            resultado += chr((ord(char) + corrimiento - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) + corrimiento - 97) % 26 + 97)
        else:
            resultado += char
    return resultado

def generar_id_unico():
    return random.randint(10000, 65535)

def generar_timestamp():
    tiempo_actual = time.time()
    segundos = int(tiempo_actual)
    microsegundos = int((tiempo_actual - segundos) * 1e6)
    timestamp = struct.pack("!II", segundos, microsegundos)
    return timestamp

def obtener_payload_estandar():
    # El payload estándar que aparece después del timestamp y el carácter cifrado
    return bytes(range(1, 49))  # Simulación del contenido estándar

def enviar_string_icmp(texto):
    seq_number = 0  
    icmp_id = generar_id_unico()

    for char in texto:
        timestamp = generar_timestamp()

        # Crear el payload manteniendo el timestamp, el carácter cifrado y el resto estándar
        payload_estandar = obtener_payload_estandar()

        # El payload debe ser exactamente de 48 bytes: timestamp (8 bytes) + carácter (1 byte) + 39 bytes restantes
        payload = timestamp + bytes(char, 'utf-8') + payload_estandar[:39]  # Asegura que sea de 48 bytes en total
        
        paquete_icmp = IP(dst="8.8.8.8") / ICMP(type=8, id=icmp_id, seq=seq_number) / payload
        
        respuesta = sr1(paquete_icmp, timeout=1)
        
        if respuesta:
            print(f"Paquete enviado con '{char}' y respuesta recibida de {respuesta.src}")
        else:
            print(f"Paquete enviado con '{char}' pero no se recibió respuesta")
        
        seq_number += 1
        time.sleep(0.5)

def main():
    texto = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento: "))
    texto_cifrado = cifrado_cesar(texto, corrimiento)

    print("Mensaje cifrado a enviar:", texto_cifrado)
    enviar_string_icmp(texto_cifrado)

if __name__ == "__main__":
    main()
