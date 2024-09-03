import pyshark
from termcolor import colored

def descifrar_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isupper():
            resultado += chr((ord(char) - corrimiento - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) - corrimiento - 97) % 26 + 97)
        else:
            resultado += char
    return resultado

def analizar_paquete(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="icmp && ip.dst == 8.8.8.8")
    
    texto_cifrado = ""
    for packet in cap:
        if hasattr(packet.icmp, 'data'):
            texto_cifrado += chr(int(packet.icmp.data[0:2], 16))  # Obtener el primer byte como carácter
    
    print("Texto cifrado extraído: " + texto_cifrado)
    print("\nPosibles descifrados:\n")
    
    posibles_mensajes = []
    
    for corrimiento in range(26):
        descifrado = descifrar_cesar(texto_cifrado, corrimiento)
        posibles_mensajes.append(descifrado)
        print(f"Corrimiento {corrimiento}: {descifrado.ljust(70)}")

    # Identificar el mensaje más probable
    mensaje_mas_probable = max(posibles_mensajes, key=lambda msg: sum([msg.count(c) for c in 'aeiou']))
    print("\nMensaje más probable:")
    print(colored(mensaje_mas_probable.ljust(70), 'green'))

if __name__ == "__main__":
    analizar_paquete('/home/simonwig/Documents/Codes/Cripto/lab1/captura_act3.pcapng')
