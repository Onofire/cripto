def cifrado_cesar(texto, corrimiento):
    resultado = ""
    
    for char in texto:
        # Cifrado para letras mayúsculas
        if char.isupper():
            resultado += chr((ord(char) + corrimiento - 65) % 26 + 65)
        # Cifrado para letras minúsculas
        elif char.islower():
            resultado += chr((ord(char) + corrimiento - 97) % 26 + 97)
        # Mantener los caracteres no alfabéticos sin cambios
        else:
            resultado += char
    
    return resultado

# Ejemplo de uso
texto = input("Ingrese el texto a cifrar: ")
corrimiento = int(input("Ingrese el valor de corrimiento: "))
texto_cifrado = cifrado_cesar(texto, corrimiento)

print(f"Texto cifrado: {texto_cifrado}")
