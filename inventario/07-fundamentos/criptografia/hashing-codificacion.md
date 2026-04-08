# Criptografía: Hashing y Codificación

## Descripción
La criptografía es el arte de proteger la información mediante técnicas matemáticas. En el pentesting, es fundamental distinguir entre **Codificación** (representación de datos para transporte), **Hashing** (verificación de integridad de un solo sentido) y **Cifrado** (confidencialidad con capacidad de reversión mediante claves). Comprender estas diferencias es clave para identificar y explotar vulnerabilidades de almacenamiento de credenciales.

## Clasificación
- **Fase**: Fundamentos
- **MITRE ATT&CK**: N/A (Concepto Base)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Conceptos Clave

### Codificación (Encoding)
Proceso de transformar datos de un formato a otro. No es una medida de seguridad, ya que no requiere una clave secreta para revertirse.
- **Ejemplos**: Base64 (muy común en payloads web), URL Encoding, Hexadecimal, ASCII.
- **Uso**: Facilitar el transporte de datos binarios a través de protocolos basados en texto.

### Hashing
Transformación de una entrada de cualquier longitud en una salida de longitud fija (digest). Es una función unidireccional (irreversible por diseño).
- **Propiedades**: Determinista (misma entrada = misma salida), resistente a colisiones (dos entradas distintas no deberían dar el mismo hash).
- **Algoritmos Comunes**:
    - **MD5 / SHA-1**: Obsoletos por colisiones, pero aún muy comunes.
    - **SHA-256 / SHA-512**: Estándares actuales de seguridad.
    - **NTLM / Net-NTLM**: Algoritmos usados por Windows.
    - **Bcrypt / Scrypt**: Algoritmos lentos diseñados específicamente para almacenar contraseñas de forma segura.

### Cifrado (Encryption)
Protege la confidencialidad mediante algoritmos que requieren una clave.
- **Simétrico**: Usa la misma clave para cifrar y descifrar (ej. AES).
- **Asimétrico**: Usa un par de claves: Pública (cifra) y Privada (descifra) (ej. RSA).

## Herramientas de Análisis

### Identificación de Hash
```bash
# Identificar el algoritmo probable de un hash desconocido
hashid <hash_desconocido>
hash-identifier
```

### Decodificación y Transformación
- **CyberChef**: La herramienta web "suiza" para codificar, decodificar y transformar datos de forma visual. Es indispensable para el análisis de payloads.

### Cracking de Hashes (Ataque de Diccionario/Brute Force)
```bash
# Usar Hashcat para romper un hash MD5 (-m 0) con el diccionario RockYou
hashcat -m 0 <hash_file> /usr/share/wordlists/rockyou.txt
# Usar John the Ripper (autodetecta el tipo)
john --wordlist=/usr/share/wordlists/rockyou.txt <hash_file>
```

## Referencias
- Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson.
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- Notas del proyecto: notas-md/HNotes/HNotes/Hacking/Hash Cracking.md
