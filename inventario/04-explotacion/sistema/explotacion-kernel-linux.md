# Explotación de Kernel Linux

## Descripción
La explotación del kernel de Linux implica aprovechar vulnerabilidades en el núcleo del sistema operativo para elevar privilegios desde un usuario con permisos limitados a root. Estas vulnerabilidades suelen residir en la gestión de memoria (como desbordamientos de búfer o race conditions) o en subsistemas específicos (como controladores de red o sistemas de archivos). Casos famosos como DirtyCow o DirtyPipe permiten la escritura arbitraria en archivos protegidos o la manipulación de la memoria del kernel para otorgar privilegios de administrador de forma inmediata.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation)
- **Plataforma**: Linux
- **Dificultad**: Avanzada

## Herramientas
- **searchsploit** — interfaz de línea de comandos para Exploit Database que permite buscar exploits locales por versión de kernel.
- **linux-exploit-suggester** — script que analiza la versión del kernel y sugiere posibles vectores de escalada de privilegios.
- **gcc** — compilador necesario para transformar el código fuente de los exploits (generalmente en C) en binarios ejecutables en el objetivo.

## Comandos / Ejemplos

### Búsqueda de exploits locales con searchsploit
```bash
# Identificar la versión del kernel objetivo
uname -a
# Buscar exploits locales para esa versión específica
searchsploit linux kernel 5.8 local
```

### Ejemplo de explotación: DirtyPipe (CVE-2022-0847)
```bash
# Clonar y compilar el exploit en la máquina objetivo
gcc exploit.c -o exploit
# Ejecutar para sobrescribir /etc/passwd o elevar privilegios directamente
./exploit /etc/passwd 1 root:
# Verificar los cambios
cat /etc/passwd | head -n 1
```

### Uso de Linux Exploit Suggester
```bash
# Ejecutar el script para identificar vulnerabilidades conocidas
./linux-exploit-suggester.sh -k 4.4.0-21-generic
# Resultado: Listado de CVEs con su respectiva probabilidad de éxito
```

## Contramedidas
- Mantener el kernel actualizado a la última versión estable mediante parches regulares.
- Implementar mecanismos de seguridad del kernel como KASLR (Kernel Address Space Layout Randomization).
- Deshabilitar el acceso de usuarios no privilegiados a binarios de compilación (como gcc) si no es estrictamente necesario.
- Utilizar módulos de seguridad de Linux (LSM) como SELinux o AppArmor para restringir las capacidades de los procesos.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1068: Exploitation for Privilege Escalation. https://attack.mitre.org/techniques/T1068/
