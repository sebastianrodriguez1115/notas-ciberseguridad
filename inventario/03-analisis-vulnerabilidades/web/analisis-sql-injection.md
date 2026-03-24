# Análisis de Vulnerabilidades: SQL Injection (SQLi)

## Descripción
La inyección SQL (SQLi) es una vulnerabilidad crítica que ocurre cuando una aplicación web permite a un atacante interferir con las consultas que realiza a su base de datos. Generalmente permite ver datos sensibles, modificar registros y, en casos extremos, obtener control total del servidor de base de datos.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **SQLMap** — Herramienta automatizada para la detección y explotación de inyecciones SQL.
- **Burp Suite** — Suite de pruebas web para la manipulación de consultas y validación manual de SQLi.
- **OWASP ZAP** — Escáner de seguridad con módulos específicos para la detección de vulnerabilidades en bases de datos.
- **SecLists** — Listas de payloads y errores SQL para facilitar la identificación de parámetros vulnerables.

## Comandos / Ejemplos
Detección automatizada con SQLMap y un archivo de solicitud (Burp export):
```bash
sqlmap -r request.txt --batch --dbs
```

Fuzzing de parámetros buscando errores SQL con `ffuf` y SecLists:
```bash
ffuf -u http://target.com/page.php?id=FUZZ -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -mr "SQL syntax|ODBC Driver|MySQL Error"
```

Inyección básica basada en error:
```sql
' OR 1=1 --
```

## Contramedidas
- Utilizar Consultas Preparadas (Sentencias Parametrizadas).
- Implementar Validación de Entradas (Lista Blanca).
- Utilizar el Principio de Privilegios Mínimos en la base de datos.
- Deshabilitar mensajes de error detallados hacia el usuario final.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide To Penetration Testing*. Secure Planet, LLC.
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
