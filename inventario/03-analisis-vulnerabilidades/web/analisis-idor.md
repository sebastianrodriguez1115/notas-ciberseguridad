---
title: Análisis de Vulnerabilidades: Insecure Direct Object Reference (IDOR)
slug: analisis-idor
aliases: ["Análisis de Vulnerabilidades: Insecure Direct Object Reference (IDOR)"]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Básica
mitre: [T1190]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Insecure Direct Object Reference (IDOR)

## Descripción
La vulnerabilidad de Referencia Directa e Insegura a Objetos (IDOR) ocurre cuando una aplicación web utiliza un identificador (como un ID en la URL o un parámetro POST) para acceder directamente a un objeto de la base de datos sin verificar los permisos del usuario que realiza la solicitud. Esto permite a un atacante acceder a datos de otros usuarios simplemente cambiando el valor del identificador.

## Herramientas
- **Burp Suite** — Suite de herramientas para la interceptación y modificación de tráfico web, esencial para pruebas IDOR.
- **Herramientas de Desarrollador** — Utilidades del navegador para el monitoreo de parámetros en tiempo real.
- **SecLists** — Listas de diccionarios para realizar ataques de fuerza bruta sobre identificadores de objetos.

## Comandos / Ejemplos
Fuzzing de IDs con `ffuf` utilizando una secuencia numérica:
```bash
seq 1 1000 > ids.txt
ffuf -u http://target.com/api/user/FUZZ -w ids.txt -H "Cookie: user_session=..." -fs 404
```

Prueba manual en Burp Suite:
1. Capturar una solicitud que use un ID: `GET /view_profile?id=123`.
2. Enviar a Repeater.
3. Cambiar `id=123` a `id=124` y observar si se visualizan datos de otro usuario.

Uso de la extensión 'Autorize' de Burp Suite:
- Configurar Autorize con las cookies de un usuario de bajo privilegio.
- Navegar la aplicación como un usuario de alto privilegio.
- Autorize repetirá las solicitudes con las cookies de bajo privilegio y resaltará los accesos exitosos (indicando IDOR o falta de control de acceso).

## Contramedidas
- Implementar controles de acceso a nivel de objeto (Object-Level Access Control).
- Utilizar identificadores no predecibles (UUIDs).
- Validar siempre que el usuario autenticado tenga permisos explícitos sobre el recurso solicitado.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide To Penetration Testing*. Secure Planet, LLC.
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
