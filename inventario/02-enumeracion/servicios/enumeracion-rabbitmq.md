---
title: Enumeración RabbitMQ (Puerto 5672 / 15672)
slug: enumeracion-rabbitmq
aliases: [Enumeración RabbitMQ (Puerto 5672 / 15672)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1021]
related: []
learning_refs: []
---

# Enumeración RabbitMQ (Puerto 5672 / 15672)

## Descripción
RabbitMQ es un software de mensajería (Message Broker) popular que utiliza el protocolo AMQP. La superficie de ataque de RabbitMQ incluye el puerto AMQP (5672) y la interfaz de gestión HTTP (15672). La enumeración de RabbitMQ se enfoca en verificar si la interfaz de gestión está expuesta con credenciales por defecto (guest/guest), listar intercambios, colas, usuarios y mensajes que pueden contener datos críticos de la aplicación.

## Herramientas
- **rabbitmqadmin** — herramienta de línea de comandos oficial para gestionar RabbitMQ
- **curl** — para interactuar con la API REST de gestión
- **nmap** — scripts NSE (amqp-info)
- **Metasploit** — módulos auxiliares para escaneo y fuerza bruta de credenciales

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Identificar servicio AMQP y obtener información básica
nmap -p 5672,15672 -sV --script amqp-info 10.10.10.10
```

### Enumeración Manual vía API REST (Interfaz de Gestión)
```bash
# Verificar acceso con credenciales por defecto guest:guest
curl -s -u guest:guest http://10.10.10.10:15672/api/overview | jq .

# Listar todos los usuarios
curl -s -u guest:guest http://10.10.10.10:15672/api/users | jq .

# Listar todas las colas
curl -s -u guest:guest http://10.10.10.10:15672/api/queues | jq .

# Listar intercambios (Exchanges)
curl -s -u guest:guest http://10.10.10.10:15672/api/exchanges | jq .

# Obtener mensajes de una cola específica (Cuidado: puede consumir el mensaje)
curl -s -u guest:guest -X POST -d'{"count":10,"requeue":true,"encoding":"auto"}' http://10.10.10.10:15672/api/queues/<vhost>/<queue_name>/get | jq .
```

### Enumeración con rabbitmqadmin
```bash
# Listar colas
rabbitmqadmin -H 10.10.10.10 -P 15672 -u guest -p guest list queues

# Listar usuarios
rabbitmqadmin -H 10.10.10.10 -P 15672 -u guest -p guest list users
```

### Fuerza bruta con Metasploit
```bash
msfconsole -q
use auxiliary/scanner/http/rabbitmq_login
set RHOSTS 10.10.10.10
set RPORT 15672
run
```

## Contramedidas
- **Cambiar las credenciales por defecto** de la cuenta `guest` inmediatamente.
- **Limitar el acceso a la interfaz de gestión (15672)** mediante firewalls o VPNs.
- **Habilitar TLS/SSL** tanto para el puerto AMQP como para la interfaz de gestión.
- **Implementar el Principio de Menor Privilegio** para los usuarios de RabbitMQ, restringiendo el acceso a vhosts específicos.
- **Mantener RabbitMQ y Erlang actualizados** para mitigar vulnerabilidades conocidas.

## Referencias
- RabbitMQ Documentation. (2024). Security Checklist. https://www.rabbitmq.com/docs/production-checklist#security
- HackTricks. (2024). 5672, 15672 - Pentesting RabbitMQ. https://book.hacktricks.xyz/network-services-pentesting/pentesting-rabbitmq
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/rabbitmq-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
