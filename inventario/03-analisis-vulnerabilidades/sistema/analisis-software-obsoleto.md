---
title: "Análisis de Vulnerabilidades: Software Obsoleto"
slug: analisis-software-obsoleto
aliases: ["Análisis de Vulnerabilidades: Software Obsoleto"]
fase: [Análisis de Vulnerabilidades]
plataforma: Multi
dificultad: Básica
mitre: [T1595.002]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Software Obsoleto

## Descripción
El software obsoleto (End-of-Life - EOL) es aquel que ya no recibe actualizaciones de seguridad por parte del fabricante. Mantener este tipo de aplicaciones en entornos productivos representa un riesgo crítico, ya que cualquier vulnerabilidad descubierta después de su fin de soporte permanecerá sin parchear permanentemente.

## Herramientas
- **GVM / OpenVAS** — Escáner de vulnerabilidades para la detección automática de versiones de software obsoletas.
- **Gestores de paquetes** (dpkg/rpm/wmic) — Herramientas nativas del sistema para listar versiones de software instalado localmente.
- **Endoflife.date** — Recurso externo para verificar fechas de fin de soporte de diversas tecnologías.
- **Herramientas de inventario** — Sistemas de gestión de activos para el seguimiento centralizado del ciclo de vida del software.

## Comandos / Ejemplos
Listar software instalado y su versión en Linux (Debian/Ubuntu):
```bash
dpkg -l | grep -E "apache2|nginx|mysql-server"
```

Listar software instalado en Windows mediante `wmic`:
```cmd
wmic product get name,version
```

Usar Nmap para identificar versiones de servicios de red:
```bash
nmap -sV --version-intensity 5 <target_ip>
```

Identificar software con CVEs conocidos utilizando la base de datos de NIST (National Vulnerability Database).

## Contramedidas
- Establecer un Inventario de Activos (Asset Inventory) actualizado.
- Definir un ciclo de vida para el software y planes de migración antes del EOL.
- Utilizar firewalls y sistemas IPS para proteger sistemas que no pueden ser actualizados.
- Automatizar la detección de versiones obsoletas mediante escáneres de vulnerabilidades.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Easttom, C. (2016). *Computer Security Fundamentals*. Pearson IT Certification.
- Conklin, W. (2017). *CompTIA Security+ Certification Guide*. McGraw-Hill Education.
