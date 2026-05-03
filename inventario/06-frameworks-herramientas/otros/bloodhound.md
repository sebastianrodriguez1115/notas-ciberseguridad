---
title: BloodHound: Análisis de Rutas de Ataque en AD
slug: bloodhound
aliases: ["BloodHound: Análisis de Rutas de Ataque en AD"]
fase: [Reconocimiento, Post-Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1087.002, T1087, T1484, T1069.002, T1069]
related: []
learning_refs: []
---

# BloodHound: Análisis de Rutas de Ataque en AD

## Descripción
BloodHound es una herramienta de análisis de grafos que utiliza la teoría de grafos para identificar rutas de ataque complejas en entornos de Active Directory (AD) y Azure. Al recolectar datos sobre usuarios, grupos, computadoras y permisos, permite visualizar relaciones de confianza y privilegios que no son evidentes mediante la enumeración manual, facilitando la identificación de caminos hacia el control total del dominio (Domain Admin). El target de la herramienta es siempre Windows AD, pero la GUI (Neo4j) y el ingestor `BloodHound.py` corren en cualquier plataforma (Linux, macOS, Windows).

## Herramientas
- **BloodHound (GUI)** — La interfaz gráfica basada en Neo4j para visualizar y consultar el grafo.
- **SharpHound (.exe / .ps1)** — El recolector oficial de datos que se ejecuta en el host objetivo (Ingestor).
- **BloodHound.py** — Recolector basado en Python que permite la ingesta de datos de AD desde sistemas Linux sin necesidad de una sesión de dominio.
- **Neo4j** — La base de datos de grafos que almacena y procesa la información recolectada.

## Comandos / Ejemplos

### Recolección de Datos con SharpHound (Windows)
```powershell
# Ejecutar SharpHound con el método por defecto (All) para recolectar todo
.\SharpHound.exe -c All --zipfilename MyDomainData.zip

# Recolección silenciosa evitando el escaneo de sesiones (para mayor sigilo)
.\SharpHound.exe -c DCOnly
```

### Recolección de Datos con BloodHound.py (Linux)
Ideal cuando tenemos credenciales pero no acceso directo a un host Windows del dominio.
```bash
# Recolectar datos del dominio usando credenciales y la IP del Domain Controller
bloodhound-python -u <usuario> -p <password> -d <dominio.local> -dc <10.10.10.5> -c All
# Resultado: Se generan varios archivos JSON listos para importar.
```

### Consultas Comunes en la Interfaz de BloodHound
Una vez importados los archivos ZIP/JSON:
1. Ir a la pestaña **Queries**.
2. **Find Shortest Paths to Domain Admins**: Muestra el camino más corto desde cualquier objeto hasta los administradores de dominio.
3. **Find Principals with DCSync Rights**: Identifica usuarios con permisos para replicar datos del dominio (útil para ataques DCSync).
4. **Shortest Paths to High Value Targets**: Visualiza rutas hacia servidores críticos o usuarios VIP.

### Análisis de un Objeto Específico
Al seleccionar un usuario o computadora, en la pestaña **Node Info**:
- **First Degree Object Control**: Qué otros objetos controla directamente.
- **Transitive Object Control**: Qué puede controlar de forma indirecta a través de grupos o permisos heredados.

## Contramedidas
- Implementar el modelo de administración de "Tiered Administration" para evitar que administradores de alto nivel inicien sesión en equipos de bajo nivel.
- Limitar los permisos de enumeración de sesiones y grupos para usuarios estándar (evitar el acceso indiscriminado a SAM y sesiones RDP).
- Monitorizar la ejecución de SharpHound y el uso excesivo de consultas LDAP/SAMR sospechosas desde un solo host.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- SpecterOps. (s.f.). *BloodHound* [Software]. GitHub. https://github.com/BloodHoundAD/BloodHound
- MITRE Corporation. (2024). ATT&CK Technique T1087.002: Domain Account Discovery. https://attack.mitre.org/techniques/T1087/002/
