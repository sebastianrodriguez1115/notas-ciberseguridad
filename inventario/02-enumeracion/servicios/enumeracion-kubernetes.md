# Enumeración Kubernetes (K8s) (Puerto 6443 / 443 / 10250)

## Descripción
Kubernetes es un orquestador de contenedores líder. La superficie de ataque de K8s incluye el API Server (típicamente en el puerto 6443 o 443) y el Kubelet (puerto 10250). La enumeración de Kubernetes se enfoca en descubrir la versión del cluster, identificar si el acceso anónimo está habilitado en el API Server o Kubelet, y extraer información sensible como secretos, configuraciones de pods y redes si se tiene acceso no autorizado.

## Clasificación
- **Fase**: Enumeración, Explotación
- **MITRE ATT&CK**: T1613 (Container and Cloud Infrastructure: Kubernetes)
- **Plataforma**: Multi
- **Dificultad**: Avanzada

## Herramientas
- **kubectl** — herramienta de línea de comandos oficial para gestionar clusters de K8s
- **curl** — para interactuar directamente con el API Server o Kubelet REST API
- **kube-hunter** — herramienta de búsqueda de vulnerabilidades en clusters de K8s
- **nmap** — para descubrimiento de servicios (6443, 10250, 10255)

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Identificar API Server (6443) y Kubelet (10250)
nmap -p 6443,10250,10255,443 -sV 10.10.10.10
```

### Enumeración Manual del API Server (Acceso Anónimo)
```bash
# Verificar si el API Server permite acceso anónimo
curl -k https://10.10.10.10:6443/version
curl -k https://10.10.10.10:6443/api/v1/namespaces
curl -k https://10.10.10.10:6443/api/v1/pods
```

### Enumeración Manual del Kubelet (Puerto 10250)
```bash
# Listar pods gestionados por el Kubelet (si el acceso anónimo está permitido)
curl -sk https://10.10.10.10:10250/pods | jq .

# Si el Kubelet permite comandos de ejecución
# curl -X POST -sk https://10.10.10.10:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

### Enumeración con kubectl (Si se obtiene un Service Account Token)
```bash
# Configurar contexto con un token obtenido
export TOKEN="<jwt_token>"
kubectl --token=$TOKEN --server=https://10.10.10.10:6443 --insecure-skip-tls-verify=true get pods

# Listar todos los recursos permitidos para el token actual
kubectl auth can-i --list --token=$TOKEN
```

### Escaneo automatizado con kube-hunter
```bash
# Ejecutar escaneo remoto
kube-hunter --remote 10.10.10.10
```

## Contramedidas
- **Deshabilitar el acceso anónimo** al API Server y al Kubelet (`--anonymous-auth=false`).
- **Implementar RBAC (Role-Based Access Control)** siguiendo el Principio de Menor Privilegio para todos los usuarios y service accounts.
- **Utilizar Admission Controllers** como Pod Security Admission para restringir configuraciones inseguras de los pods.
- **Cifrar secretos en reposo** utilizando ETCD encryption.
- **Restringir el acceso por red** a los puertos de gestión (6443, 10250, 10255) mediante Network Policies y firewalls externos.
- **Mantener Kubernetes actualizado** para corregir vulnerabilidades críticas (CVEs).

## Referencias
- Kubernetes Documentation. (2024). Securing a Cluster. https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/
- HackTricks. (2024). Pentesting Kubernetes. https://book.hacktricks.xyz/network-services-pentesting/pentesting-kubernetes
- CIS Kubernetes Benchmark. (2024). Center for Internet Security. https://www.cisecurity.org/benchmark/kubernetes
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
