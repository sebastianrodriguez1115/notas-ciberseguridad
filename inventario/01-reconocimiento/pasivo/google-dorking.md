# Google Dorking

## Descripcion
Tecnica de reconocimiento pasivo que utiliza operadores avanzados de busqueda de Google para localizar informacion expuesta. Segun *The Hacker Playbook 3*, el dorking moderno es fundamental para descubrir **activos en la nube** (S3 Buckets) y **entornos de desarrollo** (Jenkins, Gitlab) que han sido mal configurados por equipos de DevOps y expuestos a internet.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1593 (Search Open Websites/Domains)
- **Plataforma**: Web
- **Dificultad**: Basica

## Herramientas
- **Google Search Operators** — site, inurl, intitle, filetype, cache, intext
- **GHDB (Google Hacking Database)** — Repositorio mantenido por OffSec con miles de dorks funcionales

## Comandos / Ejemplos

### Descubrimiento de S3 Buckets y Cloud Storage
```
site:s3.amazonaws.com "target.com"
site:blob.core.windows.net "target.com"
site:*.googleapis.com "target.com"
```

### Busqueda de Paneles DevOps y Orquestacion (The Hacker Playbook 3)
```
intitle:"Dashboard [Kubernetes]"
intitle:"Jenkins [Jenkins]"
inurl:jenkins/login
"GitHub" intitle:"index of" "target.com"
```

### Localizacion de Secretos y Configuraciones
```
filetype:env DB_PASSWORD | DB_USERNAME
filetype:xml site:target.com "web.config"
site:github.com "target.com" "API_KEY"
site:target.com filetype:log "error" | "password"
```

### Identificar directorios abiertos con contenido sensible
```
intitle:"index of" inurl:backup site:target.com
intitle:"index of" inurl:auth site:target.com
```

## Contramedidas
- **Google Search Console**: Solicitar la eliminacion de informacion sensible ya indexada.
- **Configurar robots.txt**: Aunque no es una medida de seguridad, evita que bots bien comportados indexen rutas conocidas.
- **Implementar Autenticacion Robusta**: Ningun panel de administracion o bucket debe ser accesible sin autenticacion, independientemente de si la URL es "secreta".
- **Limpiar el Servidor**: Eliminar archivos de backup (.bak, .old) y logs del directorio raiz del servidor web.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Notas del proyecto: notas-md/HNotes/General/Google Fu.md
- OffSec. (s.f.). *Google Hacking Database*. Exploit-DB. https://www.exploit-db.com/google-hacking-database
- MITRE Corporation. (2024). ATT&CK Technique T1593: Search Open Websites/Domains. https://attack.mitre.org/techniques/T1593/
