# Fingerprinting de Tecnologias Web

## Descripción
Identificación del stack tecnologico de una aplicación web: servidor HTTP, framework, CMS, lenguaje de programacion y versiones. Puede realizarse de forma activa (herramientas CLI que interactuan con el objetivo) o pasiva (consulta de bases de datos publicas y extensiones de navegador). Es esencial para priorizar vectores de ataque y buscar CVEs especificos de las versiones detectadas.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1592.002 (Gather Victim Host Information: Software)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **WhatWeb** — fingerprinting activo desde CLI; detecta servidor, CMS, frameworks, versiones
- **Wappalyzer** — extensión de navegador y API; identificación pasiva de tecnologias
- **Builtwith** — servicio web con perfil tecnologico detallado del objetivo
- **httpx** — verificación de host vivo y cabeceras HTTP
- **Stackshare** — tecnologias auto-declaradas por empresas (OSINT)

## Comandos / Ejemplos

```bash
# WhatWeb - fingerprinting activo desde CLI
whatweb http://webapp.spoke.ai
whatweb 10.4.18.13

# WhatWeb con mayor verbosidad (nivel de agresividad)
whatweb -a 3 http://TARGET

# httpx - verificar host vivo y extraer cabeceras
httpx https://app.getiluma.ai

# httpx - pipeline con subfinder para verificar activos
cat dominios.txt | httpx | sort -u > activos_vivos.txt
```

**Servicios online (pasivos):**
- `https://www.wappalyzer.com/` — extensión de navegador y API REST
- `https://builtwith.com/TARGET` — perfil tecnologico completo con historial
- `https://stackshare.io/` — tecnologias declaradas por empresas

**Cabeceras HTTP relevantes a inspeccionar:**
```
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.10
X-Generator: Drupal 8
```

## Contramedidas
- Eliminar o falsificar cabeceras `Server`, `X-Powered-By` y `X-Generator` en la configuración del servidor
- Deshabilitar cabeceras que revelan información de versión (ej: `ServerTokens Prod` en Apache)
- Usar un WAF o reverse proxy que normalice las cabeceras de respuesta
- Mantener software actualizado para que incluso si se detecta la versión no sea vulnerable

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1592.002: Gather Victim Host Information: Software. https://attack.mitre.org/techniques/T1592/002/
