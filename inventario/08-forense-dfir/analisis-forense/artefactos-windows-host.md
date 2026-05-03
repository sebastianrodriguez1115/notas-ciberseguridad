---
title: Análisis Forense: Artefactos de Windows
slug: artefactos-windows-host
aliases: ["Análisis Forense: Artefactos de Windows"]
fase: [Forense y DFIR]
plataforma: Windows
dificultad: Intermedia
mitre: []
related: []
learning_refs: []
---

# Análisis Forense: Artefactos de Windows

## Descripción
El análisis forense en hosts Windows se basa en la identificación y examen de "artefactos", que son huellas digitales dejadas por el sistema operativo y las aplicaciones tras la actividad del usuario o un atacante. Estos artefactos permiten reconstruir una línea de tiempo (timeline) de los eventos, identificar qué programas se ejecutaron, qué archivos se abrieron y qué dispositivos se conectaron.

## Artefactos Críticos de Ejecución

| Artefacto | Ubicación / Origen | Información que Proporciona |
| :--- | :--- | :--- |
| **Prefetch** | `C:\Windows\Prefetch` | Nombre del ejecutable, número de ejecuciones, última vez que se corrió y archivos cargados. |
| **ShimCache** | Registro: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Lista de ejecutables que han estado en el sistema (incluso si no se corrieron). |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Detalles del ejecutable (tamaño, hash SHA-1, fecha de instalación). |
| **UserAssist** | Registro: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Programas ejecutados mediante la interfaz gráfica (GUI) por un usuario específico. |

## Artefactos de Archivos y Carpetas

| Artefacto | Ubicación / Origen | Información que Proporciona |
| :--- | :--- | :--- |
| **LNK Files** | `%AppData%\Microsoft\Windows\Recent` | Accesos directos creados automáticamente; muestran la ruta original de archivos abiertos. |
| **Jump Lists** | `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations` | Archivos recientemente abiertos por aplicación (ej. documentos recientes en Word). |
| **Shellbags** | Registro: `UsrClass.dat` | Historial de carpetas visitadas por el usuario, incluso si la carpeta ya no existe. |

## Herramientas de Análisis

- **Eric Zimmerman's Tools** — Suite de herramientas (PECmd, JLECmd, ShellBagsExplorer) considerada el estándar de la industria para parsear estos artefactos.
- **Autopsy** — Plataforma forense de código abierto que integra múltiples módulos de análisis.
- **FTK Imager** — Herramienta para la adquisición de imágenes de disco y memoria de forma segura (read-only).
- **Registry Explorer** — Visor avanzado para navegar por las colmenas (hives) del registro de Windows.

## Ejemplo de Análisis de Prefetch con PECmd
```bash
# Analizar todos los archivos Prefetch y generar un CSV con los resultados
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Análisis\Prefetch_Resultados.csv"
# Resultado: Un archivo detallado con nombres de archivos ejecutados y timestamps.
```

## Contramedidas (Anti-Forensics)
- Uso de herramientas de limpieza de artefactos (ej. BleachBit) o ejecución de malware "fileless" en memoria.
- Timestomping (modificación de marcas de tiempo de archivos) para evadir la creación de timelines precisas.

## Referencias
- Johansen, G. (2017). *Digital Forensics and Incident Response*. Packt Publishing.
- Luttgens, J., Pepe, M., & Hollebeek, K. (2014). *Incident Response & Computer Forensics* (3rd ed.). McGraw-Hill Education.
- Anson, S., Bunting, S., Johnson, R., & Pearson, A. (2020). *Mastering Windows Network Forensics and Investigation*. Sybex.
- MITRE Corporation. (2024). ATT&CK Matrix for Enterprise: Forensics. https://attack.mitre.org/matrices/enterprise/
