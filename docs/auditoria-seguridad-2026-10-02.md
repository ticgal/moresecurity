# Auditoría de seguridad de More Security — 2 de octubre de 2026

**Resultado:** la versión local **2.2.1** incorpora correcciones de auditorías anteriores, pero mantiene huecos en la protección de autenticación y recuperación. Se identifican **3 hallazgos altos, 6 medios y 2 bajos**. La gravedad es cualitativa y depende de las condiciones descritas; no se ha calculado CVSS. No se debe considerar cerrada la auditoría por la anotación «Plugin audited and fixed» del changelog.

**Estado de la instancia:** en GLPI **11.0.9**, contenedores `glpi11.0.9` / `mariadb11.0.9`, puerto **8090**, el plugin **no figura registrado en `glpi_plugins` y no existen sus tablas**. `notifications_mailing=0` y `use_notifications=0`; existe una notificación activa de recuperación. En este entorno el plugin no proporciona protección. Las vulnerabilidades de sus controladores públicos requieren instalarlo y activarlo; las de recuperación requieren además habilitar el correo. No se instalaron componentes, no se modificaron usuarios ni configuración y no se enviaron correos.

## Alcance, método y límites

- Lectura íntegra de los 10 archivos PHP: `setup.php`, `hook.php`, tres controladores de `front/` y cinco clases de `inc/`; dos plantillas Twig, README, changelog, tres herramientas Bash y configuración de traducciones. No hay dependencias propias Composer/NPM, endpoints HL API, subidas de archivos ni llamadas HTTP salientes en el código de producción revisado.
- Contraste con el núcleo local: autenticación, sesión, MFA, recuperación de contraseña, constructor de criterios SQL, firewall, orden de inicialización del kernel, control CSRF, formularios Twig y JavaScript de envío.
- Consulta de solo lectura de Docker y MariaDB; GET HTTP de comprobación: `/index.php` responde 200 y los controladores de configuración/recuperación del plugin responden 404, coherente con su ausencia de instalación.
- Ejecución de los métodos reales del plugin y la abstracción SQL real de GLPI contra MariaDB, exclusivamente con **tablas TEMPORARY de nombres sintéticos**. Se usó `forceTable()` en el proceso de pruebas; el código original no cambió. Al cerrar la conexión desaparecen las tablas. Los datos de pruebas son identidades `.invalid` e IP reservadas para documentación.
- Prueba adicional del hook real con la clase `Session` real, identidad sintética y dobles de autenticación/contadores. Verifica las decisiones del gate y su llegada a autenticación, no concede una sesión ni constituye una explotación HTTP completa.
- La prueba de presupuesto concurrente reproduce un intercalado determinista de comprobaciones antes de finalizar los intentos. No es una prueba de carga HTTP ni demuestra cuántas peticiones simultáneas admite una instalación concreta.
- No se probaron el login HTTP con el plugin activo, perfiles reales gestionando su whitelist, SMTP, LDAP/SSO, MFA completo, instalación/actualización ni fallos de infraestructura. Esas verificaciones siguen pendientes y están definidas al final.
- Las conclusiones se refieren al código local. Las huellas SHA-256 de los 24 archivos originales permiten identificar exactamente la revisión, sin ejecutar comandos Git.

## Hallazgos abiertos

| ID | Gravedad | Hallazgo | Validación |
| --- | --- | --- | --- |
| MS-01 | Alta | Una sesión ya autenticada permite omitir el gate del login nativo | Hook real con sesión sintética y trazado del núcleo |
| MS-02 | Alta | Un email array altera criterios SQL y modifica contadores ajenos | Reproducido con GLPI y MariaDB reales, tablas temporales |
| MS-03 | Alta | Un ataque distribuido puede bloquear una cuenta hasta 2037 sin desbloqueo en la UI | Reproducido y revisión de interfaz |
| MS-04 | Media | La recuperación nativa evita el plugin y la recuperación del plugin no aplica presupuesto por IP | Trazado y prueba aislada de contadores |
| MS-05 | Media | Los contadores de recuperación pueden producir bloqueos sin caducidad | Reproducido |
| MS-06 | Media | Los incrementos atómicos no reservan el presupuesto; recuperación mantiene actualizaciones no atómicas | Intercalado determinista y revisión SQL |
| MS-07 | Media | El nuevo POST_INIT procesa el login antes del control CSRF | Hook real con autenticación simulada y trazado del kernel |
| MS-08 | Media | Datos de intentos sin retención y agregación en PHP permiten crecimiento sostenido | Revisión de inserciones, consultas y ciclo de vida |
| MS-09 | Media | El umbral de IP distintas depende de activar y alcanzar el límite de cuenta | Reproducido |
| MS-10 | Baja | Duración cero produce un bloqueo inefectivo aunque el umbral esté activo | Reproducido |
| MS-11 | Baja | Entradas no escalares o demasiado largas pueden causar errores no gestionados | Array de login reproducido; resto por trazado |

### MS-01 — Bypass del login nativo desde una sesión autenticada

**Referencias:** `hook.php:188-219`, especialmente `201-202`; `setup.php:78-79`; núcleo `front/login.php:66-75`, `src/Auth.php:798-826,1044-1058`, `src/Session.php:123-165`.

El gate devuelve inmediatamente el control si `Session::getLoginUserID()` tiene valor. Un POST a `/front/login.php` desde una sesión autenticada sigue por el login nativo, que comprueba las credenciales recibidas sin consultar `PluginMoresecurityLogin::checkLogin()` ni `PluginMoresecurityLoginip::checkIp()`. No se exige que la identidad solicitada sea la de la sesión existente. La corrección del bypass anónimo no cubre este caso.

**Condiciones e impacto:** un atacante con acceso a una cuenta de pocos privilegios puede intentar credenciales de otra cuenta por la ruta nativa, evitando los contadores y los bloqueos del plugin. Debe disponer de una sesión válida y el CSRF correspondiente. Si un fallo cambia el estado de la sesión, puede renovarla con su propia cuenta; se debe verificar este detalle en HTTP. Esto no evita la contraseña ni el MFA nativo de la cuenta objetivo.

**Evidencia:** el hook real devuelve sin llamar a autenticación cuando recibe una identidad sintética en `glpiID`; el mismo POST sin esa identidad sí llega al método de autenticación. La continuación por el login nativo se sustenta en el núcleo revisado, pendiente de la cadena HTTP completa.

**Corrección:** aplicar los presupuestos a todo intento explícito de credenciales, también al cambiar de identidad desde una sesión existente. Integrarlo en el ciclo de autenticación del servidor con control de CSRF y un resultado común de éxito/fallo; conservar las vías legítimas de MFA, cookies y SSO. No modificar GLPI core.

### MS-02 — Inyección de criterios por email array

**Referencias:** `front/lostpassword.form.php:57-67`; `inc/lostpassword.class.php:39-67,84-116`; núcleo `src/DBmysqlIterator.php:599-629` y construcción de `UPDATE` en `src/DBmysql.php`.

Se entrega `$_POST['email']` sin validar a `checkEmail()` y `addEmailTry()`. GLPI acepta arrays de dos posiciones como operadores de consulta. El cuerpo `email[0]=LIKE&email[1]=%` transforma `['email' => $email]` en `email LIKE '%'`, tanto al seleccionar como al actualizar. El valor se escapa, pero la **estructura** del criterio está controlada por el solicitante. No es ejecución de SQL arbitrario ni acceso a otras tablas.

**Impacto:** si la primera fila seleccionada permite el intento, una sola solicitud puede alterar contadores de múltiples direcciones. Puede bloquear colectivamente la recuperación o borrar bloqueos de otras direcciones al sobrescribir sus valores con los calculados a partir de la primera fila. La posterior llamada a `User::forgetPassword(string $email)` rechaza el array después de las escrituras, por lo que el error no protege los datos.

**Evidencia aislada:** dos emails sintéticos pasan de 0 a 1 con una llamada; al repetir alcanzan 3 y ambos quedan bloqueados. En otra prueba, una fila previamente bloqueada termina con contador 1 y `blocked=NULL` porque se seleccionó primero una fila libre.

**Corrección:** rechazar arrays y otros tipos antes de consultar o escribir; admitir únicamente un email escalar válido, con longitud acotada y una normalización coherente con GLPI. Reutilizar esa identidad validada en lectura y escritura. Actualizar por la clave exacta de la fila, sin aceptar operadores de criterios desde el request. Añadir pruebas de arrays, emails inválidos y ausencia de efectos secundarios.

### MS-03 — Bloqueo prolongado de cuenta sin recuperación administrativa

**Referencias:** `inc/login.class.php:122-150`, particularmente `143-146`; `inc/loginip.class.php:177-197`; `templates/forms/config.form.html.twig:39-137`; `README.md:45-48,77-83`.

Al superar el umbral de cuenta y alcanzar `ip_threshold`, el plugin sustituye cualquier demora o tope por `2037-12-31 23:59:59`. No existe una acción de desbloqueo ni un listado de bloqueos en los controladores/plantillas actuales. La comprobación del centinela `9999-12-31` es inconsistente con lo que se escribe, aunque el bloqueo de 2037 sí se aplica por ser una fecha futura.

**Condiciones e impacto:** con `ip_threshold>0` y protección de cuenta activa, un atacante capaz de distribuir fallos sobre una cuenta puede dejarla inaccesible durante años desde las IP no exentas. El README anuncia un botón de desbloqueo que no está implementado en esta revisión. La prueba obtiene exactamente la fecha de 2037.

**Corrección:** aplicar una duración acotada y recuperar el acceso por un procedimiento administrativo autenticado, autorizado y con CSRF, historial y confirmación de resultado. Si se mantiene un bloqueo permanente por diseño, representarlo explícitamente y entregar primero un mecanismo real de desbloqueo; no anunciarlo sin implementarlo.

### MS-04 — Recuperación sin cobertura uniforme ni presupuesto por IP

**Referencias:** `hook.php:81-99,188-219`; `front/lostpassword.form.php:57-67`; `inc/lostpassword.class.php:39-119`; núcleo `front/lostpassword.php:85-91` y `src/Glpi/Http/Firewall.php:211`.

La recuperación depende de sustituir un enlace con JavaScript. Un POST ordinario con `email` a `/front/lostpassword.php` llega directamente a `User::showForgetPassword()`. El nuevo gate solo observa `login_name`, de modo que no cubre ese flujo. En la ruta del plugin, `checkEmail()` y `addEmailTry()` tampoco consultan ni actualizan el presupuesto por IP, ni aplican la whitelist a ese presupuesto.

**Impacto:** se puede evitar el límite de recuperación del plugin usando la ruta original; desde su propia ruta se puede bloquear la recuperación de una dirección sin consumir ningún presupuesto de IP. La demora nativa y la validez criptográfica de los tokens no se eluden. El correo debe estar habilitado para alcanzar estas ramas.

**Evidencia:** tres solicitudes aisladas bloquean el email; la tabla temporal de IP sigue vacía. El README describe un presupuesto compartido para recuperación/login que este código no implementa.

**Corrección:** imponer la misma política en todas las rutas de solicitud de recuperación, validar el email y aplicar un presupuesto por IP antes de consumir el de dirección o emitir correo. No depender de reescritura DOM. Mantener la respuesta genérica del núcleo para evitar revelar existencia de cuentas.

### MS-05 — Bloqueos de recuperación sin caducidad

**Referencias:** `inc/lostpassword.class.php:50-64,84-115`; configuración `inc/config.class.php:147-208`.

Si `email_try>=attempts_reset` y `blocked=NULL`, `checkEmail()` devuelve `false` sin fijar caducidad ni reiniciar el estado. Se puede llegar a esa situación al acumular solicitudes con el límite desactivado y activarlo después, o al bajar un límite existente. A diferencia del login, la recuperación no tiene ventana de inactividad ni reconciliación del estado.

**Evidencia:** una fila sintética con contador 3, umbral 3 y `blocked=NULL` queda rechazada y conserva el bloqueo lógico sin fecha. Esperar no lo resuelve.

**Corrección:** reconciliar los contadores al cambiar configuración y en la comprobación del estado, aplicar una ventana explícita de intentos y garantizar una caducidad o desbloqueo autorizado para todo rechazo por umbral.

### MS-06 — Concurrencia resuelta parcialmente

**Referencias:** `hook.php:145-174`; `inc/login.class.php:39-93,187-225`; `inc/loginip.class.php:39-62,95-150`; `inc/lostpassword.class.php:44-67,87-119,140-147`.

Los upserts de login e IP solucionan la pérdida de incrementos y se apoyan en índices únicos definidos en el instalador. Sin embargo, comprobar permiso y contar el fallo siguen siendo fases separadas; no existe una reserva del presupuesto antes de autenticar. Solicitudes en curso pueden superar simultáneamente una comprobación previa al bloqueo. El cálculo y escritura de `blocked` también se realizan fuera del incremento atómico.

En recuperación permanece `SELECT → contador + 1 → UPDATE`, y el índice de email no es único. Persisten la posibilidad de perder incrementos y de crear duplicados bajo concurrencia.

**Evidencia:** un intercalado de 12 comprobaciones previas al registro de fallos admite las 12 con umbral 3. Al terminar, el contador real es 12 en una sola fila: el upsert funciona, pero el presupuesto no se reserva. No se ha medido este comportamiento mediante carga HTTP ni se ha reproducido pérdida concurrente del contador de email en el despliegue.

**Corrección:** reservar intentos mediante una operación atómica o un limitador con bloqueo, limitar solicitudes en curso y establecer el estado de bloqueo con una actualización consistente. Para email, fusionar duplicados antes de crear un índice único y usar incrementos atómicos. Verificar tanto admisión como exactitud de contadores bajo carga.

### MS-07 — El gate se ejecuta antes del control CSRF

**Referencias:** `hook.php:188-224,106-181`; núcleo `src/Plugin.php:424-434`, `src/Glpi/Kernel/Kernel.php:170-183`, `src/Glpi/Kernel/Listener/PostBootListener/InitializePlugins.php:67-73`, `src/Glpi/Kernel/Listener/ControllerListener/CheckCsrfListener.php:58-89`.

El POST_INIT se ejecuta al inicializar plugins durante el arranque del kernel. El control CSRF normal se ejecuta después, en el evento de selección del controlador. El hook autentica, modifica contadores o termina/redirige la petición antes de llegar a ese listener. No llama explícitamente a `Session::checkCSRF()`. `glpicookietest` solo confirma una cookie de sesión y no sustituye un token CSRF.

**Evidencia:** con cookie de prueba sintética y un POST sin `_glpi_csrf_token`, el hook real llega al doble de `Auth::login()`. La cadena no procesa el controlador ni su comprobación posterior. Esto es una regresión de la corrección del bypass anónimo.

**Impacto condicionado:** abre el procesamiento de login sin la garantía CSRF nativa, con riesgo de login CSRF y cambios de contadores inducidos desde un origen que pueda enviar la cookie. SameSite y las restricciones del navegador pueden reducir la explotación entre sitios; no se ha probado esa cadena web. No se ha demostrado una escritura administrativa sin CSRF.

**Corrección:** ejecutar la política de login después de la validación de sesión y CSRF, dentro de una integración de controlador/autenticación. Si temporalmente se conserva el hook temprano, verificar el token antes de cualquier autenticación o escritura, sin duplicar ni consumir indebidamente la validación posterior. Acotar el procesamiento a los flujos de autenticación previstos.

### MS-08 — Crecimiento de datos sin retención

**Referencias:** `inc/login.class.php:81-91,206-212`; `inc/loginip.class.php:111-119,157-197`; `inc/lostpassword.class.php:65-67,114-118`; `setup.php:56-81` y `hook.php`.

Se crean filas para nombres/emails proporcionados por el solicitante sin exigir que correspondan a usuarios. La ventana de 12 horas reduce qué intentos se consideran, pero no elimina filas. No hay acción automática de limpieza, retención ni límite de cardinalidad. Las sumas por IP y recuentos de IP distintas cargan resultados en PHP.

**Impacto condicionado:** ataques prolongados con identidades nuevas, especialmente con límites desactivados o múltiples IP, aumentan datos, índices, trabajo de consulta y memoria hasta degradar disponibilidad. No se ha hecho una prueba de agotamiento ni estimado un volumen explotable en este servidor.

**Corrección:** establecer retención, limpieza periódica por lotes con índices adecuados y agregación `SUM`/`COUNT(DISTINCT)` en la base de datos; limitar nuevas identidades por IP y el volumen de datos sin perder los bloqueos válidos ni revelar cuentas existentes.

### MS-09 — La detección distribuida depende del umbral de cuenta

**Referencias:** `inc/login.class.php:219-223,143-146`; `README.md:45-48`.

`ip_threshold` se evalúa únicamente dentro de `computeBlockedUntil()`, que solo se llama al alcanzar un `number_attempts` efectivo mayor que cero. Desactivar el contador de cuenta desactiva también esta detección, aunque `ip_threshold` siga configurado. Si el umbral de cuenta es grande, alcanzar solo el umbral de IP distintas tampoco basta.

**Evidencia:** con `number_attempts=0`, `ip_max_attempts=0`, `ip_threshold=2` y dos IP distintas, el contador devuelve 2 pero la cuenta continúa permitida y `blocked=NULL`.

**Corrección:** evaluar por separado los controles que la UI documente como independientes y aplicar bloqueos acotados con recuperación. Si la dependencia es intencionada, validar esa configuración e indicarla con claridad en la UI y README.

### MS-10 — Duraciones cero inefectivas

**Referencias:** `inc/config.class.php:161-164,215-222`; `inc/login.class.php:125-141,49-64`; `inc/loginip.class.php:133-145`; `inc/lostpassword.class.php:99-102`.

La validación admite cero para `time_blocked`, `ip_time_blocked` y `time_reset`. Con un umbral activo, la fecha de bloqueo calculada puede ser la hora actual; la siguiente comprobación la trata como expirada. La prueba obtiene `allowed=true` después de alcanzar el umbral con `time_blocked=0`.

Requiere una configuración administrativa incoherente, no permite a un usuario anónimo cambiar las duraciones. **Corrección:** imponer una duración mínima positiva para bloqueos activos y distinguir los campos en los que cero significa un tope desactivado.

### MS-11 — Validación incompleta de tipos y longitudes

**Referencias:** `hook.php:112-138,165`; `inc/login.class.php:89,206-212`; `inc/lostpassword.class.php:44-67`; columnas `varchar(255)` en los instaladores.

`login_name` array supera `isset()` y la comparación con cadena vacía, pero `trim()` lanza un `TypeError`. Otras entradas como `redirect`, contraseña o fuente de autenticación carecen de validación escalar explícita. Identidades mayores que el tamaño de columna pueden provocar excepciones SQL, dependiendo del modo SQL; esto último no se explotó en HTTP.

**Impacto:** errores por petición malformada y posible ruido en logs/consumo de recursos. No se ha probado un DoS global por esta causa. El email array con escrituras colectivas tiene gravedad propia en MS-02.

**Corrección:** rechazar tipos inválidos, acotar longitudes antes de consultar y rechazar el login vacío después de normalizarlo. Devolver un error controlado sin efectos secundarios ni detalles SQL.

## Comprobación de auditorías anteriores

Se encontró el informe físico del **10/09/2026**, versión 2.2.0, en `/home/aaron/glpi_carm_latest/glpi/plugins/moresecurity/docs/plans/01-security-audit-2026-09-10.md`. También se recuperaron del historial local las conclusiones de una segunda revisión más extensa y sus verificaciones estáticas/UI. Estas últimas se conservan en la sesión `/home/aaron/.claude/projects/-home-aaron-glpi-carm-latest-glpi/c23f5840-4d56-4f1e-b3d7-b4cf8f74fcb4/`, en particular `subagents/agent-a5c4c6f5a9f80fd46.jsonl`, `agent-ae51e8e5e3f0728e6.jsonl`, `agent-afbdb8f5fdb0f1a53.jsonl` y `agent-ada77e4e9a8e481cb.jsonl`. No se encontró el segundo informe íntegro como archivo independiente. Las pruebas históricas pertenecen a **otra instancia** y no se presentan como ejecutadas hoy.

| Hallazgo anterior | Estado en la revisión actual | Comprobación |
| --- | --- | --- |
| SEV-01 / H08: whitelist con derecho `dropdown` | **Corregido en código** | `$rightname='config'`; creación/purga delegan en `canUpdate()`; gestión con perfiles reales pendiente |
| H01: rutas nativas eluden el plugin | **Parcial** | POST_INIT cubre credenciales anónimas; persisten sesión autenticada y recuperación, MS-01/MS-04 |
| H02: email array como operador SQL | **Pendiente** | MS-02, reproducción real con tablas temporales |
| H03: formulario de configuración sin destino | **Falso positivo anterior** | El parcial core usa `params['target'] ?? item.getFormURL()`; ya refutado históricamente en UI y confirmado por el núcleo actual |
| H04: login sin `trim()` | **Corregido en código** | El contador y `Auth::login()` reciben el mismo login normalizado en `hook.php:129` |
| H05: cambio de umbral bloquea sin caducidad | **Parcial** | Login ahora reconcilia y fija `blocked`; email no, MS-05 |
| H06: bloqueo distribuido hasta 2037 | **Pendiente** | MS-03; no hay interfaz de desbloqueo |
| H07: éxito borra todos los contadores de la IP | **Corregido** | Se limpia solo `(login, ip)`; prueba conserva el contador de otra cuenta |
| H09 / UC-10: concurrencia y duplicados | **Parcial** | Upsert/índice único en login/IP; presupuesto sin reserva y email no atómico, MS-06; esquema desplegado no verificable porque no está instalado |
| H10 / UC-02: GET sin credenciales cuenta fallos | **Corregido en código** | `process_login()` exige POST y campos no vacíos antes de consultar; permanece validación incompleta de tipos, MS-11 |
| H11: completar MFA no limpia los contadores | **Pendiente en integración** | `Auth::login()` redirige antes de retornar; MFA vuelve a `/front/login.php` sin credenciales POST y no ejecuta la limpieza del plugin |
| H12: IP de proxy usada como cliente | **Pendiente, condicionado al despliegue** | Se usa `REMOTE_ADDR`; no existe resolución de proxies confiables |
| H13: crecimiento y agregación en PHP | **Pendiente** | MS-08 |
| H14 / UC-06: configuración sin límites de servidor | **Corregido en lo principal** | Clamp de tipos/rangos y duración máxima de un año; pruebas de negativos, arrays y valores grandes. Duración cero sigue siendo MS-10 |
| H15: añadir UNIQUE login/IP sin fusionar duplicados | **Pendiente, condicionado a datos legacy** | `loginip::install()` añade el índice sin deduplicar; `login::install()` sí fusiona duplicados |
| H16: `exit()` / respuesta manual de legacy | **Persiste como observación** | No se demuestra por sí solo una vulnerabilidad; el gate temprano sí introduce MS-07 |
| A3a / UC-07: IP/CIDR/IPv6 inválidos o inertes | **Corregido** | Normalización, comparación binaria y CIDR; pruebas IPv6, CIDR y rechazo entre familias |
| A3a / UC-08: whitelist alimenta bloqueo de cuenta | **Corregido en código** | Los fallos exentos no llaman a `addLoginTry()` en `hook.php:172-174` |
| UC-03/backoff: al expirar se reinicia y no escala | **Corregido** | Solo se limpia `blocked`; prueba pasa de 6 a 7 fallos con demora de 600 segundos |
| UC-06: overflow TIMESTAMP del backoff | **Corregido en código actual** | Tope previo al formateo hasta 2037 y límite de duración; no se probó actualización legacy ni fallo SQL real |
| UC-11 / O07: no se auditan umbrales | **Parcial** | Ahora llama a `Log::history()`; no hay log específico de bloqueos, desbloqueos o exenciones |
| O01/O02/C-01/C-02: clases legacy, hook CSRF y variables muertas | **Persisten** | Deuda técnica/limpieza, no vulnerabilidades independientes |
| O05: empaquetado desde directorio equivocado | **Corregido en código** | La herramienta cambia al directorio del plugin antes de exportar; no se ejecutó un release |

Las auditorías anteriores no justifican considerar limpio el plugin: la primera pasó por alto la inyección de criterios y varios bypass. Su conclusión general sobre CSRF precede al POST_INIT actual y no cubre la regresión MS-07.

## Observaciones adicionales y comprobaciones sin hallazgos

- **README desalineado:** anuncia proxies confiables, geobloqueo DB-IP, actualización mensual, ventana configurable y listados/botones de desbloqueo ausentes del código actual. El campo `whitelisted_ips` es residual y no se consulta; la whitelist efectiva está en su propia tabla. No se deben dar por activos esos controles. Los límites de cuenta, IP y recuperación se crean en **0**, desactivados por defecto.
- **Proxy y whitelist:** `REMOTE_ADDR` no confía en cabeceras aportadas por el cliente, por lo que no se identifica un bypass por falsificar X-Forwarded-For. Detrás de un proxy compartido, todos pueden consumir el mismo presupuesto. Si se incluye la IP del proxy en la whitelist, todos sus clientes quedan exentos del gate de cuenta e IP. Requiere inspeccionar la topología concreta antes de diseñar resolución de IP basada en proxies confiables.
- **MFA nativo:** sigue delegado a `Auth::login()`. No se encontró una omisión directa de su segundo factor en este plugin. La limpieza de contadores tras MFA no está integrada; la coexistencia con plugins que reescriben el login debe probarse explícitamente.
- **Mezcla de tiempos, nueva respecto al informe previo:** los upserts actuales escriben `last_try` con SQL `NOW()`, mientras la suma por IP usa un corte calculado con PHP `date()`. En el CLI del contenedor, PHP reportó `12:38` y SQL `10:38`, ambos anunciando UTC; una fila creada con `NOW()-11h` quedó fuera de la ventana declarada de 12h. Esto reproduce un fallo bajo ese desfase, pero **no demuestra el mismo estado en una petición web activa** ni atribuye su origen exclusivamente al plugin. La revisión histórica que descartó el desfase se basaba en código sin `NOW()`. Unificar referencias temporales y verificarlo en HTTP antes de cerrar esa observación.
- **Autorización administrativa:** `front/config.form.php` comprueba instalación/activación, exige `config UPDATE` y verifica el objeto antes de actualizar. La whitelist exige el mismo derecho. Son controles globales por diseño; no se encontró un IDOR por entidad en estas tablas.
- **CSRF de formularios:** recuperación incorpora token explícito; configuración lo hereda del parcial core `buttons.html.twig:196`. `STRATEGY_NO_CHECK` del firewall permite acceso anónimo y no equivale a desactivar CSRF. Esta comprobación favorable no subsana el flujo temprano de MS-07.
- **Formulario y JavaScript:** el `target` de configuración tiene fallback válido. En este `public/js/common.js`, `data-submit-once` bloquea envíos repetidos y no convierte por sí solo el formulario en `fetch`; no se atribuye aquí el spinner AJAX descrito de forma genérica en la skill. El HTML de los botones de recuperación conserva un `<span>` sin cierre correcto, defecto menor.
- **XSS:** no se encontró una entrada de usuario que llegue sin escape a las plantillas. `|raw` se usa para markup formado por literales/traducciones. El script de login utiliza escape HTML dentro de cadenas JavaScript: conviene usar serialización JSON para ese contexto, pero no se demostró explotación porque las URLs proceden de configuración de servidor, no del solicitante.
- **SQL escalar:** los nuevos upserts escapan nombre de tabla y valores. Una cadena con comillas y `OR` se almacenó literalmente en una sola fila temporal. Esta comprobación no exculpa la inyección estructural de MS-02.
- **RCE/SSRF/archivos/secretos:** sin `eval`, deserialización no confiable, ejecución de comandos, URLs salientes, subidas o rutas construidas desde el request en el código de producción. Los includes de instalación usan el directorio local del plugin. No se detectaron contraseñas embebidas ni almacenamiento de contraseñas de login en sus tablas. Login, email e IP son datos personales y requieren una política de conservación.
- **Compatibilidad:** las clases siguen en `inc/` y no en `src/` con PSR-4; no es por sí solo una vulnerabilidad. No se introducen ni aparecen los helpers de URL GLPI 10 deprecados. El hook `csrf_compliant` es residual en GLPI 11. No hay assets externos propios que deban trasladarse a `public/`.
- **Herramientas Bash:** sintaxis válida. Son herramientas de desarrollo, no superficie web por diseño. Se recomienda endurecer comillas y directorios temporales predecibles; no se ejecutaron empaquetados, borrados, instalaciones de dependencias ni comandos Git contenidos en ellas.
- **Avisos externos:** se intentó consultar las páginas de advisories/releases del GitHub oficial `ticgal/moresecurity`; la herramienta no pudo recuperarlas. Esta auditoría no afirma que no existan CVE ni que otras revisiones públicas estén corregidas.

## Evidencia y validación realizada

En [security-audit-2026-10-02/](security-audit-2026-10-02/) se conservan:

- [Resultados JSON](security-audit-2026-10-02/results.json): métodos reales, SQL real y **18 aserciones satisfechas**. Que una aserción pase puede significar que se reprodujo una vulnerabilidad, no que el comportamiento sea seguro.
- [Resultados del gate](security-audit-2026-10-02/gate-results.txt): omisión con sesión, llegada a autenticación sin CSRF y `TypeError` de login array.
- [Prueba SQL aislada](security-audit-2026-10-02/verify-isolated.php.txt) y [prueba del gate](security-audit-2026-10-02/verify-gate.php.txt), almacenadas como texto, no como entrypoints ejecutables del plugin.
- [Huellas SHA-256 del código original](security-audit-2026-10-02/source-sha256.json).

Sintaxis verificada: **10/10 PHP**, **2/2 Twig** parseadas con el Twig del contenedor, JavaScript embebido con `node --check` y **3/3 Bash** con `bash -n`. El parseo Twig no valida renderizado ni permisos en UI.

Para repetir las pruebas desde este workspace, detectar primero los contenedores y confirmar el entorno. En el entorno autorizado hoy:

```bash
docker exec -i glpi11.0.9 php < plugins/moresecurity/docs/security-audit-2026-10-02/verify-isolated.php.txt
docker exec -i glpi11.0.9 php < plugins/moresecurity/docs/security-audit-2026-10-02/verify-gate.php.txt
```

Los scripts exigen CLI. El primero usa únicamente tablas temporales con nombres sintéticos; el segundo no accede a la base de datos. No instalar ni activar el plugin es parte del procedimiento usado en esta auditoría.

## Orden de corrección y aceptación pendiente

1. **Antes de considerar el plugin una barrera fiable:** corregir MS-02, cerrar MS-01 y MS-04 con una integración común, eliminar MS-07 sin reabrir los bypass, y proporcionar recuperación administrativa para MS-03.
2. Reconciliar caducidad de recuperación, reservar presupuesto concurrente y hacer atómica la persistencia de email. Corregir la dependencia de MS-09 y las duraciones cero.
3. Añadir retención, agregación SQL y validación de entrada; alinear README, resolver proxies y tiempos según el despliegue, integrar limpieza después de MFA y verificar la migración de índices con duplicados legacy.

En una instalación de pruebas **activa**, con cuentas y correo de pruebas, la aceptación debe comprobar:

- El mismo bloqueo al usar rutas nativas y del plugin, desde sesión anónima y desde una cuenta de pocos privilegios intentando otra identidad. Un login correcto sigue funcionando y exige el MFA configurado.
- Rechazo de POST sin token o con token inválido antes de autenticar o tocar contadores; cookies y SameSite en el navegador objetivo.
- Email array/malformado rechazado sin cambios en ninguna fila; recuperación limitada por IP y email en ambas rutas, sin revelar existencia de usuario.
- Límites bajo carga concurrente: admisión y contadores consistentes, sin filas duplicadas ni errores 500, incluyendo cambios de umbral y expiración durante la carga.
- Bloqueos temporales que expiran, bloqueos administrativos que se pueden retirar con permisos y CSRF, y limpieza después de MFA sin borrar señales de otras cuentas.
- Perfil con `dropdown` y sin `config` incapaz de crear/editar/purgar whitelist; perfil autorizado capaz de hacerlo con IP, IPv6 y CIDR válidos.
- Upgrade con duplicados legacy, acción de retención, uso de IP real tras proxies confiables y ventanas iguales al comparar reloj PHP/SQL.

**Trabajo realizado:** auditoría, recuperación de evidencia histórica, comprobaciones aisladas y documentación. **No se han aplicado parches funcionales ni cambiado la instalación**; los puntos anteriores son el alcance de remediación pendiente.
