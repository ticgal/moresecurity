# Remediación de la auditoría del 2 de octubre de 2026 (versión 2.2.2-beta.1)

Todos los hallazgos abiertos (MS-01 a MS-11) y los pendientes de la tabla de auditorías anteriores
están corregidos en el código y cubiertos por pruebas que **fallan con el código de 2.2.1 y pasan
con 2.2.2** (se ejecutaron ambas versiones sobre el mismo entorno).

| ID | Corrección |
| --- | --- |
| MS-01 | `plugin_moresecurity_enforce_login_gate()` ya no sale si hay sesión: cualquier POST de credenciales pasa por la política. |
| MS-02 | Los emails se validan antes de tocar la BD (`PluginMoresecurityLimiter::cleanEmail()`); `reserve()` está tipado a `string` y actualiza por clave exacta. |
| MS-03 | Sin fecha centinela de 2037: el bloqueo distribuido dura `max_time_blocked` (1 día por defecto, tope 1 año). Pestaña de configuración con listado y botón **Unblock** (derecho `config` UPDATE, CSRF nativo, historial). Los bloqueos heredados > 1 año se recortan al actualizar. |
| MS-04 | La política se aplica a `/front/lostpassword.php` y a la ruta del plugin desde el gate; presupuesto por IP compartido con el login (`ip_max_attempts`) y por email. |
| MS-05 | Ventana de inactividad (`last_try`) y reconciliación: contador ≥ umbral sin `blocked` fija caducidad y rechaza. |
| MS-06 | Reserva atómica del presupuesto antes de autenticar (exclusión mutua `GET_LOCK` por login/IP/email + upserts); email con índice `UNIQUE` y duplicados fusionados en la migración. |
| MS-07 | El gate exige un token CSRF válido antes de autenticar o escribir contadores; sin token no hace nada y el control nativo responde 403. En recuperación el token no se consume. |
| MS-08 | Acción automática diaria `Purge` (retención 7 días, por lotes), suma/recuento en SQL, no se almacenan filas con la protección desactivada y tope de 100 identidades por IP y ventana. |
| MS-09 | El umbral de IP distintas se evalúa con independencia del umbral de cuenta. |
| MS-10 | `time_blocked`, `ip_time_blocked` y `time_reset` ≥ 1 s (config y ejecución); los `max_*` admiten 0 = sin tope. |
| MS-11 | Tipo escalar, longitud ≤ 255 (contraseña ≤ 4096) y sin NUL antes de consultar; error 400 controlado. |
| H11 | Contraseña correcta pendiente de MFA libera el contador. |
| Reloj | Todas las comparaciones y fechas de bloqueo se calculan con `NOW()` de SQL. |
| H15 | `loginip::install()` fusiona duplicados antes de crear el `UNIQUE`. |
| README | Alineado con lo implementado (sin geobloqueo ni proxies de confianza). |

Además se corrige el error 500 de la pestaña de configuración con `strict_variables` (`params` no definido
en `buttons.html.twig`), y el script de login emite las URL con `json_encode`.

## Pruebas (en `docs/security-audit-2026-10-02/regression/`, como texto)

- `unit.php.txt`: 44 comprobaciones contra las tablas reales (concurrencia con 20 procesos, backoff, bloqueos,
  validación, retención, migración con duplicados). `podman exec -u www-data glpi_1109 php < unit.php.txt`
  (ajustar rutas a `/var/www/glpi` y `/var/glpi/config`).
- `http_tests.py.txt`: 34 comprobaciones HTTP reales (CSRF, sesión autenticada, recuperación nativa y del plugin,
  whitelist, desbloqueo con y sin CSRF, usuario sin derechos).
- `mfa_test.py.txt` + `mfa_helper.php.txt`: 6 comprobaciones con un usuario con TOTP real.

Limitaciones: no se probaron SMTP real, LDAP/SSO ni carga HTTP masiva; la concurrencia se verificó con 20
procesos PHP simultáneos contra la misma base de datos. Detrás de un proxy inverso todos los clientes comparten
presupuesto (se usa `REMOTE_ADDR`), como indica el README.
