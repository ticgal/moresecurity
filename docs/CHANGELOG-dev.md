# Changelog (dev)
<!-- changelog-format: 2 -->

## [2.3.2-dev] - 2026-11-09
*Working version: 2.3.2-beta.1*
### Bugs
- Security review 30/10/2026 (`docs/findings/2026-10-30-auditoria-seguridad.md`), all four findings reproduced against the running plugin before fixing:
  - **#1 MEDIUM / #2 LOW (`hook.php`, `plugin_moresecurity_enforce_login_gate()`):** the CalDAV gate only ran for `#/caldav\.php(/|$)#`, but core routes every `/caldav.php*` path to `CaldavController` (route requirement `.*`) and treats it as stateless (`SessionManager::isResourceStateless()`, `str_starts_with`). Sabre verifies Basic credentials (`Auth\Plugin`, priority 10) before resolving the path (`DAVACL`, priority 20), so `/caldav.phpX` and `/caldav.php.ics` were a password oracle with no counter, lockout, IP block, geoblock or log row (locked account: canonical path 429, suffixed paths 401 on every try, `login_try` unchanged). The gate now triggers on `str_starts_with($relative, '/caldav.php')`, where `$relative` is the path with `root_doc` stripped. Geoblocking is fixed by the same change: `isAllowed()` is only called inside the CalDAV gate and `process_login()`.
  - **#3 LOW (`hook.php`, recovery branch):** the branch checked the `passwordforget` notification for every route, but core `front/initpassword.php` depends on `passwordinit`. With `passwordforget` disabled and `passwordinit` enabled the route was ungated (every POST rotated the token, `email_try` stayed 0). The event is now chosen per route: `passwordinit` for `front/initpassword.php`, `passwordforget` for `front/lostpassword.php` and the plugin's `lostpassword.form.php`.
  - **#4 LOW (`hook.php`, recovery branch):** when the body CSRF token was invalid the gate returned to the controller, and core's `CheckCsrfListener` accepts an XHR POST whose token is only in `X-Glpi-Csrf-Token` and does not consume it (`preserve_token: true`). One token therefore sufficed for unlimited reset requests with no per-email or per-IP budget. The branch now denies with 403 (same as the login branch), so the body token is mandatory on covered routes.
- PHPStan (`theCodingMachineSafe.function`): the CalDAV gate's `Authorization` decoding uses `Safe\base64_decode()` and treats a malformed header as "no user" (same result as the previous `false`).

### Verification
- Live test on `glpi_1109` (GLPI 11.0.9) with a throwaway `@example.com` user, wrong passwords only, notification queue cron stopped and `use_notifications` left at 0 (queue unchanged, 190 pending):
  - CalDAV `/caldav.phpX`, `/caldav.php.ics`, `/caldav.php/`, `/caldav.php`: `401 401 401 429 429`, `login_try=3` on all four.
  - Reset with the token only in the header (XHR): 403, `email_try=0`, `password_forget_token_date` stays NULL. With the token in the body: 200, `email_try=1`.
  - `initpassword.php` with `passwordforget` disabled: `email_try` 1, 2.
- Podman CI preflight (`glpi-plugin-podman-ci-preflight`): everything passes except the PHPStan error above, which pre-dated these changes (`hook.php:267` in 2.3.1).

### Not changed (findings report, "Quality")
- CalDAV failures are still not written to the security log; `$PLUGIN_HOOKS['csrf_compliant']` remains declarative.
