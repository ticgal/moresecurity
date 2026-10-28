# Changelog

## 2.3.1 - 21/10/2026
### Bugfix
- Security review 21/10/2026: CalDAV Basic logins and `/front/initpassword.php` are now covered by the attempt/IP budgets and geoblocking
- A login POST with an invalid body CSRF token is denied (403) instead of reaching core, which accepted the header token and skipped geoblocking
- Per-IP overflow no longer disables the account lockout for logins without a row
- X-Forwarded-For: an entry that is not a bare IP (`ip:port`) now falls back to the proxy address instead of trusting the client-written part; IPv4-mapped IPv6 addresses are counted and whitelisted as IPv4
- Runtime reads and updates of the counters use the GLPI query builder (`$DB->request()` / `$DB->update()`); raw SQL remains only for `GET_LOCK` and the atomic upserts; installers throw instead of `die()`
- Security log: the per-IP row cap and the geoblock de-duplication key on the /64 prefix for IPv6; `AttemptLog::canCreate()` returns false
- Trusted proxies are compared in canonical IP notation (IPv6 written in any form matches)
- "Only allow these countries" with no country cannot be saved (geoblocking stays disabled with a warning)
- The `updatedb` automatic action makes no outbound request while geoblocking is disabled and a database is already present

## 2.3.0 - 19/10/2026
### Features
- Geoblocking: allow or deny logins by country, using DB-IP's free Lite database (monthly automatic action to refresh it)
- Trusted reverse proxy IPs: the real client IP is taken from X-Forwarded-For only when the request comes from one of them
- Security log page under Administration (per-attempt log and per-account/IP summary) with a dedicated read-only profile right
- Dashboard cards for top attacking IPs, most targeted accounts and top offending countries, plus a default "More Security" dashboard
- Bulk unblock (selected / all) of accounts, IPs and password reset requests
- "Active blocks" card in the configuration tab: a single always-visible table (type, user, login, email, IP, blocked at, remaining) with column filters, sorting and pagination; "Unlock all" applies only to the filtered rows
- Automatic action purging old Security log entries daily (retention parameter, 30 days by default); at most 200 log entries per IP and hour
### Bugfix
- The configuration tab warns when the REST API accepts login with credentials, a path this plugin does not protect
- IPv6 addresses are counted per /64 prefix (IP blocking and distinct-IP detection could be evaded or abused by rotating addresses)
- Login/reset counters no longer print the SQL error to anonymous clients if a write fails
- Dashboard cards without data: "Top offending countries" no longer raises `Undefined array key "series"`, every card keeps its title and the "No data found" notice is smaller and muted
- Dashboard card labels drop markup characters from attacker-supplied login names
- GeoIP database update hardened: capped download, unique temporary files and the new file is validated as a country database before replacing the current one
- Locale catalogues regenerated: most plugin strings were missing from the Spanish translation

## 2.2.2 - 05/10/2026
### Bugfix
- Security audit 02/10/2026 (MS-01 to MS-11): login policy now also applies to authenticated sessions and runs only after a valid CSRF token
- Password reset: same policy (validation, per-IP and per-email budget) on the native and plugin routes; rejects non-scalar/invalid emails
- Attempts are reserved atomically before authenticating (no more concurrent over-budget); MFA-pending logins release the counter
- Blocks are always bounded and recoverable (no more 2037 lock); administrators can unblock accounts, IPs and password reset requests from the configuration tab
- Distributed attack detection is independent from the account threshold; zero block durations are rejected
- New daily automatic action purging old attempt records; unique email index and inactivity window for password reset counters
- README aligned with the implemented features

## 2.2.1 - 11/09/2026
### Bugfix
- Plugin audited and fixed.

## 2.2.0 - 08/09/2026
### Features
- Deletes tables upon uninstall
### Bugfix
- Fixed user block by login attempts
- Fixed safety risks

## 2.1.0 - 19/05/2026
### Features
- Time window for failed login attempts to prevent unlimited accumulation
- IP-based attack tracking with temporary IP blocking
- Whitelisted IPs support
- IP threshold: permanent user lockout when too many distinct IPs fail login

## 2.0.0 - 29/04/2026
### Features
- GLPI 11 Support

## 1.0.0 - 19/07/2024
### Features
- Limit login attempts 
- Limit password reset attempts