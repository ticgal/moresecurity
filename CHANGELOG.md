# Changelog

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