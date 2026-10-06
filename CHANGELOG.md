# Changelog

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