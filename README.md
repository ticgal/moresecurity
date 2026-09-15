# More Security

[![License](https://img.shields.io/badge/License-GNU%20AGPLv3-blue.svg?style=flat-square)](https://github.com/ticgal/moresecurity/blob/master/LICENSE)
[![X](https://img.shields.io/twitter/follow/ticgalcom?style=flat-square&logo=x&label=Follow)](https://twitter.com/ticgalcom)
[![Web](https://img.shields.io/badge/Web-TICGAL-blue.svg?style=flat-square)](https://tic.gal/)
[![Localazy](https://img.shields.io/badge/Translate-Localazy-cyan)](https://localazy.com/p/moresecurity#translations)
[![Manual](https://img.shields.io/badge/Manual-docs.tic.gal-blue.svg?style=flat-square)](https://docs.tic.gal/books/more-security)
[![Marketplace](https://img.shields.io/badge/GLPI-Marketplace-orange.svg?style=flat-square)](https://plugins.glpi-project.org/#/plugins/moresecurity)

Adds brute-force protection to the GLPI login and password-reset forms.
### Setup
Install it like any other GLPI plugin from Marketplace, or download and install it in the plugin folder.
### How to use
Once activated, More Security automatically protects the login and "forgotten password" forms — no
extra action is needed from end users. Administrators configure the thresholds from the plugin's
**More Security** tab on the GLPI **Setup > General** configuration page.
### Additional features
- Limit the number of failed login attempts per account, with a configurable temporary block
- Limit the number of password reset attempts per email address, with a configurable temporary block
- Per-IP attempt tracking with temporary IP blocking, independent of the per-account block
- IP whitelist to exempt trusted networks from IP-based blocking
- Distributed attack detection: blocks an account when failed attempts come from too many distinct IPs
- Geoblocking: allow or deny logins by the country the client IP resolves to

### Configuration options
All settings live on the **More Security** tab of **Setup > General**. A value of `0` on any
attempt-count field disables that particular protection.

#### Login attempts
- **Number of attempts (0 = disabled)** — how many failed logins an account can have before it's
  blocked.
- **Access time blocked** — how long the account stays blocked once it runs out of attempts. Pick
  a fixed duration (5 minutes up to 1 day), or **Permanent**, which never expires on its own and
  needs an admin to unblock it manually (see "Permanent blocks" below).
- **Attempt counter reset window** — if this much time passes since the last failed attempt
  without hitting the limit, the attempt counter resets to zero instead of continuing to
  accumulate.

#### IP blocking
- **Trusted reverse proxy IPs (comma-separated)** — only needed if GLPI sits behind a reverse
  proxy or load balancer. The `X-Forwarded-For` header is trusted only when the direct connection
  comes from one of these IPs, e.g. `10.0.0.1,10.0.0.2`; leave empty to always use the direct
  connection IP.
- **Max attempts per IP (0 = disabled)** — how many failed attempts from a single IP — against any
  account for logins, or across any email address for password resets — can happen before that IP
  itself is blocked, independent of the per-account/per-email block above. One shared policy
  covers both login and password-reset abuse from that IP.
- **IP threshold (0 = disabled)** — distributed-attack protection: if failed logins for the same
  account come from at least this many distinct IPs (within the reset window), the account is
  permanently blocked, regardless of the "Number of attempts" setting. This block is always
  permanent and always needs a manual unblock.
- **IP block duration** — how long a blocked IP stays blocked (same duration choices as "Access
  time blocked", including **Permanent**), whether it was blocked for login or password-reset
  abuse.

#### Password reset attempts
- **Attempts for Password Reset (0 = disabled)** — how many password reset requests a given email
  address can make before access is blocked.
- **Access time blocked for Password Reset** — how long password-reset access stays blocked once
  it runs out of attempts (same duration choices, including **Permanent**).

Password-reset requests from a single IP (across any email address) count toward the same
"Max attempts per IP" / "IP block duration" policy described above under login attempts — this
is what stops someone from blocking a specific email's reset access just by repeatedly requesting
resets for it: the attacker's IP gets blocked well before the email-level limit is ever reached.

#### Geoblocking
- **Mode** — `Disabled`, `Only allow these countries`, or `Block these countries`.
- **Countries** — the country list the mode above applies to.
- IPs on the plugin's whitelist always skip this check, same as IP-based lockout. If the client
  IP can't be resolved to a country (private/local address, or the database isn't available yet),
  the login is always allowed through — geoblocking never locks everyone out on a data problem.
- The country database is [DB-IP](https://db-ip.com) Lite (Country), refreshed automatically once
  a month by an automatic action, and also on first install. IP geolocation data by DB-IP,
  licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

#### Permanent blocks
Any duration field set to **Permanent** (as well as the IP threshold's distributed-attack block,
which is always permanent) never expires on its own. When at least one login, IP, or password-reset
email/IP is under a permanent block, a matching section — "Permanently blocked accounts",
"Permanently blocked IPs", "Permanently blocked password reset requests", or "Permanently blocked
IPs (password reset)" — appears further down the same config page, right under the section it
belongs to, listing the blocked entries with an **Unblock** button next to each one.
