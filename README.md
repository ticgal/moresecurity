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
- Limit the number of failed login attempts per account, with a temporary block and exponential backoff
- Limit the number of password reset attempts per email address, with a temporary block
- Per-IP attempt tracking with temporary IP blocking, independent of the per-account block (shared by login and password reset)
- IP whitelist (single IPs, IPv6 and CIDR ranges) to exempt trusted networks from the checks
- Distributed attack detection: blocks an account for a bounded time when attempts come from too many distinct IPs
- Administrators can unblock accounts, IPs and password reset requests from the configuration tab
- Daily automatic action that purges old attempt records
- Geoblocking: allow or deny logins by country, using DB-IP's free Lite database
- Trusted reverse proxy support, so the real client IP is used behind a proxy or load balancer
- Security log (Administration > Security log) with every failed attempt, a per-account/IP summary and a dedicated read-only permission
- Dashboard cards (top attacking IPs, most targeted accounts, top offending countries) and a ready-made "More Security" dashboard
- Bulk unblock of accounts, IPs and password reset requests

### Configuration options
All settings live on the **More Security** tab of **Setup > General**. A value of `0` on any
attempt-count field disables that particular protection. Block durations must be at least one second.

#### Login attempts
- **Number of attempts** — how many login attempts an account can make before it is blocked. Each
  attempt is counted when it starts; a correct login releases it. It must be greater than "Max
  attempts per IP", otherwise it is adjusted automatically.
- **Access time blocked** — base block duration. Each further attempt above the threshold doubles
  the wait, up to the **backoff cap** (0 = no cap other than a hard limit of one year).
- Counters reset after 12 hours without activity.

#### IP blocking
- **Max attempts per IP** — how many attempts from one IP (against any account, or password reset
  requests for any email) before the IP itself is blocked, with the same backoff as above.
- **IP block duration / cap** — duration and backoff cap of the IP block.
- **IP threshold** — if attempts for the same account come from at least this many distinct IPs
  (within the 12 h window) the account is blocked for the backoff cap (one day by default). It
  works even if "Number of attempts" is 0.

By default the client IP is the direct connection address (`REMOTE_ADDR`). Behind a reverse proxy
every client would share one budget: list the proxy under **Trusted reverse proxy IPs** and the
`X-Forwarded-For` header is honoured, but only when the request comes from one of those proxies.
Do not add the proxy to the whitelist unless you accept exempting all of its clients.

#### Geoblocking
- **Mode** — *Disabled*, *Only allow these countries* or *Block these countries*. Applies to logins
  only; whitelisted IPs skip it. Denied logins are written to the Security log and count against the
  per-IP budget, so a persistent origin ends up blocked.
- **Countries** — ISO 3166-1 countries the mode applies to.
- Country data comes from DB-IP's free *IP to Country Lite* database (CC BY 4.0), downloaded into
  the GLPI plugin documents folder by the monthly automatic action *updatedb*. Until it has been
  downloaded, or for private, reserved and unresolvable addresses, geoblocking **fails open**: the
  login is allowed through. Requires the `geoip2/geoip2` and `league/iso3166` libraries (shipped
  with the release package; run `composer install` when working from a git checkout).

#### Password reset attempts
- **Attempts for Password Reset** — requests allowed per email address before it is blocked.
- **Access time blocked for Password Reset** — duration of that block.

Password reset requests also count toward the per-IP budget, so an attacker cannot lock an email's
reset access without first getting their own IP blocked.

#### Unblocking
Currently blocked accounts, IPs and password reset requests are listed at the bottom of the
configuration tab with an **Unblock** button, a checkbox for **Unlock selected** and an **Unlock
all** button (requires the `config` update right; every unblock is written to the configuration
history). Blocks always expire on their own.

#### Security log
**Administration > Security log** lists every failed login, every admitted password reset request
and every geoblocked login, with type, login/email, matching user, IP and country. The **Summary**
tab groups them by type, identifier and IP. Access is controlled by the *More Security > Security
log* right of each profile; on installation it is granted (read) to the profiles that can already
edit the GLPI configuration.

#### Data retention
The automatic action *Purge* (daily) removes attempt records inactive for more than 7 days that
are not under an active block. The automatic action *PurgeLogs* (daily) removes Security log
entries older than its parameter (30 days by default). The log keeps at most 200 entries per IP and hour, so an attacker cannot inflate it; blocking decisions do not depend on the log. Login names, emails and IPs are personal
data: adjust both actions to your retention policy.

### Scope and limits
- **Web login form only.** The protections (attempt limits, IP blocking, geoblocking) apply to the GLPI login and
  password-reset forms. Logins through other channels (the legacy REST API `apirest.php/initSession` with
  credentials, or the OAuth *password* grant of the High-Level API) do not go through the plugin and are not
  counted or geoblocked. If you do not need them, disable *Enable login with credentials* in **Setup > General >
  API** and use API tokens; otherwise apply geographic restrictions at your reverse proxy as well. The plugin's
  configuration tab shows a warning while that API login is enabled. CalDAV (`/caldav.php`, HTTP Basic) is covered:
  it honours blocks and geoblocking and counts failed passwords like the web form.
- **The Security log is global.** Attempts happen before a session and an entity exist, so the log and the
  dashboard cards are not filtered by entity. Grant the *More Security > Security log* right (and the dashboard
  cards, which require it) only to profiles that may see the logins, emails and IPs of the whole instance.
- **Lockouts can be provoked.** Counters key on the identity typed in the form, whether or not it exists, so someone
  who knows a login or email can trigger its temporary account lockout or reset block ("distinct IPs" detection makes
  this easier by design). Keep block durations short (*Time blocked*, *Time reset*) and use the whitelist for trusted
  networks. IPv6 addresses are counted per /64 prefix.

