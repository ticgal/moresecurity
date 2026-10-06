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

The client IP is always the direct connection address (`REMOTE_ADDR`). Behind a reverse proxy
every client shares one budget: add the proxy to the whitelist only if you accept exempting all
of its clients.

#### Password reset attempts
- **Attempts for Password Reset** — requests allowed per email address before it is blocked.
- **Access time blocked for Password Reset** — duration of that block.

Password reset requests also count toward the per-IP budget, so an attacker cannot lock an email's
reset access without first getting their own IP blocked.

#### Unblocking
Currently blocked accounts, IPs and password reset requests are listed at the bottom of the
configuration tab with an **Unblock** button (requires the `config` update right; every unblock is
written to the configuration history). Blocks always expire on their own.

#### Data retention
The automatic action *Purge* (daily) removes attempt records inactive for more than 7 days that
are not under an active block. Login names, emails and IPs are personal data: adjust the action
frequency to your retention policy.
