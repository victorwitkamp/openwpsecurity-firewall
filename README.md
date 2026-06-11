# OpenWPSecurity — Firewall

<img src=".wordpress-org/banner-772x250.png" alt="OpenWPSecurity Firewall" width="772">

WordPress request logging, endpoint rate limiting, captcha challenges, temporary bans, permanent bans, and security incident reporting.

[![WordPress](https://img.shields.io/badge/WordPress-6.5%2B-blue?logo=wordpress)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-8.2%2B-777BB4?logo=php)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-green)](LICENSE)

---

## Features

- Logs all WordPress request types: frontend pages, `wp-login.php`, admin, `admin-ajax.php`, REST API, `xmlrpc.php`, and `wp-cron.php`
- Per-endpoint rate limiting with configurable thresholds and windows
- Math captcha challenges for frontend and login traffic with HMAC-signed pass cookies
- Temporary IP bans with escalation to permanent bans on repeated violations
- Permanent ban enforcement before WordPress finishes loading (`init` priority 1)
- Separate request log and security incident tables with configurable retention
- Optional cross-plugin enforcement of [Login Protection](https://github.com/victorwitkamp/openwpsecurity-loginprotection) permanent bans
- Optional remote GeoIP lookup via [ipwho.is](https://ipwho.is/) (disabled by default)
- Admin dashboard with request log, security incidents, temporary bans, permanent bans, policies, and settings

## Requirements

- WordPress 6.5+
- PHP 8.2+

## Installation

1. Download the latest release ZIP from the [Releases](../../releases) page.
2. In WordPress admin go to **Plugins → Add New → Upload Plugin**.
3. Upload the ZIP and activate.
4. Configure under **OpenWPSecurity → Firewall → Settings**.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Trusted IP header | `REMOTE_ADDR` | HTTP header used to resolve the real visitor IP |
| Whitelist IPs | — | IPs exempt from all enforcement |
| Frontend rate limit | 12 req / 60 s | Requests per IP before captcha or block |
| Login rate limit | 8 req / 300 s | Login attempts per IP before captcha or block |
| Captcha failure threshold | 3 | Failures before temporary ban |
| Event retention | 90 days | How long request logs and incidents are kept |
| Remote GeoIP | Disabled | Send IP to ipwho.is for country lookup |

## Database tables

| Table | Purpose |
|-------|---------|
| `*_openwpsecurity_firewall_request_logs` | All request activity |
| `*_openwpsecurity_firewall_security_incidents` | Rate-limit events, bans, captcha events |
| `*_openwpsecurity_firewall_temporary_bans` | Active temporary bans |
| `*_openwpsecurity_firewall_temporary_ban_counts` | Per-IP ban recurrence counters |
| `*_openwpsecurity_firewall_permanent_bans` | Permanent IP bans |

All tables are dropped on plugin deletion.

## Requirements & dependency

This plugin requires [`openwpsecurity/core`](https://github.com/victorwitkamp/openwpsecurity-core), which is bundled in the release ZIP via Composer.

## License

GPL-2.0-or-later — see [LICENSE](LICENSE).
