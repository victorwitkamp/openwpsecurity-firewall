=== OpenWPSecurity - Firewall ===
Contributors: victorwitkamp
Donate link: https://github.com/sponsors/victorwitkamp
Tags: security, firewall, rate limiting, captcha, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress request logging, endpoint rate limiting, captcha challenges, temporary blocks, permanent bans, and security incident reporting.

== Description ==

OpenWPSecurity - Firewall records WordPress request activity and applies request-handling controls before abusive traffic reaches normal page handling.

Runtime behavior:

* Logs WordPress request activity for frontend pages, `wp-login.php`, admin, `admin-ajax.php`, REST API, `xmlrpc.php`, and `wp-cron.php`.
* Applies endpoint-local rate limits for frontend pages, login, AJAX, REST API, XML-RPC, and cron requests.
* Uses an HTTP 429 response for rate-limited frontend and login requests.
* Supports captcha challenges for frontend and login traffic.
* Creates global temporary request-handling blocks after configured rate-limit or captcha failure thresholds.
* Escalates repeated temporary blocks into permanent IP bans.
* Separates request activity from security incidents in the admin interface.
* Stores firewall events in the plugin's own database table.

Stored event fields include event type, timestamp, IP address, country fields, user agent, request URI, lockout expiry, and JSON details for request type, method, thresholds, captcha state, and ban context.

Remote GeoIP lookup is optional and disabled by default. Local, private, and reserved IP addresses are classified without remote lookup.

== Installation ==

1. Upload the packaged plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Firewall`.
3. Review Firewall settings for trusted IP headers, whitelisted IPs, endpoint rate limits, captcha, temporary blocks, permanent bans, retention, and GeoIP lookup.
