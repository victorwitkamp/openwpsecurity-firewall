=== OpenWPSecurity - Firewall ===
Contributors: victorwitkamp
Donate link: https://github.com/sponsors/victorwitkamp
Tags: security, firewall, rate limiting, captcha, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress request logging, endpoint rate limiting, captcha challenges, temporary bans, permanent bans, and security incident reporting.

== Description ==

OpenWPSecurity - Firewall records WordPress request activity and applies request-handling controls before abusive traffic reaches normal page handling.

Runtime behavior:

* Logs WordPress request activity for frontend pages, `wp-login.php`, admin, `admin-ajax.php`, REST API, `xmlrpc.php`, and `wp-cron.php`.
* Applies endpoint-local rate limits for frontend pages, login, AJAX, REST API, XML-RPC, and cron requests.
* Uses an HTTP 429 response for rate-limited frontend and login requests.
* Supports captcha challenges for frontend and login traffic.
* Creates temporary IP bans across all request types after configured rate-limit or captcha failure thresholds.
* Escalates repeated temporary bans into permanent IP bans.
* Separates request activity from security incidents in the admin interface.
* Stores request activity, security incidents, active temporary bans, temporary-ban counters, and permanent bans in separate plugin-owned database tables.

Stored request and incident fields include timestamp, IP address, country fields, request type, method, user agent, request URI, lockout expiry where applicable, and JSON evidence for thresholds, captcha state, and ban context.

Remote GeoIP lookup is optional and disabled by default. Local, private, and reserved IP addresses are classified without remote lookup.

== Installation ==

1. Upload the packaged plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Firewall`.
3. Review Firewall settings for trusted IP headers, whitelisted IPs, endpoint rate limits, captcha, temporary bans, permanent bans, retention, and GeoIP lookup.

== Frequently Asked Questions ==

= Does this plugin slow down my site? =

No. Rate-limit counters use WordPress transients (in-memory when an object cache is active) and the permanent-ban check runs a single indexed database query before WordPress finishes loading. The performance impact is minimal.

= Can I whitelist my own IP address? =

Yes. Add one or more IP addresses (or CIDR ranges) to the whitelist on the Settings page. Whitelisted IPs and logged-in administrators are always bypassed.

= What happens when an IP is permanently banned? =

The request is terminated with a 403 response before WordPress loads any templates or runs any hooks. Permanent bans are checked as early as possible in the `init` hook.

= Does the plugin work behind a CDN or reverse proxy? =

Yes. Configure the trusted IP header (for example `X-Forwarded-For` or `CF-Connecting-IP`) on the Settings page so the plugin reads the real visitor IP rather than the proxy address.

= What is the difference between the Firewall and the Login Protection plugin? =

The Firewall covers all WordPress request types — frontend pages, AJAX, REST API, XML-RPC, and WP-Cron — applying endpoint-specific rate limits, captcha challenges, and IP banning. Login Protection focuses exclusively on the WordPress login flow and stores detailed credential-correlation data for failed logins. The two plugins can be used independently or together.

= How do I remove all plugin data? =

Deactivate and then delete the plugin from the Plugins screen. The uninstall routine drops all plugin-owned database tables and removes all plugin options.

== External Services ==

When the **Remote GeoIP lookup** setting is enabled (disabled by default), this plugin sends the visitor's IP address to a third-party service to determine the country of origin:

* Service: [ipwho.is](https://ipwho.is/)
* Data sent: IP address only
* Purpose: Country classification for security logs and reports
* Privacy policy: https://ipwho.is/

Remote GeoIP lookup is never used for private, loopback, or reserved IP addresses, which are classified locally without any external call. You can disable remote lookup at any time on the Settings page.

== Screenshots ==

1. Dashboard showing request activity, security incidents, and active ban counts.
2. Request log with filtering by activity type, request type, IP address, and date range.
3. Security incidents view with incident type, IP, country, and evidence details.
4. Policies page for configuring per-endpoint rate limits and thresholds.
5. Settings page with trusted IP headers, whitelisting, captcha, and retention options.
6. Permanent bans management with the option to remove individual bans.

== Changelog ==

= 0.3.0 =
* Updated to openwpsecurity/core 0.4.0.
* Added plugin banner, icon, and branding assets.
* Added uninstall routine to remove all plugin-owned tables and options on deletion.
* Added FAQ, External Services, Screenshots, and Changelog sections to readme.

= 0.2.0 =
* Initial public release.
* Endpoint rate limiting for frontend pages, login, AJAX, REST API, XML-RPC, and WP-Cron.
* Math captcha challenges for frontend and login traffic with HMAC-signed pass cookies.
* Temporary IP bans with escalation to permanent bans on repeated violations.
* Separate request log and security incident tables with configurable retention.
* Optional remote GeoIP lookup via ipwho.is (disabled by default).
* Admin interface with dashboard, request log, security incidents, temporary bans, permanent bans, policies, and settings pages.
