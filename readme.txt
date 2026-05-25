=== OpenWPSecurity - Firewall ===
Contributors: victorwitkamp
Tags: security, firewall, rate limiting, captcha, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress request logging, request handling, captcha challenges, and a security dashboard.

== Description ==

OpenWPSecurity - Firewall records every request that reaches WordPress, applies request-handling rules per endpoint, manages permanent bans, and can challenge aggressive frontend traffic with a captcha.

Current highlights:

* Logs all WordPress request types, including frontend pages, `wp-login.php`, `admin-ajax.php`, REST API requests, `xmlrpc.php`, `wp-cron.php`, and admin requests.
* Separates request analytics from security incidents in the admin UI.
* Applies request-handling rules per endpoint for frontend pages, `wp-login.php`, REST API traffic, `xmlrpc.php`, cron, and other WordPress entry points.
* Includes policy scaffolding for per-endpoint handling rules, while defaulting new request-type controls to `Log Only`.

Development/build notes:

* PHP tooling is managed with Composer.
* Admin styles are authored in `assets/scss/admin.scss` and compiled to `assets/css/admin.css`.
* Run `npm run build:css` after changing SCSS sources.
* GitHub Actions workflows are included for CI and release packaging.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Firewall` in WordPress admin.
3. Review the `Settings` page before enabling stricter request-type handling rules.

== Frequently Asked Questions ==

= Does this block all request types by default? =

No. The plugin logs all request types immediately, but the new per-endpoint handling rules default to `Log Only` until you configure them.

= Where do I change the admin CSS? =

Edit `assets/scss/admin.scss` and rebuild `assets/css/admin.css` with `npm run build:css`.
