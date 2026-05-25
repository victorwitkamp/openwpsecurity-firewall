# OpenWPSecurity Firewall Memory

## Purpose
`OpenWPSecurity - Firewall` protects and logs non-login traffic:
- request logging across WordPress request types
- request handling / rate limiting
- shared captcha for HTML endpoints
- global temporary blocks for request handling
- global permanent bans for firewall-triggered abuse

## Current Structure
- `src/Runtime/`
  plugin startup, WordPress integration, container definitions
- `src/Configuration/`
  firewall settings
- `src/Http/`
  request context and denial responses
- `src/Logging/`
  event schema, lookup, writer, retention
- `src/Security/RequestHandling/`
  request classification, rate limiting, temporary blocks
- `src/Security/Captcha/`
  captcha challenge flow used by request handling
- `src/Security/Ban/`
  firewall-only permanent bans
- `src/Admin/`
  dashboard, request handling page, security incidents page, permanent bans page, settings page
- `src/Diagnostics/`
  debug bar
- `templates/`
  `rate-limited.php`, `blocked-temporary.php`, `blocked-permanent.php`, `captcha.php`

## Key Data
- settings option: `openwpsecurity_firewall_settings`
- events table: `{$wpdb->prefix}openwpsecurity_firewall_events`
- permanent bans option: `openwpsecurity_firewall_permanent_bans`
- request-handling temporary block counts option:
  `openwpsecurity_firewall_request_handling_global_temporary_block_counts`

## Admin Pages
- `Dashboard`
- `Request Handling`
- `Security Incidents`
- `Permanent Bans`
- `Settings`

## Important Current Behavior
- rate limiting is endpoint-local
- firewall temporary blocks are global within the firewall plugin
- firewall permanent bans are global within the firewall plugin
- login protection is no longer part of this plugin
- captcha is driven by request handling, not by its own request threshold engine

## Recent Work
- renamed/moved code into `VictorWitkamp\\OpenWPSecurity\\Firewall`
- old `config/container.php` removed; DI definitions are now autoloaded from `src/Runtime/ContainerDefinitions.php`
- native WordPress admin tables are preferred over custom table styling
- pagination was browser-verified on March 27, 2026 for:
  - request handling activity
  - security incidents
  - filtered pagination as well

## Build / Check Commands
- `composer phpcs`
- `npm install`
- `npm run build`

## Browser Verification Artifacts
Temporary local artifacts were written outside the plugin during debugging:
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\pagination-report.json`
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\pagination-click-report.json`
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\pagination-filtered-report.json`

## Open Follow-Ups
- continue reducing custom admin CSS where WordPress core classes are sufficient
- extract more admin page rendering into smaller presentation classes if needed
- evaluate whether any remaining legacy migration constants can be removed after cutover confidence is high
- later evaluate PSR package replacement opportunities only where they reduce maintenance
