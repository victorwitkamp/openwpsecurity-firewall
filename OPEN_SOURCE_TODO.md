# Open-Source Preparation TODO

Status on March 22, 2026:

- The plugin is already renamed to `OpenWPSecurity - Firewall`.
- Composer, npm, PHPCS, CI workflows, and release packaging are present.
- The GitHub/source repo is currently source-first, not install-from-GitHub ready.

## High Priority Before Publishing To GitHub

- Add a real `README.md` for GitHub.
  It should explain what the plugin does, the architecture, local development commands, and the difference between cloning source and installing a packaged release.
- Add a top-level `LICENSE` file.
  The plugin header already declares GPL-2.0-or-later, but the repository should also contain the full license text.
- Add `SECURITY.md`.
  This should explain how to report vulnerabilities privately and what response process to expect.
- Add `CONTRIBUTING.md`.
  Include coding standards, build commands, commit/PR expectations, and how to run checks locally.
- Add `CODE_OF_CONDUCT.md`.
- Add GitHub issue templates and a PR template.
- Replace the current `Plugin URI` and `Author URI`.
  They still point to the production site. Use canonical project URLs or repository URLs instead.

## Repo Hygiene

- Add a real GitHub `README.md`; `readme.txt` is not enough for repository visitors.
- Decide whether the repository is source-only or installable as-is.
  Right now `.gitignore` excludes `vendor/`, `node_modules/`, and generated `assets/css/`, so a GitHub clone needs build steps before it is usable.
- If the repo stays source-only, document the exact commands:
  `composer install`
  `npm install`
  `npm run build`
- Review remaining old internal prefixes such as `vwfw_*`.
  They are mostly internal CSS, nonce, and helper names now, but they are still naming debt.

## Product And Security Review

- Re-check whether the debug bar should stay in the public codebase exactly as-is.
  It is useful for development, but the feature must stay clearly off by default and documented as a diagnostics-only tool.
- Add/finish internationalization for user-facing strings.
- Decide uninstall behavior and add `uninstall.php` if data cleanup on uninstall is desired.
- Review all visible admin/page text for final public wording and consistency.
- Add a short privacy note to the README about what request/security data is stored.

## WordPress.org Readiness Later

- Review `readme.txt` against the WordPress.org parser and submission expectations.
- Prepare plugin assets: icon, banner, screenshots.
- Re-check all headers, tested-up-to values, and support links.

## Firewall-Specific Follow-Up

- Review whether the remaining generic event table should stay broad or be split further before public release.
- Decide whether `OpenWPSecurity Debug` should remain branded that way or be renamed to something even more explicit like `Firewall Debug`.
- Document which request types are logged and how request handling, captcha, temporary blocks, and permanent bans interact.
- Keep shared infrastructure aligned with `openwpsecurity-loginprotection`.
  Prefer PSR interfaces and proven packages for shared concerns such as DI, HTTP messages, response factories, and response emitting, so common code can move into the local `openwpsecurity/core` Composer package without sharing plugin-specific tables or options.
- First shared extraction is in place:
  `VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector` now lives in `../openwpsecurity-core` and is consumed through a Composer path repository that junctions `vendor/openwpsecurity/core` to the shared package.

## Sources

- WordPress header requirements: https://developer.wordpress.org/plugins/plugin-basics/header-requirements/
- WordPress readme rules: https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/
- WordPress detailed plugin guidelines: https://developer.wordpress.org/plugins/wordpress-org/detailed-plugin-guidelines/
- WordPress software license guidance: https://developer.wordpress.org/plugins/plugin-basics/including-a-software-license/
- WordPress uninstall methods: https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/
- WordPress plugin assets: https://developer.wordpress.org/plugins/wordpress-org/plugin-assets/
- GitHub READMEs: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes
- GitHub licenses: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-license-to-a-repository
- GitHub contributor guidelines: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors
- GitHub code of conduct: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project
- GitHub security policy: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/adding-a-security-policy-to-your-repository
- GitHub issue and PR templates: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates
