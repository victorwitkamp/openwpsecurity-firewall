<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsPage extends AbstractAdminPage {
	private Settings $settings;

	public function __construct( Settings $settings, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings = $settings;
	}

	public function render(): void {
		$this->assert_page_access();

		$settings_updated = $this->handle_form_submission();
		$settings         = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Settings</h1>
			<p>Configure storage, IP resolution, cross-plugin enforcement, and diagnostics.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-settings' ); ?>

			<?php if ( $settings_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p>Firewall settings saved.</p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_settings' ); ?>
				<div class="vwfw-settings-section">
					<h2>Runtime &amp; Diagnostics</h2>
					<p class="description">Policy controls for captcha, rate limiting, and escalation are managed on the <strong>Policies</strong> page.</p>
					<?php $this->render_runtime_table( $settings ); ?>
				</div>

				<p class="submit">
					<button type="submit" name="vwfw_save_settings" class="button button-primary">Save Firewall Settings</button>
				</p>
			</form>
		</div>
		<?php
	}

	private function handle_form_submission(): bool {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_settings'] ) ) {
			return false;
		}

		check_admin_referer( 'vwfw_save_settings' );
		$this->settings->update( $this->settings->sanitize_runtime_submission( wp_unslash( $_POST ) ) );
		return true;
	}

	private function render_runtime_table( array $settings ): void {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="event_retention_days">Event retention</label></th>
				<td>
					<input id="event_retention_days" name="event_retention_days" type="number" min="0" value="<?php echo esc_attr( (string) $settings['event_retention_days'] ); ?>" class="small-text"> days
					<p class="description">How long Firewall request-log and security-incident records remain in the database before automatic daily cleanup removes them. Use <strong>0</strong> to keep them forever.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="trusted_ip_headers">Trusted IP headers</label></th>
				<td>
					<input id="trusted_ip_headers" name="trusted_ip_headers" type="text" value="<?php echo esc_attr( implode( ', ', $settings['trusted_ip_headers'] ) ); ?>" class="regular-text">
					<p class="description">Comma-separated server headers. <code>REMOTE_ADDR</code> is always used as a fallback.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="whitelist_ips">Whitelisted IP addresses</label></th>
				<td>
					<textarea id="whitelist_ips" name="whitelist_ips" rows="6" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['whitelist_ips'] ) ); ?></textarea>
					<p class="description">One IP address per line. Whitelisted IPs bypass Firewall captcha challenges and request-handling enforcement.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Login Protection permanent bans</th>
				<td>
					<label for="enforce_loginprotection_bans">
						<input id="enforce_loginprotection_bans" name="enforce_loginprotection_bans" type="checkbox" value="1" <?php checked( ! empty( $settings['enforce_loginprotection_bans'] ) ); ?>>
						Enforce Login Protection permanent bans globally in Firewall
					</label>
					<p class="description">When enabled, IP addresses permanently banned by OpenWPSecurity - Login Protection are also blocked by Firewall across all request types. The Login Protection ban list remains stored separately.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Enable debug bar</th>
				<td>
					<label for="debug_bar_enabled">
						<input id="debug_bar_enabled" name="debug_bar_enabled" type="checkbox" value="1" <?php checked( ! empty( $settings['debug_bar_enabled'] ) ); ?>>
						Turn the OpenWPSecurity Firewall debug bar on for HTML responses, including frontend pages, admin screens, login screens, captcha pages, and block pages.
					</label>
					<p class="description">This exposes live counters and branch decisions from the firewall flow. Keep it enabled for testing, but turn it off when you no longer need visible runtime diagnostics.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Remote GeoIP lookup</th>
				<td>
					<label for="enable_remote_geoip">
						<input id="enable_remote_geoip" name="enable_remote_geoip" type="checkbox" value="1" <?php checked( ! empty( $settings['enable_remote_geoip'] ) ); ?>>
						Use a remote lookup when local GeoIP resolution does not resolve an IP address.
					</label>
				</td>
			</tr>
		</table>
		<?php
	}
}
