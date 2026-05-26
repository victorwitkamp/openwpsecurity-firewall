<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\RequestHandlingActionDescriber;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsPage extends AbstractAdminPage {
	private Settings $settings;
	private RequestHandlingCatalog $request_handling_catalog;
	private RequestHandlingActionDescriber $request_handling_action_describer;

	public function __construct( Settings $settings, ReportPeriod $report_period, EventReportFormatter $event_report_formatter, RequestHandlingCatalog $request_handling_catalog, RequestHandlingActionDescriber $request_handling_action_describer ) {
		parent::__construct( $report_period, $event_report_formatter );
		$this->settings                          = $settings;
		$this->request_handling_catalog          = $request_handling_catalog;
		$this->request_handling_action_describer = $request_handling_action_describer;
	}

	public function render(): void {
		$this->assert_page_access();

		$this->handle_form_submission();
		$settings = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Settings</h1>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-settings' ); ?>

			<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only success flag after redirect. ?>
			<?php if ( isset( $_GET['settings-updated'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_settings' ); ?>
				<div class="vwfw-settings-section">
					<h2>Captcha</h2>
					<p class="description">Shared captcha flow for visitor-facing HTML requests. The global on/off switch lives in <strong>Request Handling</strong>.</p>
					<?php $this->render_captcha_table( $settings ); ?>
				</div>

				<div class="vwfw-settings-section">
					<h2>Request Handling</h2>
					<p class="description">These controls run on every WordPress request during <code>init</code>. Frontend page visits are included here as <strong>Frontend Page</strong>, and the request log for this component lives on the <strong>Request Handling</strong> page.</p>
					<?php $this->render_request_handling_table( $settings ); ?>
				</div>

				<div class="vwfw-settings-section">
					<h2>Runtime &amp; Diagnostics</h2>
					<p class="description">Cross-component settings for storage, IP resolution, whitelisting, diagnostics, and GeoIP lookup.</p>
					<?php $this->render_runtime_table( $settings ); ?>
				</div>

				<p class="submit">
					<button type="submit" name="vwfw_save_settings" class="button button-primary">Save Settings</button>
				</p>
			</form>
		</div>
		<?php
	}

	private function handle_form_submission(): void {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_settings'] ) ) {
			return;
		}

		check_admin_referer( 'vwfw_save_settings' );
		$this->settings->update( $this->settings->sanitize_firewall_submission( wp_unslash( $_POST ) ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'openwpsecurity-firewall-settings',
					'settings-updated' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	private function render_captcha_table( array $settings ): void {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="captcha_failure_threshold">Temporary block after failed captcha answers</label></th>
				<td>
					<input id="captcha_failure_threshold" name="captcha_failure_threshold" type="number" min="0" value="<?php echo esc_attr( (string) $settings['captcha_failure_threshold'] ); ?>" class="small-text"> failed answers
					<p class="description">How many incorrect captcha answers from the same IP address are allowed inside the captcha failure window before the shared request-handling temporary block starts. Use <strong>0</strong> to disable temporary-block escalation from captcha failures.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_failure_window_minutes">Captcha failure window</label></th>
				<td>
					<input id="captcha_failure_window_minutes" name="captcha_failure_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_failure_window_minutes'] ); ?>" class="small-text"> minutes
					<p class="description">The rolling window used to count failed captcha answers across <strong>Frontend Page</strong> and <strong>WP Login</strong> requests.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_pass_minutes">Captcha bypass after solving</label></th>
				<td>
					<input id="captcha_pass_minutes" name="captcha_pass_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_pass_minutes'] ); ?>" class="small-text"> minutes
					<p class="description">How long a successfully solved captcha lets the same browser continue through rate-limited <strong>Frontend Page</strong> and <strong>WP Login</strong> requests without seeing another challenge.</p>
				</td>
			</tr>
		</table>
		<?php
	}

	private function render_runtime_table( array $settings ): void {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="event_retention_days">Event retention</label></th>
				<td>
					<input id="event_retention_days" name="event_retention_days" type="number" min="0" value="<?php echo esc_attr( (string) $settings['event_retention_days'] ); ?>" class="small-text"> days
					<p class="description">How long the firewall request/event tables remain in the database before automatic daily cleanup removes them. Use <strong>0</strong> to disable cleanup. Login Protection uses the same retention period in its separate login-events table.</p>
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
				<th scope="row"><label for="whitelist_ips">Whitelisted IPs</label></th>
				<td>
					<textarea id="whitelist_ips" name="whitelist_ips" rows="8" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['whitelist_ips'] ) ); ?></textarea>
					<p class="description">One IP per line. Whitelisted IPs bypass login lockouts, captcha challenges, and request handling enforcement.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Enable debug bar</th>
				<td>
					<label>
						<input name="debug_bar_enabled" type="checkbox" value="1" <?php checked( ! empty( $settings['debug_bar_enabled'] ) ); ?>>
						Turn the OpenWPSecurity Firewall debug bar on for HTML responses, including frontend pages, admin screens, login screens, captcha pages, and block pages.
					</label>
					<p class="description">This exposes live counters and branch decisions from the firewall flow. Keep it enabled for testing, but turn it off when you no longer need visible runtime diagnostics.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Remote GeoIP lookup</th>
				<td>
					<label>
						<input name="enable_remote_geoip" type="checkbox" value="1" <?php checked( ! empty( $settings['enable_remote_geoip'] ) ); ?>>
						Use a remote lookup when the PHP GeoIP extension is unavailable.
					</label>
				</td>
			</tr>
		</table>
		<?php
	}

	private function render_request_handling_table( array $settings ): void {
		$captcha_enabled_key             = $this->request_handling_catalog->captcha_enabled_setting_key();
		$temporary_block_enabled_key     = $this->request_handling_catalog->temporary_block_enabled_setting_key();
		$temporary_block_minutes_key     = $this->request_handling_catalog->temporary_block_minutes_setting_key();
		$blocks_before_permanent_ban_key = $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key();
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">Shared captcha</th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $captcha_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $captcha_enabled_key ] ) ); ?>>
						Enable shared captcha for visitor-facing HTML requests
					</label>
					<p class="description">When enabled, <strong>Frontend Page</strong> and <strong>WP Login</strong> use the same captcha history, cooldown, and pass-cookie state. Login Protection remains separate.</p>
				</td>
			</tr>
			<tr>
				<th scope="row">Global temporary blocks</th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $temporary_block_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $temporary_block_enabled_key ] ) ); ?>>
						Create a global request-handling temporary block when an enabled API-style endpoint crosses its rate limit
					</label>
					<p class="description">When active, <strong>Admin AJAX</strong>, <strong>REST API</strong>, <strong>XML-RPC</strong>, and <strong>WP Cron</strong> create a global temporary block as soon as their rate limit is exceeded. Repeated captcha failures use the same temporary-block duration and permanent-ban threshold below.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $temporary_block_minutes_key ); ?>">Temporary block duration</label></th>
				<td>
					<input id="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" name="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" type="number" min="1" value="<?php echo esc_attr( (string) $settings[ $temporary_block_minutes_key ] ); ?>" class="small-text"> minutes
					<p class="description">How long the global request-handling temporary block stays active after an enabled endpoint crosses its rate limit.</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>">Permanent ban after temporary blocks</label></th>
				<td>
					<input id="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" name="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" type="number" min="0" value="<?php echo esc_attr( (string) $settings[ $blocks_before_permanent_ban_key ] ); ?>" class="small-text"> temporary blocks
					<p class="description">How many completed request-handling temporary blocks from the same IP address are allowed before a permanent ban is created. Use <strong>0</strong> to disable permanent-ban escalation from request handling.</p>
				</td>
			</tr>
		</table>

			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-request-handling-table">
				<thead>
					<tr>
						<th>Endpoint</th>
						<th>Rate Limiting</th>
						<th>Captcha</th>
						<th>Threshold</th>
						<th>Window (sec)</th>
						<th>When Exceeded</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $this->request_handling_catalog->targets() as $request_type => $label ) : ?>
						<?php $rate_limit_enabled_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ); ?>
						<?php $rate_limit_threshold_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' ); ?>
						<?php $rate_limit_window_seconds_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' ); ?>
						<tr>
							<td><strong><?php echo esc_html( $label ); ?></strong></td>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( $rate_limit_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $rate_limit_enabled_key ] ) ); ?>>
									Enabled
								</label>
							</td>
							<td>
								<?php echo esc_html( $this->request_handling_action_describer->captcha_note( $settings, $request_type ) ); ?>
							</td>
							<td>
								<input type="number" min="1" class="small-text" name="<?php echo esc_attr( $rate_limit_threshold_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_threshold_key ] ); ?>">
							</td>
							<td>
								<input type="number" min="1" class="small-text" name="<?php echo esc_attr( $rate_limit_window_seconds_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_window_seconds_key ] ); ?>">
							</td>
							<td class="vwfw-break">
								<?php echo esc_html( $this->request_handling_action_describer->describe( $settings, $request_type ) ); ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<p class="description">Rate limiting is endpoint-local. <strong>Frontend Page</strong> and <strong>WP Login</strong> return an HTTP 429 page, optionally with shared captcha. The API-style endpoints above can return HTTP 429 or create a global temporary block that denies all request types with a firewall response.</p>
		<?php
	}
}
