<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\RequestHandlingActionDescriber;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PoliciesPage extends AbstractAdminPage {
	private Settings $settings;
	private RequestHandlingCatalog $request_handling_catalog;
	private RequestHandlingActionDescriber $request_handling_action_describer;

	public function __construct( Settings $settings, RequestHandlingCatalog $request_handling_catalog, RequestHandlingActionDescriber $request_handling_action_describer, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings                          = $settings;
		$this->request_handling_catalog          = $request_handling_catalog;
		$this->request_handling_action_describer = $request_handling_action_describer;
	}

	public function render(): void {
		$this->assert_page_access();

		$policies_updated = $this->handle_form_submission();
		$settings         = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Policies</h1>
			<p>Configure how Firewall challenges, rate-limits, temporarily bans, and permanently bans request sources.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-policies' ); ?>

			<?php if ( $policies_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p>Firewall policies saved.</p></div>
			<?php endif; ?>

			<form method="post">
				<?php wp_nonce_field( 'vwfw_save_policies' ); ?>

				<div class="vwfw-grid vwfw-grid--two">
					<section class="vwfw-panel">
						<h2>Shared Captcha Policy</h2>
						<p class="description">Applies to visitor-facing HTML endpoints that support a challenge.</p>
						<?php $this->render_captcha_policy( $settings ); ?>
					</section>

					<section class="vwfw-panel">
						<h2>Temporary Ban Escalation</h2>
						<p class="description">Controls temporary bans shared across request types and their escalation to permanent bans.</p>
						<?php $this->render_global_block_policy( $settings ); ?>
					</section>
				</div>

				<section class="vwfw-panel">
					<h2>Endpoint Policies</h2>
					<p class="description">Each endpoint has an independent rate-limit threshold and escalation path.</p>
					<?php $this->render_endpoint_policies( $settings ); ?>
				</section>

				<p class="submit">
					<button type="submit" name="vwfw_save_policies" class="button button-primary">Save Firewall Policies</button>
				</p>
			</form>
		</div>
		<?php
	}

	private function handle_form_submission(): bool {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_policies'] ) ) {
			return false;
		}

		check_admin_referer( 'vwfw_save_policies' );
		$this->settings->update( $this->settings->sanitize_policy_submission( wp_unslash( $_POST ) ) );
		return true;
	}

	private function render_captcha_policy( array $settings ): void {
		$captcha_enabled_key = $this->request_handling_catalog->captcha_enabled_setting_key();
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">Shared captcha</th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $captcha_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $captcha_enabled_key ] ) ); ?>>
						Enable challenges for supported endpoints
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_failure_threshold">Temporary ban after failed answers</label></th>
				<td><input id="captcha_failure_threshold" name="captcha_failure_threshold" type="number" min="0" value="<?php echo esc_attr( (string) $settings['captcha_failure_threshold'] ); ?>" class="small-text"> answers</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_failure_window_minutes">Failure window</label></th>
				<td><input id="captcha_failure_window_minutes" name="captcha_failure_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_failure_window_minutes'] ); ?>" class="small-text"> minutes</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_pass_minutes">Bypass after solving</label></th>
				<td><input id="captcha_pass_minutes" name="captcha_pass_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_pass_minutes'] ); ?>" class="small-text"> minutes</td>
			</tr>
		</table>
		<?php
	}

	private function render_global_block_policy( array $settings ): void {
		$temporary_block_enabled_key     = $this->request_handling_catalog->temporary_block_enabled_setting_key();
		$temporary_block_minutes_key     = $this->request_handling_catalog->temporary_block_minutes_setting_key();
		$blocks_before_permanent_ban_key = $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key();
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">Global temporary bans</th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $temporary_block_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $temporary_block_enabled_key ] ) ); ?>>
						Block all request types after an API-style endpoint exceeds its limit
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $temporary_block_minutes_key ); ?>">Temporary ban duration</label></th>
				<td><input id="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" name="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" type="number" min="1" value="<?php echo esc_attr( (string) $settings[ $temporary_block_minutes_key ] ); ?>" class="small-text"> minutes</td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>">Permanent ban after temporary bans</label></th>
				<td>
					<input id="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" name="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" type="number" min="0" value="<?php echo esc_attr( (string) $settings[ $blocks_before_permanent_ban_key ] ); ?>" class="small-text"> temporary bans
					<p class="description">Use 0 to disable this repeated-temporary-ban escalation path.</p>
				</td>
			</tr>
		</table>
		<?php
	}

	private function render_endpoint_policies( array $settings ): void {
		?>
		<div class="vwfw-policy-grid">
			<?php foreach ( $this->request_handling_catalog->targets() as $request_type => $label ) : ?>
				<?php $rate_limit_enabled_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ); ?>
				<?php $rate_limit_threshold_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' ); ?>
				<?php $rate_limit_window_seconds_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' ); ?>
				<?php $active_block_denials_key = $this->request_handling_catalog->setting_key( $request_type, 'active_block_denials_before_permanent_ban' ); ?>
				<?php $captcha_challenges_key = $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' ); ?>
				<article class="vwfw-policy-card">
					<div class="vwfw-policy-card-heading">
						<h3><?php echo esc_html( $label ); ?></h3>
						<label>
							<input type="checkbox" name="<?php echo esc_attr( $rate_limit_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $rate_limit_enabled_key ] ) ); ?>>
							Rate limiting enabled
						</label>
					</div>
					<div class="vwfw-policy-fields">
						<label class="vwfw-policy-field">
							<span>Request threshold</span>
							<input type="number" min="1" name="<?php echo esc_attr( $rate_limit_threshold_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_threshold_key ] ); ?>">
						</label>
						<label class="vwfw-policy-field">
							<span>Window (seconds)</span>
							<input type="number" min="1" name="<?php echo esc_attr( $rate_limit_window_seconds_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_window_seconds_key ] ); ?>">
						</label>
						<label class="vwfw-policy-field">
							<span>Permanent ban after active temporary-ban denials</span>
							<input type="number" min="0" name="<?php echo esc_attr( $active_block_denials_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $active_block_denials_key ] ); ?>">
						</label>
						<?php if ( $this->request_handling_catalog->supports_captcha( $request_type ) ) : ?>
							<label class="vwfw-policy-field">
								<span>Temporary ban after captcha pages</span>
								<input type="number" min="0" name="<?php echo esc_attr( $captcha_challenges_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $captcha_challenges_key ] ); ?>">
							</label>
						<?php else : ?>
							<input type="hidden" name="<?php echo esc_attr( $captcha_challenges_key ); ?>" value="0">
						<?php endif; ?>
					</div>
					<details class="vwfw-policy-outcome">
						<summary>When exceeded</summary>
						<p><?php echo esc_html( $this->request_handling_action_describer->describe( $settings, $request_type ) ); ?></p>
					</details>
				</article>
			<?php endforeach; ?>
		</div>
		<?php
	}
}
