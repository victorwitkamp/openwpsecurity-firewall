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
			<h1><?php esc_html_e( 'OpenWPSecurity - Firewall Policies', 'openwpsecurity-firewall' ); ?></h1>
			<p><?php esc_html_e( 'Configure how Firewall challenges, rate-limits, temporarily bans, and permanently bans request sources.', 'openwpsecurity-firewall' ); ?></p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-policies' ); ?>

			<?php if ( $policies_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Firewall policies saved.', 'openwpsecurity-firewall' ); ?></p></div>
			<?php endif; ?>

			<form method="post">
				<?php wp_nonce_field( 'vwfw_save_policies' ); ?>

				<div class="vwfw-grid vwfw-grid--two">
					<section class="vwfw-panel">
						<h2><?php esc_html_e( 'Shared Captcha Policy', 'openwpsecurity-firewall' ); ?></h2>
						<p class="description"><?php esc_html_e( 'Applies to visitor-facing HTML endpoints that support a challenge.', 'openwpsecurity-firewall' ); ?></p>
						<?php $this->render_captcha_policy( $settings ); ?>
					</section>

					<section class="vwfw-panel">
						<h2><?php esc_html_e( 'Temporary Ban Escalation', 'openwpsecurity-firewall' ); ?></h2>
						<p class="description"><?php esc_html_e( 'Controls temporary bans shared across request types and their escalation to permanent bans.', 'openwpsecurity-firewall' ); ?></p>
						<?php $this->render_global_block_policy( $settings ); ?>
					</section>
				</div>

				<section class="vwfw-panel">
					<h2><?php esc_html_e( 'Endpoint Policies', 'openwpsecurity-firewall' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Each endpoint has an independent rate-limit threshold and escalation path.', 'openwpsecurity-firewall' ); ?></p>
					<?php $this->render_endpoint_policies( $settings ); ?>
				</section>

				<p class="submit">
					<button type="submit" name="vwfw_save_policies" class="button button-primary"><?php esc_html_e( 'Save Firewall Policies', 'openwpsecurity-firewall' ); ?></button>
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
				<th scope="row"><?php esc_html_e( 'Shared captcha', 'openwpsecurity-firewall' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $captcha_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $captcha_enabled_key ] ) ); ?>>
						<?php esc_html_e( 'Enable challenges for supported endpoints', 'openwpsecurity-firewall' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_failure_threshold"><?php esc_html_e( 'Temporary ban after failed answers', 'openwpsecurity-firewall' ); ?></label></th>
				<td><input id="captcha_failure_threshold" name="captcha_failure_threshold" type="number" min="0" value="<?php echo esc_attr( (string) $settings['captcha_failure_threshold'] ); ?>" class="small-text"> <?php esc_html_e( 'answers', 'openwpsecurity-firewall' ); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_failure_window_minutes"><?php esc_html_e( 'Failure window', 'openwpsecurity-firewall' ); ?></label></th>
				<td><input id="captcha_failure_window_minutes" name="captcha_failure_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_failure_window_minutes'] ); ?>" class="small-text"> <?php esc_html_e( 'minutes', 'openwpsecurity-firewall' ); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="captcha_pass_minutes"><?php esc_html_e( 'Bypass after solving', 'openwpsecurity-firewall' ); ?></label></th>
				<td><input id="captcha_pass_minutes" name="captcha_pass_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['captcha_pass_minutes'] ); ?>" class="small-text"> <?php esc_html_e( 'minutes', 'openwpsecurity-firewall' ); ?></td>
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
				<th scope="row"><?php esc_html_e( 'Global temporary bans', 'openwpsecurity-firewall' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( $temporary_block_enabled_key ); ?>" value="1" <?php checked( ! empty( $settings[ $temporary_block_enabled_key ] ) ); ?>>
						<?php esc_html_e( 'Block all request types after an API-style endpoint exceeds its limit', 'openwpsecurity-firewall' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $temporary_block_minutes_key ); ?>"><?php esc_html_e( 'Temporary ban duration', 'openwpsecurity-firewall' ); ?></label></th>
				<td><input id="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" name="<?php echo esc_attr( $temporary_block_minutes_key ); ?>" type="number" min="1" value="<?php echo esc_attr( (string) $settings[ $temporary_block_minutes_key ] ); ?>" class="small-text"> <?php esc_html_e( 'minutes', 'openwpsecurity-firewall' ); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>"><?php esc_html_e( 'Permanent ban after temporary bans', 'openwpsecurity-firewall' ); ?></label></th>
				<td>
					<input id="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" name="<?php echo esc_attr( $blocks_before_permanent_ban_key ); ?>" type="number" min="0" value="<?php echo esc_attr( (string) $settings[ $blocks_before_permanent_ban_key ] ); ?>" class="small-text"> <?php esc_html_e( 'temporary bans', 'openwpsecurity-firewall' ); ?>
					<p class="description"><?php esc_html_e( 'Use 0 to disable this repeated-temporary-ban escalation path.', 'openwpsecurity-firewall' ); ?></p>
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
							<?php esc_html_e( 'Rate limiting enabled', 'openwpsecurity-firewall' ); ?>
						</label>
					</div>
					<div class="vwfw-policy-fields">
						<label class="vwfw-policy-field">
							<span><?php esc_html_e( 'Request threshold', 'openwpsecurity-firewall' ); ?></span>
							<input type="number" min="1" name="<?php echo esc_attr( $rate_limit_threshold_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_threshold_key ] ); ?>">
						</label>
						<label class="vwfw-policy-field">
							<span><?php esc_html_e( 'Window (seconds)', 'openwpsecurity-firewall' ); ?></span>
							<input type="number" min="1" name="<?php echo esc_attr( $rate_limit_window_seconds_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $rate_limit_window_seconds_key ] ); ?>">
						</label>
						<label class="vwfw-policy-field">
							<span><?php esc_html_e( 'Permanent ban after active temporary-ban denials', 'openwpsecurity-firewall' ); ?></span>
							<input type="number" min="0" name="<?php echo esc_attr( $active_block_denials_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $active_block_denials_key ] ); ?>">
						</label>
						<?php if ( $this->request_handling_catalog->supports_captcha( $request_type ) ) : ?>
							<label class="vwfw-policy-field">
								<span><?php esc_html_e( 'Temporary ban after captcha pages', 'openwpsecurity-firewall' ); ?></span>
								<input type="number" min="0" name="<?php echo esc_attr( $captcha_challenges_key ); ?>" value="<?php echo esc_attr( (string) $settings[ $captcha_challenges_key ] ); ?>">
							</label>
						<?php else : ?>
							<input type="hidden" name="<?php echo esc_attr( $captcha_challenges_key ); ?>" value="0">
						<?php endif; ?>
					</div>
					<details class="vwfw-policy-outcome">
						<summary><?php esc_html_e( 'When exceeded', 'openwpsecurity-firewall' ); ?></summary>
						<p><?php echo esc_html( $this->request_handling_action_describer->describe( $settings, $request_type ) ); ?></p>
					</details>
				</article>
			<?php endforeach; ?>
		</div>
		<?php
	}
}
