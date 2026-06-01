<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\RequestHandlingActionDescriber;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\DashboardReport;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardPage extends AbstractAdminPage {
	private DashboardReport $dashboard_report;
	private PermanentBanStore $ban_store;
	private Settings $settings;
	private RequestHandlingCatalog $request_handling_catalog;
	private RequestHandlingActionDescriber $request_handling_action_describer;

	public function __construct( Settings $settings, DashboardReport $dashboard_report, PermanentBanStore $ban_store, RequestHandlingCatalog $request_handling_catalog, RequestHandlingActionDescriber $request_handling_action_describer, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings                          = $settings;
		$this->dashboard_report                  = $dashboard_report;
		$this->ban_store                         = $ban_store;
		$this->request_handling_catalog          = $request_handling_catalog;
		$this->request_handling_action_describer = $request_handling_action_describer;
	}

	public function render(): void {
		$this->assert_page_access();

		$period = $this->current_period( '24h' );
		$data   = $this->load_dashboard_data();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall</h1>
			<p>Request handling, captcha challenges, security incidents, and permanent bans.</p>

			<?php $this->render_page_tabs( 'openwpsecurity-firewall' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall', $period, false ); ?>

			<?php $this->render_summary_cards( $data ); ?>

			<div class="vwfw-grid">
				<?php $this->render_captcha_panel( $data['settings'] ); ?>
				<?php $this->render_request_handling_panel( $data['settings'] ); ?>
				<?php $this->render_permanent_ban_panel( $data['permanent_bans'] ); ?>
			</div>
		</div>
		<?php
	}

	private function load_dashboard_data(): array {
		$period_seconds = $this->report_period->seconds( $this->current_period( '24h' ) );

		return array(
			'summary'        => $this->dashboard_report->summary( $period_seconds ),
			'permanent_bans' => $this->ban_store->count_bans(),
			'settings'       => $this->settings->get(),
		);
	}

	private function render_summary_cards( array $data ): void {
		$summary = $data['summary'];
		?>
		<div class="vwfw-cards">
			<?php $this->render_summary_card( 'Request Log Entries', (int) $summary['total_requests'] ); ?>
			<?php $this->render_summary_card( 'Frontend Page Visits', (int) $summary['page_visits'] ); ?>
			<?php $this->render_summary_card( 'Security Incidents', (int) $summary['security_incidents'] ); ?>
			<?php $this->render_summary_card( 'Unique IPs', (int) $summary['unique_ips'] ); ?>
			<?php $this->render_summary_card( 'Temporary Blocks', (int) $summary['temporary_blocks'] ); ?>
			<?php $this->render_summary_card( 'Captcha Triggered', (int) $summary['captcha_required'] ); ?>
			<?php $this->render_summary_card( 'Captcha Solved', (int) $summary['captcha_passed'] ); ?>
			<?php $this->render_summary_card( 'Permanent Bans', (int) $data['permanent_bans'] ); ?>
		</div>
		<?php
	}

	private function render_captcha_panel( array $settings ): void {
		$captcha_enabled_key = $this->request_handling_catalog->captcha_enabled_setting_key();
		?>
		<div class="vwfw-panel">
			<h2>Captcha</h2>
			<table class="widefat striped">
				<tbody>
					<tr><td>Enabled</td><td><?php echo esc_html( ! empty( $settings[ $captcha_enabled_key ] ) ? 'Yes' : 'No' ); ?></td></tr>
					<tr><td>Temporary Block After Failed Answers</td><td><?php echo esc_html( (string) $settings['captcha_failure_threshold'] ); ?> failed answer(s)</td></tr>
					<tr><td>Failure Window</td><td><?php echo esc_html( (string) $settings['captcha_failure_window_minutes'] ); ?> minutes</td></tr>
					<tr><td>Bypass after success</td><td><?php echo esc_html( (string) $settings['captcha_pass_minutes'] ); ?> minutes</td></tr>
					<tr><td>Enabled Endpoints</td><td><?php echo esc_html( $this->enabled_captcha_targets_label( $settings ) ); ?></td></tr>
				</tbody>
			</table>
		</div>
		<?php
	}

	private function render_request_handling_panel( array $settings ): void {
		$temporary_block_enabled_key     = $this->request_handling_catalog->temporary_block_enabled_setting_key();
		$temporary_block_minutes_key     = $this->request_handling_catalog->temporary_block_minutes_setting_key();
		$blocks_before_permanent_ban_key = $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key();
		?>
		<div class="vwfw-panel">
			<h2>Request Handling</h2>
			<table class="widefat striped">
				<tbody>
					<tr><td>Global Temporary Blocks</td><td><?php echo esc_html( ! empty( $settings[ $temporary_block_enabled_key ] ) ? 'Enabled' : 'Disabled' ); ?></td></tr>
					<tr><td>Temporary Block Duration</td><td><?php echo esc_html( (string) $settings[ $temporary_block_minutes_key ] ); ?> minutes</td></tr>
					<tr><td>Permanent Ban After Temporary Blocks</td><td><?php echo esc_html( (string) $settings[ $blocks_before_permanent_ban_key ] ); ?> blocks</td></tr>
				</tbody>
			</table>
			<br>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-request-handling-summary-table">
					<thead>
						<tr>
							<th>Endpoint</th>
							<th>Rate Limiting</th>
							<th>Captcha</th>
							<th>Threshold</th>
							<th>Window</th>
							<th>Active Block Ban</th>
							<th>Captcha Temp Block</th>
							<th>When Exceeded</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $this->request_handling_catalog->targets() as $request_type => $label ) : ?>
							<?php $rate_limit_enabled_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ); ?>
							<?php $rate_limit_threshold_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' ); ?>
							<?php $rate_limit_window_seconds_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' ); ?>
							<?php $active_block_denials_key = $this->request_handling_catalog->setting_key( $request_type, 'active_block_denials_before_permanent_ban' ); ?>
							<?php $captcha_challenges_key = $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' ); ?>
							<tr>
								<td><?php echo esc_html( $label ); ?></td>
								<td><?php echo esc_html( ! empty( $settings[ $rate_limit_enabled_key ] ) ? 'Enabled' : 'Disabled' ); ?></td>
								<td><?php echo esc_html( $this->request_handling_action_describer->captcha_note( $settings, $request_type ) ); ?></td>
								<td><?php echo esc_html( (string) $settings[ $rate_limit_threshold_key ] ); ?></td>
								<td><?php echo esc_html( (string) $settings[ $rate_limit_window_seconds_key ] ); ?> sec</td>
								<td><?php echo esc_html( (string) $settings[ $active_block_denials_key ] ); ?> denials</td>
								<td>
									<?php
									echo esc_html(
										$this->request_handling_catalog->supports_captcha( $request_type )
											? (string) $settings[ $captcha_challenges_key ] . ' challenges'
											: 'Not used'
									);
									?>
								</td>
								<td class="vwfw-break"><?php echo esc_html( $this->request_handling_action_describer->describe( $settings, $request_type ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function enabled_captcha_targets_label( array $settings ): string {
		if ( empty( $settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ] ) ) {
			return 'None';
		}

		$labels = array();

		foreach ( $this->request_handling_catalog->targets() as $request_type => $label ) {
			if ( $this->request_handling_catalog->supports_captcha( $request_type ) ) {
				$labels[] = $label;
			}
		}

		return empty( $labels ) ? 'None' : implode( ', ', $labels );
	}

	private function render_permanent_ban_panel( int $permanent_ban_count ): void {
		?>
		<div class="vwfw-panel">
			<h2>Permanent Bans</h2>
			<p class="description">Permanent bans can be created by Request Handling and Login Protection, and they block all request types.</p>
			<table class="widefat striped">
				<tbody>
					<tr><td>Current permanent bans</td><td><?php echo esc_html( number_format_i18n( $permanent_ban_count ) ); ?></td></tr>
					<tr><td>Management page</td><td><a href="<?php echo esc_url( admin_url( 'admin.php?page=openwpsecurity-firewall-bans' ) ); ?>">Open Permanent Bans</a></td></tr>
				</tbody>
			</table>
		</div>
		<?php
	}
}
