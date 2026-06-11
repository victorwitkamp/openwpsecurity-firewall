<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\DashboardReport;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardPage extends AbstractAdminPage {
	private DashboardReport $dashboard_report;
	private PermanentBanStore $ban_store;
	private Settings $settings;
	private RequestHandlingCatalog $request_handling_catalog;
	private TemporaryBanRepository $temporary_ban_repository;

	public function __construct( Settings $settings, DashboardReport $dashboard_report, PermanentBanStore $ban_store, RequestHandlingCatalog $request_handling_catalog, TemporaryBanRepository $temporary_ban_repository, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings                 = $settings;
		$this->dashboard_report         = $dashboard_report;
		$this->ban_store                = $ban_store;
		$this->request_handling_catalog = $request_handling_catalog;
		$this->temporary_ban_repository = $temporary_ban_repository;
	}

	public function render(): void {
		$this->assert_page_access();

		$period = $this->current_period( '24h' );

		if ( 'all' === $period ) {
			$period = '24h';
		}

		$data = $this->load_dashboard_data( $period );
		?>
		<div class="wrap vwfw-admin vwfw-dashboard">
			<h1>OpenWPSecurity - Firewall</h1>
			<p>Selected-range firewall activity and current enforcement state.</p>

			<?php $this->render_page_tabs( 'openwpsecurity-firewall' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall', $period, false ); ?>

			<?php $this->render_summary_cards( $data ); ?>
			<?php $this->render_current_state( $data ); ?>
		</div>
		<?php
	}

	private function load_dashboard_data( string $period ): array {
		$period_seconds = $this->report_period->seconds( $period );

		return array(
			'summary'        => $this->dashboard_report->summary( $period_seconds ),
			'permanent_bans' => $this->ban_store->count_bans(),
			'temporary_bans' => $this->temporary_ban_repository->count_active_temporary_bans(),
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
			<?php $this->render_summary_card( 'Temporary Bans Created', (int) $summary['temporary_blocks'] ); ?>
			<?php $this->render_summary_card( 'Captcha Triggered', (int) $summary['captcha_required'] ); ?>
			<?php $this->render_summary_card( 'Captcha Solved', (int) $summary['captcha_passed'] ); ?>
			<?php $this->render_summary_card( 'Permanent Bans Created', (int) $summary['permanent_bans'] ); ?>
		</div>
		<?php
	}

	private function render_current_state( array $data ): void {
		$settings                    = $data['settings'];
		$captcha_enabled_key         = $this->request_handling_catalog->captcha_enabled_setting_key();
		$temporary_block_enabled_key = $this->request_handling_catalog->temporary_block_enabled_setting_key();
		$permanent_bans_url          = admin_url( 'admin.php?page=openwpsecurity-firewall-bans' );
		$temporary_bans_url          = admin_url( 'admin.php?page=openwpsecurity-firewall-temporary-bans' );
		$policies_url                = admin_url( 'admin.php?page=openwpsecurity-firewall-policies' );
		$enabled_endpoint_policies   = 0;

		foreach ( array_keys( $this->request_handling_catalog->targets() ) as $request_type ) {
			if ( ! empty( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ) ] ) ) {
				++$enabled_endpoint_policies;
			}
		}
		?>
		<section class="vwfw-current-state">
			<div class="vwfw-section-heading">
				<div>
					<h2>Current Enforcement</h2>
					<p class="description">Live state and policy status. These values are not affected by the selected reporting range.</p>
				</div>
			</div>
			<div class="vwfw-state-grid vwfw-state-grid--compact">
				<a class="vwfw-state-item" href="<?php echo esc_url( $temporary_bans_url ); ?>">
					<span>Current Temporary Bans</span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['temporary_bans'] ) ); ?></strong>
					<small>Open management page</small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $permanent_bans_url ); ?>">
					<span>Current Permanent Bans</span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['permanent_bans'] ) ); ?></strong>
					<small>Open management page</small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span>Endpoint Policies</span>
					<strong><?php echo esc_html( number_format_i18n( $enabled_endpoint_policies ) ); ?> of <?php echo esc_html( number_format_i18n( count( $this->request_handling_catalog->targets() ) ) ); ?> enabled</strong>
					<small>Review endpoint rate limits</small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span>Shared Captcha</span>
					<strong><?php echo esc_html( ! empty( $settings[ $captcha_enabled_key ] ) ? 'Enabled' : 'Disabled' ); ?></strong>
					<small>Review challenge policy</small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span>Temporary Ban Policy</span>
					<strong><?php echo esc_html( ! empty( $settings[ $temporary_block_enabled_key ] ) ? 'Enabled' : 'Disabled' ); ?></strong>
					<small>Review escalation policy</small>
				</a>
			</div>
		</section>
		<?php
	}
}
