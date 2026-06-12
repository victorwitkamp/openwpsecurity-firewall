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
			<h1><?php esc_html_e( 'OpenWPSecurity - Firewall', 'openwpsecurity-firewall' ); ?></h1>
			<p><?php esc_html_e( 'Selected-range firewall activity and current enforcement state.', 'openwpsecurity-firewall' ); ?></p>

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
			<?php $this->render_summary_card( __( 'Request Log Entries', 'openwpsecurity-firewall' ), (int) $summary['total_requests'] ); ?>
			<?php $this->render_summary_card( __( 'Frontend Page Visits', 'openwpsecurity-firewall' ), (int) $summary['page_visits'] ); ?>
			<?php $this->render_summary_card( __( 'Security Incidents', 'openwpsecurity-firewall' ), (int) $summary['security_incidents'] ); ?>
			<?php $this->render_summary_card( __( 'Unique IPs', 'openwpsecurity-firewall' ), (int) $summary['unique_ips'] ); ?>
			<?php $this->render_summary_card( __( 'Temporary Bans Created', 'openwpsecurity-firewall' ), (int) $summary['temporary_blocks'] ); ?>
			<?php $this->render_summary_card( __( 'Captcha Triggered', 'openwpsecurity-firewall' ), (int) $summary['captcha_required'] ); ?>
			<?php $this->render_summary_card( __( 'Captcha Solved', 'openwpsecurity-firewall' ), (int) $summary['captcha_passed'] ); ?>
			<?php $this->render_summary_card( __( 'Permanent Bans Created', 'openwpsecurity-firewall' ), (int) $summary['permanent_bans'] ); ?>
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
					<h2><?php esc_html_e( 'Current Enforcement', 'openwpsecurity-firewall' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Live state and policy status. These values are not affected by the selected reporting range.', 'openwpsecurity-firewall' ); ?></p>
				</div>
			</div>
			<div class="vwfw-state-grid vwfw-state-grid--compact">
				<a class="vwfw-state-item" href="<?php echo esc_url( $temporary_bans_url ); ?>">
					<span><?php esc_html_e( 'Current Temporary Bans', 'openwpsecurity-firewall' ); ?></span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['temporary_bans'] ) ); ?></strong>
					<small><?php esc_html_e( 'Open management page', 'openwpsecurity-firewall' ); ?></small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $permanent_bans_url ); ?>">
					<span><?php esc_html_e( 'Current Permanent Bans', 'openwpsecurity-firewall' ); ?></span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['permanent_bans'] ) ); ?></strong>
					<small><?php esc_html_e( 'Open management page', 'openwpsecurity-firewall' ); ?></small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span><?php esc_html_e( 'Endpoint Policies', 'openwpsecurity-firewall' ); ?></span>
					<strong><?php echo esc_html( number_format_i18n( $enabled_endpoint_policies ) ); ?> <?php esc_html_e( 'of', 'openwpsecurity-firewall' ); ?> <?php echo esc_html( number_format_i18n( count( $this->request_handling_catalog->targets() ) ) ); ?> <?php esc_html_e( 'enabled', 'openwpsecurity-firewall' ); ?></strong>
					<small><?php esc_html_e( 'Review endpoint rate limits', 'openwpsecurity-firewall' ); ?></small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span><?php esc_html_e( 'Shared Captcha', 'openwpsecurity-firewall' ); ?></span>
					<strong><?php echo esc_html( ! empty( $settings[ $captcha_enabled_key ] ) ? __( 'Enabled', 'openwpsecurity-firewall' ) : __( 'Disabled', 'openwpsecurity-firewall' ) ); ?></strong>
					<small><?php esc_html_e( 'Review challenge policy', 'openwpsecurity-firewall' ); ?></small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $policies_url ); ?>">
					<span><?php esc_html_e( 'Temporary Ban Policy', 'openwpsecurity-firewall' ); ?></span>
					<strong><?php echo esc_html( ! empty( $settings[ $temporary_block_enabled_key ] ) ? __( 'Enabled', 'openwpsecurity-firewall' ) : __( 'Disabled', 'openwpsecurity-firewall' ) ); ?></strong>
					<small><?php esc_html_e( 'Review escalation policy', 'openwpsecurity-firewall' ); ?></small>
				</a>
			</div>
		</section>
		<?php
	}
}
