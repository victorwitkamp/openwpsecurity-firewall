<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pagination\AdminPaginator;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\ReportPeriod;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class AbstractAdminPage {
	protected ReportPeriod $report_period;
	protected EventReportFormatter $event_report_formatter;

	public function __construct( ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		$this->report_period          = $report_period;
		$this->event_report_formatter = $event_report_formatter;
	}

	protected function render_page_tabs( string $active_page ): void {
		$tabs = array(
			'openwpsecurity-firewall'                  => 'Dashboard',
			'openwpsecurity-firewall-request-handling' => 'Request Handling',
			'openwpsecurity-firewall-security'         => 'Security Incidents',
			'openwpsecurity-firewall-bans'             => 'Permanent Bans',
			'openwpsecurity-firewall-settings'         => 'Settings',
		);
		?>
		<div class="nav-tab-wrapper">
			<?php foreach ( $tabs as $page => $label ) : ?>
				<a class="nav-tab <?php echo esc_attr( $active_page === $page ? 'nav-tab-active' : '' ); ?>" href="<?php echo esc_url( admin_url( 'admin.php?page=' . $page ) ); ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			<?php endforeach; ?>
		</div>
		<?php
	}

	protected function render_period_form( string $page_slug, string $period, bool $include_all_time, array $query_args = array() ): void {
		$periods = $include_all_time ? array( 'all', '24h', '7d', '30d', '365d' ) : array( '24h', '7d', '30d', '365d' );
		?>
		<form class="vwfw-period-form" method="get">
			<input type="hidden" name="page" value="<?php echo esc_attr( $page_slug ); ?>">
			<?php foreach ( $query_args as $name => $value ) : ?>
				<input type="hidden" name="<?php echo esc_attr( (string) $name ); ?>" value="<?php echo esc_attr( (string) $value ); ?>">
			<?php endforeach; ?>
			<label for="vwfw-period"><strong>Range</strong></label>
			<select id="vwfw-period" name="period">
				<?php foreach ( $periods as $period_option ) : ?>
					<option value="<?php echo esc_attr( $period_option ); ?>" <?php selected( $period, $period_option ); ?>>
						<?php echo esc_html( $period_option === 'all' ? 'All Time' : $this->report_period->label( $period_option ) ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<button type="submit" class="button">Apply</button>
		</form>
		<?php
	}

	protected function current_period( string $default_period ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameter.
		$period  = isset( $_GET['period'] ) ? sanitize_key( (string) wp_unslash( $_GET['period'] ) ) : $default_period;
		$allowed = array( 'all', '24h', '7d', '30d', '365d' );

		return in_array( $period, $allowed, true ) ? $period : $default_period;
	}

	protected function current_page_number(): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin pagination parameter.
		return max( 1, (int) ( $_GET['paged'] ?? 1 ) );
	}

	protected function period_seconds_for( string $period ): ?int {
		return 'all' === $period ? null : $this->report_period->seconds( $period );
	}

	protected function create_paginator( int $total_items, int $items_per_page, string $page_slug, string $period = 'all', array $query_args = array() ): AdminPaginator {
		return new AdminPaginator( $total_items, $items_per_page, $this->current_page_number(), $page_slug, $period, $query_args );
	}

	protected function render_summary_card( string $label, int $value ): void {
		?>
		<div class="vwfw-card">
			<span class="vwfw-card-label"><?php echo esc_html( $label ); ?></span>
			<strong><?php echo esc_html( number_format_i18n( $value ) ); ?></strong>
		</div>
		<?php
	}

	protected function render_record_header( string $title, string $description, int $total_items, bool $show_total = true ): void {
		?>
		<div class="vwfw-record-header">
			<div>
				<h2><?php echo esc_html( $title ); ?></h2>
				<p class="description"><?php echo esc_html( $description ); ?></p>
			</div>
			<?php if ( $show_total ) : ?>
				<div class="vwfw-record-total">
					<span class="vwfw-record-total-label">Total matching rows</span>
					<strong><?php echo esc_html( number_format_i18n( $total_items ) ); ?></strong>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	protected function assert_page_access(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions.' );
		}
	}
}
