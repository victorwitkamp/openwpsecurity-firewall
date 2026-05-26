<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\PermanentBanStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PermanentBansPage extends AbstractAdminPage {
	private const PER_PAGE = 50;

	private PermanentBanStore $ban_store;

	public function __construct( PermanentBanStore $ban_store, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter );
		$this->ban_store = $ban_store;
	}

	public function render(): void {
		$this->assert_page_access();

		$rows = array_values( $this->ban_store->get_all_bans() );

		usort(
			$rows,
			static function ( array $left, array $right ): int {
				return strcmp( (string) ( $right['banned_at'] ?? '' ), (string) ( $left['banned_at'] ?? '' ) );
			}
		);

		$total_items = count( $rows );
		$paginator   = $this->create_paginator( $total_items, self::PER_PAGE, 'openwpsecurity-firewall-bans' );
		$rows        = array_slice( $rows, $paginator->offset(), self::PER_PAGE );
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Permanent Bans</h1>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-bans' ); ?>

			<div class="vwfw-panel vwfw-record-panel">
				<?php $this->render_record_header( 'Permanently Banned IP Addresses', 'These IP addresses are blocked from all request types and will only receive the firewall error response.', $total_items ); ?>
				<?php echo wp_kses_post( $paginator->render() ); ?>
				<div class="vwfw-record-table-wrap">
					<table class="widefat striped fixed">
						<thead>
							<tr>
								<th>Banned At</th>
								<th>IP Address</th>
								<th>Source</th>
								<th>Reason</th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $rows ) ) : ?>
								<tr>
									<td colspan="4">No permanently banned IP addresses were found.</td>
								</tr>
							<?php else : ?>
								<?php foreach ( $rows as $row ) : ?>
									<tr>
										<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) ( $row['banned_at'] ?? '' ) ) ); ?></td>
										<td><?php echo esc_html( (string) ( $row['ip_address'] ?? '' ) ); ?></td>
										<td><?php echo esc_html( $this->event_report_formatter->ban_source_label( (string) ( $row['source'] ?? '' ) ) ); ?></td>
										<td class="vwfw-break"><?php echo esc_html( (string) ( $row['reason'] ?? '' ) ); ?></td>
									</tr>
								<?php endforeach; ?>
							<?php endif; ?>
						</tbody>
					</table>
				</div>
				<?php echo wp_kses_post( $paginator->render() ); ?>
			</div>
		</div>
		<?php
	}
}
