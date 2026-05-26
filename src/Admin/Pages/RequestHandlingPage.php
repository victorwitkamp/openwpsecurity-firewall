<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests\RequestActivityFilterInput;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\RequestActivityReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingPage extends AbstractAdminPage {
	private const PER_PAGE = 50;

	private RequestActivityReport $request_activity_report;
	private RequestActivityFilterInput $request_activity_filter_input;
	private CountryDistributionPanel $country_distribution_panel;

	public function __construct( RequestActivityReport $request_activity_report, RequestActivityFilterInput $request_activity_filter_input, CountryDistributionPanel $country_distribution_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter );
		$this->request_activity_report       = $request_activity_report;
		$this->request_activity_filter_input = $request_activity_filter_input;
		$this->country_distribution_panel    = $country_distribution_panel;
	}

	public function render(): void {
		$this->assert_page_access();

		$period          = $this->current_period( 'all' );
		$period_seconds  = $this->period_seconds_for( $period );
		$filters         = $this->request_activity_filter_input->read();
		$total_items     = $this->request_activity_report->count( $filters, $period_seconds );
		$paginator       = $this->create_paginator( $total_items, self::PER_PAGE, 'openwpsecurity-firewall-request-handling', $period, $this->request_activity_filter_input->query_args( $filters ) );
		$rows            = $this->request_activity_report->rows( $filters, $period_seconds, self::PER_PAGE, $paginator->offset() );
		$countries       = $this->request_activity_report->countries( $filters, $period_seconds );
		$country_options = $this->request_activity_report->country_options( $this->request_activity_filter_input->country_option_filters( $filters ), $period_seconds );
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Request Handling</h1>
			<p>Every request that reaches WordPress is logged here. Frontend page visits are included as <strong>Frontend Page</strong> requests, rate limits are endpoint-local, <strong>Frontend Page</strong> and <strong>WP Login</strong> return an HTTP 429 page when exceeded, and any active request-handling temporary block denies all request types.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-request-handling' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall-request-handling', $period, true, $this->request_activity_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_request_filters_form( $filters, $country_options ); ?>

			<?php $this->country_distribution_panel->render( $countries, 'Requests by Country', 'Requests' ); ?>

			<div class="vwfw-panel vwfw-record-panel">
				<?php $this->render_record_header( 'Request Log', 'This view includes frontend pages, login, admin, AJAX, REST API, XML-RPC, and wp-cron requests.', $total_items ); ?>
				<?php echo wp_kses_post( $paginator->render() ); ?>
				<div class="vwfw-record-table-wrap">
					<table class="widefat striped fixed">
						<thead>
							<tr>
								<th>Time</th>
								<th>Request Type</th>
								<th>Method</th>
								<th>IP</th>
								<th>Country</th>
								<th>Frontend HTML</th>
								<th>Request URI</th>
								<th>User Agent</th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $rows ) ) : ?>
								<tr>
									<td colspan="8">No requests found for this period.</td>
								</tr>
							<?php else : ?>
								<?php foreach ( $rows as $row ) : ?>
									<?php $details = $this->event_report_formatter->details_from_json( (string) ( $row['details'] ?? '' ) ); ?>
									<tr>
										<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
										<td><?php echo esc_html( $this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ) ); ?></td>
										<td><?php echo esc_html( (string) ( $details['method'] ?? '' ) ); ?></td>
										<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
										<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
										<td><?php echo esc_html( ! empty( $details['is_frontend_html'] ) ? 'Yes' : 'No' ); ?></td>
										<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
										<td class="vwfw-break"><?php echo esc_html( (string) $row['user_agent'] ); ?></td>
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

	private function render_request_filters_form( array $filters, array $country_options ): void {
		?>
		<form class="vwfw-record-filters vwfw-panel" method="get">
			<input type="hidden" name="page" value="openwpsecurity-firewall-request-handling">
			<input type="hidden" name="period" value="<?php echo esc_attr( $this->current_period( 'all' ) ); ?>">
			<div class="vwfw-filter-grid">
				<div>
					<label for="vwfw-request-type"><strong>Request Type</strong></label>
					<select id="vwfw-request-type" name="request_type">
						<?php foreach ( $this->event_report_formatter->request_type_options() as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $filters['request_type'], $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-request-method"><strong>Method</strong></label>
					<select id="vwfw-request-method" name="method">
						<?php foreach ( $this->event_report_formatter->method_options() as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $filters['method'], $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-country-code"><strong>Country</strong></label>
					<select id="vwfw-country-code" name="country_code">
						<option value="">All Countries</option>
						<?php foreach ( $country_options as $country ) : ?>
							<option value="<?php echo esc_attr( (string) $country['code'] ); ?>" <?php selected( $filters['country_code'], (string) $country['code'] ); ?>>
								<?php echo esc_html( (string) $country['label'] ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-request-ip"><strong>IP Contains</strong></label>
					<input id="vwfw-request-ip" type="text" name="ip_address" value="<?php echo esc_attr( $filters['ip_address'] ); ?>">
				</div>
				<div>
					<label for="vwfw-request-uri"><strong>URI Contains</strong></label>
					<input id="vwfw-request-uri" type="text" name="request_uri" value="<?php echo esc_attr( $filters['request_uri'] ); ?>">
				</div>
				<div>
					<label for="vwfw-request-agent"><strong>User Agent Contains</strong></label>
					<input id="vwfw-request-agent" type="text" name="user_agent" value="<?php echo esc_attr( $filters['user_agent'] ); ?>">
				</div>
				<div class="vwfw-filter-flags">
					<label><input type="checkbox" name="external_only" value="1" <?php checked( ! empty( $filters['external_only'] ) ); ?>> External only</label>
					<label><input type="checkbox" name="exclude_internal" value="1" <?php checked( ! empty( $filters['exclude_internal'] ) ); ?>> Hide admin/ajax/cron</label>
					<label><input type="checkbox" name="exclude_my_ip" value="1" <?php checked( ! empty( $filters['exclude_my_ip'] ) ); ?>> Exclude my IP</label>
				</div>
				<div class="vwfw-filter-actions">
					<button type="submit" class="button button-primary">Apply Filters</button>
					<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=openwpsecurity-firewall-request-handling&period=' . $this->current_period( 'all' ) ) ); ?>">Reset</a>
				</div>
			</div>
		</form>
		<?php
	}
}
