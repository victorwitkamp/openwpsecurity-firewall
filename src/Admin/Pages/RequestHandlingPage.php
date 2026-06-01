<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\FilterFormRenderer;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\RecordTablePanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests\RequestActivityFilterInput;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\RequestActivityReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingPage extends AbstractAdminPage {
	private const PER_PAGE = 25;

	private RequestActivityReport $request_activity_report;
	private RequestActivityFilterInput $request_activity_filter_input;
	private CountryDistributionPanel $country_distribution_panel;
	private FilterFormRenderer $filter_form_renderer;
	private RecordTablePanel $record_table_panel;

	public function __construct( RequestActivityReport $request_activity_report, RequestActivityFilterInput $request_activity_filter_input, CountryDistributionPanel $country_distribution_panel, FilterFormRenderer $filter_form_renderer, RecordTablePanel $record_table_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->request_activity_report       = $request_activity_report;
		$this->request_activity_filter_input = $request_activity_filter_input;
		$this->country_distribution_panel    = $country_distribution_panel;
		$this->filter_form_renderer          = $filter_form_renderer;
		$this->record_table_panel            = $record_table_panel;
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

			<?php
			$this->record_table_panel->render(
				'Request Log',
				'This view includes frontend pages, login, admin, AJAX, REST API, XML-RPC, and wp-cron requests.',
				$total_items,
				$paginator->render(),
				array( 'Time', 'Request Type', 'Method', 'IP', 'Country', 'Frontend HTML', 'Request URI', 'User Agent' ),
				$rows,
				'No requests found for this period.',
				'widefat striped fixed vwfw-request-log-table',
				function ( array $row ): void {
					$details = $this->event_report_formatter->details_from_json( (string) ( $row['details'] ?? '' ) );
					?>
					<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
					<td><?php echo esc_html( $this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ) ); ?></td>
					<td><?php echo esc_html( (string) ( $details['method'] ?? '' ) ); ?></td>
					<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
					<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
					<td><?php echo esc_html( ! empty( $details['is_frontend_html'] ) ? 'Yes' : 'No' ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( (string) $row['user_agent'] ); ?></td>
					<?php
				}
			);
		?>
		</div>
		<?php
	}

	private function render_request_filters_form( array $filters, array $country_options ): void {
		$country_select_options = array( '' => 'All Countries' );

		foreach ( $country_options as $country ) {
			$country_select_options[ (string) $country['code'] ] = (string) $country['label'];
		}

		$this->filter_form_renderer->render(
			'openwpsecurity-firewall-request-handling',
			$this->current_period( 'all' ),
			array(
				array(
					'type'    => 'select',
					'id'      => 'vwfw-request-type',
					'name'    => 'request_type',
					'label'   => 'Request Type',
					'value'   => $filters['request_type'],
					'options' => $this->event_report_formatter->request_type_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-request-method',
					'name'    => 'method',
					'label'   => 'Method',
					'value'   => $filters['method'],
					'options' => $this->event_report_formatter->method_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-country-code',
					'name'    => 'country_code',
					'label'   => 'Country',
					'value'   => $filters['country_code'],
					'options' => $country_select_options,
				),
				array(
					'id'    => 'vwfw-request-ip',
					'name'  => 'ip_address',
					'label' => 'IP Contains',
					'value' => $filters['ip_address'],
				),
				array(
					'id'    => 'vwfw-request-uri',
					'name'  => 'request_uri',
					'label' => 'URI Contains',
					'value' => $filters['request_uri'],
				),
				array(
					'id'    => 'vwfw-request-agent',
					'name'  => 'user_agent',
					'label' => 'User Agent Contains',
					'value' => $filters['user_agent'],
				),
				array(
					'type'    => 'checkboxes',
					'choices' => array(
						array(
							'name'    => 'external_only',
							'label'   => 'External only',
							'checked' => ! empty( $filters['external_only'] ),
						),
						array(
							'name'    => 'exclude_internal',
							'label'   => 'Hide admin/ajax/cron',
							'checked' => ! empty( $filters['exclude_internal'] ),
						),
						array(
							'name'    => 'exclude_my_ip',
							'label'   => 'Exclude my IP',
							'checked' => ! empty( $filters['exclude_my_ip'] ),
						),
					),
				),
			),
			admin_url( 'admin.php?page=openwpsecurity-firewall-request-handling&period=' . $this->current_period( 'all' ) )
		);
	}
}
