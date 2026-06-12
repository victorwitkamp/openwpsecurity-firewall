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
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests\RequestLogFilterInput;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\RequestLogReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestLogPage extends AbstractAdminPage {
	private const PER_PAGE  = 25;
	private const PAGE_SLUG = 'openwpsecurity-firewall-request-log';

	private RequestLogReport $request_log_report;
	private RequestLogFilterInput $request_log_filter_input;
	private CountryDistributionPanel $country_distribution_panel;
	private FilterFormRenderer $filter_form_renderer;
	private RecordTablePanel $record_table_panel;

	public function __construct( RequestLogReport $request_log_report, RequestLogFilterInput $request_log_filter_input, CountryDistributionPanel $country_distribution_panel, FilterFormRenderer $filter_form_renderer, RecordTablePanel $record_table_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->request_log_report         = $request_log_report;
		$this->request_log_filter_input   = $request_log_filter_input;
		$this->country_distribution_panel = $country_distribution_panel;
		$this->filter_form_renderer       = $filter_form_renderer;
		$this->record_table_panel         = $record_table_panel;
	}

	public function render(): void {
		$this->assert_page_access();

		$period          = $this->current_period( 'all' );
		$period_seconds  = $this->period_seconds_for( $period );
		$filters         = $this->request_log_filter_input->read();
		$total_items     = $this->request_log_report->count( $filters, $period_seconds );
		$paginator       = $this->create_paginator( $total_items, self::PER_PAGE, self::PAGE_SLUG, $period, $this->request_log_filter_input->query_args( $filters ) );
		$rows            = $this->request_log_report->rows( $filters, $period_seconds, self::PER_PAGE, $paginator->offset() );
		$countries       = $this->request_log_report->countries( $filters, $period_seconds );
		$country_options = $this->request_log_report->country_options( $this->request_log_filter_input->country_option_filters( $filters ), $period_seconds );
		?>
		<div class="wrap vwfw-admin">
			<h1><?php esc_html_e( 'OpenWPSecurity - Firewall Request Log', 'openwpsecurity-firewall' ); ?></h1>
			<p><?php echo wp_kses_post( __( 'Inspect requests that reached WordPress. Current enforcement behavior is configured on the <strong>Policies</strong> page.', 'openwpsecurity-firewall' ) ); ?></p>
			<?php $this->render_page_tabs( self::PAGE_SLUG ); ?>
			<?php $this->render_period_form( self::PAGE_SLUG, $period, true, $this->request_log_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_request_filters_form( $filters, $country_options ); ?>

			<?php $this->country_distribution_panel->render( $countries, __( 'Requests by Country', 'openwpsecurity-firewall' ), __( 'Requests', 'openwpsecurity-firewall' ) ); ?>

			<?php
			$this->record_table_panel->render(
				__( 'Request Log', 'openwpsecurity-firewall' ),
				__( 'This view includes frontend pages, login, admin, AJAX, REST API, XML-RPC, and wp-cron requests.', 'openwpsecurity-firewall' ),
				$total_items,
				$paginator->render(),
				array(
					__( 'Time', 'openwpsecurity-firewall' ),
					__( 'Request Type', 'openwpsecurity-firewall' ),
					__( 'Method', 'openwpsecurity-firewall' ),
					__( 'IP', 'openwpsecurity-firewall' ),
					__( 'Country', 'openwpsecurity-firewall' ),
					__( 'Frontend HTML', 'openwpsecurity-firewall' ),
					__( 'Request URI', 'openwpsecurity-firewall' ),
					__( 'User Agent', 'openwpsecurity-firewall' ),
				),
				$rows,
				__( 'No requests found for this period.', 'openwpsecurity-firewall' ),
				'widefat striped fixed vwfw-request-log-table',
				function ( array $row ): void {
					?>
					<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
					<td><?php echo esc_html( $this->event_report_formatter->request_type_label( (string) ( $row['request_type'] ?? '' ) ) ); ?></td>
					<td><?php echo esc_html( (string) ( $row['method'] ?? '' ) ); ?></td>
					<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
					<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
					<td><?php echo esc_html( ! empty( $row['is_frontend_html'] ) ? __( 'Yes', 'openwpsecurity-firewall' ) : __( 'No', 'openwpsecurity-firewall' ) ); ?></td>
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
		$country_select_options = array( '' => __( 'All Countries', 'openwpsecurity-firewall' ) );

		foreach ( $country_options as $country ) {
			$country_select_options[ (string) $country['code'] ] = (string) $country['label'];
		}

		$this->filter_form_renderer->render(
			self::PAGE_SLUG,
			$this->current_period( 'all' ),
			array(
				array(
					'type'    => 'select',
					'id'      => 'vwfw-request-type',
					'name'    => 'request_type',
					'label'   => __( 'Request Type', 'openwpsecurity-firewall' ),
					'value'   => $filters['request_type'],
					'options' => $this->event_report_formatter->request_type_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-request-method',
					'name'    => 'method',
					'label'   => __( 'Method', 'openwpsecurity-firewall' ),
					'value'   => $filters['method'],
					'options' => $this->event_report_formatter->method_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-country-code',
					'name'    => 'country_code',
					'label'   => __( 'Country', 'openwpsecurity-firewall' ),
					'value'   => $filters['country_code'],
					'options' => $country_select_options,
				),
				array(
					'id'    => 'vwfw-request-ip',
					'name'  => 'ip_address',
					'label' => __( 'IP Contains', 'openwpsecurity-firewall' ),
					'value' => $filters['ip_address'],
				),
				array(
					'id'    => 'vwfw-request-uri',
					'name'  => 'request_uri',
					'label' => __( 'URI Contains', 'openwpsecurity-firewall' ),
					'value' => $filters['request_uri'],
				),
				array(
					'id'    => 'vwfw-request-agent',
					'name'  => 'user_agent',
					'label' => __( 'User Agent Contains', 'openwpsecurity-firewall' ),
					'value' => $filters['user_agent'],
				),
				array(
					'type'    => 'checkboxes',
					'choices' => array(
						array(
							'name'    => 'external_only',
							'label'   => __( 'External only', 'openwpsecurity-firewall' ),
							'checked' => ! empty( $filters['external_only'] ),
						),
						array(
							'name'    => 'exclude_internal',
							'label'   => __( 'Hide admin/ajax/cron', 'openwpsecurity-firewall' ),
							'checked' => ! empty( $filters['exclude_internal'] ),
						),
						array(
							'name'    => 'exclude_my_ip',
							'label'   => __( 'Exclude my IP', 'openwpsecurity-firewall' ),
							'checked' => ! empty( $filters['exclude_my_ip'] ),
						),
					),
				),
			),
			admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&period=' . $this->current_period( 'all' ) )
		);
	}
}
