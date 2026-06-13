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
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\SecurityIncidentDetailsFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests\SecurityIncidentFilterInput;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\SecurityIncidentReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentsPage extends AbstractAdminPage {
	private const PER_PAGE = 25;

	private SecurityIncidentReport $security_incident_report;
	private SecurityIncidentFilterInput $security_incident_filter_input;
	private CountryDistributionPanel $country_distribution_panel;
	private FilterFormRenderer $filter_form_renderer;
	private RecordTablePanel $record_table_panel;
	private SecurityIncidentDetailsFormatter $security_incident_details_formatter;

	public function __construct( SecurityIncidentReport $security_incident_report, SecurityIncidentFilterInput $security_incident_filter_input, CountryDistributionPanel $country_distribution_panel, FilterFormRenderer $filter_form_renderer, RecordTablePanel $record_table_panel, SecurityIncidentDetailsFormatter $security_incident_details_formatter, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->security_incident_report            = $security_incident_report;
		$this->security_incident_filter_input      = $security_incident_filter_input;
		$this->country_distribution_panel          = $country_distribution_panel;
		$this->filter_form_renderer                = $filter_form_renderer;
		$this->record_table_panel                  = $record_table_panel;
		$this->security_incident_details_formatter = $security_incident_details_formatter;
	}

	public function render(): void {
		$this->assert_page_access();

		$period          = $this->current_period( 'all' );
		$period_seconds  = $this->period_seconds_for( $period );
		$filters         = $this->security_incident_filter_input->read();
		$total_items     = $this->security_incident_report->count( $filters, $period_seconds );
		$paginator       = $this->create_paginator( $total_items, self::PER_PAGE, 'openwpsecurity-firewall-security', $period, $this->security_incident_filter_input->query_args( $filters ) );
		$rows            = $this->security_incident_report->rows( $filters, $period_seconds, self::PER_PAGE, $paginator->offset() );
		$countries       = $this->security_incident_report->countries( $filters, $period_seconds );
		$country_options = $this->security_incident_report->country_options( $this->security_incident_filter_input->country_option_filters( $filters ), $period_seconds );
		?>
		<div class="wrap vwfw-admin">
			<h1><?php esc_html_e( 'OpenWPSecurity - Firewall Security Incidents', 'openwpsecurity-firewall' ); ?></h1>
			<p><?php esc_html_e( 'Review firewall interventions, challenge outcomes, temporary bans, and permanent-ban escalations.', 'openwpsecurity-firewall' ); ?></p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-security' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall-security', $period, true, $this->security_incident_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_filters_form( $filters, $country_options ); ?>

			<?php $this->country_distribution_panel->render( $countries, __( 'Security Incidents by Country', 'openwpsecurity-firewall' ), __( 'Incidents', 'openwpsecurity-firewall' ) ); ?>

			<?php
			$this->record_table_panel->render(
				__( 'Security Incidents', 'openwpsecurity-firewall' ),
				__( 'Firewall interventions, challenge events, temporary bans, and permanent bans, separate from Login Protection activity.', 'openwpsecurity-firewall' ),
				$total_items,
				$paginator->render(),
				array(
					__( 'Time', 'openwpsecurity-firewall' ),
					__( 'Type', 'openwpsecurity-firewall' ),
					__( 'IP', 'openwpsecurity-firewall' ),
					__( 'Country', 'openwpsecurity-firewall' ),
					__( 'Request Type', 'openwpsecurity-firewall' ),
					__( 'Temporary Ban Expires', 'openwpsecurity-firewall' ),
					__( 'Details', 'openwpsecurity-firewall' ),
					__( 'Request URI', 'openwpsecurity-firewall' ),
				),
				$rows,
				__( 'No security incidents found for this period.', 'openwpsecurity-firewall' ),
				'widefat striped fixed vwfw-incident-table',
				function ( array $row ): void {
					$details = $this->event_report_formatter->details_from_json( (string) ( $row['details'] ?? '' ) );
					?>
					<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
					<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
					<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
					<td><?php echo esc_html( trim( ( (string) $row['country_code'] ) . ' ' . ( (string) $row['country_name'] ) ) ); ?></td>
					<td><?php echo esc_html( $this->security_incident_details_formatter->request_type_label( (string) ( $row['request_type'] ?? '' ), $details ) ); ?></td>
					<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( $this->security_incident_details_formatter->details( (string) $row['event_type'], $details ) ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
					<?php
				}
			);
		?>
		</div>
		<?php
	}

	private function render_filters_form( array $filters, array $country_options ): void {
		$country_select_options = array( '' => __( 'All Countries', 'openwpsecurity-firewall' ) );

		foreach ( $country_options as $country ) {
			$country_select_options[ (string) $country['code'] ] = (string) $country['label'];
		}

		$this->filter_form_renderer->render(
			'openwpsecurity-firewall-security',
			$this->current_period( 'all' ),
			array(
				array(
					'type'    => 'select',
					'id'      => 'vwfw-incident-event-type',
					'name'    => 'event_type',
					'label'   => __( 'Event Type', 'openwpsecurity-firewall' ),
					'value'   => $filters['event_type'],
					'options' => $this->event_report_formatter->event_type_options( $this->security_incident_filter_input->event_types() ),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-incident-request-type',
					'name'    => 'request_type',
					'label'   => __( 'Request Type', 'openwpsecurity-firewall' ),
					'value'   => $filters['request_type'],
					'options' => $this->event_report_formatter->request_type_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-incident-country',
					'name'    => 'country_code',
					'label'   => __( 'Country', 'openwpsecurity-firewall' ),
					'value'   => $filters['country_code'],
					'options' => $country_select_options,
				),
				array(
					'id'    => 'vwfw-incident-ip',
					'name'  => 'ip_address',
					'label' => __( 'IP Contains', 'openwpsecurity-firewall' ),
					'value' => $filters['ip_address'],
				),
				array(
					'id'    => 'vwfw-incident-uri',
					'name'  => 'request_uri',
					'label' => __( 'URI Contains', 'openwpsecurity-firewall' ),
					'value' => $filters['request_uri'],
				),
			),
			admin_url( 'admin.php?page=openwpsecurity-firewall-security&period=' . $this->current_period( 'all' ) )
		);
	}
}
