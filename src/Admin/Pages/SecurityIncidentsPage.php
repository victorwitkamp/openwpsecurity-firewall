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

	public function __construct( SecurityIncidentReport $security_incident_report, SecurityIncidentFilterInput $security_incident_filter_input, CountryDistributionPanel $country_distribution_panel, FilterFormRenderer $filter_form_renderer, RecordTablePanel $record_table_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->security_incident_report       = $security_incident_report;
		$this->security_incident_filter_input = $security_incident_filter_input;
		$this->country_distribution_panel     = $country_distribution_panel;
		$this->filter_form_renderer           = $filter_form_renderer;
		$this->record_table_panel             = $record_table_panel;
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
			<h1>OpenWPSecurity - Firewall Security Incidents</h1>
			<p>Review firewall interventions, challenge outcomes, temporary bans, and permanent-ban escalations.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-security' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall-security', $period, true, $this->security_incident_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_filters_form( $filters, $country_options ); ?>

			<?php $this->country_distribution_panel->render( $countries, 'Security Incidents by Country', 'Incidents' ); ?>

			<?php
			$this->record_table_panel->render(
				'Security Incidents',
				'Firewall interventions, challenge events, temporary bans, and permanent bans, separate from Login Protection activity.',
				$total_items,
				$paginator->render(),
				array( 'Time', 'Type', 'IP', 'Country', 'Request Type', 'Temporary Ban Expires', 'Details', 'Request URI' ),
				$rows,
				'No security incidents found for this period.',
				'widefat striped fixed vwfw-incident-table',
				function ( array $row ): void {
					$details = $this->event_report_formatter->details_from_json( (string) ( $row['details'] ?? '' ) );
					?>
					<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
					<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
					<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
					<td><?php echo esc_html( trim( ( (string) $row['country_code'] ) . ' ' . ( (string) $row['country_name'] ) ) ); ?></td>
					<td><?php echo esc_html( $this->incident_request_type_label( (string) ( $row['request_type'] ?? '' ), $details ) ); ?></td>
					<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( $this->format_incident_details( (string) $row['event_type'], $details ) ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
					<?php
				}
			);
		?>
		</div>
		<?php
	}

	private function render_filters_form( array $filters, array $country_options ): void {
		$country_select_options = array( '' => 'All Countries' );

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
					'label'   => 'Event Type',
					'value'   => $filters['event_type'],
					'options' => $this->event_report_formatter->event_type_options( $this->security_incident_filter_input->event_types() ),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-incident-request-type',
					'name'    => 'request_type',
					'label'   => 'Request Type',
					'value'   => $filters['request_type'],
					'options' => $this->event_report_formatter->request_type_options(),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-incident-country',
					'name'    => 'country_code',
					'label'   => 'Country',
					'value'   => $filters['country_code'],
					'options' => $country_select_options,
				),
				array(
					'id'    => 'vwfw-incident-ip',
					'name'  => 'ip_address',
					'label' => 'IP Contains',
					'value' => $filters['ip_address'],
				),
				array(
					'id'    => 'vwfw-incident-uri',
					'name'  => 'request_uri',
					'label' => 'URI Contains',
					'value' => $filters['request_uri'],
				),
			),
			admin_url( 'admin.php?page=openwpsecurity-firewall-security&period=' . $this->current_period( 'all' ) )
		);
	}

	private function incident_request_type_label( string $request_type, array $details ): string {
		if ( '' !== $request_type ) {
			return $this->event_report_formatter->request_type_label( $request_type );
		}

		if ( ! empty( $details['request_type'] ) ) {
			return $this->event_report_formatter->request_type_label( (string) $details['request_type'] );
		}

		return '';
	}

	private function format_incident_details( string $event_type, array $details ): string {
		if ( 'captcha_required' === $event_type ) {
			$message = sprintf(
				'Rate limit reached on %s at %d hits in %d seconds. A shared captcha challenge was rendered.',
				$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 )
			);

			if ( isset( $details['captcha_challenge_count'], $details['captcha_challenges_before_temporary_block'] ) && (int) $details['captcha_challenges_before_temporary_block'] > 0 ) {
				$message .= sprintf(
					' Unsolved challenge pages: %d/%d.',
					(int) $details['captcha_challenge_count'],
					(int) $details['captcha_challenges_before_temporary_block']
				);
			}

			return $message;
		}

		if ( 'captcha_failed' === $event_type ) {
			return sprintf(
				'Captcha answer did not match the stored challenge. Failures: %d/%d in %d minute(s).',
				(int) ( $details['captcha_failure_count'] ?? 0 ),
				(int) ( $details['captcha_failure_threshold'] ?? 0 ),
				(int) ( $details['captcha_failure_window_minutes'] ?? 0 )
			);
		}

		if ( 'captcha_passed' === $event_type ) {
			return sprintf(
				'Captcha solved successfully. Bypass cookie active for %d minute(s).',
				(int) ( $details['captcha_pass_minutes'] ?? 0 )
			);
		}

		if ( 'permanent_ban_created' === $event_type ) {
			if ( 'request_handling' === (string) ( $details['source'] ?? '' ) ) {
				if ( 'active_temporary_block_denials' === (string) ( $details['reason'] ?? '' ) ) {
					return sprintf(
						'Request handling permanently banned this IP after %d denied request(s) during an active temporary ban triggered by %s.',
						(int) ( $details['active_block_denial_count'] ?? 0 ),
						$this->event_report_formatter->request_type_label( (string) ( $details['trigger_request_type'] ?? '' ) )
					);
				}

				if ( 'captcha_challenge_volume' === (string) ( $details['reason'] ?? '' ) ) {
					return sprintf(
						'Request handling permanently banned this IP after repeated unsolved captcha challenge pages on %s and %d temporary ban(s).',
						$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
						(int) ( $details['temporary_block_count'] ?? 0 )
					);
				}

				return sprintf(
					'%s via request handling on %s after %d temporary ban(s).',
					(string) ( $details['reason'] ?? 'Permanent ban created' ),
					$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
					(int) ( $details['temporary_block_count'] ?? 0 )
				);
			}

			return sprintf(
				'%s via %s after %d lockout(s).',
				(string) ( $details['reason'] ?? 'Permanent ban created' ),
				$this->event_report_formatter->ban_source_label( (string) ( $details['source'] ?? 'unknown source' ) ),
				(int) ( $details['lockout_count'] ?? 0 )
			);
		}

		if ( 'request_rate_limited' === $event_type ) {
			$message = sprintf(
				'%d hits in %d seconds against a threshold of %d.',
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? ( $details['window_seconds'] ?? 0 ) ),
				(int) ( $details['rate_limit_threshold'] ?? ( $details['threshold'] ?? 0 ) )
			);

			if ( ! empty( $details['response_action'] ) ) {
				if ( 'captcha_page' === $details['response_action'] ) {
					$message .= ' A shared captcha challenge handled the response.';
				} elseif ( 'rate_limit_page' === $details['response_action'] ) {
					$message .= ' A 429 rate-limit page handled the response.';
				} elseif ( 'message_only' === $details['response_action'] ) {
					$message .= ' The endpoint returned a 429 firewall message without creating a temporary ban.';
				} elseif ( 'temporary_block' === $details['response_action'] ) {
					$message .= ' Request handling escalated immediately into a temporary ban.';
				}
			}

			if ( ! empty( $details['temporary_block_enabled'] ) ) {
				$message .= ' Temporary bans were enabled for this request.';
			}

			return $message;
		}

		if ( 'request_temporary_block_created' === $event_type ) {
			if ( 'captcha_failed' === (string) ( $details['reason'] ?? '' ) ) {
				$message = sprintf(
					'%d failed captcha answer(s) in %d minute(s) created a temporary ban for %d minute(s).',
					(int) ( $details['captcha_failure_count'] ?? 0 ),
					(int) ( $details['captcha_failure_window_minutes'] ?? 0 ),
					(int) ( $details['temporary_block_minutes'] ?? 0 )
				);

				if ( isset( $details['temporary_block_count'] ) && isset( $details['temporary_blocks_before_permanent_ban'] ) ) {
					$message .= sprintf(
						' Temporary bans: %d/%d.',
						(int) $details['temporary_block_count'],
						(int) $details['temporary_blocks_before_permanent_ban']
					);
				}

				return $message;
			}

			if ( 'captcha_challenge_volume' === (string) ( $details['reason'] ?? '' ) ) {
				$message = sprintf(
					'%d unsolved captcha challenge page(s) in %d seconds created a temporary ban for %d minute(s).',
					(int) ( $details['captcha_challenge_count'] ?? 0 ),
					(int) ( $details['captcha_challenge_window_seconds'] ?? 0 ),
					(int) ( $details['temporary_block_minutes'] ?? 0 )
				);

				if ( isset( $details['temporary_block_count'] ) && isset( $details['temporary_blocks_before_permanent_ban'] ) ) {
					$message .= sprintf(
						' Temporary bans: %d/%d.',
						(int) $details['temporary_block_count'],
						(int) $details['temporary_blocks_before_permanent_ban']
					);
				}

				return $message;
			}

			$message = sprintf(
				'%d hits in %d seconds against a threshold of %d created a temporary ban for %d minute(s).',
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 ),
				(int) ( $details['rate_limit_threshold'] ?? 0 ),
				(int) ( $details['temporary_block_minutes'] ?? 0 )
			);

			if ( isset( $details['temporary_block_count'] ) && isset( $details['temporary_blocks_before_permanent_ban'] ) ) {
				$message .= sprintf(
					' Temporary bans: %d/%d.',
					(int) $details['temporary_block_count'],
					(int) $details['temporary_blocks_before_permanent_ban']
				);
			}

			return $message;
		}

		if ( 'request_temporarily_blocked' === $event_type ) {
			$message = 'An active Firewall temporary ban denied this request.';

			if ( ! empty( $details['trigger_request_type'] ) ) {
				$message .= ' Triggered by ' . $this->event_report_formatter->request_type_label( (string) $details['trigger_request_type'] ) . '.';
			}

			if ( isset( $details['active_block_denial_count'], $details['active_block_denials_before_permanent_ban'] ) && (int) $details['active_block_denials_before_permanent_ban'] > 0 ) {
				$message .= sprintf(
					' Active-block denials: %d/%d.',
					(int) $details['active_block_denial_count'],
					(int) $details['active_block_denials_before_permanent_ban']
				);
			}

			return $message;
		}

		return '';
	}
}
