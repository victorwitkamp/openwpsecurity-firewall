<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests\SecurityIncidentFilterInput;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports\SecurityIncidentReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentsPage extends AbstractAdminPage {
	private const PER_PAGE = 50;

	private SecurityIncidentReport $security_incident_report;
	private SecurityIncidentFilterInput $security_incident_filter_input;
	private CountryDistributionPanel $country_distribution_panel;

	public function __construct( SecurityIncidentReport $security_incident_report, SecurityIncidentFilterInput $security_incident_filter_input, CountryDistributionPanel $country_distribution_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter );
		$this->security_incident_report       = $security_incident_report;
		$this->security_incident_filter_input = $security_incident_filter_input;
		$this->country_distribution_panel     = $country_distribution_panel;
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
			<?php $this->render_page_tabs( 'openwpsecurity-firewall-security' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-firewall-security', $period, true, $this->security_incident_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_filters_form( $filters, $country_options ); ?>

			<?php $this->country_distribution_panel->render( $countries, 'Security Incidents by Country', 'Incidents' ); ?>

			<div class="vwfw-panel vwfw-record-panel">
				<?php $this->render_record_header( 'Security Incidents', 'Firewall interventions and challenge events from Request Handling and Captcha, separate from Login Protection activity.', $total_items ); ?>
				<?php echo wp_kses_post( $paginator->render() ); ?>
				<div class="vwfw-record-table-wrap">
					<table class="widefat striped fixed">
						<thead>
							<tr>
								<th>Time</th>
								<th>Type</th>
								<th>IP</th>
								<th>Country</th>
								<th>Request Type</th>
								<th>Lockout Expires</th>
								<th>Details</th>
								<th>Request URI</th>
							</tr>
						</thead>
						<tbody>
							<?php if ( empty( $rows ) ) : ?>
								<tr>
									<td colspan="8">No security incidents found for this period.</td>
								</tr>
							<?php else : ?>
								<?php foreach ( $rows as $row ) : ?>
									<?php $details = $this->event_report_formatter->details_from_json( (string) ( $row['details'] ?? '' ) ); ?>
									<tr>
										<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
										<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
										<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
										<td><?php echo esc_html( trim( ( (string) $row['country_code'] ) . ' ' . ( (string) $row['country_name'] ) ) ); ?></td>
										<td><?php echo esc_html( $this->incident_request_type_label( $details ) ); ?></td>
										<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
										<td class="vwfw-break"><?php echo esc_html( $this->format_incident_details( (string) $row['event_type'], $details ) ); ?></td>
										<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
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

	private function render_filters_form( array $filters, array $country_options ): void {
		?>
		<form class="vwfw-record-filters vwfw-panel" method="get">
			<input type="hidden" name="page" value="openwpsecurity-firewall-security">
			<input type="hidden" name="period" value="<?php echo esc_attr( $this->current_period( 'all' ) ); ?>">
			<div class="vwfw-filter-grid">
				<div>
					<label for="vwfw-incident-event-type"><strong>Event Type</strong></label>
					<select id="vwfw-incident-event-type" name="event_type">
						<?php foreach ( $this->event_report_formatter->event_type_options( $this->security_incident_filter_input->event_types() ) as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $filters['event_type'], $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-incident-request-type"><strong>Request Type</strong></label>
					<select id="vwfw-incident-request-type" name="request_type">
						<?php foreach ( $this->event_report_formatter->request_type_options() as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $filters['request_type'], $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-incident-country"><strong>Country</strong></label>
					<select id="vwfw-incident-country" name="country_code">
						<option value="">All Countries</option>
						<?php foreach ( $country_options as $country ) : ?>
							<option value="<?php echo esc_attr( (string) $country['code'] ); ?>" <?php selected( $filters['country_code'], (string) $country['code'] ); ?>>
								<?php echo esc_html( (string) $country['label'] ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-incident-ip"><strong>IP Contains</strong></label>
					<input id="vwfw-incident-ip" type="text" name="ip_address" value="<?php echo esc_attr( $filters['ip_address'] ); ?>">
				</div>
				<div>
					<label for="vwfw-incident-uri"><strong>URI Contains</strong></label>
					<input id="vwfw-incident-uri" type="text" name="request_uri" value="<?php echo esc_attr( $filters['request_uri'] ); ?>">
				</div>
				<div class="vwfw-filter-actions">
					<button type="submit" class="button button-primary">Apply Filters</button>
					<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=openwpsecurity-firewall-security&period=' . $this->current_period( 'all' ) ) ); ?>">Reset</a>
				</div>
			</div>
		</form>
		<?php
	}

	private function incident_request_type_label( array $details ): string {
		if ( ! empty( $details['request_type'] ) ) {
			return $this->event_report_formatter->request_type_label( (string) $details['request_type'] );
		}

		return '';
	}

	private function format_incident_details( string $event_type, array $details ): string {
		if ( 'captcha_required' === $event_type ) {
			return sprintf(
				'Rate limit reached on %s at %d hits in %d seconds. A shared captcha challenge was rendered.',
				$this->event_report_formatter->request_type_label( (string) ( $details['request_type'] ?? '' ) ),
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 )
			);
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
				return sprintf(
					'%s via request handling on %s after %d temporary block(s).',
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
					$message .= ' The endpoint returned a 429 firewall message without a global temporary block.';
				} elseif ( 'temporary_block' === $details['response_action'] ) {
					$message .= ' Request handling escalated immediately into a global temporary block.';
				}
			}

			if ( ! empty( $details['temporary_block_enabled'] ) ) {
				$message .= ' Global temporary blocks were enabled for this request.';
			}

			return $message;
		}

		if ( 'request_temporary_block_created' === $event_type ) {
			if ( 'captcha_failed' === (string) ( $details['reason'] ?? '' ) ) {
				$message = sprintf(
					'%d failed captcha answer(s) in %d minute(s) created a global temporary block for %d minute(s).',
					(int) ( $details['captcha_failure_count'] ?? 0 ),
					(int) ( $details['captcha_failure_window_minutes'] ?? 0 ),
					(int) ( $details['temporary_block_minutes'] ?? 0 )
				);

				if ( isset( $details['temporary_block_count'] ) && isset( $details['temporary_blocks_before_permanent_ban'] ) ) {
					$message .= sprintf(
						' Temporary blocks: %d/%d.',
						(int) $details['temporary_block_count'],
						(int) $details['temporary_blocks_before_permanent_ban']
					);
				}

				return $message;
			}

			$message = sprintf(
				'%d hits in %d seconds against a threshold of %d created a global temporary block for %d minute(s).',
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? 0 ),
				(int) ( $details['rate_limit_threshold'] ?? 0 ),
				(int) ( $details['temporary_block_minutes'] ?? 0 )
			);

			if ( isset( $details['temporary_block_count'] ) && isset( $details['temporary_blocks_before_permanent_ban'] ) ) {
				$message .= sprintf(
					' Temporary blocks: %d/%d.',
					(int) $details['temporary_block_count'],
					(int) $details['temporary_blocks_before_permanent_ban']
				);
			}

			return $message;
		}

		if ( 'request_temporarily_blocked' === $event_type ) {
			$message = 'A global request-handling temporary block denied this request.';

			if ( ! empty( $details['trigger_request_type'] ) ) {
				$message .= ' Triggered by ' . $this->event_report_formatter->request_type_label( (string) $details['trigger_request_type'] ) . '.';
			}

			return $message;
		}

		return '';
	}
}
