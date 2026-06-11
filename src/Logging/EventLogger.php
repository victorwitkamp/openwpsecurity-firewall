<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Location\GeoIpLookup;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventLogger {
	private Settings $settings;
	private GeoIpLookup $geo_ip_lookup;
	private RequestContext $request_context;
	private RequestLogRepository $request_logs;
	private SecurityIncidentRepository $security_incidents;

	public function __construct( RequestLogRepository $request_logs, SecurityIncidentRepository $security_incidents, Settings $settings, GeoIpLookup $geo_ip_lookup, RequestContext $request_context ) {
		$this->settings           = $settings;
		$this->geo_ip_lookup      = $geo_ip_lookup;
		$this->request_context    = $request_context;
		$this->request_logs       = $request_logs;
		$this->security_incidents = $security_incidents;
	}

	public function log( string $event_type, string $ip, string $username = '', array $extra = array() ): void {
		$settings = $this->settings->get();
		$geo      = $this->geo_ip_lookup->lookup( $ip, ! empty( $settings['enable_remote_geoip'] ) );
		$details  = isset( $extra['details'] ) && is_array( $extra['details'] ) ? $extra['details'] : array();

		$event = array(
			'incident_type'      => $event_type,
			'event_type'         => $event_type,
			'ip_address'         => $ip,
			'country_code'       => (string) ( $geo['country_code'] ?? '' ),
			'country_name'       => (string) ( $geo['country_name'] ?? '' ),
			'username'           => $username,
			'user_agent'         => $this->request_context->current_user_agent(),
			'request_uri'        => $this->request_context->current_url(),
			'lockout_expires_at' => $extra['lockout_expires_at'] ?? null,
			'request_type'       => (string) ( $details['request_type'] ?? '' ),
			'method'             => (string) ( $details['method'] ?? $this->request_context->current_method() ),
			'is_frontend_html'   => ! empty( $details['is_frontend_html'] ) ? 1 : 0,
			'evidence_json'      => $details ? wp_json_encode( $details ) : '',
			'details'            => $details ? wp_json_encode( $details ) : '',
			'summary'            => $this->summary( $event_type, $details ),
		);

		/**
		 * Filters an event payload before it is written to the database.
		 *
		 * @param array<string,mixed> $event      Event payload.
		 * @param string              $event_type Event type.
		 * @param array<string,mixed> $extra      Extra arguments supplied by the caller.
		 */
		$event = (array) apply_filters( 'openwpsecurity_firewall_log_event_data', $event, $event_type, $extra );

		if ( $this->is_request_log_type( $event_type ) ) {
			$this->request_logs->insert(
				new RequestLog(
					$event_type,
					(string) $event['request_type'],
					(string) $event['method'],
					$ip,
					(string) $event['country_code'],
					(string) $event['country_name'],
					! empty( $event['is_frontend_html'] ),
					(string) $event['request_uri'],
					(string) $event['user_agent']
				)
			);
		} else {
			$this->security_incidents->insert(
				new SecurityIncident(
					$event_type,
					$ip,
					(string) $event['country_code'],
					(string) $event['country_name'],
					(string) $event['request_type'],
					(string) $event['method'],
					null === $event['lockout_expires_at'] ? null : (string) $event['lockout_expires_at'],
					(string) $event['summary'],
					(string) $event['request_uri'],
					(string) $event['user_agent'],
					(string) $event['evidence_json']
				)
			);
		}

		/**
		 * Fires after the firewall logs an event.
		 *
		 * @param string              $event_type Event type.
		 * @param array<string,mixed> $event      Inserted event payload.
		 */
		do_action( 'openwpsecurity_firewall_logged_event', $event_type, $event );
	}

	private function is_request_log_type( string $event_type ): bool {
		return in_array( $event_type, array( 'request_hit', 'page_visit' ), true );
	}

	private function summary( string $event_type, array $details ): string {
		if ( 'request_rate_limited' === $event_type ) {
			return sprintf(
				'%d hits in %d seconds',
				(int) ( $details['hit_count'] ?? 0 ),
				(int) ( $details['rate_limit_window_seconds'] ?? ( $details['window_seconds'] ?? 0 ) )
			);
		}

		if ( 'request_temporary_block_created' === $event_type ) {
			return 'Temporary block created';
		}

		if ( 'request_temporarily_blocked' === $event_type ) {
			return 'Request denied by active temporary ban';
		}

		if ( 'permanent_ban_created' === $event_type ) {
			return (string) ( $details['reason'] ?? 'Permanent ban created' );
		}

		if ( str_starts_with( $event_type, 'captcha_' ) ) {
			return str_replace( '_', ' ', $event_type );
		}

		return '';
	}
}
