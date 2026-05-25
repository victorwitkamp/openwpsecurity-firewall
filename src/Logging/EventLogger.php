<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Firewall\Location\GeoIpLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventLogger {
	private EventWriter $event_writer;
	private Settings $settings;
	private GeoIpLookup $geo_ip_lookup;
	private RequestContext $request_context;

	public function __construct( EventWriter $event_writer, Settings $settings, GeoIpLookup $geo_ip_lookup, RequestContext $request_context ) {
		$this->event_writer    = $event_writer;
		$this->settings        = $settings;
		$this->geo_ip_lookup   = $geo_ip_lookup;
		$this->request_context = $request_context;
	}

	public function log( string $event_type, string $ip, string $username = '', array $extra = array() ): void {
		$settings = $this->settings->get();
		$geo      = $this->geo_ip_lookup->lookup( $ip, ! empty( $settings['enable_remote_geoip'] ) );
		$details  = isset( $extra['details'] ) && is_array( $extra['details'] ) ? $extra['details'] : array();

		$event = array(
			'event_type'         => $event_type,
			'ip_address'         => $ip,
			'country_code'       => (string) ( $geo['country_code'] ?? '' ),
			'country_name'       => (string) ( $geo['country_name'] ?? '' ),
			'username'           => $username,
			'user_agent'         => $this->request_context->current_user_agent(),
			'request_uri'        => $this->request_context->current_url(),
			'lockout_expires_at' => $extra['lockout_expires_at'] ?? null,
			'details'            => $details ? wp_json_encode( $details ) : '',
		);

		/**
		 * Filters an event payload before it is written to the database.
		 *
		 * @param array<string,mixed> $event      Event payload.
		 * @param string              $event_type Event type.
		 * @param array<string,mixed> $extra      Extra arguments supplied by the caller.
		 */
		$event = (array) apply_filters( 'openwpsecurity_firewall_log_event_data', $event, $event_type, $extra );

		$this->event_writer->insert( $event );

		/**
		 * Fires after the firewall logs an event.
		 *
		 * @param string              $event_type Event type.
		 * @param array<string,mixed> $event      Inserted event payload.
		 */
		do_action( 'openwpsecurity_firewall_logged_event', $event_type, $event );
	}
}
