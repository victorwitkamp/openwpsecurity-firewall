<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventWriter {
	private EventTable $event_table;

	public function __construct( EventTable $event_table ) {
		$this->event_table = $event_table;
	}

	public function insert( array $event ): void {
		global $wpdb;

		$defaults = array(
			'created_at'         => current_time( 'mysql', true ),
			'event_type'         => '',
			'ip_address'         => '',
			'country_code'       => '',
			'country_name'       => '',
			'username'           => '',
			'user_agent'         => '',
			'request_uri'        => '',
			'lockout_expires_at' => null,
			'details'            => '',
		);

		$event = wp_parse_args( $event, $defaults );

		$wpdb->insert(
			$this->event_table->name(),
			$event,
			array(
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
			)
		);
	}
}
