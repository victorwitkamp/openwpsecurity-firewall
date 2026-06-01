<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventLookup as CoreEventLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventLookup extends CoreEventLookup {
	public function __construct( EventTable $event_table ) {
		parent::__construct(
			$event_table,
			array(
				'created_at',
				'event_type',
				'ip_address',
				'country_code',
				'country_name',
				'username',
				'user_agent',
				'request_uri',
				'lockout_expires_at',
				'details',
			),
			array(
				'event_type',
				'request_type',
				'method',
				'country_code',
				'ip_address',
				'username',
				'request_uri',
				'user_agent',
				'external_only',
				'exclude_internal',
				'exclude_my_ip',
			)
		);
	}

	public function count_request_events( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->count_events_matching_types( array( 'request_hit' ), $filters, $period_seconds );
	}

	public function find_request_rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->find_rows_matching_types( array( 'request_hit' ), $filters, $period_seconds, $limit, $offset );
	}

	public function request_country_totals( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->country_totals_matching_types( array( 'request_hit' ), $filters, $period_seconds, $limit );
	}

	public function request_country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->country_options_matching_types( array( 'request_hit' ), $filters, $period_seconds, 20 );
	}
}
