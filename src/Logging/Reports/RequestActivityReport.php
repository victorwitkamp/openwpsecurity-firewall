<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestActivityReport {
	private EventLookup $event_lookup;

	public function __construct( EventLookup $event_lookup ) {
		$this->event_lookup = $event_lookup;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->event_lookup->count_request_events( $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->event_lookup->find_request_rows( $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->event_lookup->request_country_totals( $filters, $period_seconds, $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->event_lookup->request_country_options( $filters, $period_seconds );
	}
}
