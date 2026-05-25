<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLookup;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentReport {
	private EventLookup $event_lookup;
	private RequestHandlingCatalog $request_handling_catalog;

	public function __construct( EventLookup $event_lookup, RequestHandlingCatalog $request_handling_catalog ) {
		$this->event_lookup             = $event_lookup;
		$this->request_handling_catalog = $request_handling_catalog;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->event_lookup->count_events_matching_types( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->event_lookup->find_rows_matching_types( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->event_lookup->country_totals_matching_types( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds, $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->event_lookup->country_options_matching_types( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds );
	}

	public function event_types(): array {
		return $this->request_handling_catalog->security_incident_event_types();
	}
}
