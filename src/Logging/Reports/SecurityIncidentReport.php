<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\CountryDistribution;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\SecurityIncidentLookup;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentReport {
	private SecurityIncidentLookup $security_incident_lookup;
	private RequestHandlingCatalog $request_handling_catalog;
	private CountryDistribution $country_distribution;

	public function __construct( SecurityIncidentLookup $security_incident_lookup, RequestHandlingCatalog $request_handling_catalog, CountryDistribution $country_distribution ) {
		$this->security_incident_lookup = $security_incident_lookup;
		$this->request_handling_catalog = $request_handling_catalog;
		$this->country_distribution     = $country_distribution;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->security_incident_lookup->count( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->security_incident_lookup->rows( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->country_distribution->summarize( $this->security_incident_lookup->country_totals( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds, null ), $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->security_incident_lookup->country_options( $this->request_handling_catalog->security_incident_event_types(), $filters, $period_seconds );
	}

	public function event_types(): array {
		return $this->request_handling_catalog->security_incident_event_types();
	}
}
