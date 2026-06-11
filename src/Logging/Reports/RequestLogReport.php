<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\CountryDistribution;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\RequestLogLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestLogReport {
	private RequestLogLookup $request_log_lookup;
	private CountryDistribution $country_distribution;

	public function __construct( RequestLogLookup $request_log_lookup, CountryDistribution $country_distribution ) {
		$this->request_log_lookup   = $request_log_lookup;
		$this->country_distribution = $country_distribution;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->request_log_lookup->count( $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->request_log_lookup->rows( $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->country_distribution->summarize( $this->request_log_lookup->country_totals( $filters, $period_seconds, null ), $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->request_log_lookup->country_options( $filters, $period_seconds );
	}
}
