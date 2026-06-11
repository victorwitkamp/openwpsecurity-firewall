<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncident {
	private string $incident_type;
	private string $ip_address;
	private string $country_code;
	private string $country_name;
	private string $request_type;
	private string $method;
	private ?string $lockout_expires_at;
	private string $summary;
	private string $request_uri;
	private string $user_agent;
	private string $evidence_json;

	public function __construct( string $incident_type, string $ip_address, string $country_code, string $country_name, string $request_type, string $method, ?string $lockout_expires_at, string $summary, string $request_uri, string $user_agent, string $evidence_json ) {
		$this->incident_type      = $incident_type;
		$this->ip_address         = $ip_address;
		$this->country_code       = $country_code;
		$this->country_name       = $country_name;
		$this->request_type       = $request_type;
		$this->method             = $method;
		$this->lockout_expires_at = $lockout_expires_at;
		$this->summary            = $summary;
		$this->request_uri        = $request_uri;
		$this->user_agent         = $user_agent;
		$this->evidence_json      = $evidence_json;
	}

	public function to_row(): array {
		return array(
			'incident_type'      => $this->incident_type,
			'ip_address'         => $this->ip_address,
			'country_code'       => $this->country_code,
			'country_name'       => $this->country_name,
			'request_type'       => $this->request_type,
			'method'             => $this->method,
			'lockout_expires_at' => $this->lockout_expires_at,
			'summary'            => $this->summary,
			'request_uri'        => $this->request_uri,
			'user_agent'         => $this->user_agent,
			'evidence_json'      => $this->evidence_json,
		);
	}
}
