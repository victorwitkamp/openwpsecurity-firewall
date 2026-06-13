<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final readonly class RequestLog {
	private string $activity_type;
	private string $request_type;
	private string $method;
	private string $ip_address;
	private string $country_code;
	private string $country_name;
	private bool $is_frontend_html;
	private string $request_uri;
	private string $user_agent;

	public function __construct( string $activity_type, string $request_type, string $method, string $ip_address, string $country_code, string $country_name, bool $is_frontend_html, string $request_uri, string $user_agent ) {
		$this->activity_type    = $activity_type;
		$this->request_type     = $request_type;
		$this->method           = $method;
		$this->ip_address       = $ip_address;
		$this->country_code     = $country_code;
		$this->country_name     = $country_name;
		$this->is_frontend_html = $is_frontend_html;
		$this->request_uri      = $request_uri;
		$this->user_agent       = $user_agent;
	}

	/**
	 * @return array<string, int|string>
	 */
	public function to_row(): array {
		return array(
			'activity_type'    => $this->activity_type,
			'request_type'     => $this->request_type,
			'method'           => $this->method,
			'ip_address'       => $this->ip_address,
			'country_code'     => $this->country_code,
			'country_name'     => $this->country_name,
			'is_frontend_html' => $this->is_frontend_html ? 1 : 0,
			'request_uri'      => $this->request_uri,
			'user_agent'       => $this->user_agent,
		);
	}
}
