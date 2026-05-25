<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests;

use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentFilterInput {
	private RequestHandlingCatalog $request_handling_catalog;
	private EventReportFormatter $event_report_formatter;

	public function __construct( RequestHandlingCatalog $request_handling_catalog, EventReportFormatter $event_report_formatter ) {
		$this->request_handling_catalog = $request_handling_catalog;
		$this->event_report_formatter   = $event_report_formatter;
	}

	public function read(): array {
		$event_types   = $this->request_handling_catalog->security_incident_event_types();
		$request_types = array_keys( $this->event_report_formatter->request_type_options() );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameters.
		$event_type = isset( $_GET['event_type'] ) ? sanitize_key( (string) wp_unslash( $_GET['event_type'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameters.
		$request_type = isset( $_GET['request_type'] ) ? sanitize_key( (string) wp_unslash( $_GET['request_type'] ) ) : '';

		if ( ! in_array( $event_type, $event_types, true ) ) {
			$event_type = '';
		}

		if ( ! in_array( $request_type, $request_types, true ) ) {
			$request_type = '';
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameters.
		return array(
			'event_type'   => $event_type,
			'request_type' => $request_type,
			'country_code' => isset( $_GET['country_code'] ) ? strtoupper( sanitize_text_field( (string) wp_unslash( $_GET['country_code'] ) ) ) : '',
			'ip_address'   => isset( $_GET['ip_address'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['ip_address'] ) ) : '',
			'request_uri'  => isset( $_GET['request_uri'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['request_uri'] ) ) : '',
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	public function event_types(): array {
		return $this->request_handling_catalog->security_incident_event_types();
	}

	public function country_option_filters( array $filters ): array {
		unset( $filters['country_code'] );

		return $filters;
	}

	public function query_args( array $filters ): array {
		$query_args = array();

		if ( '' !== $filters['event_type'] ) {
			$query_args['event_type'] = $filters['event_type'];
		}

		if ( '' !== $filters['request_type'] ) {
			$query_args['request_type'] = $filters['request_type'];
		}

		if ( '' !== $filters['country_code'] ) {
			$query_args['country_code'] = $filters['country_code'];
		}

		if ( '' !== $filters['ip_address'] ) {
			$query_args['ip_address'] = $filters['ip_address'];
		}

		if ( '' !== $filters['request_uri'] ) {
			$query_args['request_uri'] = $filters['request_uri'];
		}

		return $query_args;
	}
}
