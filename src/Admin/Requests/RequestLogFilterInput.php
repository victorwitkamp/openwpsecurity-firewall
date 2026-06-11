<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Requests;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestLogFilterInput {
	private RequestContext $request_context;
	private EventReportFormatter $event_report_formatter;

	public function __construct( RequestContext $request_context, EventReportFormatter $event_report_formatter ) {
		$this->request_context        = $request_context;
		$this->event_report_formatter = $event_report_formatter;
	}

	public function read(): array {
		$current_ip    = $this->request_context->current_ip();
		$request_types = array_keys( $this->event_report_formatter->request_type_options() );
		$methods       = array_keys( $this->event_report_formatter->method_options() );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameter.
		$request_type = isset( $_GET['request_type'] ) ? sanitize_key( (string) wp_unslash( $_GET['request_type'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameter.
		$method = isset( $_GET['method'] ) ? strtoupper( sanitize_text_field( (string) wp_unslash( $_GET['method'] ) ) ) : '';

		if ( ! in_array( $request_type, $request_types, true ) ) {
			$request_type = '';
		}

		if ( ! in_array( $method, $methods, true ) ) {
			$method = '';
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameters.
		return array(
			'request_type'     => $request_type,
			'method'           => $method,
			'country_code'     => isset( $_GET['country_code'] ) ? strtoupper( sanitize_text_field( (string) wp_unslash( $_GET['country_code'] ) ) ) : '',
			'ip_address'       => isset( $_GET['ip_address'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['ip_address'] ) ) : '',
			'request_uri'      => isset( $_GET['request_uri'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['request_uri'] ) ) : '',
			'user_agent'       => isset( $_GET['user_agent'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['user_agent'] ) ) : '',
			'external_only'    => ! empty( $_GET['external_only'] ),
			'exclude_internal' => ! empty( $_GET['exclude_internal'] ),
			'exclude_my_ip'    => ! empty( $_GET['exclude_my_ip'] ),
			'current_ip'       => $current_ip,
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	public function country_option_filters( array $filters ): array {
		unset( $filters['country_code'] );

		return $filters;
	}

	public function query_args( array $filters ): array {
		$query_args = array();

		if ( '' !== $filters['request_type'] ) {
			$query_args['request_type'] = $filters['request_type'];
		}

		if ( '' !== $filters['method'] ) {
			$query_args['method'] = $filters['method'];
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

		if ( '' !== $filters['user_agent'] ) {
			$query_args['user_agent'] = $filters['user_agent'];
		}

		if ( ! empty( $filters['external_only'] ) ) {
			$query_args['external_only'] = '1';
		}

		if ( ! empty( $filters['exclude_internal'] ) ) {
			$query_args['exclude_internal'] = '1';
		}

		if ( ! empty( $filters['exclude_my_ip'] ) ) {
			$query_args['exclude_my_ip'] = '1';
		}

		return $query_args;
	}
}
