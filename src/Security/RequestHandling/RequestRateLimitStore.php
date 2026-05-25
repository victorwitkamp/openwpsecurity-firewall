<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\TransientKeyBuilder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestRateLimitStore {
	private TransientKeyBuilder $transient_key_builder;

	public function __construct( TransientKeyBuilder $transient_key_builder ) {
		$this->transient_key_builder = $transient_key_builder;
	}

	public function record_request( string $request_type, string $ip, int $window_seconds ): int {
		$key     = $this->transient_key_builder->request_handling_rate_limit_hits( $request_type, $ip );
		$history = get_transient( $key );
		$history = is_array( $history ) ? $history : array();
		$now     = time();

		$history = array_values(
			array_filter(
				$history,
				static function ( $timestamp ) use ( $now, $window_seconds ): bool {
					return ( (int) $timestamp ) >= ( $now - $window_seconds );
				}
			)
		);

		$history[] = $now;
		set_transient( $key, $history, max( 30, $window_seconds * 2 ) );

		return count( $history );
	}
}
