<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Captcha;

use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\TransientKeyBuilder;

final class CaptchaFailureStore {
	private TransientKeyBuilder $transient_key_builder;

	public function __construct( TransientKeyBuilder $transient_key_builder ) {
		$this->transient_key_builder = $transient_key_builder;
	}

	public function record( string $ip_address, int $window_minutes ): array {
		$state     = $this->state( $ip_address, $window_minutes );
		$history   = $state['history'];
		$history[] = time();

		set_transient(
			$this->transient_key_builder->captcha_failure_history( $ip_address ),
			$history,
			max( MINUTE_IN_SECONDS, $window_minutes * MINUTE_IN_SECONDS * 2 )
		);

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	public function clear( string $ip_address ): void {
		delete_transient( $this->transient_key_builder->captcha_failure_history( $ip_address ) );
	}

	private function state( string $ip_address, int $window_minutes ): array {
		$key     = $this->transient_key_builder->captcha_failure_history( $ip_address );
		$history = get_transient( $key );
		$history = is_array( $history ) ? $history : array();
		$now     = time();

		$history = array_values(
			array_filter(
				$history,
				static function ( mixed $timestamp ) use ( $now, $window_minutes ): bool {
					return (int) $timestamp >= $now - $window_minutes * MINUTE_IN_SECONDS;
				}
			)
		);

		if ( empty( $history ) ) {
			delete_transient( $key );
		} else {
			set_transient( $key, $history, max( MINUTE_IN_SECONDS, $window_minutes * MINUTE_IN_SECONDS * 2 ) );
		}

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}
}
