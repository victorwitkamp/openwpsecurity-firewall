<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Captcha;

use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\TransientKeyBuilder;

final class CaptchaChallengeStore {
	private TransientKeyBuilder $transient_key_builder;

	public function __construct( TransientKeyBuilder $transient_key_builder ) {
		$this->transient_key_builder = $transient_key_builder;
	}

	public function record( string $ip_address, string $request_type, int $window_seconds ): array {
		$state     = $this->state( $ip_address, $request_type, $window_seconds );
		$history   = $state['history'];
		$history[] = time();

		set_transient(
			$this->transient_key_builder->captcha_challenge_history( $request_type, $ip_address ),
			$history,
			max( MINUTE_IN_SECONDS, $window_seconds * 2 )
		);

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	public function clear( string $ip_address, string $request_type ): void {
		delete_transient( $this->transient_key_builder->captcha_challenge_history( $request_type, $ip_address ) );
	}

	private function state( string $ip_address, string $request_type, int $window_seconds ): array {
		$key     = $this->transient_key_builder->captcha_challenge_history( $request_type, $ip_address );
		$history = get_transient( $key );
		$history = is_array( $history ) ? $history : array();
		$now     = time();

		$history = array_values(
			array_filter(
				$history,
				static function ( mixed $timestamp ) use ( $now, $window_seconds ): bool {
					return (int) $timestamp >= $now - $window_seconds;
				}
			)
		);

		if ( empty( $history ) ) {
			delete_transient( $key );
		} else {
			set_transient( $key, $history, max( MINUTE_IN_SECONDS, $window_seconds * 2 ) );
		}

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}
}
