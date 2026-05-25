<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Location;

use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class GeoIpLookup {
	private IpAddressInspector $ip_address_inspector;

	public function __construct( IpAddressInspector $ip_address_inspector ) {
		$this->ip_address_inspector = $ip_address_inspector;
	}

	public function lookup( string $ip, bool $enabled = true ): array {
		if ( $ip === '' ) {
			return array(
				'country_code' => '',
				'country_name' => '',
			);
		}

		if ( $this->ip_address_inspector->is_private( $ip ) ) {
			return array(
				'country_code' => 'LOCAL',
				'country_name' => 'Private / Reserved',
			);
		}

		$cache_key = 'vwfw_geo_' . md5( $ip );
		$cached    = get_transient( $cache_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$result = array(
			'country_code' => '',
			'country_name' => '',
		);

		if ( function_exists( 'geoip_record_by_name' ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- This extension may emit warnings for unsupported lookups.
			$record = @geoip_record_by_name( $ip );

			if ( is_array( $record ) ) {
				$result = array(
					'country_code' => isset( $record['country_code'] ) ? (string) $record['country_code'] : '',
					'country_name' => isset( $record['country_name'] ) ? (string) $record['country_name'] : '',
				);
			}
		}

		if ( $enabled && $result['country_code'] === '' ) {
			$response = wp_remote_get(
				'https://ipwho.is/' . rawurlencode( $ip ),
				array(
					'timeout' => 4,
				)
			);

			if ( ! is_wp_error( $response ) ) {
				$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

				if ( is_array( $body ) && ! empty( $body['success'] ) ) {
					$result = array(
						'country_code' => isset( $body['country_code'] ) ? (string) $body['country_code'] : '',
						'country_name' => isset( $body['country'] ) ? (string) $body['country'] : '',
					);
				}
			}
		}

		set_transient( $cache_key, $result, DAY_IN_SECONDS );

		return $result;
	}
}
