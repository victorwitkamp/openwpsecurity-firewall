<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Configuration;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsInputSanitizer {
	public function lines( string $value ): array {
		$lines = preg_split( '/\r\n|\r|\n/', $value );

		if ( false === $lines ) {
			return array();
		}

		$lines = array_map( 'trim', $lines );

		return array_values(
			array_filter(
				$lines,
				static function ( string $line ): bool {
					return '' !== $line;
				}
			)
		);
	}

	public function headers( string $value ): array {
		$headers = array_map( 'trim', explode( ',', $value ) );

		return array_values(
			array_filter(
				$headers,
				static function ( string $header ): bool {
					return '' !== $header;
				}
			)
		);
	}

	public function ip_addresses( array $ip_addresses ): array {
		$normalized = array();

		foreach ( $ip_addresses as $ip_address ) {
			$ip_address = trim( (string) $ip_address );

			if ( '' === $ip_address ) {
				continue;
			}

			$normalized[] = $ip_address;
		}

		return array_values( array_unique( $normalized ) );
	}
}
