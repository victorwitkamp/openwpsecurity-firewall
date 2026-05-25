<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting;

use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingActionDescriber {
	private RequestHandlingCatalog $request_handling_catalog;

	public function __construct( RequestHandlingCatalog $request_handling_catalog ) {
		$this->request_handling_catalog = $request_handling_catalog;
	}

	public function describe( array $settings, string $request_type ): string {
		$rate_limit_enabled_key  = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' );
		$captcha_enabled         = ! empty( $settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ] );
		$temporary_block_enabled = ! empty( $settings[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ] );
		$temporary_block_minutes = (int) ( $settings[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ] ?? 0 );
		$permanent_ban_threshold = (int) ( $settings[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] ?? 0 );

		if ( empty( $settings[ $rate_limit_enabled_key ] ) ) {
			return 'Requests are logged, but this endpoint does not enforce a rate-limit response.';
		}

		if ( $this->request_handling_catalog->uses_rate_limit_page( $request_type ) ) {
			if ( $captcha_enabled && $this->request_handling_catalog->supports_captcha( $request_type ) ) {
				return 'Returns HTTP 429 and renders a rate-limit page with shared captcha. Solving the captcha sets a temporary bypass cookie. Repeated captcha failures create a global temporary block for '
					. $temporary_block_minutes . ' minute(s)' . $this->permanent_ban_tail( $permanent_ban_threshold ) . '.';
			}

			return 'Returns HTTP 429 and renders a rate-limit page without captcha for this endpoint.';
		}

		if ( $temporary_block_enabled ) {
			return 'Creates a global temporary block and returns an immediate firewall denial for the current request, typically HTTP 403 with a firewall message. The same temporary block then denies all request types until it expires. Repeated temporary blocks across request handling can create a permanent ban'
				. $this->threshold_fragment( $permanent_ban_threshold ) . '.';
		}

		return 'Returns HTTP 429 with a firewall message for this endpoint only. No global temporary block is created from the rate-limit threshold.';
	}

	public function captcha_note( array $settings, string $request_type ): string {
		if ( empty( $settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ] ) ) {
			return '';
		}

		if ( ! $this->request_handling_catalog->supports_captcha( $request_type ) ) {
			return '';
		}

		return 'Shared captcha when rate-limited';
	}

	private function permanent_ban_tail( int $permanent_ban_threshold ): string {
		if ( $permanent_ban_threshold <= 0 ) {
			return '';
		}

		return ', and repeated temporary blocks can create a permanent ban after ' . $permanent_ban_threshold . ' block(s)';
	}

	private function threshold_fragment( int $permanent_ban_threshold ): string {
		if ( $permanent_ban_threshold <= 0 ) {
			return '';
		}

		return ' after ' . $permanent_ban_threshold . ' block(s)';
	}
}
