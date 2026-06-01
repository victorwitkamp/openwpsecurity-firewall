<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingResolver {
	private Settings $settings;
	private RequestHandlingCatalog $request_handling_catalog;

	public function __construct( Settings $settings, RequestHandlingCatalog $request_handling_catalog ) {
		$this->settings                 = $settings;
		$this->request_handling_catalog = $request_handling_catalog;
	}

	public function for_request_type( string $request_type ): array {
		$default_map = $this->request_handling_catalog->endpoint_defaults();

		if ( ! isset( $default_map[ $request_type ] ) ) {
			return array();
		}

		$settings = $this->settings->get();

		return array(
			'rate_limit_enabled'                        => ! empty( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ) ] ),
			'rate_limit_threshold'                      => (int) ( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' ) ] ?? $default_map[ $request_type ]['rate_limit_threshold'] ),
			'rate_limit_window_seconds'                 => (int) ( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' ) ] ?? $default_map[ $request_type ]['rate_limit_window_seconds'] ),
			'active_block_denials_before_permanent_ban' => (int) ( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'active_block_denials_before_permanent_ban' ) ] ?? $default_map[ $request_type ]['active_block_denials_before_permanent_ban'] ),
			'captcha_challenges_before_temporary_block' => (int) ( $settings[ $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' ) ] ?? $default_map[ $request_type ]['captcha_challenges_before_temporary_block'] ),
		);
	}

	public function active_block_denials_before_permanent_ban( string $request_type ): int {
		$request_handling = $this->for_request_type( $request_type );

		if ( array() === $request_handling ) {
			return 0;
		}

		return max( 0, (int) $request_handling['active_block_denials_before_permanent_ban'] );
	}

	public function captcha_challenges_before_temporary_block( string $request_type ): int {
		$request_handling = $this->for_request_type( $request_type );

		if ( array() === $request_handling ) {
			return 0;
		}

		return max( 0, (int) $request_handling['captcha_challenges_before_temporary_block'] );
	}

	public function temporary_block_settings(): array {
		$settings = $this->settings->get();
		$defaults = $this->request_handling_catalog->temporary_block_defaults();

		return array(
			'enabled'                     => ! empty( $settings[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ] ),
			'temporary_block_minutes'     => (int) ( $settings[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ] ?? $defaults['temporary_block_minutes'] ),
			'blocks_before_permanent_ban' => (int) ( $settings[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] ?? $defaults['blocks_before_permanent_ban'] ),
		);
	}
}
