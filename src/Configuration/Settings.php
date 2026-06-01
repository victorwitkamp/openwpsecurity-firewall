<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Configuration;

use VictorWitkamp\OpenWPSecurity\Core\Configuration\OptionBackedSettingsStore;
use VictorWitkamp\OpenWPSecurity\Core\Configuration\SettingsInputSanitizer;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings extends OptionBackedSettingsStore {
	private const OPTION_NAME = 'openwpsecurity_firewall_settings';

	private SettingsInputSanitizer $input_sanitizer;
	private RequestHandlingCatalog $request_handling_catalog;

	public function __construct( SettingsInputSanitizer $input_sanitizer, RequestHandlingCatalog $request_handling_catalog ) {
		$this->input_sanitizer          = $input_sanitizer;
		$this->request_handling_catalog = $request_handling_catalog;
	}

	public function option_name(): string {
		return self::OPTION_NAME;
	}

	public function sanitize_firewall_submission( array $submission ): array {
		return array_merge(
			array(
				'captcha_failure_threshold'      => max( 0, (int) ( $submission['captcha_failure_threshold'] ?? 3 ) ),
				'captcha_failure_window_minutes' => max( 1, (int) ( $submission['captcha_failure_window_minutes'] ?? 10 ) ),
				'captcha_pass_minutes'           => max( 1, (int) ( $submission['captcha_pass_minutes'] ?? 30 ) ),
				'event_retention_days'           => max( 0, (int) ( $submission['event_retention_days'] ?? 90 ) ),
				'trusted_ip_headers'             => $this->input_sanitizer->headers( (string) ( $submission['trusted_ip_headers'] ?? 'REMOTE_ADDR' ) ),
				'whitelist_ips'                  => $this->input_sanitizer->ip_addresses(
					$this->input_sanitizer->lines( (string) ( $submission['whitelist_ips'] ?? '' ) )
				),
				'debug_bar_enabled'              => empty( $submission['debug_bar_enabled'] ) ? 0 : 1,
				'enable_remote_geoip'            => empty( $submission['enable_remote_geoip'] ) ? 0 : 1,
				'enforce_loginprotection_bans'   => empty( $submission['enforce_loginprotection_bans'] ) ? 0 : 1,
			),
			$this->sanitize_request_handling_settings( $submission )
		);
	}

	protected function default_settings(): array {
		return array_merge(
			array(
				'captcha_failure_threshold'      => 3,
				'captcha_failure_window_minutes' => 10,
				'captcha_pass_minutes'           => 30,
				'event_retention_days'           => 90,
				'trusted_ip_headers'             => array( 'REMOTE_ADDR' ),
				'whitelist_ips'                  => array(),
				'debug_bar_enabled'              => 0,
				'enable_remote_geoip'            => 0,
				'enforce_loginprotection_bans'   => 0,
			),
			$this->request_handling_defaults()
		);
	}

	protected function default_settings_filter(): string {
		return 'openwpsecurity_firewall_default_settings';
	}

	protected function normalize( array $settings ): array {
		$settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ]                       = empty( $settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ] ) ? 0 : 1;
		$settings[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ]               = empty( $settings[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ] ) ? 0 : 1;
		$settings[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ]               = max( 1, (int) $settings[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ] );
		$settings[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] = max( 0, (int) $settings[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] );
		$settings['captcha_failure_threshold']      = max( 0, (int) $settings['captcha_failure_threshold'] );
		$settings['captcha_failure_window_minutes'] = max( 1, (int) $settings['captcha_failure_window_minutes'] );
		$settings['captcha_pass_minutes']           = max( 1, (int) $settings['captcha_pass_minutes'] );
		$settings['event_retention_days']           = max( 0, (int) $settings['event_retention_days'] );
		$settings['trusted_ip_headers']             = $this->input_sanitizer->headers( implode( ',', (array) $settings['trusted_ip_headers'] ) );
		$settings['whitelist_ips']                  = $this->input_sanitizer->ip_addresses( (array) $settings['whitelist_ips'] );
		$settings['debug_bar_enabled']              = empty( $settings['debug_bar_enabled'] ) ? 0 : 1;
		$settings['enable_remote_geoip']            = empty( $settings['enable_remote_geoip'] ) ? 0 : 1;
		$settings['enforce_loginprotection_bans']   = empty( $settings['enforce_loginprotection_bans'] ) ? 0 : 1;
		$settings                                  += $this->sanitize_request_handling_settings( $settings );

		if ( ! in_array( 'REMOTE_ADDR', $settings['trusted_ip_headers'], true ) ) {
			$settings['trusted_ip_headers'][] = 'REMOTE_ADDR';
		}

		return $settings;
	}

	private function request_handling_defaults(): array {
		$defaults = array();

		foreach ( $this->request_handling_catalog->endpoint_defaults() as $request_type => $request_handling ) {
			$defaults[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' ) ]                        = (int) $request_handling['rate_limit_enabled'];
			$defaults[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' ) ]                      = (int) $request_handling['rate_limit_threshold'];
			$defaults[ $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' ) ]                 = (int) $request_handling['rate_limit_window_seconds'];
			$defaults[ $this->request_handling_catalog->setting_key( $request_type, 'active_block_denials_before_permanent_ban' ) ] = (int) $request_handling['active_block_denials_before_permanent_ban'];
			$defaults[ $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' ) ] = (int) $request_handling['captcha_challenges_before_temporary_block'];
		}

		$temporary_block_defaults = $this->request_handling_catalog->temporary_block_defaults();

		$defaults[ $this->request_handling_catalog->captcha_enabled_setting_key() ]                       = $this->request_handling_catalog->default_captcha_enabled();
		$defaults[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ]               = (int) $temporary_block_defaults['enabled'];
		$defaults[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ]               = (int) $temporary_block_defaults['temporary_block_minutes'];
		$defaults[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] = (int) $temporary_block_defaults['blocks_before_permanent_ban'];

		return $defaults;
	}

	private function sanitize_request_handling_settings( array $source ): array {
		$sanitized                = array();
		$default_map              = $this->request_handling_catalog->endpoint_defaults();
		$temporary_block_defaults = $this->request_handling_catalog->temporary_block_defaults();
		$sanitized[ $this->request_handling_catalog->captcha_enabled_setting_key() ]                       = empty( $source[ $this->request_handling_catalog->captcha_enabled_setting_key() ] ) ? 0 : 1;
		$sanitized[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ]               = empty( $source[ $this->request_handling_catalog->temporary_block_enabled_setting_key() ] ) ? 0 : 1;
		$sanitized[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ]               = max( 1, (int) ( $source[ $this->request_handling_catalog->temporary_block_minutes_setting_key() ] ?? $temporary_block_defaults['temporary_block_minutes'] ) );
		$sanitized[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] = max( 0, (int) ( $source[ $this->request_handling_catalog->temporary_blocks_before_permanent_ban_setting_key() ] ?? $temporary_block_defaults['blocks_before_permanent_ban'] ) );

		foreach ( $default_map as $request_type => $request_handling_defaults ) {
			$rate_limit_enabled_key        = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_enabled' );
			$rate_limit_threshold_key      = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_threshold' );
			$rate_limit_window_seconds_key = $this->request_handling_catalog->setting_key( $request_type, 'rate_limit_window_seconds' );
			$active_block_denials_key      = $this->request_handling_catalog->setting_key( $request_type, 'active_block_denials_before_permanent_ban' );
			$captcha_challenges_key        = $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' );

			$sanitized[ $rate_limit_enabled_key ]        = empty( $source[ $rate_limit_enabled_key ] ) ? 0 : 1;
			$sanitized[ $rate_limit_threshold_key ]      = max( 1, (int) ( $source[ $rate_limit_threshold_key ] ?? $request_handling_defaults['rate_limit_threshold'] ) );
			$sanitized[ $rate_limit_window_seconds_key ] = max( 1, (int) ( $source[ $rate_limit_window_seconds_key ] ?? $request_handling_defaults['rate_limit_window_seconds'] ) );
			$sanitized[ $active_block_denials_key ]      = max( 0, (int) ( $source[ $active_block_denials_key ] ?? $request_handling_defaults['active_block_denials_before_permanent_ban'] ) );
			$sanitized[ $captcha_challenges_key ]        = max( 0, (int) ( $source[ $captcha_challenges_key ] ?? $request_handling_defaults['captcha_challenges_before_temporary_block'] ) );
		}

		return $sanitized;
	}
}
