<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingCatalog {
	public function endpoint_setting_fields(): array {
		return array(
			'rate_limit_enabled',
			'rate_limit_threshold',
			'rate_limit_window_seconds',
			'active_block_denials_before_permanent_ban',
			'captcha_challenges_before_temporary_block',
		);
	}

	public function setting_key( string $request_type, string $field ): string {
		return 'request_handling_' . $request_type . '_' . $field;
	}

	public function captcha_enabled_setting_key(): string {
		return 'request_handling_captcha_enabled';
	}

	public function temporary_block_enabled_setting_key(): string {
		return 'request_handling_temporary_block_enabled';
	}

	public function temporary_block_minutes_setting_key(): string {
		return 'request_handling_temporary_block_minutes';
	}

	public function temporary_blocks_before_permanent_ban_setting_key(): string {
		return 'request_handling_temporary_blocks_before_permanent_ban';
	}

	public function targets(): array {
		return array(
			'frontend_page' => 'Frontend Page',
			'wp_login'      => 'WP Login',
			'admin_ajax'    => 'Admin AJAX',
			'rest_api'      => 'REST API',
			'xmlrpc'        => 'XML-RPC',
			'wp_cron'       => 'WP Cron',
		);
	}

	public function endpoint_defaults(): array {
		return array(
			'frontend_page' => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 12,
				'rate_limit_window_seconds' => 60,
				'active_block_denials_before_permanent_ban' => 20,
				'captcha_challenges_before_temporary_block' => 40,
			),
			'wp_login'      => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 8,
				'rate_limit_window_seconds' => 300,
				'active_block_denials_before_permanent_ban' => 20,
				'captcha_challenges_before_temporary_block' => 25,
			),
			'admin_ajax'    => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 20,
				'rate_limit_window_seconds' => 60,
				'active_block_denials_before_permanent_ban' => 20,
				'captcha_challenges_before_temporary_block' => 0,
			),
			'rest_api'      => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 15,
				'rate_limit_window_seconds' => 60,
				'active_block_denials_before_permanent_ban' => 20,
				'captcha_challenges_before_temporary_block' => 0,
			),
			'xmlrpc'        => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 5,
				'rate_limit_window_seconds' => 300,
				'active_block_denials_before_permanent_ban' => 10,
				'captcha_challenges_before_temporary_block' => 0,
			),
			'wp_cron'       => array(
				'rate_limit_enabled'        => 1,
				'rate_limit_threshold'      => 6,
				'rate_limit_window_seconds' => 300,
				'active_block_denials_before_permanent_ban' => 20,
				'captcha_challenges_before_temporary_block' => 0,
			),
		);
	}

	public function captcha_supported_targets(): array {
		return array(
			'frontend_page',
			'wp_login',
		);
	}

	public function rate_limit_page_targets(): array {
		return array(
			'frontend_page',
			'wp_login',
		);
	}

	public function supports_captcha( string $request_type ): bool {
		return in_array( $request_type, $this->captcha_supported_targets(), true );
	}

	public function uses_rate_limit_page( string $request_type ): bool {
		return in_array( $request_type, $this->rate_limit_page_targets(), true );
	}

	public function default_captcha_enabled(): int {
		return 1;
	}

	public function temporary_block_defaults(): array {
		return array(
			'enabled'                     => 1,
			'temporary_block_minutes'     => 10,
			'blocks_before_permanent_ban' => 2,
		);
	}

	public function security_incident_event_types(): array {
		return array(
			'request_rate_limited',
			'request_temporary_block_created',
			'request_temporarily_blocked',
			'permanent_ban_created',
			'captcha_required',
			'captcha_failed',
			'captcha_passed',
		);
	}
}
