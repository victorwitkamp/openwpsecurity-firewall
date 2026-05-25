<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventReportFormatter {
	public function details_from_json( string $details_json ): array {
		if ( '' === $details_json ) {
			return array();
		}

		$decoded = json_decode( $details_json, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	public function admin_datetime( string $gmt_datetime ): string {
		return get_date_from_gmt( $gmt_datetime, 'Y-m-d H:i:s' );
	}

	public function event_type_label( string $event_type ): string {
		$labels = $this->event_type_labels();

		return $labels[ $event_type ] ?? $event_type;
	}

	public function event_type_options( array $event_types, string $all_label = 'All Types' ): array {
		$options = array(
			'' => $all_label,
		);
		$labels  = $this->event_type_labels();

		foreach ( $event_types as $event_type ) {
			$options[ $event_type ] = $labels[ $event_type ] ?? $event_type;
		}

		return $options;
	}

	public function request_type_label( string $request_type ): string {
		$labels = array(
			'frontend_page' => 'Frontend Page',
			'wp_login'      => 'WP Login',
			'wp_admin'      => 'WP Admin',
			'admin_ajax'    => 'Admin AJAX',
			'rest_api'      => 'REST API',
			'xmlrpc'        => 'XML-RPC',
			'wp_cron'       => 'WP Cron',
			'cli'           => 'WP-CLI',
			'other'         => 'Other',
		);

		return $labels[ $request_type ] ?? $request_type;
	}

	public function request_type_options(): array {
		return array(
			''              => 'All Types',
			'frontend_page' => 'Frontend Page',
			'wp_login'      => 'WP Login',
			'wp_admin'      => 'WP Admin',
			'admin_ajax'    => 'Admin AJAX',
			'rest_api'      => 'REST API',
			'xmlrpc'        => 'XML-RPC',
			'wp_cron'       => 'WP Cron',
			'other'         => 'Other',
		);
	}

	public function method_options(): array {
		return array(
			''        => 'All Methods',
			'GET'     => 'GET',
			'POST'    => 'POST',
			'PUT'     => 'PUT',
			'PATCH'   => 'PATCH',
			'DELETE'  => 'DELETE',
			'HEAD'    => 'HEAD',
			'OPTIONS' => 'OPTIONS',
		);
	}

	public function ban_source_label( string $source ): string {
		$labels = array(
			'request_handling' => 'Request Handling',
			'manual'           => 'Manual',
		);

		return $labels[ $source ] ?? $source;
	}

	private function event_type_labels(): array {
		return array(
			'request_hit'                     => 'WordPress Request',
			'request_rate_limited'            => 'Request Rate Limited',
			'request_temporary_block_created' => 'Request Temporary Block Created',
			'request_temporarily_blocked'     => 'Request Denied By Temporary Block',
			'permanent_ban_created'           => 'Permanent Ban Created',
			'page_visit'                      => 'Page Visit',
			'captcha_required'                => 'Captcha Required',
			'captcha_failed'                  => 'Captcha Failed',
			'captcha_passed'                  => 'Captcha Passed',
		);
	}
}
