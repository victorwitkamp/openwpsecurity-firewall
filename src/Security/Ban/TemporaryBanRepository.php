<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\AbstractTemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\TemporaryBan;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemporaryBanRepository extends AbstractTemporaryBanRepository {
	public function __construct( TableSchemaInstaller $schema_installer ) {
		parent::__construct(
			$schema_installer,
			'openwpsecurity_firewall_temporary_bans_db_version',
			'openwpsecurity_firewall_temporary_bans'
		);
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_temporary_bans';
	}

	public function active_temporary_ban( string $ip_address ): array {
		$temporary_ban = $this->find_active_temporary_ban( $ip_address );

		return null === $temporary_ban ? array() : $this->temporary_ban_data( $temporary_ban );
	}

	public function create_temporary_ban( string $ip_address, string $trigger_request_type, int $ban_minutes, int $ban_count ): array {
		$created_at    = time();
		$temporary_ban = new TemporaryBan(
			$ip_address,
			$created_at,
			$created_at + max( 1, $ban_minutes ) * MINUTE_IN_SECONDS,
			'firewall',
			'All request types',
			'A Firewall request-handling threshold was exceeded.',
			'Triggered by ' . $this->request_type_label( $trigger_request_type ) . '.',
			(string) wp_json_encode(
				array(
					'trigger_request_type' => $trigger_request_type,
					'denial_count'         => 0,
					'temporary_ban_count'  => $ban_count,
				)
			)
		);

		$this->save_temporary_ban( $temporary_ban );

		return $this->temporary_ban_data( $temporary_ban );
	}

	public function record_active_temporary_ban_denial( string $ip_address, string $request_type ): array {
		$temporary_ban = $this->find_active_temporary_ban( $ip_address );

		if ( null === $temporary_ban ) {
			return array();
		}

		$evidence                             = $temporary_ban->evidence();
		$evidence['denial_count']             = (int) ( $evidence['denial_count'] ?? 0 ) + 1;
		$evidence['last_denied_request_type'] = $request_type;
		$trigger_request_type                 = (string) ( $evidence['trigger_request_type'] ?? '' );
		$details                              = sprintf(
			'Triggered by %s. %d request(s) denied while active; most recent request type: %s.',
			$this->request_type_label( $trigger_request_type ),
			(int) $evidence['denial_count'],
			$this->request_type_label( $request_type )
		);
		$temporary_ban                        = new TemporaryBan(
			$temporary_ban->ip_address(),
			$temporary_ban->created_at(),
			$temporary_ban->expires_at(),
			$temporary_ban->source(),
			$temporary_ban->scope(),
			$temporary_ban->reason(),
			$details,
			(string) wp_json_encode( $evidence )
		);

		$this->save_temporary_ban( $temporary_ban );

		return $this->temporary_ban_data( $temporary_ban );
	}

	private function temporary_ban_data( TemporaryBan $temporary_ban ): array {
		return array_merge( $temporary_ban->to_array(), $temporary_ban->evidence() );
	}

	private function request_type_label( string $request_type ): string {
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
}
