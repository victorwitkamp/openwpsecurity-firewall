<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PermanentBanStore {
	private const OPTION_NAME = 'openwpsecurity_firewall_permanent_bans';

	private EventLogger $event_logger;
	private IpAddressInspector $ip_address_inspector;

	public function __construct( EventLogger $event_logger, IpAddressInspector $ip_address_inspector ) {
		$this->event_logger         = $event_logger;
		$this->ip_address_inspector = $ip_address_inspector;
	}

	public function ensure_storage(): void {
		if ( get_option( self::OPTION_NAME, null ) === null ) {
			add_option( self::OPTION_NAME, array(), '', false );
		}
	}

	public function get_all_bans(): array {
		$bans = get_option( self::OPTION_NAME, array() );
		$bans = is_array( $bans ) ? $bans : array();

		foreach ( $bans as $ip => $ban ) {
			if ( ! is_array( $ban ) ) {
				unset( $bans[ $ip ] );
			}
		}

		return $bans;
	}

	public function count_bans(): int {
		return count( $this->get_all_bans() );
	}

	public function get_ban_for_ip( string $ip ): array {
		$bans = $this->get_all_bans();

		return isset( $bans[ $ip ] ) && is_array( $bans[ $ip ] ) ? $bans[ $ip ] : array();
	}

	public function is_banned( string $ip ): bool {
		return array() !== $this->get_ban_for_ip( $ip );
	}

	public function create_ban( string $ip, string $reason, string $source = 'manual', array $context = array() ): void {
		if ( '' === $ip || $this->ip_address_inspector->is_private( $ip ) ) {
			return;
		}

		$bans = $this->get_all_bans();

		if ( isset( $bans[ $ip ] ) ) {
			return;
		}

		$bans[ $ip ] = array(
			'ip_address' => $ip,
			'banned_at'  => current_time( 'mysql', true ),
			'reason'     => $reason,
			'source'     => $source,
		);
		update_option( self::OPTION_NAME, $bans, false );

		$this->event_logger->log(
			'permanent_ban_created',
			$ip,
			'',
			array(
				'details' => array_merge(
					array(
						'reason' => $reason,
						'source' => $source,
					),
					$context
				),
			)
		);
	}
}
