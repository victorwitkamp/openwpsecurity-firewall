<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\TransientKeyBuilder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestTemporaryBlockStore {
	private const TEMPORARY_BLOCK_COUNTS_OPTION_NAME = 'openwpsecurity_firewall_request_handling_global_temporary_block_counts';

	private TransientKeyBuilder $transient_key_builder;

	public function __construct( TransientKeyBuilder $transient_key_builder ) {
		$this->transient_key_builder = $transient_key_builder;
	}

	public function ensure_storage(): void {
		if ( get_option( self::TEMPORARY_BLOCK_COUNTS_OPTION_NAME, null ) === null ) {
			add_option( self::TEMPORARY_BLOCK_COUNTS_OPTION_NAME, array(), '', false );
		}
	}

	public function active_temporary_block( string $ip ): array {
		$block = get_transient( $this->transient_key_builder->request_handling_temporary_block( $ip ) );

		if ( is_array( $block ) ) {
			$block = $this->sanitize_temporary_block( $block );

			if ( array() === $block ) {
				$this->clear_active_temporary_block( $ip );
			}

			return $block;
		}

		if ( is_numeric( $block ) ) {
			$block = $this->sanitize_temporary_block(
				array(
					'expires_at' => (int) $block,
				)
			);

			if ( array() === $block ) {
				$this->clear_active_temporary_block( $ip );
			}

			return $block;
		}

		return array();
	}

	public function start_temporary_block( string $ip, string $trigger_request_type, int $block_minutes ): array {
		$block = array(
			'expires_at'           => time() + $block_minutes * MINUTE_IN_SECONDS,
			'trigger_request_type' => $trigger_request_type,
		);

		set_transient(
			$this->transient_key_builder->request_handling_temporary_block( $ip ),
			$block,
			$block_minutes * MINUTE_IN_SECONDS
		);

		return $block;
	}

	public function clear_active_temporary_block( string $ip ): void {
		delete_transient( $this->transient_key_builder->request_handling_temporary_block( $ip ) );
	}

	public function temporary_block_count( string $ip ): int {
		$counts = $this->temporary_block_counts();

		return isset( $counts[ $ip ] ) ? (int) $counts[ $ip ] : 0;
	}

	public function record_temporary_block( string $ip ): int {
		$counts                        = $this->temporary_block_counts();
		$current_temporary_block_count = $this->temporary_block_count( $ip ) + 1;
		$counts[ $ip ]                 = $current_temporary_block_count;

		update_option( self::TEMPORARY_BLOCK_COUNTS_OPTION_NAME, $counts, false );

		return $current_temporary_block_count;
	}

	private function sanitize_temporary_block( array $block ): array {
		$expires_at = isset( $block['expires_at'] ) ? (int) $block['expires_at'] : 0;

		if ( $expires_at <= time() ) {
			return array();
		}

		return array(
			'expires_at'           => $expires_at,
			'trigger_request_type' => isset( $block['trigger_request_type'] ) ? (string) $block['trigger_request_type'] : '',
		);
	}

	private function temporary_block_counts(): array {
		$counts = get_option( self::TEMPORARY_BLOCK_COUNTS_OPTION_NAME, array() );
		return is_array( $counts ) ? $counts : array();
	}
}
