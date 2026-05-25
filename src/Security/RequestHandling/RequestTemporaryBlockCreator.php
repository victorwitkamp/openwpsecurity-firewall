<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\PermanentBanStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestTemporaryBlockCreator {
	private EventLogger $event_logger;
	private RequestTemporaryBlockStore $request_temporary_block_store;
	private RequestHandlingResolver $request_handling_resolver;
	private PermanentBanStore $ban_store;

	public function __construct( EventLogger $event_logger, RequestTemporaryBlockStore $request_temporary_block_store, RequestHandlingResolver $request_handling_resolver, PermanentBanStore $ban_store ) {
		$this->event_logger                  = $event_logger;
		$this->request_temporary_block_store = $request_temporary_block_store;
		$this->request_handling_resolver     = $request_handling_resolver;
		$this->ban_store                     = $ban_store;
	}

	public function create_from_rate_limit( string $ip, string $request_type, int $hit_count, int $rate_limit_threshold, int $rate_limit_window_seconds ): array {
		$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
		$temporary_block          = $this->request_temporary_block_store->start_temporary_block( $ip, $request_type, (int) $temporary_block_settings['temporary_block_minutes'] );
		$temporary_block_count    = $this->request_temporary_block_store->record_temporary_block( $ip );
		$permanent_ban_created    = $this->create_permanent_ban_after_temporary_blocks(
			$ip,
			$request_type,
			$temporary_block_count,
			$temporary_block_settings,
			array(
				'reason'                    => 'rate_limit',
				'hit_count'                 => $hit_count,
				'rate_limit_threshold'      => $rate_limit_threshold,
				'rate_limit_window_seconds' => $rate_limit_window_seconds,
			)
		);

		$this->event_logger->log(
			'request_temporary_block_created',
			$ip,
			'',
			array(
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $temporary_block['expires_at'] ),
				'details'            => array(
					'reason'                    => 'rate_limit',
					'request_type'              => $request_type,
					'hit_count'                 => $hit_count,
					'rate_limit_threshold'      => $rate_limit_threshold,
					'rate_limit_window_seconds' => $rate_limit_window_seconds,
					'temporary_block_minutes'   => (int) $temporary_block_settings['temporary_block_minutes'],
					'temporary_block_count'     => $temporary_block_count,
					'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
				),
			)
		);

		return array(
			'temporary_block'          => $temporary_block,
			'temporary_block_count'    => $temporary_block_count,
			'permanent_ban_created'    => $permanent_ban_created,
			'temporary_block_settings' => $temporary_block_settings,
		);
	}

	public function create_from_captcha_failures( string $ip, string $request_type, int $failure_count, int $failure_threshold, int $failure_window_minutes ): array {
		$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
		$temporary_block          = $this->request_temporary_block_store->start_temporary_block( $ip, $request_type, (int) $temporary_block_settings['temporary_block_minutes'] );
		$temporary_block_count    = $this->request_temporary_block_store->record_temporary_block( $ip );
		$permanent_ban_created    = $this->create_permanent_ban_after_temporary_blocks(
			$ip,
			$request_type,
			$temporary_block_count,
			$temporary_block_settings,
			array(
				'reason'                         => 'captcha_failed',
				'captcha_failure_count'          => $failure_count,
				'captcha_failure_threshold'      => $failure_threshold,
				'captcha_failure_window_minutes' => $failure_window_minutes,
			)
		);

		$this->event_logger->log(
			'request_temporary_block_created',
			$ip,
			'',
			array(
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $temporary_block['expires_at'] ),
				'details'            => array(
					'reason'                         => 'captcha_failed',
					'request_type'                   => $request_type,
					'captcha_failure_count'          => $failure_count,
					'captcha_failure_threshold'      => $failure_threshold,
					'captcha_failure_window_minutes' => $failure_window_minutes,
					'temporary_block_minutes'        => (int) $temporary_block_settings['temporary_block_minutes'],
					'temporary_block_count'          => $temporary_block_count,
					'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
				),
			)
		);

		return array(
			'temporary_block'          => $temporary_block,
			'temporary_block_count'    => $temporary_block_count,
			'permanent_ban_created'    => $permanent_ban_created,
			'temporary_block_settings' => $temporary_block_settings,
		);
	}

	private function create_permanent_ban_after_temporary_blocks( string $ip, string $request_type, int $temporary_block_count, array $temporary_block_settings, array $details ): bool {
		if ( (int) $temporary_block_settings['blocks_before_permanent_ban'] <= 0 ) {
			return false;
		}

		if ( $temporary_block_count < (int) $temporary_block_settings['blocks_before_permanent_ban'] ) {
			return false;
		}

		if ( $this->ban_store->is_banned( $ip ) ) {
			return false;
		}

		$this->ban_store->create_ban(
			$ip,
			'Request handling escalated this IP address to a permanent ban after repeated temporary blocks.',
			'request_handling',
			array_merge(
				$details,
				array(
					'request_type'          => $request_type,
					'temporary_block_count' => $temporary_block_count,
					'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
				)
			)
		);

		return true;
	}
}
