<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingResolver;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemporaryBanCreator {
	private EventLogger $event_logger;
	private TemporaryBanRepository $temporary_ban_repository;
	private TemporaryBanCounterStore $temporary_ban_counter_store;
	private RequestHandlingResolver $request_handling_resolver;
	private PermanentBanStore $ban_store;

	public function __construct( EventLogger $event_logger, TemporaryBanRepository $temporary_ban_repository, TemporaryBanCounterStore $temporary_ban_counter_store, RequestHandlingResolver $request_handling_resolver, PermanentBanStore $ban_store ) {
		$this->event_logger                = $event_logger;
		$this->temporary_ban_repository    = $temporary_ban_repository;
		$this->temporary_ban_counter_store = $temporary_ban_counter_store;
		$this->request_handling_resolver   = $request_handling_resolver;
		$this->ban_store                   = $ban_store;
	}

	public function create_from_rate_limit( string $ip, string $request_type, int $hit_count, int $rate_limit_threshold, int $rate_limit_window_seconds ): array {
		$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
		$temporary_block_count    = $this->temporary_ban_counter_store->increment_for_ip( $ip );
		$temporary_block          = $this->temporary_ban_repository->create_temporary_ban( $ip, $request_type, (int) $temporary_block_settings['temporary_block_minutes'], $temporary_block_count );
		$permanent_ban_created    = $this->create_permanent_ban_after_temporary_bans(
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
		$temporary_block_count    = $this->temporary_ban_counter_store->increment_for_ip( $ip );
		$temporary_block          = $this->temporary_ban_repository->create_temporary_ban( $ip, $request_type, (int) $temporary_block_settings['temporary_block_minutes'], $temporary_block_count );
		$permanent_ban_created    = $this->create_permanent_ban_after_temporary_bans(
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

	public function create_from_captcha_challenge_volume( string $ip, string $request_type, int $challenge_count, int $challenge_threshold, int $challenge_window_seconds ): array {
		$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
		$temporary_block_count    = $this->temporary_ban_counter_store->increment_for_ip( $ip );
		$temporary_block          = $this->temporary_ban_repository->create_temporary_ban( $ip, $request_type, (int) $temporary_block_settings['temporary_block_minutes'], $temporary_block_count );
		$permanent_ban_created    = $this->create_permanent_ban_after_temporary_bans(
			$ip,
			$request_type,
			$temporary_block_count,
			$temporary_block_settings,
			array(
				'reason'                           => 'captcha_challenge_volume',
				'captcha_challenge_count'          => $challenge_count,
				'captcha_challenge_threshold'      => $challenge_threshold,
				'captcha_challenge_window_seconds' => $challenge_window_seconds,
			)
		);

		$this->event_logger->log(
			'request_temporary_block_created',
			$ip,
			'',
			array(
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $temporary_block['expires_at'] ),
				'details'            => array(
					'reason'                           => 'captcha_challenge_volume',
					'request_type'                     => $request_type,
					'captcha_challenge_count'          => $challenge_count,
					'captcha_challenge_threshold'      => $challenge_threshold,
					'captcha_challenge_window_seconds' => $challenge_window_seconds,
					'temporary_block_minutes'          => (int) $temporary_block_settings['temporary_block_minutes'],
					'temporary_block_count'            => $temporary_block_count,
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

	public function create_permanent_ban_after_active_temporary_ban_denials( string $ip, string $request_type, string $trigger_request_type, int $active_block_denial_count, int $active_block_denials_before_permanent_ban, int $temporary_block_count ): bool {
		if ( $active_block_denials_before_permanent_ban <= 0 ) {
			return false;
		}

		if ( $active_block_denial_count < $active_block_denials_before_permanent_ban ) {
			return false;
		}

		if ( $this->ban_store->is_banned( $ip ) ) {
			return false;
		}

		$this->ban_store->create_ban(
			$ip,
			'Request handling escalated this IP address to a permanent ban after repeated requests during an active temporary ban.',
			'request_handling',
			array(
				'reason'                                => 'active_temporary_block_denials',
				'request_type'                          => $request_type,
				'trigger_request_type'                  => $trigger_request_type,
				'active_block_denial_count'             => $active_block_denial_count,
				'active_block_denials_before_permanent_ban' => $active_block_denials_before_permanent_ban,
				'temporary_block_count'                 => $temporary_block_count,
				'temporary_blocks_before_permanent_ban' => (int) $this->request_handling_resolver->temporary_block_settings()['blocks_before_permanent_ban'],
			)
		);

		return true;
	}

	private function create_permanent_ban_after_temporary_bans( string $ip, string $request_type, int $temporary_block_count, array $temporary_block_settings, array $details ): bool {
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
			'Request handling escalated this IP address to a permanent ban after repeated temporary bans.',
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
