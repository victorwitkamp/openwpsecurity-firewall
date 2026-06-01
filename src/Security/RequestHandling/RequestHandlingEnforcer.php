<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling;

use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Http\Response\RequestDenialResponder;
use VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics\RequestDebugState;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Captcha\CaptchaGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestHandlingEnforcer {
	private EventLogger $event_logger;
	private RequestDenialResponder $denial_responder;
	private RequestDebugState $debug_state;
	private RequestHandlingResolver $request_handling_resolver;
	private RequestRateLimitStore $request_rate_limit_store;
	private RequestTemporaryBlockStore $request_temporary_block_store;
	private RequestContext $request_context;
	private RequestHandlingCatalog $request_handling_catalog;
	private CaptchaGuard $captcha_guard;
	private RequestTemporaryBlockCreator $request_temporary_block_creator;

	public function __construct( EventLogger $event_logger, RequestDenialResponder $denial_responder, RequestDebugState $debug_state, RequestHandlingResolver $request_handling_resolver, RequestRateLimitStore $request_rate_limit_store, RequestTemporaryBlockStore $request_temporary_block_store, RequestContext $request_context, RequestHandlingCatalog $request_handling_catalog, CaptchaGuard $captcha_guard, RequestTemporaryBlockCreator $request_temporary_block_creator ) {
		$this->event_logger                    = $event_logger;
		$this->denial_responder                = $denial_responder;
		$this->debug_state                     = $debug_state;
		$this->request_handling_resolver       = $request_handling_resolver;
		$this->request_rate_limit_store        = $request_rate_limit_store;
		$this->request_temporary_block_store   = $request_temporary_block_store;
		$this->request_context                 = $request_context;
		$this->request_handling_catalog        = $request_handling_catalog;
		$this->captcha_guard                   = $captcha_guard;
		$this->request_temporary_block_creator = $request_temporary_block_creator;
	}

	public function enforce_for_request( string $ip, string $request_type ): void {
		if ( $this->should_bypass( $ip ) ) {
			$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
			$this->write_request_handling_debug(
				$request_type,
				array(
					'temporary_block_enabled' => ! empty( $temporary_block_settings['enabled'] ),
					'temporary_block_minutes' => (int) $temporary_block_settings['temporary_block_minutes'],
					'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
					'status'                  => 'Bypassed for a local, whitelisted, or administrator request.',
				)
			);
			$this->debug_state->add_condition( 'Request handling bypassed for this request.' );
			return;
		}

		$request_handling         = $this->request_handling_resolver->for_request_type( $request_type );
		$temporary_block_settings = $this->request_handling_resolver->temporary_block_settings();
		$active_temporary_block   = $this->request_temporary_block_store->active_temporary_block( $ip );
		$temporary_block_count    = $this->request_temporary_block_store->temporary_block_count( $ip );

		$this->write_request_handling_debug(
			$request_type,
			array(
				'temporary_block_enabled'               => ! empty( $temporary_block_settings['enabled'] ),
				'temporary_block_active'                => ! empty( $active_temporary_block ),
				'temporary_block_expires_at'            => isset( $active_temporary_block['expires_at'] ) ? gmdate( 'Y-m-d H:i:s', (int) $active_temporary_block['expires_at'] ) : '',
				'temporary_block_trigger_request_type'  => (string) ( $active_temporary_block['trigger_request_type'] ?? '' ),
				'temporary_block_minutes'               => (int) $temporary_block_settings['temporary_block_minutes'],
				'temporary_block_count'                 => $temporary_block_count,
				'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
				'status'                                => 'Monitoring the current request handling state.',
			)
		);

		if ( ! empty( $active_temporary_block ) ) {
			$this->deny_active_temporary_block( $ip, $request_type, $active_temporary_block, $temporary_block_count, $temporary_block_settings );
		}

		if ( array() === $request_handling ) {
			$this->debug_state->merge( 'request_handling', array( 'status' => 'No endpoint-local rate limit is configured for this request type.' ) );
			return;
		}

		$this->write_request_handling_debug(
			$request_type,
			array(
				'rate_limit_enabled'        => ! empty( $request_handling['rate_limit_enabled'] ),
				'rate_limit_threshold'      => (int) $request_handling['rate_limit_threshold'],
				'rate_limit_window_seconds' => (int) $request_handling['rate_limit_window_seconds'],
				'status'                    => 'Monitoring the current endpoint rate-limit counter.',
			)
		);

		if ( empty( $request_handling['rate_limit_enabled'] ) ) {
			$this->debug_state->merge( 'request_handling', array( 'status' => 'Endpoint-local rate limiting is disabled for this request type.' ) );
			return;
		}

		$hits = $this->request_rate_limit_store->record_request( $request_type, $ip, (int) $request_handling['rate_limit_window_seconds'] );

		$this->write_request_handling_debug(
			$request_type,
			array(
				'hit_count' => $hits,
				'status'    => 'Monitoring the current endpoint rate-limit counter.',
			)
		);

		if ( $hits < (int) $request_handling['rate_limit_threshold'] ) {
			return;
		}

		if ( $this->request_handling_catalog->uses_rate_limit_page( $request_type ) ) {
			$this->handle_rate_limited_page_request(
				$ip,
				$request_type,
				$hits,
				(int) $request_handling['rate_limit_threshold'],
				(int) $request_handling['rate_limit_window_seconds']
			);
			return;
		}

		$this->event_logger->log(
			'request_rate_limited',
			$ip,
			'',
			array(
				'details' => array(
					'request_type'              => $request_type,
					'hit_count'                 => $hits,
					'rate_limit_threshold'      => (int) $request_handling['rate_limit_threshold'],
					'rate_limit_window_seconds' => (int) $request_handling['rate_limit_window_seconds'],
					'temporary_block_enabled'   => ! empty( $temporary_block_settings['enabled'] ),
					'response_action'           => empty( $temporary_block_settings['enabled'] ) ? 'message_only' : 'temporary_block',
				),
			)
		);

		if ( empty( $temporary_block_settings['enabled'] ) ) {
			$this->write_request_handling_debug(
				$request_type,
				array(
					'status' => 'Endpoint rate-limit threshold reached on this request.',
				)
			);
			$this->debug_state->add_condition( 'Request handling rate limiting triggered for this endpoint.' );
			$this->denial_responder->deny_rate_limited(
				$ip,
				$request_type,
				(int) $request_handling['rate_limit_window_seconds'],
				'Request rate limited',
				'Too many requests from this IP address were detected for this endpoint in a short period.'
			);
		}

		$temporary_block_result = $this->request_temporary_block_creator->create_from_rate_limit(
			$ip,
			$request_type,
			$hits,
			(int) $request_handling['rate_limit_threshold'],
			(int) $request_handling['rate_limit_window_seconds']
		);
		$active_temporary_block = $temporary_block_result['temporary_block'];
		$temporary_block_count  = (int) $temporary_block_result['temporary_block_count'];

		if ( ! empty( $temporary_block_result['permanent_ban_created'] ) ) {
			$this->write_request_handling_debug(
				$request_type,
				array(
					'temporary_block_count' => $temporary_block_count,
					'status'                => 'Permanent ban created after repeated request-handling temporary blocks.',
				)
			);
			$this->debug_state->add_condition( 'Request handling created a permanent ban after repeated temporary blocks.' );
			$this->denial_responder->deny_permanently(
				$ip,
				$request_type,
				'Access permanently blocked',
				'This IP address has been permanently banned by request handling after repeated temporary blocks.',
				'All request types are now blocked for this IP address.'
			);
		}

		$this->write_request_handling_debug(
			$request_type,
			array(
				'temporary_block_active'               => true,
				'temporary_block_expires_at'           => gmdate( 'Y-m-d H:i:s', (int) $active_temporary_block['expires_at'] ),
				'temporary_block_trigger_request_type' => $request_type,
				'temporary_block_count'                => $temporary_block_count,
				'status'                               => 'Global request-handling temporary block created on this request.',
			)
		);
		$this->debug_state->add_condition( 'Request handling temporary block triggered.' );
		$this->denial_responder->deny_temporarily(
			$ip,
			$request_type,
			(int) $active_temporary_block['expires_at'],
			403,
			'Access temporarily blocked',
			'This IP address has been temporarily blocked by request handling across all request types.'
		);
	}

	private function handle_rate_limited_page_request( string $ip, string $request_type, int $hits, int $rate_limit_threshold, int $rate_limit_window_seconds ): void {
		$this->write_request_handling_debug(
			$request_type,
			array(
				'hit_count' => $hits,
				'status'    => 'HTML rate limit matched. A 429 rate-limit response is being prepared for this endpoint.',
			)
		);

		if ( ! empty( $this->request_handling_resolver->temporary_block_settings()['enabled'] ) ) {
			$this->debug_state->add_condition( 'Global temporary blocks remain available, but HTML rate limits use the shared rate-limit page flow first.' );
		}

		if ( $this->request_handling_catalog->supports_captcha( $request_type ) && ! empty( $this->request_handling_resolver->temporary_block_settings()['enabled'] ) ) {
			$this->write_request_handling_debug(
				$request_type,
				array(
					'hit_count' => $hits,
					'status'    => 'HTML rate limit matched. Shared captcha or a rate-limit page will handle the response before any temporary block is created.',
				)
			);
		}

		if ( $this->request_handling_catalog->supports_captcha( $request_type ) ) {
			$this->captcha_guard->respond_to_rate_limited_request( $ip, $request_type, $hits, $rate_limit_threshold, $rate_limit_window_seconds );
			return;
		}

		$this->event_logger->log(
			'request_rate_limited',
			$ip,
			'',
			array(
				'details' => array(
					'request_type'              => $request_type,
					'hit_count'                 => $hits,
					'rate_limit_threshold'      => $rate_limit_threshold,
					'rate_limit_window_seconds' => $rate_limit_window_seconds,
					'response_action'           => 'rate_limit_page',
				),
			)
		);

		$this->write_request_handling_debug(
			$request_type,
			array(
				'hit_count' => $hits,
				'status'    => 'HTML rate limit matched. A 429 rate-limit page was rendered for this request.',
			)
		);
		$this->debug_state->add_condition( 'Request handling rendered a 429 rate-limit page for this endpoint.' );
		$this->denial_responder->deny_rate_limited(
			$ip,
			$request_type,
			$rate_limit_window_seconds,
			'Too many requests',
			'This endpoint received too many requests from your IP address. Please try again shortly.'
		);
	}

	private function should_bypass( string $ip ): bool {
		if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return true;
		}

		return $this->request_context->is_ip_whitelisted( $ip );
	}

	private function deny_active_temporary_block( string $ip, string $request_type, array $active_temporary_block, int $temporary_block_count, array $temporary_block_settings ): void {
		$active_temporary_block = $this->request_temporary_block_store->record_active_temporary_block_denial( $ip, $request_type );

		if ( array() === $active_temporary_block ) {
			return;
		}

		$trigger_request_type                      = (string) ( $active_temporary_block['trigger_request_type'] ?? '' );
		$trigger_request_type                      = '' !== $trigger_request_type ? $trigger_request_type : $request_type;
		$active_block_denial_count                 = (int) ( $active_temporary_block['denial_count'] ?? 0 );
		$active_block_denials_before_permanent_ban = $this->request_handling_resolver->active_block_denials_before_permanent_ban( $trigger_request_type );

		$this->event_logger->log(
			'request_temporarily_blocked',
			$ip,
			'',
			array(
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $active_temporary_block['expires_at'] ),
				'details'            => array(
					'request_type'              => $request_type,
					'trigger_request_type'      => $trigger_request_type,
					'reason'                    => 'active_temporary_block',
					'temporary_block_count'     => $temporary_block_count,
					'temporary_blocks_before_permanent_ban' => (int) $temporary_block_settings['blocks_before_permanent_ban'],
					'active_block_denial_count' => $active_block_denial_count,
					'active_block_denials_before_permanent_ban' => $active_block_denials_before_permanent_ban,
				),
			)
		);

		$this->write_request_handling_debug(
			$request_type,
			array(
				'temporary_block_active'               => true,
				'temporary_block_expires_at'           => gmdate( 'Y-m-d H:i:s', (int) $active_temporary_block['expires_at'] ),
				'temporary_block_trigger_request_type' => $trigger_request_type,
				'temporary_block_count'                => $temporary_block_count,
				'active_block_denial_count'            => $active_block_denial_count,
				'active_block_denials_before_permanent_ban' => $active_block_denials_before_permanent_ban,
				'status'                               => 'A global request-handling temporary block is still active.',
			)
		);
		$this->debug_state->add_condition( 'Request handling matched an active temporary block.' );

		if ( $this->request_temporary_block_creator->create_permanent_ban_after_active_temporary_block_denials( $ip, $request_type, $trigger_request_type, $active_block_denial_count, $active_block_denials_before_permanent_ban, $temporary_block_count ) ) {
			$this->request_temporary_block_store->clear_active_temporary_block( $ip );
			$this->write_request_handling_debug(
				$request_type,
				array(
					'temporary_block_active'    => false,
					'active_block_denial_count' => $active_block_denial_count,
					'active_block_denials_before_permanent_ban' => $active_block_denials_before_permanent_ban,
					'status'                    => 'Permanent ban created after repeated requests during an active temporary block.',
				)
			);
			$this->debug_state->add_condition( 'Request handling created a permanent ban during an active temporary block.' );
			$this->denial_responder->deny_permanently(
				$ip,
				$request_type,
				'Access permanently blocked',
				'This IP address has been permanently banned after repeated requests during an active temporary block.',
				'All request types are now blocked for this IP address.'
			);
		}

		$this->denial_responder->deny_temporarily(
			$ip,
			$request_type,
			(int) $active_temporary_block['expires_at'],
			403,
			'Access temporarily blocked',
			'This IP address is currently under a request-handling temporary block across all request types.'
		);
	}

	private function write_request_handling_debug( string $request_type, array $values ): void {
		$this->debug_state->merge(
			'request_handling',
			array_merge(
				array(
					'request_type' => $request_type,
				),
				$values
			)
		);
	}
}
