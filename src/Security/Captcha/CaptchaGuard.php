<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Captcha;

use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Http\Response\RequestDenialResponder;
use VictorWitkamp\OpenWPSecurity\Core\Http\Response\ResponseDispatcher;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics\RequestDebugState;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\TransientKeyBuilder;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingCatalog;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\TemporaryBanCreator;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CaptchaGuard {
	private const CAPTCHA_COOKIE = 'openwpsecurity_firewall_pass';

	private Settings $settings;
	private EventLogger $event_logger;
	private RequestDenialResponder $denial_responder;
	private ResponseDispatcher $response_dispatcher;
	private RequestDebugState $debug_state;
	private RequestContext $request_context;
	private TransientKeyBuilder $transient_key_builder;
	private PermanentBanStore $ban_store;
	private RequestHandlingCatalog $request_handling_catalog;
	private TemporaryBanCreator $temporary_ban_creator;

	public function __construct(
		Settings $settings,
		EventLogger $event_logger,
		RequestDenialResponder $denial_responder,
		ResponseDispatcher $response_dispatcher,
		RequestDebugState $debug_state,
		RequestContext $request_context,
		TransientKeyBuilder $transient_key_builder,
		PermanentBanStore $ban_store,
		RequestHandlingCatalog $request_handling_catalog,
		TemporaryBanCreator $temporary_ban_creator
	) {
		$this->settings                 = $settings;
		$this->event_logger             = $event_logger;
		$this->denial_responder         = $denial_responder;
		$this->response_dispatcher      = $response_dispatcher;
		$this->debug_state              = $debug_state;
		$this->request_context          = $request_context;
		$this->transient_key_builder    = $transient_key_builder;
		$this->ban_store                = $ban_store;
		$this->request_handling_catalog = $request_handling_catalog;
		$this->temporary_ban_creator    = $temporary_ban_creator;
	}

	public function respond_to_rate_limited_request( string $ip, string $request_type, int $hit_count, int $rate_limit_threshold, int $rate_limit_window_seconds ): void {
		$this->update_debug_snapshot(
			$ip,
			$request_type,
			array(
				'rate_limited'              => true,
				'rate_limit_hit_count'      => $hit_count,
				'rate_limit_threshold'      => $rate_limit_threshold,
				'rate_limit_window_seconds' => $rate_limit_window_seconds,
				'challenge_active'          => false,
				'status'                    => 'A captcha-capable endpoint exceeded its rate limit.',
			)
		);

		if ( ! $this->request_handling_catalog->supports_captcha( $request_type ) || ! $this->is_enabled() ) {
			$this->event_logger->log(
				'request_rate_limited',
				$ip,
				'',
				array(
					'details' => array(
						'request_type'              => $request_type,
						'hit_count'                 => $hit_count,
						'rate_limit_threshold'      => $rate_limit_threshold,
						'rate_limit_window_seconds' => $rate_limit_window_seconds,
						'response_action'           => 'rate_limit_page',
					),
				)
			);

			$this->render_rate_limit_page(
				$ip,
				$request_type,
				$hit_count,
				$rate_limit_threshold,
				$rate_limit_window_seconds,
				$rate_limit_window_seconds,
				'',
				false
			);
		}

		if ( $this->has_valid_pass_cookie( $ip ) ) {
			$this->update_debug_snapshot(
				$ip,
				$request_type,
				array(
					'rate_limited'              => true,
					'rate_limit_hit_count'      => $hit_count,
					'rate_limit_threshold'      => $rate_limit_threshold,
					'rate_limit_window_seconds' => $rate_limit_window_seconds,
					'challenge_active'          => false,
					'has_pass_cookie'           => true,
					'status'                    => 'Captcha bypass cookie allowed the rate-limited request to continue.',
				)
			);
			$this->debug_state->add_condition( 'Captcha bypass cookie was accepted for this rate-limited request.' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified inside handle_submission().
		if ( 'POST' === $this->request_context->current_method() && isset( $_POST['vwfw_captcha_submit'] ) ) {
			$this->debug_state->add_condition( 'Captcha submission detected for a rate-limited request.' );
			$this->handle_submission( $ip, $request_type, $hit_count, $rate_limit_threshold, $rate_limit_window_seconds );
			return;
		}

		$challenge_threshold    = $this->captcha_challenges_before_temporary_block( $request_type );
		$challenge_state        = $this->record_captcha_challenge( $ip, $request_type, $rate_limit_window_seconds );
		$create_temporary_block = $this->should_create_temporary_block_after_challenges( $challenge_state['count'], $challenge_threshold );

		$this->event_logger->log(
			'request_rate_limited',
			$ip,
			'',
			array(
				'details' => array(
					'request_type'              => $request_type,
					'hit_count'                 => $hit_count,
					'rate_limit_threshold'      => $rate_limit_threshold,
					'rate_limit_window_seconds' => $rate_limit_window_seconds,
					'response_action'           => $create_temporary_block ? 'temporary_block' : 'captcha_page',
					'captcha_challenge_count'   => $challenge_state['count'],
					'captcha_challenges_before_temporary_block' => $challenge_threshold,
				),
			)
		);

		if ( $create_temporary_block ) {
			$result = $this->temporary_ban_creator->create_from_captcha_challenge_volume(
				$ip,
				$request_type,
				$challenge_state['count'],
				$challenge_threshold,
				$rate_limit_window_seconds
			);

			$this->clear_captcha_challenges( $ip, $request_type );

			if ( ! empty( $result['permanent_ban_created'] ) ) {
				$this->debug_state->merge(
					'request_handling',
					array(
						'temporary_block_active'     => true,
						'temporary_block_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $result['temporary_block']['expires_at'] ),
						'temporary_block_trigger_request_type' => $request_type,
						'temporary_block_count'      => (int) $result['temporary_block_count'],
						'captcha_challenge_count'    => $challenge_state['count'],
						'captcha_challenges_before_temporary_block' => $challenge_threshold,
						'status'                     => 'Repeated unsolved captcha challenges created a temporary block and then escalated into a permanent ban.',
					)
				);
				$this->debug_state->add_condition( 'Permanent ban created because repeated captcha challenges caused repeated temporary blocks.' );
				$this->denial_responder->deny_permanently(
					$ip,
					$request_type,
					'Access permanently blocked',
					'This IP address has been permanently banned after repeated unsolved captcha challenges and temporary blocks.',
					'All request types are now blocked for this IP address.'
				);
			}

			$this->debug_state->merge(
				'request_handling',
				array(
					'temporary_block_active'               => true,
					'temporary_block_expires_at'           => gmdate( 'Y-m-d H:i:s', (int) $result['temporary_block']['expires_at'] ),
					'temporary_block_trigger_request_type' => $request_type,
					'temporary_block_count'                => (int) $result['temporary_block_count'],
					'captcha_challenge_count'              => $challenge_state['count'],
					'captcha_challenges_before_temporary_block' => $challenge_threshold,
					'status'                               => 'Repeated unsolved captcha challenges created a global request-handling temporary block.',
				)
			);
			$this->debug_state->add_condition( 'Repeated unsolved captcha challenges created a global temporary block.' );
			$this->denial_responder->deny_temporarily(
				$ip,
				$request_type,
				(int) $result['temporary_block']['expires_at'],
				403,
				'Access temporarily blocked',
				'Too many captcha challenges were requested without being solved. Access is temporarily blocked across all request types.'
			);
		}

		$this->event_logger->log(
			'captcha_required',
			$ip,
			'',
			array(
				'details' => array(
					'request_type'                   => $request_type,
					'hit_count'                      => $hit_count,
					'rate_limit_threshold'           => $rate_limit_threshold,
					'rate_limit_window_seconds'      => $rate_limit_window_seconds,
					'captcha_failure_threshold'      => (int) $this->settings->get()['captcha_failure_threshold'],
					'captcha_failure_window_minutes' => (int) $this->settings->get()['captcha_failure_window_minutes'],
					'captcha_challenge_count'        => $challenge_state['count'],
					'captcha_challenges_before_temporary_block' => $challenge_threshold,
				),
			)
		);

		$this->update_debug_snapshot(
			$ip,
			$request_type,
			array(
				'rate_limited'              => true,
				'rate_limit_hit_count'      => $hit_count,
				'rate_limit_threshold'      => $rate_limit_threshold,
				'rate_limit_window_seconds' => $rate_limit_window_seconds,
				'challenge_active'          => true,
				'has_pass_cookie'           => false,
				'status'                    => 'Shared captcha challenge rendered for the rate-limited request.',
			)
		);
		$this->debug_state->add_condition( 'Shared captcha challenge rendered because the endpoint rate limit was exceeded.' );

		$this->render_rate_limit_page(
			$ip,
			$request_type,
			$hit_count,
			$rate_limit_threshold,
			$rate_limit_window_seconds,
			$rate_limit_window_seconds,
			'',
			true
		);
	}

	public function update_debug_snapshot( string $ip, ?string $request_type = null, array $captcha_overrides = array() ): void {
		$settings          = $this->settings->get();
		$request_type      = null !== $request_type ? $request_type : $this->request_context->current_request_type();
		$failure_state     = $this->captcha_failure_state( $ip, (int) $settings['captcha_failure_window_minutes'] );
		$captcha_enabled   = $this->request_handling_catalog->supports_captcha( $request_type ) && $this->is_enabled();
		$failure_threshold = (int) $settings['captcha_failure_threshold'];

		$ban = $this->ban_store->get_ban_for_ip( $ip );

		$this->debug_state->merge(
			'ban',
			array(
				'is_banned' => array() !== $ban,
				'banned_at' => (string) ( $ban['banned_at'] ?? '' ),
				'source'    => (string) ( $ban['source'] ?? '' ),
				'reason'    => (string) ( $ban['reason'] ?? '' ),
			)
		);
		$this->debug_state->merge(
			'captcha',
			array_merge(
				array(
					'request_type'                    => $request_type,
					'enabled'                         => $captcha_enabled,
					'failure_count'                   => $failure_state['count'],
					'failure_threshold'               => $failure_threshold,
					'failure_window_minutes'          => (int) $settings['captcha_failure_window_minutes'],
					'remaining_until_temporary_block' => $failure_threshold > 0 ? max( 0, $failure_threshold - $failure_state['count'] ) : 0,
					'challenge_active'                => false,
					'has_pass_cookie'                 => $captcha_enabled ? $this->has_valid_pass_cookie( $ip ) : false,
					'rate_limited'                    => false,
				),
				$captcha_overrides
			)
		);
	}

	private function has_valid_pass_cookie( string $ip ): bool {
		if ( empty( $_COOKIE[ self::CAPTCHA_COOKIE ] ) ) {
			return false;
		}

		$value = explode( '|', (string) wp_unslash( $_COOKIE[ self::CAPTCHA_COOKIE ] ) );

		if ( count( $value ) !== 2 ) {
			return false;
		}

		[ $expires, $hash ] = $value;
		$expires            = (int) $expires;

		if ( $expires < time() ) {
			return false;
		}

		$expected = hash_hmac( 'sha256', $ip . '|' . $expires, wp_salt( 'logged_in' ) );

		return hash_equals( $expected, $hash );
	}

	private function set_pass_cookie( string $ip ): void {
		$settings = $this->settings->get();
		$expires  = time() + ( $settings['captcha_pass_minutes'] * MINUTE_IN_SECONDS );
		$hash     = hash_hmac( 'sha256', $ip . '|' . $expires, wp_salt( 'logged_in' ) );

		setcookie(
			self::CAPTCHA_COOKIE,
			$expires . '|' . $hash,
			array(
				'expires'  => $expires,
				'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	private function handle_submission( string $ip, string $request_type, int $hit_count, int $rate_limit_threshold, int $rate_limit_window_seconds ): void {
		$settings = $this->settings->get();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Raw nonce is required for verification.
		$nonce = isset( $_POST['vwfw_nonce'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['vwfw_nonce'] ) ) : '';

		if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'vwfw_captcha_submit' ) ) {
			$this->render_rate_limit_page(
				$ip,
				$request_type,
				$hit_count,
				$rate_limit_threshold,
				$rate_limit_window_seconds,
				$rate_limit_window_seconds,
				'Security token expired. Please try again.',
				true
			);
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified above.
		$token = isset( $_POST['vwfw_token'] ) ? sanitize_text_field( (string) wp_unslash( $_POST['vwfw_token'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified above.
		$answer = isset( $_POST['vwfw_answer'] ) ? trim( (string) wp_unslash( $_POST['vwfw_answer'] ) ) : '';
		$data   = get_transient( $this->transient_key_builder->captcha_challenge( $token ) );

		if ( ! is_array( $data ) || empty( $data['ip'] ) || (string) $data['ip'] !== $ip || ! hash_equals( (string) $data['answer'], $answer ) ) {
			$failure_state = $this->record_captcha_failure( $ip, (int) $settings['captcha_failure_window_minutes'] );

			$this->event_logger->log(
				'captcha_failed',
				$ip,
				'',
				array(
					'details' => array(
						'request_type'                   => $request_type,
						'token'                          => $token,
						'captcha_failure_count'          => $failure_state['count'],
						'captcha_failure_threshold'      => (int) $settings['captcha_failure_threshold'],
						'captcha_failure_window_minutes' => (int) $settings['captcha_failure_window_minutes'],
					),
				)
			);

			$this->update_debug_snapshot(
				$ip,
				$request_type,
				array(
					'failure_count'                   => $failure_state['count'],
					'failure_threshold'               => (int) $settings['captcha_failure_threshold'],
					'failure_window_minutes'          => (int) $settings['captcha_failure_window_minutes'],
					'remaining_until_temporary_block' => (int) $settings['captcha_failure_threshold'] > 0 ? max( 0, (int) $settings['captcha_failure_threshold'] - $failure_state['count'] ) : 0,
					'challenge_active'                => true,
					'has_pass_cookie'                 => false,
					'rate_limited'                    => true,
					'rate_limit_hit_count'            => $hit_count,
					'rate_limit_threshold'            => $rate_limit_threshold,
					'rate_limit_window_seconds'       => $rate_limit_window_seconds,
					'status'                          => 'Captcha validation failed for the rate-limited request.',
				)
			);
			$this->debug_state->add_condition( 'Captcha validation failed.' );

			if ( $this->should_create_temporary_block_after_failures( $failure_state['count'], (int) $settings['captcha_failure_threshold'] ) ) {
				$result = $this->temporary_ban_creator->create_from_captcha_failures(
					$ip,
					$request_type,
					$failure_state['count'],
					(int) $settings['captcha_failure_threshold'],
					(int) $settings['captcha_failure_window_minutes']
				);

				if ( ! empty( $result['permanent_ban_created'] ) ) {
					$this->debug_state->merge(
						'request_handling',
						array(
							'temporary_block_active'     => true,
							'temporary_block_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $result['temporary_block']['expires_at'] ),
							'temporary_block_trigger_request_type' => $request_type,
							'temporary_block_count'      => (int) $result['temporary_block_count'],
							'status'                     => 'Repeated captcha failures created a temporary block and then escalated into a permanent ban.',
						)
					);
					$this->debug_state->add_condition( 'Permanent ban created because repeated captcha failures caused repeated temporary blocks.' );
					$this->denial_responder->deny_permanently(
						$ip,
						$request_type,
						'Access permanently blocked',
						'This IP address has been permanently banned after repeated captcha failures and temporary blocks.',
						'All request types are now blocked for this IP address.'
					);
				}

				$this->debug_state->merge(
					'request_handling',
					array(
						'temporary_block_active'     => true,
						'temporary_block_expires_at' => gmdate( 'Y-m-d H:i:s', (int) $result['temporary_block']['expires_at'] ),
						'temporary_block_trigger_request_type' => $request_type,
						'temporary_block_count'      => (int) $result['temporary_block_count'],
						'status'                     => 'Repeated captcha failures created a global request-handling temporary block.',
					)
				);
				$this->debug_state->add_condition( 'Repeated captcha failures created a global temporary block.' );
				$this->denial_responder->deny_temporarily(
					$ip,
					$request_type,
					(int) $result['temporary_block']['expires_at'],
					403,
					'Access temporarily blocked',
					'Too many incorrect captcha answers were submitted from this IP address. Access is temporarily blocked across all request types.'
				);
			}

			$this->render_rate_limit_page(
				$ip,
				$request_type,
				$hit_count,
				$rate_limit_threshold,
				$rate_limit_window_seconds,
				$rate_limit_window_seconds,
				'Incorrect captcha answer.',
				true
			);
		}

		delete_transient( $this->transient_key_builder->captcha_challenge( $token ) );
		$this->clear_captcha_failures( $ip );
		$this->clear_captcha_challenges( $ip, $request_type );
		$this->set_pass_cookie( $ip );

		$this->event_logger->log(
			'captcha_passed',
			$ip,
			'',
			array(
				'details' => array(
					'request_type'         => $request_type,
					'captcha_pass_minutes' => (int) $settings['captcha_pass_minutes'],
				),
			)
		);

		$this->update_debug_snapshot(
			$ip,
			$request_type,
			array(
				'enabled'                         => true,
				'challenge_active'                => false,
				'has_pass_cookie'                 => true,
				'failure_count'                   => 0,
				'remaining_until_temporary_block' => (int) $settings['captcha_failure_threshold'],
				'rate_limited'                    => true,
				'rate_limit_hit_count'            => $hit_count,
				'rate_limit_threshold'            => $rate_limit_threshold,
				'rate_limit_window_seconds'       => $rate_limit_window_seconds,
				'status'                          => 'Captcha solved successfully for the rate-limited request.',
			)
		);
		$this->debug_state->add_condition( 'Captcha solved successfully.' );

		$redirect_url = wp_validate_redirect( $this->request_context->current_url(), home_url( '/' ) );
		$this->response_dispatcher->redirect( $redirect_url );
	}

	private function render_rate_limit_page( string $ip, string $request_type, int $hit_count, int $rate_limit_threshold, int $rate_limit_window_seconds, int $retry_after_seconds, string $error = '', bool $show_captcha = false ): void {
		nocache_headers();

		$template_variables = array(
			'ip'                  => $ip,
			'title'               => 'Too many requests',
			'message'             => $show_captcha
				? 'This endpoint received too many requests from your IP address. Complete the captcha to continue browsing.'
				: 'This endpoint received too many requests from your IP address. Please slow down and try again shortly.',
			'error'               => $error,
			'show_captcha'        => $show_captcha,
			'retry_after_seconds' => $retry_after_seconds,
		);

		if ( $show_captcha ) {
			$a     = wp_rand( 1, 9 );
			$b     = wp_rand( 1, 9 );
			$token = wp_generate_password( 20, false, false );

			set_transient(
				$this->transient_key_builder->captcha_challenge( $token ),
				array(
					'ip'           => $ip,
					'answer'       => (string) ( $a + $b ),
					'request_type' => $request_type,
				),
				10 * MINUTE_IN_SECONDS
			);

			$template_variables['token'] = $token;
			$template_variables['a']     = $a;
			$template_variables['b']     = $b;
		}

		$this->update_debug_snapshot(
			$ip,
			$request_type,
			array(
				'rate_limited'                    => true,
				'rate_limit_hit_count'            => $hit_count,
				'rate_limit_threshold'            => $rate_limit_threshold,
				'rate_limit_window_seconds'       => $rate_limit_window_seconds,
				'challenge_active'                => $show_captcha,
				'has_pass_cookie'                 => false,
				'remaining_until_temporary_block' => max( 0, (int) $this->settings->get()['captcha_failure_threshold'] - $this->captcha_failure_state( $ip, (int) $this->settings->get()['captcha_failure_window_minutes'] )['count'] ),
			)
		);

		$this->denial_responder->deny_rate_limited(
			$ip,
			$request_type,
			$retry_after_seconds,
			'Too many requests',
			(string) $template_variables['message'],
			$template_variables,
			array(
				'request_type'              => $request_type,
				'hit_count'                 => $hit_count,
				'rate_limit_threshold'      => $rate_limit_threshold,
				'rate_limit_window_seconds' => $rate_limit_window_seconds,
				'show_captcha'              => $show_captcha ? '1' : '0',
			)
		);
	}

	private function is_enabled(): bool {
		$settings = $this->settings->get();

		return ! empty( $settings[ $this->request_handling_catalog->captcha_enabled_setting_key() ] );
	}

	private function captcha_failure_state( string $ip, int $window_minutes ): array {
		$key     = $this->transient_key_builder->captcha_failure_history( $ip );
		$history = get_transient( $key );
		$history = is_array( $history ) ? $history : array();
		$now     = time();

		$history = array_values(
			array_filter(
				$history,
				static function ( $timestamp ) use ( $now, $window_minutes ): bool {
					return ( (int) $timestamp ) >= ( $now - ( $window_minutes * MINUTE_IN_SECONDS ) );
				}
			)
		);

		if ( empty( $history ) ) {
			delete_transient( $key );
		} else {
			set_transient( $key, $history, max( MINUTE_IN_SECONDS, ( $window_minutes * MINUTE_IN_SECONDS * 2 ) ) );
		}

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	private function record_captcha_failure( string $ip, int $window_minutes ): array {
		$state     = $this->captcha_failure_state( $ip, $window_minutes );
		$history   = $state['history'];
		$history[] = time();

		set_transient(
			$this->transient_key_builder->captcha_failure_history( $ip ),
			$history,
			max( MINUTE_IN_SECONDS, ( $window_minutes * MINUTE_IN_SECONDS * 2 ) )
		);

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	private function clear_captcha_failures( string $ip ): void {
		delete_transient( $this->transient_key_builder->captcha_failure_history( $ip ) );
	}

	private function captcha_challenges_before_temporary_block( string $request_type ): int {
		$settings = $this->settings->get();
		$key      = $this->request_handling_catalog->setting_key( $request_type, 'captcha_challenges_before_temporary_block' );

		return max( 0, (int) ( $settings[ $key ] ?? 0 ) );
	}

	private function captcha_challenge_state( string $ip, string $request_type, int $window_seconds ): array {
		$key     = $this->transient_key_builder->captcha_challenge_history( $request_type, $ip );
		$history = get_transient( $key );
		$history = is_array( $history ) ? $history : array();
		$now     = time();

		$history = array_values(
			array_filter(
				$history,
				static function ( $timestamp ) use ( $now, $window_seconds ): bool {
					return ( (int) $timestamp ) >= ( $now - $window_seconds );
				}
			)
		);

		if ( empty( $history ) ) {
			delete_transient( $key );
		} else {
			set_transient( $key, $history, max( MINUTE_IN_SECONDS, $window_seconds * 2 ) );
		}

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	private function record_captcha_challenge( string $ip, string $request_type, int $window_seconds ): array {
		$state     = $this->captcha_challenge_state( $ip, $request_type, $window_seconds );
		$history   = $state['history'];
		$history[] = time();

		set_transient(
			$this->transient_key_builder->captcha_challenge_history( $request_type, $ip ),
			$history,
			max( MINUTE_IN_SECONDS, $window_seconds * 2 )
		);

		return array(
			'count'   => count( $history ),
			'history' => $history,
		);
	}

	private function clear_captcha_challenges( string $ip, string $request_type ): void {
		delete_transient( $this->transient_key_builder->captcha_challenge_history( $request_type, $ip ) );
	}

	private function should_create_temporary_block_after_failures( int $failure_count, int $failure_threshold ): bool {
		return $failure_threshold > 0 && $failure_count >= $failure_threshold;
	}

	private function should_create_temporary_block_after_challenges( int $challenge_count, int $challenge_threshold ): bool {
		return $challenge_threshold > 0 && $challenge_count >= $challenge_threshold;
	}
}
