<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security;

use VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics\RequestDebugState;
use VictorWitkamp\OpenWPSecurity\Firewall\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Firewall\Http\Response\RequestDenialResponder;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Captcha\CaptchaGuard;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\FrontendPageVisitLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingEnforcer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestGuard {
	private PermanentBanStore $ban_store;
	private EventLogger $event_logger;
	private RequestHandlingEnforcer $request_handling_enforcer;
	private RequestDenialResponder $denial_responder;
	private RequestDebugState $debug_state;
	private RequestContext $request_context;
	private FrontendPageVisitLogger $frontend_page_visit_logger;
	private CaptchaGuard $captcha_guard;
	private bool $request_logged = false;

	public function __construct( PermanentBanStore $ban_store, EventLogger $event_logger, RequestHandlingEnforcer $request_handling_enforcer, RequestDenialResponder $denial_responder, RequestDebugState $debug_state, RequestContext $request_context, FrontendPageVisitLogger $frontend_page_visit_logger, CaptchaGuard $captcha_guard ) {
		$this->ban_store                  = $ban_store;
		$this->event_logger               = $event_logger;
		$this->request_handling_enforcer  = $request_handling_enforcer;
		$this->denial_responder           = $denial_responder;
		$this->debug_state                = $debug_state;
		$this->request_context            = $request_context;
		$this->frontend_page_visit_logger = $frontend_page_visit_logger;
		$this->captcha_guard              = $captcha_guard;
	}

	public function register_hooks(): void {
		add_action( 'init', array( $this, 'log_current_request' ), 0 );
		add_action( 'init', array( $this, 'block_banned_request' ), 1 );
		add_action( 'init', array( $this, 'enforce_request_handling' ), 2 );
		add_action( 'template_redirect', array( $this, 'handle_frontend_request' ), 0 );
	}

	public function log_current_request(): void {
		if ( $this->request_logged ) {
			return;
		}

		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$ip                   = $this->get_ip();
		$request_type         = $this->request_context->current_request_type();
		$is_frontend_html     = $this->request_context->is_frontend_html_request();
		$request_method       = $this->request_context->current_method();
		$this->request_logged = true;

		$this->debug_state->merge(
			'request',
			array(
				'ip'               => $ip,
				'request_type'     => $request_type,
				'method'           => $request_method,
				'uri'              => $this->request_context->current_url(),
				'is_frontend_html' => $is_frontend_html,
			)
		);
		$this->debug_state->add_condition( 'WordPress request logging ran during init.' );
		$this->captcha_guard->update_debug_snapshot( $ip, $request_type );

		$this->event_logger->log(
			'request_hit',
			$ip,
			'',
			array(
				'details' => array(
					'method'           => $request_method,
					'request_type'     => $request_type,
					'is_frontend_html' => $is_frontend_html ? '1' : '0',
				),
			)
		);
	}

	public function block_banned_request(): void {
		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$ip  = $this->get_ip();
		$ban = $this->ban_store->get_ban_for_ip( $ip );

		if ( array() === $ban ) {
			return;
		}

		$this->captcha_guard->update_debug_snapshot( $ip, $this->request_context->current_request_type() );
		$this->debug_state->add_condition( 'Permanent ban matched before content rendering.' );
		$this->denial_responder->deny_permanently(
			$ip,
			$this->request_context->current_request_type(),
			'Access permanently blocked',
			'This IP address has been permanently banned by OpenWPSecurity - Firewall.',
			'All page views, login attempts, admin requests, AJAX calls, REST API requests, XML-RPC requests, and cron requests are blocked.'
		);
	}

	public function enforce_request_handling(): void {
		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$this->request_handling_enforcer->enforce_for_request(
			$this->get_ip(),
			$this->request_context->current_request_type()
		);
	}

	public function handle_frontend_request(): void {
		if ( ! $this->request_context->is_frontend_html_request() ) {
			return;
		}

		$ip = $this->get_ip();
		$this->frontend_page_visit_logger->record( $ip );
	}

	private function get_ip(): string {
		return $this->request_context->current_ip();
	}
}
