<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security;

use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Core\Database\WordPressTableReference;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Http\Response\RequestDenialResponder;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\FrontendPageVisitLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestHandlingEnforcer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestGuard {
	private const LOGINPROTECTION_BAN_TABLE = 'openwpsecurity_loginprotection_permanent_bans';

	private Settings $settings;
	private PermanentBanStore $ban_store;
	private EventLogger $event_logger;
	private RequestHandlingEnforcer $request_handling_enforcer;
	private RequestDenialResponder $denial_responder;
	private RequestContext $request_context;
	private FrontendPageVisitLogger $frontend_page_visit_logger;
	private bool $request_logged = false;

	public function __construct( Settings $settings, PermanentBanStore $ban_store, EventLogger $event_logger, RequestHandlingEnforcer $request_handling_enforcer, RequestDenialResponder $denial_responder, RequestContext $request_context, FrontendPageVisitLogger $frontend_page_visit_logger ) {
		$this->settings                   = $settings;
		$this->ban_store                  = $ban_store;
		$this->event_logger               = $event_logger;
		$this->request_handling_enforcer  = $request_handling_enforcer;
		$this->denial_responder           = $denial_responder;
		$this->request_context            = $request_context;
		$this->frontend_page_visit_logger = $frontend_page_visit_logger;
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
		$ban = $this->get_enforced_ban_for_ip( $ip );

		if ( array() === $ban ) {
			return;
		}

		$this->denial_responder->deny_permanently(
			$ip,
			$this->request_context->current_request_type(),
			'Access permanently blocked',
			$this->permanent_ban_message( $ban ),
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

	private function get_enforced_ban_for_ip( string $ip ): array {
		$ban = $this->ban_store->get_ban_for_ip( $ip );

		if ( array() !== $ban ) {
			$ban['enforced_source'] = 'firewall';
			return $ban;
		}

		if ( empty( $this->settings->get()['enforce_loginprotection_bans'] ) ) {
			return array();
		}

		global $wpdb;

		$table = ( new WordPressTableReference( self::LOGINPROTECTION_BAN_TABLE ) )->name();

		if ( ! $this->table_exists( $table ) ) {
			return array();
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT created_at, ip_address, country_code, country_name, source, reason, request_uri, user_agent, evidence_json FROM {$table} WHERE ip_address = %s LIMIT 1",
				$ip
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( ! is_array( $row ) ) {
			return array();
		}

		$ban                    = array(
			'ip_address'    => (string) ( $row['ip_address'] ?? '' ),
			'banned_at'     => (string) ( $row['created_at'] ?? '' ),
			'created_at'    => (string) ( $row['created_at'] ?? '' ),
			'country_code'  => (string) ( $row['country_code'] ?? '' ),
			'country_name'  => (string) ( $row['country_name'] ?? '' ),
			'source'        => (string) ( $row['source'] ?? '' ),
			'reason'        => (string) ( $row['reason'] ?? '' ),
			'request_uri'   => (string) ( $row['request_uri'] ?? '' ),
			'user_agent'    => (string) ( $row['user_agent'] ?? '' ),
			'evidence_json' => (string) ( $row['evidence_json'] ?? '' ),
		);
		$ban['enforced_source'] = 'login_protection';

		return $ban;
	}

	private function table_exists( string $table ): bool {
		global $wpdb;

		$match = $wpdb->get_var(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$table
			)
		);

		return is_string( $match ) && $match === $table;
	}

	private function permanent_ban_message( array $ban ): string {
		if ( 'login_protection' === (string) ( $ban['enforced_source'] ?? '' ) ) {
			return 'This IP address has been permanently banned by OpenWPSecurity - Login Protection and is being enforced globally by OpenWPSecurity - Firewall.';
		}

		return 'This IP address has been permanently banned by OpenWPSecurity - Firewall.';
	}
}
