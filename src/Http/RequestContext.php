<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Http;

use Psr\Http\Message\ServerRequestInterface;
use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestContext {
	private Settings $settings;
	private IpAddressInspector $ip_address_inspector;
	private ServerRequestInterface $request;

	public function __construct( Settings $settings, IpAddressInspector $ip_address_inspector, ServerRequestInterface $request ) {
		$this->settings             = $settings;
		$this->ip_address_inspector = $ip_address_inspector;
		$this->request              = $request;
	}

	public function current_ip(): string {
		$settings = $this->settings->get();

		return $this->ip_address_inspector->resolve_from_headers( wp_unslash( $_SERVER ), (array) $settings['trusted_ip_headers'] );
	}

	public function is_private_ip( string $ip_address ): bool {
		return $this->ip_address_inspector->is_private( $ip_address );
	}

	public function is_ip_whitelisted( string $ip_address ): bool {
		if ( '' === $ip_address || $this->is_private_ip( $ip_address ) ) {
			return true;
		}

		$settings       = $this->settings->get();
		$is_whitelisted = in_array( $ip_address, (array) $settings['whitelist_ips'], true );

		return (bool) apply_filters( 'openwpsecurity_firewall_is_ip_whitelisted', $is_whitelisted, $ip_address );
	}

	public function current_url(): string {
		return (string) $this->request->getUri();
	}

	public function current_method(): string {
		return strtoupper( $this->request->getMethod() );
	}

	public function current_user_agent(): string {
		return $this->request->getHeaderLine( 'User-Agent' );
	}

	public function current_header( string $name ): string {
		return $this->request->getHeaderLine( $name );
	}

	public function is_frontend_html_request(): bool {
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}

		if ( ! in_array( $this->current_method(), array( 'GET', 'POST' ), true ) ) {
			return false;
		}

		$request_path     = $this->request->getUri()->getPath();
		$blocked_prefixes = array(
			'/wp-login.php',
			'/wp-admin/',
			'/wp-json/',
			'/xmlrpc.php',
		);

		foreach ( $blocked_prefixes as $blocked_prefix ) {
			if ( str_starts_with( $request_path, $blocked_prefix ) ) {
				return false;
			}
		}

		$extension = strtolower( pathinfo( $request_path, PATHINFO_EXTENSION ) );

		if ( '' !== $extension && ! in_array( $extension, array( 'html', 'htm' ), true ) ) {
			return false;
		}

		$accept_header = strtolower( $this->request->getHeaderLine( 'Accept' ) );

		if ( '' !== $accept_header && false === strpos( $accept_header, 'text/html' ) && false === strpos( $accept_header, '*/*' ) ) {
			return false;
		}

		return true;
	}

	public function current_request_type(): string {
		$request_path = $this->request->getUri()->getPath();

		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return 'cli';
		}

		if ( wp_doing_cron() || '/wp-cron.php' === $request_path ) {
			return 'wp_cron';
		}

		if ( wp_doing_ajax() || '/wp-admin/admin-ajax.php' === $request_path ) {
			return 'admin_ajax';
		}

		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || '/xmlrpc.php' === $request_path ) {
			return 'xmlrpc';
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest_api';
		}

		$rest_route = (string) ( $this->request->getQueryParams()['rest_route'] ?? '' );

		if ( str_starts_with( $request_path, '/wp-json/' ) || str_starts_with( $rest_route, '/' ) ) {
			return 'rest_api';
		}

		if ( ( defined( 'WP_LOGIN' ) && WP_LOGIN ) || '/wp-login.php' === $request_path ) {
			return 'wp_login';
		}

		if ( is_admin() || str_starts_with( $request_path, '/wp-admin/' ) ) {
			return 'wp_admin';
		}

		if ( $this->is_frontend_html_request() ) {
			return 'frontend_page';
		}

		return 'other';
	}
}
