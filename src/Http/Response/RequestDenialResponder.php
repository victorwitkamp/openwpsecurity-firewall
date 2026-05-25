<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Http\Response;

use VictorWitkamp\OpenWPSecurity\Core\Http\Response\ResponseDispatcher;
use VictorWitkamp\OpenWPSecurity\Firewall\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Firewall\Presentation\Templates\TemplateRenderer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestDenialResponder {
	private TemplateRenderer $template_renderer;
	private RequestContext $request_context;
	private ResponseDispatcher $response_dispatcher;

	public function __construct( TemplateRenderer $template_renderer, RequestContext $request_context, ResponseDispatcher $response_dispatcher ) {
		$this->template_renderer   = $template_renderer;
		$this->request_context     = $request_context;
		$this->response_dispatcher = $response_dispatcher;
	}

	public function deny_temporarily( string $ip, string $request_type, int $expires, int $status_code, string $title, string $message ): void {
		$minutes_left = max( 1, (int) ceil( ( $expires - time() ) / MINUTE_IN_SECONDS ) );

		$this->send_response(
			$request_type,
			$status_code,
			$message,
			array(
				'message'  => $message,
				'expires'  => $expires,
				'endpoint' => $request_type,
			),
			'blocked-temporary.php',
			array(
				'ip'              => $ip,
				'minutes_left'    => $minutes_left,
				'lockout_expires' => $expires,
				'title'           => $title,
				'message'         => $message,
			)
		);
	}

	public function deny_rate_limited( string $ip, string $request_type, int $retry_after_seconds, string $title, string $message, array $template_variables = array(), array $json_payload = array() ): void {
		$retry_after_seconds = max( 1, $retry_after_seconds );

		$this->send_response(
			$request_type,
			429,
			$message,
			array_merge(
				array(
					'message'             => $message,
					'endpoint'            => $request_type,
					'retry_after_seconds' => $retry_after_seconds,
					'expires'             => time() + $retry_after_seconds,
				),
				$json_payload
			),
			'rate-limited.php',
			array_merge(
				array(
					'ip'                  => $ip,
					'title'               => $title,
					'message'             => $message,
					'retry_after_seconds' => $retry_after_seconds,
					'show_captcha'        => false,
					'error'               => '',
				),
				$template_variables
			)
		);
	}

	public function deny_permanently( string $ip, string $request_type, string $title, string $message, string $message_secondary = '' ): void {
		$this->send_response(
			$request_type,
			403,
			$message,
			array(
				'message'  => $message,
				'endpoint' => $request_type,
			),
			'blocked-permanent.php',
			array(
				'ip'                => $ip,
				'title'             => $title,
				'message'           => $message,
				'message_secondary' => $message_secondary,
			)
		);
	}

	private function send_response( string $request_type, int $status_code, string $message, array $json_payload, string $template_name, array $template_variables ): void {
		$headers = array();

		if ( 429 === $status_code ) {
			$headers['Retry-After'] = (string) max( 1, (int) ( $json_payload['expires'] ?? 0 ) - time() );
		}

		if ( $this->should_render_html( $request_type ) ) {
			$html = $this->template_renderer->render( $template_name, $template_variables );
			$this->response_dispatcher->html( $status_code, $html, $headers );
		}

		if ( wp_doing_ajax() || 'rest_api' === $request_type ) {
			$this->response_dispatcher->json(
				$status_code,
				array(
					'success' => false,
					'data'    => $json_payload,
				),
				$headers
			);
		}

		$this->response_dispatcher->text( $status_code, $message, $headers );
	}

	private function should_render_html( string $request_type ): bool {
		if ( in_array( $request_type, array( 'frontend_page', 'wp_login', 'wp_admin' ), true ) ) {
			return true;
		}

		if ( $this->request_context->is_frontend_html_request() ) {
			return true;
		}

		$accept = strtolower( $this->request_context->current_header( 'Accept' ) );

		return $accept !== '' && strpos( $accept, 'text/html' ) !== false;
	}
}
