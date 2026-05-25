<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics;

use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DebugBar {
	private Settings $settings;
	private RequestDebugState $debug_state;
	private EventReportFormatter $event_display_formatter;
	private bool $rendered = false;

	public function __construct( Settings $settings, RequestDebugState $debug_state, EventReportFormatter $event_display_formatter ) {
		$this->settings                = $settings;
		$this->debug_state             = $debug_state;
		$this->event_display_formatter = $event_display_formatter;
	}

	public function register_hooks(): void {
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_footer', array( $this, 'render' ), PHP_INT_MAX );
		add_action( 'admin_footer', array( $this, 'render' ), PHP_INT_MAX );
		add_action( 'login_footer', array( $this, 'render' ), PHP_INT_MAX );
		add_action( 'openwpsecurity_firewall_render_debug_bar', array( $this, 'render' ), PHP_INT_MAX );
	}

	public function enqueue_assets( string $hook_suffix = '' ): void {
		unset( $hook_suffix );

		if ( ! $this->is_enabled() ) {
			return;
		}

		wp_enqueue_style(
			'openwpsecurity-firewall-runtime',
			OPENWPSECURITY_FIREWALL_URL . 'assets/css/runtime.css',
			array(),
			OPENWPSECURITY_FIREWALL_VERSION
		);

		wp_enqueue_script(
			'openwpsecurity-firewall-runtime',
			OPENWPSECURITY_FIREWALL_URL . 'assets/js/runtime.js',
			array(),
			OPENWPSECURITY_FIREWALL_VERSION,
			true
		);
	}

	public function render(): void {
		if ( $this->rendered || ! $this->is_enabled() || ! $this->should_render() ) {
			return;
		}

		$this->rendered = true;

		$state            = $this->debug_state->all();
		$request          = isset( $state['request'] ) && is_array( $state['request'] ) ? $state['request'] : array();
		$captcha          = isset( $state['captcha'] ) && is_array( $state['captcha'] ) ? $state['captcha'] : array();
		$request_handling = isset( $state['request_handling'] ) && is_array( $state['request_handling'] ) ? $state['request_handling'] : array();
		$ban              = isset( $state['ban'] ) && is_array( $state['ban'] ) ? $state['ban'] : array();
		$conditions       = isset( $state['conditions'] ) && is_array( $state['conditions'] ) ? $state['conditions'] : array();
		$summary          = array();

		if ( ! empty( $request['request_type'] ) ) {
			$summary[] = $this->event_display_formatter->request_type_label( (string) $request['request_type'] );
		}

		if ( ! empty( $captcha['enabled'] ) && isset( $captcha['failure_count'], $captcha['failure_threshold'] ) ) {
			$summary[] = 'Captcha ' . (int) $captcha['failure_count'] . '/' . (int) $captcha['failure_threshold'];
		}

		if ( isset( $request_handling['hit_count'], $request_handling['rate_limit_threshold'] ) && ! empty( $request_handling['rate_limit_enabled'] ) ) {
			$summary[] = 'Rate ' . (int) $request_handling['hit_count'] . '/' . (int) $request_handling['rate_limit_threshold'];
		}

		if ( isset( $request_handling['temporary_block_count'], $request_handling['temporary_blocks_before_permanent_ban'] ) && (int) $request_handling['temporary_blocks_before_permanent_ban'] > 0 ) {
			$summary[] = 'Request Blocks ' . (int) $request_handling['temporary_block_count'] . '/' . (int) $request_handling['temporary_blocks_before_permanent_ban'];
		}

		if ( ! empty( $request_handling['temporary_block_active'] ) ) {
			$summary[] = 'Request Block Active';
		}

		if ( ! empty( $ban['is_banned'] ) ) {
			$summary[] = 'Permanent Ban Active';
		}
		?>
		<div class="vwfw-debug-bar">
			<details open>
				<summary>
					<div class="vwfw-debug-summary">
						<div class="vwfw-debug-summary-main">
							<span class="vwfw-debug-summary-title">OpenWPSecurity Debug</span>
							<?php foreach ( $summary as $chip ) : ?>
								<span class="vwfw-debug-chip"><?php echo esc_html( (string) $chip ); ?></span>
							<?php endforeach; ?>
						</div>
						<button type="button" class="vwfw-debug-hide" data-vwfw-debug-hide>Hide</button>
					</div>
				</summary>
				<div class="vwfw-debug-body">
					<div class="vwfw-debug-grid">
						<?php $this->render_panel( 'Request', $this->request_rows( $request ) ); ?>
						<?php $this->render_panel( 'Captcha', $this->captcha_rows( $captcha ) ); ?>
						<?php $this->render_panel( 'Request Handling', $this->request_handling_rows( $request_handling ) ); ?>
						<?php $this->render_panel( 'Permanent Ban', $this->ban_rows( $ban ) ); ?>
					</div>
					<div class="vwfw-debug-panel">
						<h4>Triggered Conditions</h4>
						<?php if ( empty( $conditions ) ) : ?>
							<p>No plugin conditions recorded on this request.</p>
						<?php else : ?>
							<ul class="vwfw-debug-conditions">
								<?php foreach ( $conditions as $condition ) : ?>
									<li><?php echo esc_html( (string) $condition ); ?></li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
				</div>
			</details>
		</div>
		<?php
	}

	private function is_enabled(): bool {
		$settings = $this->settings->get();

		return ! empty( $settings['debug_bar_enabled'] );
	}

	private function should_render(): bool {
		if ( 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}

		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}

		return true;
	}

	private function render_panel( string $title, array $rows ): void {
		?>
		<div class="vwfw-debug-panel">
			<h4><?php echo esc_html( $title ); ?></h4>
			<dl class="vwfw-debug-list">
				<?php foreach ( $rows as $label => $value ) : ?>
					<div class="vwfw-debug-row">
						<dt><?php echo esc_html( (string) $label ); ?></dt>
						<dd><?php echo esc_html( (string) $value ); ?></dd>
					</div>
				<?php endforeach; ?>
			</dl>
		</div>
		<?php
	}

	private function request_rows( array $request ): array {
		return array(
			'IP'            => (string) ( $request['ip'] ?? '' ),
			'Type'          => ! empty( $request['request_type'] ) ? $this->event_display_formatter->request_type_label( (string) $request['request_type'] ) : '',
			'Method'        => (string) ( $request['method'] ?? '' ),
			'Frontend HTML' => ! empty( $request['is_frontend_html'] ) ? 'Yes' : 'No',
			'URI'           => (string) ( $request['uri'] ?? '' ),
		);
	}

	private function captcha_rows( array $captcha ): array {
		$remaining = isset( $captcha['remaining_until_temporary_block'] ) ? (string) (int) $captcha['remaining_until_temporary_block'] : '';

		return array(
			'Target'                => ! empty( $captcha['request_type'] ) ? $this->event_display_formatter->request_type_label( (string) $captcha['request_type'] ) : '',
			'Enabled'               => ! empty( $captcha['enabled'] ) ? 'Yes' : 'No',
			'Failures / Threshold'  => isset( $captcha['failure_count'], $captcha['failure_threshold'] ) ? (int) $captcha['failure_count'] . ' / ' . (int) $captcha['failure_threshold'] : '',
			'Failure Window'        => isset( $captcha['failure_window_minutes'] ) ? (int) $captcha['failure_window_minutes'] . ' min' : '',
			'Remaining Until Block' => $remaining === '' ? '' : $remaining . ' failure(s)',
			'Rate-Limited Request'  => ! empty( $captcha['rate_limited'] ) ? 'Yes' : 'No',
			'Rate Hits / Limit'     => isset( $captcha['rate_limit_hit_count'], $captcha['rate_limit_threshold'] ) ? (int) $captcha['rate_limit_hit_count'] . ' / ' . (int) $captcha['rate_limit_threshold'] : '',
			'Rate Window'           => isset( $captcha['rate_limit_window_seconds'] ) ? (int) $captcha['rate_limit_window_seconds'] . ' sec' : '',
			'Challenge Active'      => ! empty( $captcha['challenge_active'] ) ? 'Yes' : 'No',
			'Pass Cookie'           => ! empty( $captcha['has_pass_cookie'] ) ? 'Yes' : 'No',
			'Captcha Status'        => (string) ( $captcha['status'] ?? '' ),
		);
	}

	private function request_handling_rows( array $request_handling ): array {
		return array(
			'Target'                       => ! empty( $request_handling['request_type'] ) ? $this->event_display_formatter->request_type_label( (string) $request_handling['request_type'] ) : '',
			'Rate Limiting'                => ! empty( $request_handling['rate_limit_enabled'] ) ? 'Enabled' : 'Disabled',
			'Hits / Limit'                 => isset( $request_handling['hit_count'], $request_handling['rate_limit_threshold'] ) ? (int) $request_handling['hit_count'] . ' / ' . (int) $request_handling['rate_limit_threshold'] : '',
			'Window'                       => isset( $request_handling['rate_limit_window_seconds'] ) ? (int) $request_handling['rate_limit_window_seconds'] . ' sec' : '',
			'Temporary Blocks'             => ! empty( $request_handling['temporary_block_enabled'] ) ? 'Enabled' : 'Disabled',
			'Temporary Block Active'       => ! empty( $request_handling['temporary_block_active'] ) ? 'Yes' : 'No',
			'Temporary Block Expires'      => $this->format_datetime( (string) ( $request_handling['temporary_block_expires_at'] ?? '' ) ),
			'Temporary Block Triggered By' => ! empty( $request_handling['temporary_block_trigger_request_type'] ) ? $this->event_display_formatter->request_type_label( (string) $request_handling['temporary_block_trigger_request_type'] ) : '',
			'Block Duration'               => isset( $request_handling['temporary_block_minutes'] ) ? (int) $request_handling['temporary_block_minutes'] . ' min' : '',
			'Blocks'                       => isset( $request_handling['temporary_block_count'], $request_handling['temporary_blocks_before_permanent_ban'] ) ? (int) $request_handling['temporary_block_count'] . ' / ' . (int) $request_handling['temporary_blocks_before_permanent_ban'] : '',
			'Handling Status'              => (string) ( $request_handling['status'] ?? '' ),
		);
	}

	private function ban_rows( array $ban ): array {
		return array(
			'Banned'    => ! empty( $ban['is_banned'] ) ? 'Yes' : 'No',
			'Banned At' => $this->format_datetime( $ban['banned_at'] ?? '' ),
			'Source'    => (string) ( $ban['source'] ?? '' ),
			'Reason'    => (string) ( $ban['reason'] ?? '' ),
		);
	}

	private function format_datetime( string $gmt_datetime ): string {
		if ( '' === $gmt_datetime ) {
			return '';
		}

		return $this->event_display_formatter->admin_datetime( $gmt_datetime );
	}
}
