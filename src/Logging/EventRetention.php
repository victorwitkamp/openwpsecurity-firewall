<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventRetention {
	private const CLEANUP_HOOK = 'openwpsecurity_firewall_delete_expired_events';

	private Settings $settings;
	private EventTable $event_table;

	public function __construct( Settings $settings, EventTable $event_table ) {
		$this->settings    = $settings;
		$this->event_table = $event_table;
	}

	public function register_hooks(): void {
		add_action( self::CLEANUP_HOOK, array( $this, 'delete_expired_events' ) );
		add_action( 'init', array( $this, 'synchronize_schedule' ), 5 );
		add_action( 'update_option_' . $this->settings->option_name(), array( $this, 'handle_settings_update' ), 10, 0 );
	}

	public function activate(): void {
		$this->synchronize_schedule();
		$this->delete_expired_events();
	}

	public function deactivate(): void {
		wp_clear_scheduled_hook( self::CLEANUP_HOOK );
	}

	public function handle_settings_update(): void {
		$this->synchronize_schedule();
	}

	public function synchronize_schedule(): void {
		$retention_days = (int) $this->settings->get()['event_retention_days'];
		$scheduled_at   = wp_next_scheduled( self::CLEANUP_HOOK );

		if ( $retention_days <= 0 ) {
			if ( false !== $scheduled_at ) {
				wp_clear_scheduled_hook( self::CLEANUP_HOOK );
			}

			return;
		}

		if ( false === $scheduled_at ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK );
		}
	}

	public function delete_expired_events(): void {
		global $wpdb;

		$retention_days = (int) $this->settings->get()['event_retention_days'];

		if ( $retention_days <= 0 ) {
			return;
		}

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $retention_days * DAY_IN_SECONDS ) );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$this->event_table->name()} WHERE created_at < %s",
				$cutoff
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}
}
