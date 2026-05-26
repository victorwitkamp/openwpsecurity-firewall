<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventSchema {
	private const DB_VERSION        = '1.2.1';
	private const DB_VERSION_OPTION = 'openwpsecurity_firewall_db_version';

	private EventTable $event_table;

	public function __construct( EventTable $event_table ) {
		$this->event_table = $event_table;
	}

	public function maybe_upgrade_schema(): void {
		$current_version = (string) get_option( self::DB_VERSION_OPTION, '' );
		$table_exists    = $this->table_exists( $this->event_table->name() );

		if ( ! $table_exists || $current_version !== self::DB_VERSION ) {
			$this->create_table();
		}

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION, false );
	}

	private function create_table(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table_name      = $this->event_table->name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			event_type varchar(50) NOT NULL,
			ip_address varchar(45) NOT NULL,
			country_code varchar(12) NOT NULL DEFAULT '',
			country_name varchar(191) NOT NULL DEFAULT '',
			username varchar(191) NOT NULL DEFAULT '',
			user_agent text NULL,
			request_uri text NULL,
			lockout_expires_at datetime NULL,
			details longtext NULL,
			PRIMARY KEY  (id),
			KEY event_type_created_at (event_type, created_at),
			KEY ip_address_created_at (ip_address, created_at)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	private function table_exists( string $table_name ): bool {
		global $wpdb;

		$match = $wpdb->get_var(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$table_name
			)
		);

		return is_string( $match ) && $match === $table_name;
	}
}
