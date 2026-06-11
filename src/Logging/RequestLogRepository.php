<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableColumn;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableIndex;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableReference;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchema;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableWriter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestLogRepository implements TableReference {
	private const DB_VERSION = '1.0.0';

	private TableSchemaInstaller $schema_installer;
	private TableWriter $writer;

	public function __construct( TableSchemaInstaller $schema_installer ) {
		$this->schema_installer = $schema_installer;
		$this->writer           = new TableWriter( $this, $this->table_schema() );
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_request_logs';
	}

	public function maybe_upgrade_schema(): void {
		$this->schema_installer->maybe_upgrade_schema( $this->table_schema() );
	}

	public function insert( RequestLog $request_log ): bool {
		return $this->writer->insert( $request_log->to_row() );
	}

	public function table_schema(): TableSchema {
		return new TableSchema(
			$this,
			'openwpsecurity_firewall_request_logs_db_version',
			self::DB_VERSION,
			array(
				new TableColumn( 'id', 'id bigint(20) unsigned NOT NULL AUTO_INCREMENT' ),
				new TableColumn( 'created_at', 'created_at datetime NOT NULL', '', '%s' ),
				new TableColumn( 'activity_type', "activity_type varchar(50) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'request_type', "request_type varchar(80) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'method', "method varchar(12) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'ip_address', 'ip_address varchar(45) NOT NULL', '', '%s' ),
				new TableColumn( 'country_code', "country_code varchar(12) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'country_name', "country_name varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'is_frontend_html', 'is_frontend_html tinyint(1) unsigned NOT NULL DEFAULT 0', 0, '%d' ),
				new TableColumn( 'request_uri', 'request_uri text NULL', '', '%s' ),
				new TableColumn( 'user_agent', 'user_agent text NULL', '', '%s' ),
			),
			array(
				new TableIndex( 'PRIMARY KEY  (id)' ),
				new TableIndex( 'KEY created_at (created_at)' ),
				new TableIndex( 'KEY activity_type_created_at (activity_type, created_at)' ),
				new TableIndex( 'KEY ip_created_at (ip_address, created_at)' ),
				new TableIndex( 'KEY request_type_created_at (request_type, created_at)' ),
				new TableIndex( 'KEY country_created_at (country_code, created_at)' ),
				new TableIndex( 'KEY method_created_at (method, created_at)' ),
			)
		);
	}
}
