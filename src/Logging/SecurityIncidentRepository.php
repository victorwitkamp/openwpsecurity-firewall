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

final class SecurityIncidentRepository implements TableReference {
	private const DB_VERSION = '1.0.0';

	private TableSchemaInstaller $schema_installer;
	private TableWriter $writer;

	public function __construct( TableSchemaInstaller $schema_installer ) {
		$this->schema_installer = $schema_installer;
		$this->writer           = new TableWriter( $this, $this->table_schema() );
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_security_incidents';
	}

	public function maybe_upgrade_schema(): void {
		$this->schema_installer->maybe_upgrade_schema( $this->table_schema() );
	}

	public function insert( SecurityIncident $security_incident ): bool {
		return $this->writer->insert( $security_incident->to_row() );
	}

	public function table_schema(): TableSchema {
		return new TableSchema(
			$this,
			'openwpsecurity_firewall_security_incidents_db_version',
			self::DB_VERSION,
			array(
				new TableColumn( 'id', 'id bigint(20) unsigned NOT NULL AUTO_INCREMENT' ),
				new TableColumn( 'created_at', 'created_at datetime NOT NULL', '', '%s' ),
				new TableColumn( 'incident_type', "incident_type varchar(80) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'ip_address', 'ip_address varchar(45) NOT NULL', '', '%s' ),
				new TableColumn( 'country_code', "country_code varchar(12) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'country_name', "country_name varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'request_type', "request_type varchar(80) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'method', "method varchar(12) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'lockout_expires_at', 'lockout_expires_at datetime NULL', null, '%s' ),
				new TableColumn( 'summary', "summary varchar(255) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'request_uri', 'request_uri text NULL', '', '%s' ),
				new TableColumn( 'user_agent', 'user_agent text NULL', '', '%s' ),
				new TableColumn( 'evidence_json', 'evidence_json longtext NULL', '', '%s' ),
			),
			array(
				new TableIndex( 'PRIMARY KEY  (id)' ),
				new TableIndex( 'KEY created_at (created_at)' ),
				new TableIndex( 'KEY incident_type_created_at (incident_type, created_at)' ),
				new TableIndex( 'KEY ip_created_at (ip_address, created_at)' ),
				new TableIndex( 'KEY request_type_created_at (request_type, created_at)' ),
				new TableIndex( 'KEY country_created_at (country_code, created_at)' ),
				new TableIndex( 'KEY lockout_expires_at (lockout_expires_at)' ),
			)
		);
	}
}
