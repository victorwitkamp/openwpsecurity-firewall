<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityIncidentLookup {
	private SecurityIncidentRepository $security_incidents;

	public function __construct( SecurityIncidentRepository $security_incidents ) {
		$this->security_incidents = $security_incidents;
	}

	public function count( array $incident_types, array $filters = array(), ?int $period_seconds = null ): int {
		global $wpdb;

		if ( empty( $incident_types ) ) {
			return 0;
		}

		$params = array();
		$sql    = $this->query( 'SELECT COUNT(*)', $incident_types, $params, $filters, $period_seconds );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
	}

	public function rows( array $incident_types, array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		global $wpdb;

		if ( empty( $incident_types ) ) {
			return array();
		}

		$params = array();
		$sql    = $this->query(
			'SELECT created_at, incident_type, incident_type AS event_type, ip_address, country_code, country_name, request_type, method, lockout_expires_at, summary, request_uri, user_agent, evidence_json, evidence_json AS details',
			$incident_types,
			$params,
			$filters,
			$period_seconds
		);
		$sql   .= ' ORDER BY created_at DESC';

		if ( null !== $limit ) {
			$sql     .= ' LIMIT %d OFFSET %d';
			$params[] = max( 1, $limit );
			$params[] = max( 0, $offset );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

		return is_array( $rows ) ? $rows : array();
	}

	public function country_totals( array $incident_types, array $filters = array(), ?int $period_seconds = null, ?int $limit = 8 ): array {
		global $wpdb;

		if ( empty( $incident_types ) ) {
			return array();
		}

		$params = array();
		$sql    = $this->query(
			"SELECT
				CASE WHEN country_code = '' THEN '--' ELSE country_code END AS country_code,
				CASE WHEN country_name = '' THEN 'Unknown' ELSE country_name END AS country_name,
				COUNT(*) AS total",
			$incident_types,
			$params,
			$filters,
			$period_seconds
		);
		$sql   .= " GROUP BY
				CASE WHEN country_code = '' THEN '--' ELSE country_code END,
				CASE WHEN country_name = '' THEN 'Unknown' ELSE country_name END
			ORDER BY total DESC";

		if ( null !== $limit ) {
			$sql     .= ' LIMIT %d';
			$params[] = max( 1, $limit );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

		return is_array( $rows ) ? $this->normalize_country_rows( $rows ) : array();
	}

	public function country_options( array $incident_types, array $filters = array(), ?int $period_seconds = null ): array {
		return array_map(
			static function ( array $row ): array {
				return array(
					'code'  => (string) $row['country_code'],
					'label' => trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ),
				);
			},
			$this->country_totals( $incident_types, $filters, $period_seconds, null )
		);
	}

	private function query( string $select_clause, array $incident_types, array &$params, array $filters, ?int $period_seconds ): string {
		global $wpdb;

		$params      = array_values( $incident_types );
		$placeholder = implode( ', ', array_fill( 0, count( $incident_types ), '%s' ) );
		$sql         = "{$select_clause} FROM {$this->security_incidents->name()} WHERE incident_type IN ({$placeholder})";

		if ( null !== $period_seconds ) {
			$sql     .= ' AND created_at >= %s';
			$params[] = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		}

		if ( ! empty( $filters['event_type'] ) && in_array( (string) $filters['event_type'], $incident_types, true ) ) {
			$sql     .= ' AND incident_type = %s';
			$params[] = (string) $filters['event_type'];
		}

		if ( ! empty( $filters['request_type'] ) ) {
			$sql     .= ' AND request_type = %s';
			$params[] = (string) $filters['request_type'];
		}

		if ( ! empty( $filters['country_code'] ) ) {
			$sql     .= ' AND country_code = %s';
			$params[] = (string) $filters['country_code'];
		}

		if ( ! empty( $filters['ip_address'] ) ) {
			$sql     .= ' AND ip_address LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['ip_address'] ) . '%';
		}

		if ( ! empty( $filters['request_uri'] ) ) {
			$sql     .= ' AND request_uri LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['request_uri'] ) . '%';
		}

		return $sql;
	}

	private function normalize_country_rows( array $rows ): array {
		return array_map(
			static function ( array $row ): array {
				return array(
					'country_code' => (string) ( $row['country_code'] ?? '--' ),
					'country_name' => (string) ( $row['country_name'] ?? 'Unknown' ),
					'total'        => (int) ( $row['total'] ?? 0 ),
				);
			},
			$rows
		);
	}
}
