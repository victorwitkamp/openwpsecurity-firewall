<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RequestLogLookup {
	private RequestLogRepository $request_logs;

	public function __construct( RequestLogRepository $request_logs ) {
		$this->request_logs = $request_logs;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		global $wpdb;

		$params = array();
		$sql    = $this->query( 'SELECT COUNT(*)', $params, $filters, $period_seconds );

		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query contains only internal SQL fragments.
			return (int) $wpdb->get_var( $sql );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $params ) );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		global $wpdb;

		$params = array();
		$sql    = $this->query(
			'SELECT created_at, activity_type, request_type, method, ip_address, country_code, country_name, is_frontend_html, request_uri, user_agent',
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

		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query contains only internal SQL fragments.
			$rows = $wpdb->get_results( $sql, ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
		}

		return is_array( $rows ) ? $rows : array();
	}

	public function country_totals( array $filters = array(), ?int $period_seconds = null, ?int $limit = 8 ): array {
		global $wpdb;

		$params = array();
		$sql    = $this->query(
			"SELECT
				CASE WHEN country_code = '' THEN '--' ELSE country_code END AS country_code,
				CASE WHEN country_name = '' THEN 'Unknown' ELSE country_name END AS country_name,
				COUNT(*) AS total",
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

		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query contains only internal SQL fragments.
			$rows = $wpdb->get_results( $sql, ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
		}

		return is_array( $rows ) ? $this->normalize_country_rows( $rows ) : array();
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return array_map(
			static function ( array $row ): array {
				return array(
					'code'  => (string) $row['country_code'],
					'label' => trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ),
				);
			},
			$this->country_totals( $filters, $period_seconds, null )
		);
	}

	private function query( string $select_clause, array &$params, array $filters, ?int $period_seconds ): string {
		global $wpdb;

		$params = array();
		$sql    = "{$select_clause} FROM {$this->request_logs->name()} WHERE activity_type = 'request_hit'";

		if ( null !== $period_seconds ) {
			$sql     .= ' AND created_at >= %s';
			$params[] = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		}

		if ( ! empty( $filters['request_type'] ) ) {
			$sql     .= ' AND request_type = %s';
			$params[] = (string) $filters['request_type'];
		}

		if ( ! empty( $filters['method'] ) ) {
			$sql     .= ' AND method = %s';
			$params[] = strtoupper( (string) $filters['method'] );
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

		if ( ! empty( $filters['user_agent'] ) ) {
			$sql     .= ' AND user_agent LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['user_agent'] ) . '%';
		}

		if ( ! empty( $filters['external_only'] ) ) {
			$sql .= " AND country_code <> 'LOCAL' AND ip_address <> ''";
		}

		if ( ! empty( $filters['exclude_internal'] ) ) {
			$sql .= " AND request_type NOT IN ('wp_admin', 'admin_ajax', 'wp_cron')";
		}

		if ( ! empty( $filters['exclude_my_ip'] ) && ! empty( $filters['current_ip'] ) ) {
			$sql     .= ' AND ip_address <> %s';
			$params[] = (string) $filters['current_ip'];
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
