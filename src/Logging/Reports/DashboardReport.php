<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventTable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardReport {
	private EventTable $event_table;

	public function __construct( EventTable $event_table ) {
		$this->event_table = $event_table;
	}

	public function summary( int $period_seconds ): array {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		$table = $this->event_table->name();

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT
					SUM(CASE WHEN event_type = 'request_hit' THEN 1 ELSE 0 END) AS total_requests,
					SUM(CASE WHEN event_type = 'page_visit' THEN 1 ELSE 0 END) AS page_visits,
					SUM(CASE WHEN event_type IN ('request_rate_limited', 'request_temporary_block_created', 'request_temporarily_blocked', 'permanent_ban_created', 'captcha_required', 'captcha_failed', 'captcha_passed') THEN 1 ELSE 0 END) AS security_incidents,
					SUM(CASE WHEN event_type = 'request_temporary_block_created' THEN 1 ELSE 0 END) AS temporary_blocks,
					SUM(CASE WHEN event_type = 'captcha_required' THEN 1 ELSE 0 END) AS captcha_required,
					SUM(CASE WHEN event_type = 'captcha_passed' THEN 1 ELSE 0 END) AS captcha_passed,
					COUNT(DISTINCT CASE WHEN event_type = 'request_hit' THEN ip_address ELSE NULL END) AS unique_ips
				FROM {$table}
				WHERE created_at >= %s",
				$since
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'total_requests'     => isset( $row['total_requests'] ) ? (int) $row['total_requests'] : 0,
			'page_visits'        => isset( $row['page_visits'] ) ? (int) $row['page_visits'] : 0,
			'security_incidents' => isset( $row['security_incidents'] ) ? (int) $row['security_incidents'] : 0,
			'temporary_blocks'   => isset( $row['temporary_blocks'] ) ? (int) $row['temporary_blocks'] : 0,
			'captcha_required'   => isset( $row['captcha_required'] ) ? (int) $row['captcha_required'] : 0,
			'captcha_passed'     => isset( $row['captcha_passed'] ) ? (int) $row['captcha_passed'] : 0,
			'unique_ips'         => isset( $row['unique_ips'] ) ? (int) $row['unique_ips'] : 0,
		);
	}
}
