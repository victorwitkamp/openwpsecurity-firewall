<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging\Reports;

use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\RequestLogRepository;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\SecurityIncidentRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardReport {
	private RequestLogRepository $request_logs;
	private SecurityIncidentRepository $security_incidents;
	private PermanentBanStore $ban_store;

	public function __construct( RequestLogRepository $request_logs, SecurityIncidentRepository $security_incidents, PermanentBanStore $ban_store ) {
		$this->request_logs       = $request_logs;
		$this->security_incidents = $security_incidents;
		$this->ban_store          = $ban_store;
	}

	public function summary( int $period_seconds ): array {
		global $wpdb;

		$since          = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		$request_table  = $this->request_logs->name();
		$incident_table = $this->security_incidents->name();
		$permanent_bans = $this->ban_store->count_since( $period_seconds );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		$request_row  = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT
					SUM(CASE WHEN activity_type = 'request_hit' THEN 1 ELSE 0 END) AS total_requests,
					SUM(CASE WHEN activity_type = 'page_visit' THEN 1 ELSE 0 END) AS page_visits,
					COUNT(DISTINCT CASE WHEN activity_type = 'request_hit' THEN ip_address ELSE NULL END) AS unique_ips
				FROM {$request_table}
				WHERE created_at >= %s",
				$since
			),
			ARRAY_A
		);
		$incident_row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT
					COUNT(*) AS security_incidents,
					SUM(CASE WHEN incident_type = 'request_temporary_block_created' THEN 1 ELSE 0 END) AS temporary_blocks,
					SUM(CASE WHEN incident_type = 'captcha_required' THEN 1 ELSE 0 END) AS captcha_required,
					SUM(CASE WHEN incident_type = 'captcha_passed' THEN 1 ELSE 0 END) AS captcha_passed
				FROM {$incident_table}
				WHERE created_at >= %s",
				$since
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'total_requests'     => isset( $request_row['total_requests'] ) ? (int) $request_row['total_requests'] : 0,
			'page_visits'        => isset( $request_row['page_visits'] ) ? (int) $request_row['page_visits'] : 0,
			'security_incidents' => isset( $incident_row['security_incidents'] ) ? (int) $incident_row['security_incidents'] : 0,
			'temporary_blocks'   => isset( $incident_row['temporary_blocks'] ) ? (int) $incident_row['temporary_blocks'] : 0,
			'captcha_required'   => isset( $incident_row['captcha_required'] ) ? (int) $incident_row['captcha_required'] : 0,
			'captcha_passed'     => isset( $incident_row['captcha_passed'] ) ? (int) $incident_row['captcha_passed'] : 0,
			'permanent_bans'     => $permanent_bans,
			'unique_ips'         => isset( $request_row['unique_ips'] ) ? (int) $request_row['unique_ips'] : 0,
		);
	}
}
