<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Reporting;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ReportPeriod {
	public function label( string $period ): string {
		$labels = array(
			'24h'  => 'Last 24 Hours',
			'7d'   => 'Last 7 Days',
			'30d'  => 'Last 30 Days',
			'365d' => 'Last 365 Days',
		);

		return $labels[ $period ] ?? $labels['24h'];
	}

	public function seconds( string $period ): int {
		$seconds = array(
			'24h'  => DAY_IN_SECONDS,
			'7d'   => 7 * DAY_IN_SECONDS,
			'30d'  => 30 * DAY_IN_SECONDS,
			'365d' => 365 * DAY_IN_SECONDS,
		);

		return $seconds[ $period ] ?? $seconds['24h'];
	}
}
