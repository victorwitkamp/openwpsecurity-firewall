<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventTable {
	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_events';
	}
}
