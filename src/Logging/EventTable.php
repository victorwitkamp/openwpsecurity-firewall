<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Logging;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventTableReference;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventTable implements EventTableReference {
	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_events';
	}
}
