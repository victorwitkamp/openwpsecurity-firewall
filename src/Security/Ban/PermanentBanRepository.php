<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableReference;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PermanentBanRepository implements TableReference {
	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_firewall_permanent_bans';
	}
}
