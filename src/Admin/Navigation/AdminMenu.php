<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Navigation\AdminMenuRegistrar;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\DashboardPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\PermanentBansPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\RequestHandlingPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SecurityIncidentsPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SettingsPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminMenu {
	private const PAGE_TABS = array(
		'openwpsecurity-firewall'                  => 'Dashboard',
		'openwpsecurity-firewall-request-handling' => 'Request Handling',
		'openwpsecurity-firewall-security'         => 'Security Incidents',
		'openwpsecurity-firewall-bans'             => 'Permanent Bans',
		'openwpsecurity-firewall-settings'         => 'Settings',
	);

	private AdminMenuRegistrar $registrar;

	public function __construct(
		DashboardPage $dashboard_page,
		RequestHandlingPage $request_handling_page,
		SecurityIncidentsPage $security_incidents_page,
		PermanentBansPage $permanent_bans_page,
		SettingsPage $settings_page
	) {
		$this->registrar = new AdminMenuRegistrar(
			'OpenWPSecurity - Firewall',
			'OpenWPSecurity - Firewall',
			'manage_options',
			'openwpsecurity-firewall',
			array( $dashboard_page, 'render' ),
			'dashicons-shield-alt',
			74,
			array(
				$this->submenu_page( 'openwpsecurity-firewall', 'Dashboard', array( $dashboard_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-request-handling', 'Request Handling', array( $request_handling_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-security', 'Security Incidents', array( $security_incidents_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-bans', 'Permanent Bans', array( $permanent_bans_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-settings', 'Settings', array( $settings_page, 'render' ) ),
			),
			'openwpsecurity-firewall',
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . 'assets/css/admin.css',
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . 'assets/js/admin.js',
			OPENWPSECURITY_FIREWALL_VERSION
		);
	}

	public function register_hooks(): void {
		$this->registrar->register_hooks();
	}

	public static function page_tabs(): array {
		return self::PAGE_TABS;
	}

	private function submenu_page( string $slug, string $label, array $callback ): array {
		return array(
			'slug'       => $slug,
			'page_title' => $label,
			'menu_title' => $label,
			'callback'   => $callback,
		);
	}
}
