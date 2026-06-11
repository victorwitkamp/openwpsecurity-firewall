<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Assets\AssetVersion;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Navigation\AdminMenuRegistrar;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\DashboardPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\PermanentBansPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\PoliciesPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\RequestLogPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SecurityIncidentsPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SettingsPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\TemporaryBansPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminMenu {
	private const PAGE_TABS = array(
		'openwpsecurity-firewall'                => 'Dashboard',
		'openwpsecurity-firewall-policies'       => 'Policies',
		'openwpsecurity-firewall-request-log'    => 'Request Log',
		'openwpsecurity-firewall-security'       => 'Security Incidents',
		'openwpsecurity-firewall-temporary-bans' => 'Temporary Bans',
		'openwpsecurity-firewall-bans'           => 'Permanent Bans',
		'openwpsecurity-firewall-settings'       => 'Settings',
	);

	private AdminMenuRegistrar $registrar;

	public function __construct(
		DashboardPage $dashboard_page,
		PoliciesPage $policies_page,
		RequestLogPage $request_log_page,
		SecurityIncidentsPage $security_incidents_page,
		TemporaryBansPage $temporary_bans_page,
		PermanentBansPage $permanent_bans_page,
		SettingsPage $settings_page,
		AssetVersion $asset_version
	) {
		$core_admin_script = 'vendor/openwpsecurity/core/assets/js/admin.js';

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
				$this->submenu_page( 'openwpsecurity-firewall-policies', 'Policies', array( $policies_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-request-log', 'Request Log', array( $request_log_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-security', 'Security Incidents', array( $security_incidents_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-temporary-bans', 'Temporary Bans', array( $temporary_bans_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-bans', 'Permanent Bans', array( $permanent_bans_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-firewall-settings', 'Settings', array( $settings_page, 'render' ) ),
			),
			'openwpsecurity-firewall',
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . 'assets/css/admin.css',
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . $core_admin_script,
			$asset_version->for_files(
				array(
					OPENWPSECURITY_FIREWALL_DIR . 'assets/css/admin.css',
					OPENWPSECURITY_FIREWALL_DIR . $core_admin_script,
				),
				OPENWPSECURITY_FIREWALL_VERSION
			)
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
