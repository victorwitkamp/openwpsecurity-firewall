<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation;

use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\DashboardPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\PermanentBansPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\RequestHandlingPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SecurityIncidentsPage;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages\SettingsPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminMenu {
	private DashboardPage $dashboard_page;
	private RequestHandlingPage $request_handling_page;
	private SecurityIncidentsPage $security_incidents_page;
	private PermanentBansPage $permanent_bans_page;
	private SettingsPage $settings_page;

	public function __construct(
		DashboardPage $dashboard_page,
		RequestHandlingPage $request_handling_page,
		SecurityIncidentsPage $security_incidents_page,
		PermanentBansPage $permanent_bans_page,
		SettingsPage $settings_page
	) {
		$this->dashboard_page          = $dashboard_page;
		$this->request_handling_page   = $request_handling_page;
		$this->security_incidents_page = $security_incidents_page;
		$this->permanent_bans_page     = $permanent_bans_page;
		$this->settings_page           = $settings_page;
	}

	public function register_hooks(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	public function register_menu(): void {
		add_menu_page(
			'OpenWPSecurity - Firewall',
			'OpenWPSecurity - Firewall',
			'manage_options',
			'openwpsecurity-firewall',
			array( $this->dashboard_page, 'render' ),
			'dashicons-shield-alt',
			74
		);

		add_submenu_page(
			'openwpsecurity-firewall',
			'Dashboard',
			'Dashboard',
			'manage_options',
			'openwpsecurity-firewall',
			array( $this->dashboard_page, 'render' )
		);

		add_submenu_page(
			'openwpsecurity-firewall',
			'Request Handling',
			'Request Handling',
			'manage_options',
			'openwpsecurity-firewall-request-handling',
			array( $this->request_handling_page, 'render' )
		);

		add_submenu_page(
			'openwpsecurity-firewall',
			'Security Incidents',
			'Security Incidents',
			'manage_options',
			'openwpsecurity-firewall-security',
			array( $this->security_incidents_page, 'render' )
		);

		add_submenu_page(
			'openwpsecurity-firewall',
			'Permanent Bans',
			'Permanent Bans',
			'manage_options',
			'openwpsecurity-firewall-bans',
			array( $this->permanent_bans_page, 'render' )
		);

		add_submenu_page(
			'openwpsecurity-firewall',
			'Settings',
			'Settings',
			'manage_options',
			'openwpsecurity-firewall-settings',
			array( $this->settings_page, 'render' )
		);
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( strpos( $hook_suffix, 'openwpsecurity-firewall' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . 'assets/css/admin.css',
			array(),
			OPENWPSECURITY_FIREWALL_VERSION
		);

		wp_enqueue_script(
			'openwpsecurity-firewall-admin',
			OPENWPSECURITY_FIREWALL_URL . 'assets/js/admin.js',
			array(),
			OPENWPSECURITY_FIREWALL_VERSION,
			true
		);
	}
}
