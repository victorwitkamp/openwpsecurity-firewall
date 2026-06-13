<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Runtime;

use VictorWitkamp\OpenWPSecurity\Core\Runtime\PluginLifecycle;
use VictorWitkamp\OpenWPSecurity\Core\Database\CreatedAtRetention;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\RequestLogRepository;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\SecurityIncidentRepository;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\TemporaryBanCleanup;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\TemporaryBanCounterStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin implements PluginLifecycle {
	private Settings $settings;
	private RequestLogRepository $request_logs;
	private SecurityIncidentRepository $security_incidents;
	private CreatedAtRetention $retention;
	private PermanentBanStore $ban_store;
	private TemporaryBanRepository $temporary_ban_repository;
	private TemporaryBanCounterStore $temporary_ban_counter_store;
	private TemporaryBanCleanup $temporary_ban_cleanup;
	private RequestGuard $request_guard;
	private AdminMenu $admin_menu;
	private bool $runtime_initialized = false;

	public function __construct(
		Settings $settings,
		RequestLogRepository $request_logs,
		SecurityIncidentRepository $security_incidents,
		CreatedAtRetention $retention,
		PermanentBanStore $ban_store,
		TemporaryBanRepository $temporary_ban_repository,
		TemporaryBanCounterStore $temporary_ban_counter_store,
		TemporaryBanCleanup $temporary_ban_cleanup,
		RequestGuard $request_guard,
		AdminMenu $admin_menu
	) {
		$this->settings                    = $settings;
		$this->request_logs                = $request_logs;
		$this->security_incidents          = $security_incidents;
		$this->retention                   = $retention;
		$this->ban_store                   = $ban_store;
		$this->temporary_ban_repository    = $temporary_ban_repository;
		$this->temporary_ban_counter_store = $temporary_ban_counter_store;
		$this->temporary_ban_cleanup       = $temporary_ban_cleanup;
		$this->request_guard               = $request_guard;
		$this->admin_menu                  = $admin_menu;
	}

	public function activate(): void {
		$this->prepare_storage();
		$this->retention->activate();
		$this->temporary_ban_cleanup->activate();
	}

	public function deactivate(): void {
		$this->retention->deactivate();
		$this->temporary_ban_cleanup->deactivate();
	}

	public function initialize_runtime(): void {
		if ( $this->runtime_initialized ) {
			return;
		}

		$this->prepare_storage();
		$this->request_guard->register_hooks();
		$this->retention->register_hooks();
		$this->temporary_ban_cleanup->register_hooks();

		if ( is_admin() ) {
			$this->admin_menu->register_hooks();
		}

		$this->runtime_initialized = true;
	}

	private function prepare_storage(): void {
		$this->settings->ensure_defaults();
		$this->ban_store->ensure_storage();
		$this->temporary_ban_repository->maybe_upgrade_schema();
		$this->temporary_ban_counter_store->maybe_upgrade_schema();
		$this->request_logs->maybe_upgrade_schema();
		$this->security_incidents->maybe_upgrade_schema();
	}
}
