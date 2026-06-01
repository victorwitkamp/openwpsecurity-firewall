<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Runtime;

use VictorWitkamp\OpenWPSecurity\Core\Runtime\PluginLifecycle;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Diagnostics\DebugBar;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventRetention;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventSchema;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestGuard;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\RequestHandling\RequestTemporaryBlockStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin implements PluginLifecycle {
	private Settings $settings;
	private EventSchema $event_schema;
	private EventRetention $event_retention;
	private PermanentBanStore $ban_store;
	private RequestTemporaryBlockStore $request_temporary_block_store;
	private RequestGuard $request_guard;
	private DebugBar $debug_bar;
	private AdminMenu $admin_menu;
	private bool $runtime_initialized = false;

	public function __construct(
		Settings $settings,
		EventSchema $event_schema,
		EventRetention $event_retention,
		PermanentBanStore $ban_store,
		RequestTemporaryBlockStore $request_temporary_block_store,
		RequestGuard $request_guard,
		DebugBar $debug_bar,
		AdminMenu $admin_menu
	) {
		$this->settings                      = $settings;
		$this->event_schema                  = $event_schema;
		$this->event_retention               = $event_retention;
		$this->ban_store                     = $ban_store;
		$this->request_temporary_block_store = $request_temporary_block_store;
		$this->request_guard                 = $request_guard;
		$this->debug_bar                     = $debug_bar;
		$this->admin_menu                    = $admin_menu;
	}

	public function activate(): void {
		$this->prepare_storage();
		$this->event_retention->activate();
	}

	public function deactivate(): void {
		$this->event_retention->deactivate();
	}

	public function initialize_runtime(): void {
		if ( $this->runtime_initialized ) {
			return;
		}

		$this->prepare_storage();
		$this->request_guard->register_hooks();
		$this->debug_bar->register_hooks();
		$this->event_retention->register_hooks();

		if ( is_admin() ) {
			$this->admin_menu->register_hooks();
		}

		$this->runtime_initialized = true;
	}

	private function prepare_storage(): void {
		$this->settings->ensure_defaults();
		$this->ban_store->ensure_storage();
		$this->request_temporary_block_store->ensure_storage();
		$this->event_schema->maybe_upgrade_schema();
	}
}
