<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\TemporaryBansPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\Firewall\Security\Ban\TemporaryBanRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemporaryBansPage extends AbstractAdminPage {
	private const PAGE_SLUG    = 'openwpsecurity-firewall-temporary-bans';
	private const NONCE_ACTION = 'openwpsecurity_firewall_temporary_bans_action';

	private TemporaryBansPanel $temporary_bans_panel;
	private TemporaryBanRepository $temporary_ban_repository;

	public function __construct( TemporaryBansPanel $temporary_bans_panel, TemporaryBanRepository $temporary_ban_repository, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->temporary_bans_panel     = $temporary_bans_panel;
		$this->temporary_ban_repository = $temporary_ban_repository;
	}

	public function render(): void {
		$this->assert_page_access();

		$notice = $this->temporary_bans_panel->handle_actions( $this->temporary_ban_repository, self::NONCE_ACTION );
		$rows   = $this->temporary_bans_panel->sorted_rows( $this->temporary_ban_repository );
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Firewall Temporary Bans</h1>
			<p>Manage IP addresses currently denied across all request types by Firewall.</p>
			<?php $this->render_page_tabs( self::PAGE_SLUG ); ?>
			<?php $this->temporary_bans_panel->render_notice( $notice ); ?>
			<?php
			$this->temporary_bans_panel->render(
				self::PAGE_SLUG,
				self::NONCE_ACTION,
				'Currently Temporarily Banned IP Addresses',
				'Firewall temporary bans deny every request type until they expire or are manually removed.',
				$rows,
				'No Firewall temporary bans are currently active.'
			);
			?>
		</div>
		<?php
	}
}
