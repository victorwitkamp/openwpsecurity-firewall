<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\Firewall\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\PermanentBansPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Firewall\Admin\Navigation\AdminMenu;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PermanentBansPage extends AbstractAdminPage {
	private const PER_PAGE     = 25;
	private const PAGE_SLUG    = 'openwpsecurity-firewall-bans';
	private const NONCE_ACTION = 'openwpsecurity_firewall_bans_action';

	private PermanentBansPanel $permanent_bans_panel;

	public function __construct( PermanentBansPanel $permanent_bans_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->permanent_bans_panel = $permanent_bans_panel;
	}

	public function render(): void {
		$this->assert_page_access();

		$notice      = $this->permanent_bans_panel->handle_actions( self::NONCE_ACTION );
		$total_items = $this->permanent_bans_panel->count_bans();
		$paginator   = $this->create_paginator( $total_items, self::PER_PAGE, self::PAGE_SLUG );
		$rows        = $this->permanent_bans_panel->get_bans( self::PER_PAGE, $paginator->offset() );
		?>
		<div class="wrap vwfw-admin">
			<h1><?php esc_html_e( 'OpenWPSecurity - Firewall Permanent Bans', 'openwpsecurity-firewall' ); ?></h1>
			<p><?php esc_html_e( 'Manage IP addresses that Firewall blocks across every request type.', 'openwpsecurity-firewall' ); ?></p>
			<?php $this->render_page_tabs( self::PAGE_SLUG ); ?>
			<?php $this->permanent_bans_panel->render_notice( $notice ); ?>

			<?php
			$this->permanent_bans_panel->render(
				self::PAGE_SLUG,
				self::NONCE_ACTION,
				__( 'Permanently Banned IP Addresses', 'openwpsecurity-firewall' ),
				__( 'These IP addresses are blocked from all request types and will only receive the firewall error response.', 'openwpsecurity-firewall' ),
				$total_items,
				$rows,
				$paginator->render(),
				__( 'No permanently banned IP addresses were found.', 'openwpsecurity-firewall' )
			);
			?>
		</div>
		<?php
	}
}
