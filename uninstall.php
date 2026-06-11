<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 * Drops all plugin-owned database tables and removes all plugin options.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$tables = array(
	$wpdb->prefix . 'openwpsecurity_firewall_request_logs',
	$wpdb->prefix . 'openwpsecurity_firewall_security_incidents',
	$wpdb->prefix . 'openwpsecurity_firewall_temporary_bans',
	$wpdb->prefix . 'openwpsecurity_firewall_temporary_ban_counts',
	$wpdb->prefix . 'openwpsecurity_firewall_permanent_bans',
);

foreach ( $tables as $table ) {
	$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}

$options = array(
	'openwpsecurity_firewall_settings',
	'openwpsecurity_firewall_request_logs_db_version',
	'openwpsecurity_firewall_security_incidents_db_version',
	'openwpsecurity_firewall_temporary_bans_db_version',
	'openwpsecurity_firewall_temporary_ban_counts_db_version',
	'openwpsecurity_firewall_permanent_bans_db_version',
);

foreach ( $options as $option ) {
	delete_option( $option );
}

wp_clear_scheduled_hook( 'openwpsecurity_firewall_purge_expired_temporary_bans' );
wp_clear_scheduled_hook( 'openwpsecurity_firewall_delete_expired_rows' );
