<?php
/**
 * Plugin Name: OpenWPSecurity - Firewall
 * Plugin URI:  https://victorwitkamp.nl/
 * Description: WordPress request handling, captcha challenges, permanent bans, event logging, and a security dashboard.
 * Version:     0.2.0
 * Requires at least: 6.5
 * Requires PHP: 8.2
 * Author:      Victor Witkamp
 * Author URI:  https://victorwitkamp.nl/
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: openwpsecurity-firewall
 */

declare(strict_types=1);

use Psr\Http\Message\ServerRequestInterface;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventRetention;
use VictorWitkamp\OpenWPSecurity\Core\Presentation\Templates\TemplateRenderer;
use VictorWitkamp\OpenWPSecurity\Core\Runtime\WordPressPluginIntegration;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Firewall\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventLogger;
use VictorWitkamp\OpenWPSecurity\Firewall\Logging\EventTable;
use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'OPENWPSECURITY_FIREWALL_VERSION', '0.2.0' );
define( 'OPENWPSECURITY_FIREWALL_FILE', __FILE__ );
define( 'OPENWPSECURITY_FIREWALL_DIR', plugin_dir_path( __FILE__ ) );
define( 'OPENWPSECURITY_FIREWALL_URL', plugin_dir_url( __FILE__ ) );

$composer_autoload = OPENWPSECURITY_FIREWALL_DIR . 'vendor/autoload.php';

if ( ! file_exists( $composer_autoload ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>OpenWPSecurity - Firewall is missing Composer dependencies. Run <code>composer install --no-dev</code> in the plugin directory.</p></div>';
		}
	);
	return;
}

require_once $composer_autoload;

$wordpress_integration = new WordPressPluginIntegration(
	Plugin::class,
	'Firewall',
	array(
		RequestContext::class       => static function ( Settings $settings, IpAddressInspector $ip_address_inspector, ServerRequestInterface $request ): RequestContext {
			return new RequestContext( $settings, $ip_address_inspector, $request, 'openwpsecurity_firewall_is_ip_whitelisted' );
		},
		TemplateRenderer::class     => static function (): TemplateRenderer {
			return new TemplateRenderer(
				OPENWPSECURITY_FIREWALL_DIR . 'templates/',
				'Firewall template file was not found.',
				'openwpsecurity-firewall-runtime',
				OPENWPSECURITY_FIREWALL_URL . 'assets/css/runtime.css',
				'openwpsecurity-firewall-runtime',
				OPENWPSECURITY_FIREWALL_URL . 'assets/js/runtime.js',
				OPENWPSECURITY_FIREWALL_VERSION
			);
		},
		EventRetention::class       => static function ( Settings $settings, EventTable $event_table ): EventRetention {
			return new EventRetention( $settings, $event_table, 'openwpsecurity_firewall_delete_expired_events' );
		},
		PermanentBanStore::class    => static function ( EventLogger $event_logger, IpAddressInspector $ip_address_inspector ): PermanentBanStore {
			return new PermanentBanStore(
				'openwpsecurity_firewall_permanent_bans',
				$ip_address_inspector,
				static function ( string $ip, string $reason, string $source, array $context ) use ( $event_logger ): void {
					$event_logger->log(
						'permanent_ban_created',
						$ip,
						'',
						array(
							'details' => array_merge(
								array(
									'reason' => $reason,
									'source' => $source,
								),
								$context
							),
						)
					);
				},
				'manual'
			);
		},
		EventReportFormatter::class => static function (): EventReportFormatter {
			return new EventReportFormatter(
				array(
					'request_hit'                     => 'WordPress Request',
					'request_rate_limited'            => 'Request Rate Limited',
					'request_temporary_block_created' => 'Request Temporary Block Created',
					'request_temporarily_blocked'     => 'Request Denied By Temporary Block',
					'permanent_ban_created'           => 'Permanent Ban Created',
					'page_visit'                      => 'Page Visit',
					'captcha_required'                => 'Captcha Required',
					'captcha_failed'                  => 'Captcha Failed',
					'captcha_passed'                  => 'Captcha Passed',
				),
				array(
					'request_handling' => 'Request Handling',
					'manual'           => 'Manual',
				)
			);
		},
	)
);

register_activation_hook( OPENWPSECURITY_FIREWALL_FILE, array( $wordpress_integration, 'activate' ) );
register_deactivation_hook( OPENWPSECURITY_FIREWALL_FILE, array( $wordpress_integration, 'deactivate' ) );

add_action( 'plugins_loaded', array( $wordpress_integration, 'initialize_runtime' ) );
