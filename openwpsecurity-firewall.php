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

use VictorWitkamp\OpenWPSecurity\Firewall\Runtime\WordPressIntegration;

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

$wordpress_integration = new WordPressIntegration();

register_activation_hook( OPENWPSECURITY_FIREWALL_FILE, array( $wordpress_integration, 'activate' ) );
register_deactivation_hook( OPENWPSECURITY_FIREWALL_FILE, array( $wordpress_integration, 'deactivate' ) );

add_action( 'plugins_loaded', array( $wordpress_integration, 'initialize_runtime' ) );
