<?php
/*
Plugin Name: Xyo Security
Plugin URI: https://xyo.dev/plugins/securityq
Description: Secure and clean your WordPress: trim head cruft, harden headers, lock the REST API (with a public-route whitelist) and tame Yoast.
Version: 3.0.0
Author: Patrick Petit (Xyo)
Author URI: https://xyo.dev/
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: xyo-security
Requires at least: 5.0
Requires PHP: 7.4
*/

use Xyo\WordpressSecurity\Actions\Cleanup;
use Xyo\WordpressSecurity\Actions\Footer;
use Xyo\WordpressSecurity\Actions\Header;
use Xyo\WordpressSecurity\Actions\Integrity;
use Xyo\WordpressSecurity\Actions\Security;
use Xyo\WordpressSecurity\Actions\WpJson;
use Xyo\WordpressSecurity\Actions\Yoast;
use Xyo\WordpressSecurity\Admin\Settings;

if (!defined('ABSPATH')) {
    exit;
}

define('XYO_SECURITY_VERSION', '3.0.0');
define('XYO_SECURITY_MINIMUM_WP_VERSION', '^5.0');
define('XYO_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));

/**
 * Minimal PSR-4 autoloader: Xyo\WordpressSecurity\ => src/. No Composer/vendor
 * needed — the plugin ships no external dependencies, so a ~10-line loader keeps
 * it fully self-contained with zero build step.
 */
spl_autoload_register(function ($class) {
    $prefix = 'Xyo\\WordpressSecurity\\';
    $len = strlen($prefix);
    if (strncmp($class, $prefix, $len) !== 0) {
        return;
    }

    $file = XYO_SECURITY_PLUGIN_DIR . 'src/' . str_replace('\\', '/', substr($class, $len)) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

if (!function_exists('add_action')) {
    exit;
}

// Admin settings screen (Settings → Xyo Security) + "Settings" plugin link.
add_action('admin_menu', [Settings::class, 'registerMenu']);
add_action('admin_init', [Settings::class, 'registerSettings']);
add_filter('plugin_action_links_' . plugin_basename(__FILE__), [Settings::class, 'actionLinks']);

// Each feature is wired only when its toggle is enabled (all default to on).
if (Settings::isEnabled('login_errors')) {
    add_action('init', [Security::class, 'init']);
}
if (Settings::isEnabled('cleanup')) {
    add_action('init', [Cleanup::class, 'clean']);
}
if (Settings::isEnabled('admin_footer')) {
    add_action('init', [Footer::class, 'init']);
}
if (Settings::isEnabled('headers')) {
    add_action('init', [Header::class, 'setHeader']);
}
if (Settings::isEnabled('yoast')) {
    add_action('init', [Yoast::class, 'init']);
}
if (Settings::isEnabled('rest_lock')) {
    add_filter('rest_authentication_errors', [WpJson::class, 'disable']);
}

// File integrity monitoring. The cron callback is registered unconditionally so
// a scan event queued before the toggle was turned off can still fire once and
// self-unschedule; scheduling + admin UI are wired only while the feature is on.
add_action(Integrity::CRON_HOOK, [Integrity::class, 'runScan']);
if (Settings::isEnabled('integrity')) {
    add_action('init', [Integrity::class, 'init']);
}
register_deactivation_hook(__FILE__, [Integrity::class, 'unschedule']);
