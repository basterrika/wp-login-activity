<?php
/**
 * Plugin Name: Login Activity
 * Description: Monitor user login activities.
 * Version: 1.0.0
 * Author: Mikel
 * Author URI: https://basterrika.com
 * Text Domain: wp-login-activity
 * Requires PHP: 8.4
 * Tested up to: 6.9.1
 */

defined('ABSPATH') || exit;

define('LOGIN_ACTIVITY_PLUGIN_DIR', plugin_dir_path(__FILE__));

require_once LOGIN_ACTIVITY_PLUGIN_DIR . 'logger.php';

if (is_admin()) {
    require_once LOGIN_ACTIVITY_PLUGIN_DIR . 'interface.php';
}

/*
 * Activation hook – runs on plugin activation.
 * If the plugin is network activated in multisite, it also creates the table for all existing sites.
 */
register_activation_hook(__FILE__, static function($network_wide): void {
    Activity_Logger::create_table();

    if ($network_wide && is_multisite()) {
        global $wpdb;

        $blog_ids = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");

        foreach ($blog_ids as $blog_id) {
            switch_to_blog($blog_id);
            Activity_Logger::create_table();
            restore_current_blog();
        }
    }
});

/*
 * In a multisite network, create the table for each new site upon its creation,
 * but only if the plugin is network activated.
 */
add_action('wpmu_new_blog', static function(int $blog_id): void {
    if (!function_exists('is_plugin_active_for_network')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    if (!is_plugin_active_for_network(plugin_basename(__FILE__))) {
        return;
    }

    switch_to_blog($blog_id);
    Activity_Logger::create_table();
    restore_current_blog();
});
