<?php
/**
 * Plugin Name: Login Activity
 * Description: Monitor user login activities.
 * Version: 1.0.0
 * Author: Mikel
 * Author URI: https://basterrika.com
 * Update URI: https://github.com/basterrika/wp-login-activity
 * Text Domain: wp-login-activity
 * Requires PHP: 8.4
 * Tested up to: 6.9.1
 * Requires at least: 6.7
 */

defined('ABSPATH') || exit;

require_once __DIR__ . '/logger.php';

if (is_admin()) {
    require_once __DIR__ . '/interface.php';
}

/*
 * Activation hook – runs on plugin activation.
 * If the plugin is network activated in multisite, it also creates the tables for all existing sites.
 * A failed table creation aborts activation so the plugin never runs without its tables.
 */
register_activation_hook(__FILE__, static function($network_wide): void {
    require_once __DIR__ . '/install.php';

    $created = true;

    if (!$network_wide || !is_multisite()) {
        $created = Activity_Installer::create_tables();
    }
    else {
        global $wpdb;

        foreach ($wpdb->get_col("SELECT blog_id FROM $wpdb->blogs") as $blog_id) {
            switch_to_blog($blog_id);
            $created = Activity_Installer::create_tables() && $created;
            restore_current_blog();
        }
    }

    if (!$created) {
        wp_die(
            esc_html__('Login Activity could not create its database tables, so it was not activated. Check the PHP error log for the database error.', 'wp-login-activity'),
            esc_html__('Plugin activation failed', 'wp-login-activity'),
            ['back_link' => true]
        );
    }
});

/*
 * In a multisite network, create the tables for each new site upon its creation,
 * but only if the plugin is network activated.
 */
add_action('wp_initialize_site', static function(WP_Site $site): void {
    if (!function_exists('is_plugin_active_for_network')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    if (!is_plugin_active_for_network(plugin_basename(__FILE__))) {
        return;
    }

    require_once __DIR__ . '/install.php';

    // No abort here. Failing site creation over a plugin table is worse than an unprotected site.
    switch_to_blog($site->blog_id);
    Activity_Installer::create_tables();
    restore_current_blog();
});
