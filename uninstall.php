<?php

defined('WP_UNINSTALL_PLUGIN') || exit;

global $wpdb;

$blog_ids = is_multisite() ? $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs") : [get_current_blog_id()];

foreach ($blog_ids as $blog_id) {
    $wpdb->query('DROP TABLE IF EXISTS `' . $wpdb->get_blog_prefix($blog_id) . 'login_activity`');
}

$wpdb->query("DROP TABLE IF EXISTS `{$wpdb->base_prefix}login_attempts`");

// Each user's "Logs per page" screen option
delete_metadata('user', 0, 'login_logs_per_page', '', true);
