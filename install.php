<?php

defined('ABSPATH') || exit;

final class Activity_Installer {

    /**
     * Creates both per-site tables for the current blog.
     * Returns false if either failed.
     */
    public static function create_tables(): bool {
        return self::create_log_table() && self::create_attempts_table();
    }

    private static function create_log_table(): bool {
        global $wpdb;

        $table = $wpdb->prefix . 'login_activity';
        $charset_collate = $wpdb->get_charset_collate();

        return $wpdb->query("CREATE TABLE IF NOT EXISTS $table (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            login VARCHAR(191) NOT NULL,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            status TINYINT UNSIGNED NOT NULL,
            log_date DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY idx_log_date (log_date),
            KEY idx_status_date (status, log_date)
        ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC $charset_collate") !== false;
    }

    private static function create_attempts_table(): bool {
        global $wpdb;

        $table = $wpdb->prefix . 'login_attempts';

        return $wpdb->query("CREATE TABLE IF NOT EXISTS $table (
            bucket_key CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            attempts SMALLINT UNSIGNED NOT NULL,
            expires INT UNSIGNED NOT NULL,
            PRIMARY KEY (bucket_key),
            KEY idx_expires (expires)
        ) ENGINE=InnoDB") !== false;
    }

}
