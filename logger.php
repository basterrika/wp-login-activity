<?php

defined('ABSPATH') || exit;

class Activity_Logger {

    private readonly string $table_name;

    private const int MAX_ATTEMPTS = 10;
    private const int WINDOW_SECONDS = 30;
    private const int LOCKOUT_SECONDS = 300;

    private ?string $cached_ip = null;

    public static function create_table(): void {
        global $wpdb;

        $table = $wpdb->prefix . 'login_activity';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            login VARCHAR(191) NOT NULL,
            login_url varchar(255) NOT NULL,
            ip VARBINARY(16) NOT NULL,
            status TINYINT UNSIGNED NOT NULL,
            log_date DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY idx_log_date (log_date),
            KEY idx_status_date (status, log_date)
        ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public function __construct() {
        global $wpdb;

        $this->table_name = $wpdb->prefix . 'login_activity';

        add_filter('authenticate', [$this, 'maybe_block_auth'], 5, 3);
        add_action('wp_login', [$this, 'log_successful_login']);
        add_action('wp_login_failed', [$this, 'log_failed_login']);
    }

    public function log_successful_login($user_login): void {
        $this->create_login_log($user_login, 'success');
        $this->clear_rate_state_for_ip();
        $this->clear_rate_state_for_user($user_login);
    }

    public function log_failed_login($username): void {
        $this->create_login_log($username, 'error');
        $this->bump_attempts_for_ip();
        $this->bump_attempts_for_user($username);
    }

    public function maybe_block_auth($user, string $username, string $password) {
        $now = current_time('timestamp');
        $ip_until = $this->locked_until_for_ip();

        if ($ip_until && $ip_until > $now) {
            $this->wp_die_lock(
                sprintf(
                    /* translators: %s: human-readable remaining time */
                    esc_html__('Too many failed login attempts. Please try again in %s.', 'wp-login-activity'),
                    esc_html(human_time_diff($now, $ip_until))
                )
            );
        }

        if ($username !== '') {
            $user_until = $this->locked_until_for_user($username);

            if ($user_until && $user_until > $now) {
                $this->wp_die_lock(
                    sprintf(
                        /* translators: %s: human-readable remaining time */
                        esc_html__('This account is temporarily locked due to too many failed attempts. Try again in %s.', 'wp-login-activity'),
                        esc_html(human_time_diff($now, $user_until))
                    )
                );
            }
        }

        return $user;
    }

    private function wp_die_lock(string $message): void {
        wp_die(
            esc_html($message),
            esc_html__('Login blocked', 'wp-login-activity'),
            [
                'response' => 403,
                'back_link' => false,
            ]
        );
    }

    private function bump_attempts_for_ip(): void {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return;
        }

        $keys = $this->get_keys_for_ip($ip);
        $this->bump_attempts($keys['attempts'], $keys['lock']);
    }

    private function bump_attempts_for_user(string $username): void {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return;
        }

        $uname = sanitize_user(mb_strtolower($username, 'UTF-8'));

        if ($uname === '') {
            return;
        }

        $keys = $this->get_keys_for_user($uname, $ip);
        $this->bump_attempts($keys['attempts'], $keys['lock']);
    }

    private function bump_attempts(string $attempts_key, string $lock_key): void {
        $count = (int)get_transient($attempts_key);
        $count++;

        set_transient($attempts_key, $count, self::WINDOW_SECONDS);

        if ($count >= self::MAX_ATTEMPTS) {
            $until = current_time('timestamp') + self::LOCKOUT_SECONDS;

            set_transient($lock_key, $until, self::LOCKOUT_SECONDS);
            delete_transient($attempts_key);
        }
    }

    private function locked_until_for_ip(): int {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return 0;
        }

        $keys = $this->get_keys_for_ip($ip);

        return (int)get_transient($keys['lock']);
    }

    private function locked_until_for_user(string $username): int {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return 0;
        }

        $uname = sanitize_user(mb_strtolower($username, 'UTF-8'));

        if ($uname === '') {
            return 0;
        }

        $keys = $this->get_keys_for_user($uname, $ip);

        return (int)get_transient($keys['lock']);
    }

    private function clear_rate_state_for_ip(): void {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return;
        }

        $keys = $this->get_keys_for_ip($ip);

        delete_transient($keys['attempts']);
        delete_transient($keys['lock']);
    }

    private function clear_rate_state_for_user(string $username): void {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return;
        }

        $uname = sanitize_user(mb_strtolower($username, 'UTF-8'));

        if ($uname === '') {
            return;
        }

        $keys = $this->get_keys_for_user($uname, $ip);

        delete_transient($keys['attempts']);
        delete_transient($keys['lock']);
    }

    private function get_keys_for_ip(string $ip): array {
        $hash = md5($ip);

        return [
            'attempts' => 'al_atm_ip_' . $hash,
            'lock' => 'al_lck_ip_' . $hash,
        ];
    }

    private function get_keys_for_user(string $uname, string $ip): array {
        $hash = md5($uname . '|' . $ip);

        return [
            'attempts' => 'al_atm_u_' . $hash,
            'lock' => 'al_lck_u_' . $hash,
        ];
    }

    private function create_login_log($username, $status): void {
        global $wpdb;

        $login = sanitize_user(mb_strtolower((string)$username, 'UTF-8'));
        $status_int = $status === 'success' ? 1 : 0;

        // Pack to binary (16B). If invalid/missing, use 16 x 0x00 (still valid VARBINARY(16)).
        $ip_str = $this->get_public_ip();
        $ip_bin = $ip_str !== '' ? @inet_pton($ip_str) : false;

        if ($ip_bin === false) {
            $ip_bin = str_repeat("\x00", 16);
        }

        $data = [
            'login' => $login,
            'login_url' => esc_url_raw($this->get_login_url()),
            'ip' => $ip_bin,
            'status' => $status_int,
            'log_date' => current_time('mysql'),
        ];

        $format = ['%s', '%s', '%s', '%d', '%s'];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert($this->table_name, $data, $format);
    }

    private function get_login_url(): string {
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        return home_url($uri);
    }

    private function get_public_ip(): string {
        if ($this->cached_ip !== null) {
            return $this->cached_ip;
        }

        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string)wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        $this->cached_ip = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';

        return $this->cached_ip;
    }

}

new Activity_Logger();
