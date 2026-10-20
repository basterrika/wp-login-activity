<?php

defined('ABSPATH') || exit;

class Activity_Logger {

    private readonly string $activity_table;
    private readonly string $attempts_table;

    private const int IP_LOGIN_MAX_ATTEMPTS = 10;
    private const int IP_LOGIN_WINDOW_SECONDS = 900; // 15 minutes
    private const int IP_RESET_MAX_REQUESTS = 5;
    private const int IP_RESET_WINDOW_SECONDS = 3600; // 1 hour
    private const int ACCOUNT_LOGIN_MAX_ATTEMPTS = 20;
    private const int ACCOUNT_LOGIN_WINDOW_SECONDS = 3600; // 1 hour

    private array $reserved_keys = [];

    public function __construct() {
        global $wpdb;

        $this->activity_table = $wpdb->prefix . 'login_activity';
        $this->attempts_table = $wpdb->prefix . 'login_attempts';

        add_filter('authenticate', [$this, 'reserve_attempt'], 5, 3);
        add_filter('authenticate', [$this, 'refund_attempt'], PHP_INT_MAX);
        add_action('lostpassword_post', [$this, 'throttle_password_reset']);
        add_action('wp_login', [$this, 'log_successful_login']);
        add_action('wp_login_failed', [$this, 'log_failed_login']);
    }

    public function log_successful_login($user_login): void {
        $this->create_login_log($user_login, 'success');
    }

    public function log_failed_login($username): void {
        $this->create_login_log($username, 'error');
    }

    public function reserve_attempt($user, $username, $password) {
        if ((string)$username === '' || (string)$password === '' || $user instanceof WP_User) {
            return $user;
        }

        $ip_key = $this->bucket_key('auth');

        if ($ip_key !== null && $this->hit($ip_key, self::IP_LOGIN_MAX_ATTEMPTS, self::IP_LOGIN_WINDOW_SECONDS) > self::IP_LOGIN_MAX_ATTEMPTS) {
            $this->block(self::IP_LOGIN_WINDOW_SECONDS);
        }

        // Per-account limit across all IPs. Counts unknown usernames too. Locks out the real user while under attack.
        $account_key = $this->account_key((string)$username);

        if ($this->hit($account_key, self::ACCOUNT_LOGIN_MAX_ATTEMPTS, self::ACCOUNT_LOGIN_WINDOW_SECONDS) > self::ACCOUNT_LOGIN_MAX_ATTEMPTS) {
            $this->block(self::ACCOUNT_LOGIN_WINDOW_SECONDS);
        }

        $this->reserved_keys = array_filter([$ip_key, $account_key]);

        return $user;
    }

    public function refund_attempt($user) {
        if ($this->reserved_keys && $user instanceof WP_User) {
            global $wpdb;

            $placeholders = implode(',', array_fill(0, count($this->reserved_keys), '%s'));

            $wpdb->query($wpdb->prepare("UPDATE $this->attempts_table SET attempts = attempts - 1 WHERE bucket_key IN ($placeholders) AND attempts > 0", ...$this->reserved_keys));
        }

        $this->reserved_keys = [];

        return $user;
    }

    private function block(int $seconds): never {
        header('Retry-After: ' . $seconds);

        wp_die(
            esc_html(sprintf(
                /* translators: %s: human-readable remaining time */
                __('Too many failed login attempts. Please try again in %s.', 'wp-login-activity'),
                human_time_diff(0, $seconds)
            )),
            esc_html__('Login blocked', 'wp-login-activity'),
            [
                'response' => 429,
                'back_link' => false,
            ]
        );
    }

    public function throttle_password_reset(WP_Error $errors): void {
        if (current_user_can('edit_users')) {
            return;
        }

        $key = $this->bucket_key('reset');

        if ($key !== null && $this->hit($key, self::IP_RESET_MAX_REQUESTS, self::IP_RESET_WINDOW_SECONDS) > self::IP_RESET_MAX_REQUESTS) {
            $errors->add('too_many_requests', esc_html__('Too many password reset requests. Please try again later.', 'wp-login-activity'));
        }
    }

    private function hit(string $key, int $max, int $window): int {
        global $wpdb;

        $table = $this->attempts_table;
        $now = time();

        $result = $wpdb->query($wpdb->prepare(
            "INSERT INTO $table (bucket_key, attempts, expires)
             VALUES (%s, 1, %d)
             ON DUPLICATE KEY UPDATE
                 attempts = LAST_INSERT_ID(IF(expires <= %d, 1, LEAST(attempts + 1, %d))),
                 expires = IF(attempts = 1 OR attempts > %d, %d, expires)",
            $key,
            $now + $window,
            $now,
            $max + 1,
            $max,
            $now + $window
        ));

        // Fail open: a DB error must not lock everyone out. wpdb already writes the error to the PHP error log.
        if ($result === false) {
            return 0;
        }

        // A fresh insert leaves insert_id at 0 (no AUTO_INCREMENT). Updates return the count via LAST_INSERT_ID().
        $count = $wpdb->insert_id ?: 1;

        if (mt_rand(1, 100) === 1) {
            $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE expires < %d LIMIT 1000", $now));
        }

        return $count;
    }

    private function bucket_key(string $scope): ?string {
        $ip = $this->get_public_ip();

        if ($ip === '') {
            return null;
        }

        $packed = inet_pton($ip);

        if (strlen($packed) === 16 && strncmp($packed, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) !== 0) {
            $ip = inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8));
        }

        return md5($scope . '|' . $ip);
    }

    private function account_key(string $username): string {
        $name = mb_strtolower(trim($username), 'UTF-8');

        // Email and username of the same account share one bucket.
        if (is_email($name) && ($account = get_user_by('email', $name))) {
            $name = mb_strtolower($account->user_login, 'UTF-8');
        }

        return md5('account|' . $name);
    }

    private function create_login_log($username, $status): void {
        global $wpdb;

        $login = sanitize_user(mb_strtolower((string)$username, 'UTF-8'));
        $status_int = $status === 'success' ? 1 : 0;

        $data = [
            'login' => mb_substr($login, 0, 191, 'UTF-8'),
            'ip' => $this->get_public_ip(),
            'status' => $status_int,
            'log_date' => current_time('mysql', true),
        ];

        $format = ['%s', '%s', '%d', '%s'];

        if ($wpdb->insert($this->activity_table, $data, $format) === false) {
            error_log('WP Login Activity: failed to insert login activity.');
        }
    }

    private function get_public_ip(): string {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string)wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

}

new Activity_Logger();
