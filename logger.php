<?php

defined('ABSPATH') || exit;

class Activity_Logger {

    private readonly string $activity_table;
    private readonly string $attempts_table;

    private const int IP_LOGIN_MAX_ATTEMPTS = 10;
    private const int IP_LOGIN_WINDOW_SECONDS = 900; // 15 minutes

    private const int IP_RESET_MAX_REQUESTS = 5;
    private const int IP_RESET_WINDOW_SECONDS = 3600; // 1 hour

    private const int ACCOUNT_RESET_MAX_REQUESTS = 3;
    private const int ACCOUNT_RESET_WINDOW_SECONDS = 3600; // 1 hour

    private const int ACCOUNT_LOGIN_MAX_ATTEMPTS = 20;
    private const int ACCOUNT_LOGIN_WINDOW_SECONDS = 3600; // 1 hour

    private const int DEVICE_LOGIN_MAX_ATTEMPTS = 10;
    private const int DEVICE_LOGIN_WINDOW_SECONDS = 900; // 15 minutes

    private const int DEVICE_COOKIE_SECONDS = 31536000; // 1 year
    private const string DEVICE_COOKIE_PREFIX = 'wpld_'; // ld: login device

    private array $reserved_keys = [];
    private bool $account_blocked = false;

    public function __construct() {
        global $wpdb;

        $this->activity_table = $wpdb->prefix . 'login_activity';
        $this->attempts_table = $wpdb->base_prefix . 'login_attempts'; // On multisite, all sites share this table

        add_filter('authenticate', [$this, 'reserve_attempt'], 5, 3);
        add_filter('authenticate', [$this, 'refund_attempt'], PHP_INT_MAX - 1); // Before anti-enumeration.php, which writes the generic message
        add_filter('wp_authenticate_user', fn($user) => $this->account_blocked ? new WP_Error('incorrect_password') : $user); // Skips the password hash check
        add_action('lostpassword_post', [$this, 'throttle_password_reset'], 10, 2);
        add_action('after_password_reset', [$this, 'trust_after_password_reset']);
        add_action('wp_login', [$this, 'log_successful_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'log_failed_login']);
    }

    public function log_successful_login($user_login, $user): void {
        $this->create_login_log($user_login, 'success');

        if ($user instanceof WP_User) {
            $this->issue_device_cookie($user->ID);
        }
    }

    public function log_failed_login($username): void {
        if (!$this->account_blocked) {
            $this->create_login_log($username, 'error');
        }
    }

    public function reserve_attempt($user, $username, $password) {
        $this->account_blocked = false;

        if ((string)$username === '' || (string)$password === '' || $user instanceof WP_User) {
            return $user;
        }

        $accounts = $this->find_users((string)$username);
        $device_key = count($accounts) === 1 ? $this->device_key($accounts[0]) : null;

        // A device that logged in to this account before only gets its own limit, so neither an attack on the account nor failures from others on the same IP lock it out.
        if ($device_key !== null) {
            if ($this->hit($device_key, self::DEVICE_LOGIN_MAX_ATTEMPTS, self::DEVICE_LOGIN_WINDOW_SECONDS) > self::DEVICE_LOGIN_MAX_ATTEMPTS) {
                $this->block(self::DEVICE_LOGIN_WINDOW_SECONDS);
            }

            $this->reserved_keys = [$device_key];

            return $user;
        }

        $ip_key = $this->bucket_key('auth');

        if ($ip_key !== null && $this->hit($ip_key, self::IP_LOGIN_MAX_ATTEMPTS, self::IP_LOGIN_WINDOW_SECONDS) > self::IP_LOGIN_MAX_ATTEMPTS) {
            $this->block(self::IP_LOGIN_WINDOW_SECONDS);
        }

        // Limit failures per account, from any IP. Unknown usernames are counted too.
        // Over the limit, show the normal "wrong password" error. A "blocked" page would reveal the account's email.
        $account_keys = $accounts
            ? array_map(fn(WP_User $account) => $this->account_key($account->user_login), $accounts)
            : [$this->account_key((string)$username)];

        foreach ($account_keys as $account_key) {
            if ($this->hit($account_key, self::ACCOUNT_LOGIN_MAX_ATTEMPTS, self::ACCOUNT_LOGIN_WINDOW_SECONDS) > self::ACCOUNT_LOGIN_MAX_ATTEMPTS) {
                $this->account_blocked = true;
            }
        }

        $this->reserved_keys = array_filter([$ip_key, ...$account_keys]);

        return $user;
    }

    public function refund_attempt($user) {
        // Last word over every other authenticate callback, so no password or app password gets past the block.
        if ($this->account_blocked) {
            $user = new WP_Error('incorrect_password');
        }

        if ($this->reserved_keys && $user instanceof WP_User) {
            global $wpdb;

            $placeholders = implode(',', array_fill(0, count($this->reserved_keys), '%s'));

            $wpdb->query($wpdb->prepare("UPDATE $this->attempts_table SET attempts = attempts - 1 WHERE bucket_key IN ($placeholders) AND attempts > 0", ...$this->reserved_keys));
        }

        $this->reserved_keys = [];

        return $user;
    }

    // Proving the account's email by resetting the password unlocks the account and trusts the resetting browser,
    // so an ongoing attack can't lock the owner out again before they log in.
    public function trust_after_password_reset($user): void {
        global $wpdb;

        if ($user instanceof WP_User) {
            $wpdb->delete($this->attempts_table, ['bucket_key' => $this->account_key($user->user_login)], ['%s']);
            $this->issue_device_cookie($user->ID);
        }
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

    public function throttle_password_reset(WP_Error $errors, $user_data): void {
        if (current_user_can('edit_users')) {
            return;
        }

        $key = $this->bucket_key('reset');

        if ($key !== null && $this->hit($key, self::IP_RESET_MAX_REQUESTS, self::IP_RESET_WINDOW_SECONDS) > self::IP_RESET_MAX_REQUESTS) {
            $errors->add('too_many_requests', esc_html__('Too many password reset requests. Please try again later.', 'wp-login-activity'));
        }
        // Per-account cap so resets spread across IPs can't flood one inbox. anti-enumeration.php answers it with the normal confirmation.
        elseif ($user_data instanceof WP_User && $this->hit(md5('reset_account|' . $user_data->ID), self::ACCOUNT_RESET_MAX_REQUESTS, self::ACCOUNT_RESET_WINDOW_SECONDS, false) > self::ACCOUNT_RESET_MAX_REQUESTS) {
            $errors->add('reset_account_throttled', esc_html__('Too many password reset requests. Please try again later.', 'wp-login-activity'));
        }
    }

    // $extend_when_blocked restarts the window on every blocked hit. Off for buckets an attacker could hold shut against the owner.
    private function hit(string $key, int $max, int $window, bool $extend_when_blocked = true): int {
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
            $extend_when_blocked ? $max : $max + 1, // attempts is capped at $max + 1 so this never matches
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
        return md5('account|' . mb_strtolower(trim($username), 'UTF-8'));
    }

    // Email and username of the same account resolve to one user, so they share one bucket.
    // Usernames can look like emails, so the input can also be one account's username and another's email: core
    // then checks the password against both, so both count and no device of either is trusted.
    private function find_users(string $username): array {
        $name = trim($username);
        $users = [];

        foreach ([get_user_by('login', $name), is_email($name) ? get_user_by('email', $name) : false] as $user) {
            if ($user) {
                $users[$user->ID] = $user;
            }
        }

        return array_values($users);
    }

    private function device_cookie_name(WP_User $user): string {
        // Keyed, so the name can't be reversed into the account it belongs to.
        return self::DEVICE_COOKIE_PREFIX . wp_hash('device_cookie|' . $user->ID);
    }

    // The password hash is signed in, so changing the password untrusts every device.
    private function device_signature(WP_User $user, string $nonce, int $expires): string {
        return wp_hash($user->ID . '|' . $nonce . '|' . $expires . '|' . $user->user_pass, 'auth', 'sha256');
    }

    private function issue_device_cookie(int $user_id): void {
        $user = get_userdata($user_id);

        if (!$user || headers_sent()) {
            return;
        }

        $nonce = bin2hex(random_bytes(16));
        $expires = time() + self::DEVICE_COOKIE_SECONDS;

        setcookie($this->device_cookie_name($user), $nonce . '|' . $expires . '|' . $this->device_signature($user, $nonce, $expires), [
            'expires' => $expires,
            'path' => COOKIEPATH,
            'domain' => COOKIE_DOMAIN,
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    // Bucket key of this device for the account, or null if the device has no valid cookie for it.
    private function device_key(WP_User $user): ?string {
        $cookie = $_COOKIE[$this->device_cookie_name($user)] ?? '';
        [$nonce, $expires, $signature] = explode('|', is_string($cookie) ? wp_unslash($cookie) : '', 3) + ['', '', ''];

        if ($nonce === '' || (int)$expires < time() || !hash_equals($this->device_signature($user, $nonce, (int)$expires), $signature)) {
            return null;
        }

        return md5('device|' . $user->ID . '|' . $nonce);
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
