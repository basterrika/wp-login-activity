<?php

defined('ABSPATH') || exit;

// Same error for unknown user and wrong password. wp_signon() covers wp-login.php and WooCommerce /my-account/.
add_filter('authenticate', static function($user) {
    if (is_wp_error($user) && array_intersect($user->get_error_codes(), ['invalid_username', 'invalid_email', 'incorrect_password'])) {
        return new WP_Error('incorrect_password', __('<strong>Error:</strong> The username, email address or password is incorrect.', 'wp-login-activity'));
    }

    return $user;
}, PHP_INT_MAX);

// Same confirmation page for unknown and existing accounts.
// Priority 20 runs after the reset throttle, whose error must still show.
add_action('lostpassword_post', static function(WP_Error $errors, $user_data): void {
    if ($user_data || array_diff($errors->get_error_codes(), ['invalid_email'])) {
        return;
    }

    if (isset($_POST['wc_reset_password']) && function_exists('wc_get_account_endpoint_url')) {
        wp_safe_redirect(add_query_arg('reset-link-sent', 'true', wc_get_account_endpoint_url('lost-password')));
    }
    else {
        wp_safe_redirect(empty($_REQUEST['redirect_to']) ? 'wp-login.php?checkemail=confirm' : wp_unslash($_REQUEST['redirect_to']));
    }

    exit;
}, 20, 2);
