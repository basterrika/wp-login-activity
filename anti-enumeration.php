<?php

defined('ABSPATH') || exit;

// Same error for unknown user and wrong password. wp_signon() covers wp-login.php and WooCommerce /my-account/.
add_filter('authenticate', static function($user) {
    if (is_wp_error($user) && array_intersect($user->get_error_codes(), ['invalid_username', 'invalid_email', 'incorrect_password'])) {
        return new WP_Error('incorrect_password', __('<strong>Error:</strong> The username, email address or password is incorrect.', 'wp-login-activity'));
    }

    return $user;
}, PHP_INT_MAX);

// Same confirmation page for unknown accounts and per-account throttled resets.
// Priority 20 runs after the reset throttle, whose per-IP error must still show.
add_action('lostpassword_post', static function(WP_Error $errors, $user_data): void {
    if ($user_data ? $errors->get_error_codes() !== ['reset_account_throttled'] : array_diff($errors->get_error_codes(), ['invalid_email'])) {
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

// ?author=N redirects to /author/{nicename}/. 404 both for visitors.
// Priority 1 runs before redirect_canonical().
add_action('template_redirect', static function(): void {
    if (is_user_logged_in() || (!isset($_GET['author']) && !is_author())) {
        return;
    }

    global $wp_query;
    $wp_query->set_404();
    // set_404() keeps is_feed, and template-loader.php would still render the author's feed.
    $wp_query->is_feed = false;
    // WP::send_headers() already sent the feed Content-Type.
    header('Content-Type: ' . get_option('html_type') . '; charset=' . get_option('blog_charset'));
    status_header(404);
    nocache_headers();
}, 1);

// /wp/v2/users lists author slugs. The block editor still gets it when logged in.
add_filter('rest_endpoints', static function(array $endpoints): array {
    if (!is_user_logged_in()) {
        unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }

    return $endpoints;
});

// /wp-sitemap-users-1.xml lists author archives.
add_filter('wp_sitemaps_add_provider', static function($provider, string $name) {
    return $name === 'users' ? false : $provider;
}, 10, 2);

// oEmbed responses expose the author name and archive URL.
add_filter('oembed_response_data', static function(array $data): array {
    unset($data['author_name'], $data['author_url']);

    return $data;
});
