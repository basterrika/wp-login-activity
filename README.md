# Login Activity

Just a WordPress plugin that logs authentication attempts and provides a basic admin report under
`Tools > Login activity`.

## Current functionality

- Logs successful and failed login attempts.
- Stores:
  - sanitized username (`login`)
  - request URL used for login (`login_url`)
  - IP address (IPv4/IPv6, stored as binary)
  - status (`success` or `error`)
  - timestamp (`log_date`)
- Adds a lockout layer before authentication:
  - `10` failed attempts
  - in `30` seconds
  - lockout for `300` seconds (5 minutes)
- Admin listing screen:
  - search by username
  - filter by status
  - filter by month/year

## Installation

1. Upload the plugin folder to `/wp-content/plugins/` or install it from a zip in `Plugins > Add New`.
2. Activate `Login Activity`.
3. Open `Tools > Login activity` to view logs.

## Multisite behavior

- On network activation, the log table is created for all existing sites.
- When a new site is created in a network, its log table is also created if the plugin is network-active.

## Data storage

The plugin creates a table named:

- Single site: `{wp_prefix}login_activity`
- Multisite: `{blog_prefix}login_activity` per site

## Support

Open issues or feature requests at [GitHub](https://github.com/basterrika/wp-login-activity).
