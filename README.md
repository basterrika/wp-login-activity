# Login Activity

A small WordPress plugin that does two things:

1. **Records every login attempt** (who, from where, when, and whether it worked).
2. **Stops password guessing** by blocking anyone who fails too many times.

You can see the records in `Tools > Login activity`.

## What gets recorded

Every finished login attempt is saved with:

| Field      | Example            | Notes                                            |
|------------|--------------------|--------------------------------------------------|
| `login`    | `admin`            | The username that was typed (lowercased)         |
| `ip`       | `203.0.113.45`     | IPv4 or IPv6, full address                       |
| `status`   | success / error    | Whether the password was correct                 |
| `log_date` | `2026-10-20 09:15` | Stored in UTC; displayed in the site's time zone |

Attempts that are blocked are not recorded. Successful XML-RPC logins are not recorded either, because WordPress
only fires its login hook for form logins; failed XML-RPC logins are.

## How the protection works

Think of it as **counters**. Every login attempt adds `+1`. If the password is correct, that `+1` is
taken back, so **only failures count**. When a counter goes over its limit, the login page shows *"Login blocked, try
again later"* (HTTP `429`), even if the password is correct.

There are four counters:

| Counter            | Counts attempts from...    | Limit                   | Stops                                |
|--------------------|----------------------------|-------------------------|--------------------------------------|
| **Per IP**         | one computer or network    | 10 per 15 minutes       | one attacker guessing from one place |
| **Per account**    | anywhere, for one username | 20 per hour             | many computers attacking one user    |
| **Per device**     | one trusted device         | 10 per 15 minutes       | guessing with a stolen device cookie |
| **Password reset** | one computer or network    | 5 reset emails per hour | flooding the reset form              |

**Examples**

- You mistype your password 10 times. The 11th try is blocked for 15 minutes.
- 1.000 hacked computers each try once to log in as `admin`. After 20 tries, `admin` is blocked on every device that
  hasn't logged in as `admin` before, for an hour.
- A blocked attacker who keeps trying keeps the block running. The timer restarts on every try.
- The window starts with the first failure: 10 failures within 15 minutes of it trigger the block. Once
  the window ends with no block, the counter starts again from zero.

**Good to know**

- Username and email are the same account: `admin` and `admin@example.com` share one counter.
  Upper/lower case doesn't matter.
- Usernames that don't exist are counted too, so attackers can't tell real accounts from fake ones.
- **Trusted devices keep working during an attack.** After a successful login, the browser gets a signed cookie
  for that account (valid 1 year). Logins from that browser only use their own *per device* counter instead of the *per
  IP* and *per account* ones, so neither an attack on your account nor failures from others on your network
  block you there. Changing the password untrusts every device until it logs in again.
- **On a new device, you are blocked too while someone attacks your account**, even with the right password.
  Resetting the password through the "Lost your password?" email clears the account's counter and trusts the browser
  you reset from. To unlock everyone immediately, empty the `{base_prefix}login_attempts` table.
- Admins sending a password reset from the Users screen are never limited.

**What counts as "one computer or network"**

- **IPv4** (`203.0.113.45`): each address is its own counter.
- **IPv6** (`2001:db8:1234:5678:…`): only the first 4 groups count. A single home connection can
  switch between billions of addresses that share those first 4 groups (a "/64"), so they are
  treated as one.

**Where it applies**

| Login through            | Limited | Recorded |
|--------------------------|---------|----------|
| `wp-login.php`           | yes     | yes      |
| WooCommerce login        | yes     | yes      |
| XML-RPC                  | yes     | failures |
| REST API (app passwords) | no      | no       |

App passwords are 24 random characters, so guessing them isn't realistic.

> **Behind Cloudflare, a load balancer or another proxy?** The server must pass the visitor's real IP
> (e.g. nginx `real_ip`). Otherwise every visitor looks like the same IP, and 10 failures from anyone
> block everyone.

## The admin screen

`Tools > Login activity` (administrators only):

- Tabs for **All**, **Successful** and **Failed** attempts, with counts.
- Search by username.
- Filter by month in the site's time zone.
- Choose how many rows per page in *Screen Options* (default 100).

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`, or install the zip from `Plugins > Add New`.
2. Activate **Login Activity**. This creates the database tables.
3. Open `Tools > Login activity`.

## Database tables

| Table                         | Holds                                                  |
|-------------------------------|--------------------------------------------------------|
| `{prefix}login_activity`      | The login records shown in the admin screen            |
| `{base_prefix}login_attempts` | The counters. Old entries are cleaned up automatically |

**Multisite:** every site has its own log table, and all sites share one counters table, because users are shared
across the network. An account gets 20 failures per hour on the whole network, not on each site, and a password reset
unlocks it everywhere. Network activation creates the tables, and new sites get their log table automatically while
the plugin is network-active.

## Support

Open issues or feature requests on [GitHub](https://github.com/basterrika/wp-login-activity).
