=== Security by Xyo ===
Contributors: mrxyo
Tags: security, hardening, rest api, headers, file integrity
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 3.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Clean and harden WordPress: trim <head> cruft, send hardened headers, lock the REST API, and watch file integrity — each feature individually toggleable.

== Description ==

Security by Xyo bundles a set of independent hardening features behind a single
settings screen (Settings > Security by Xyo). Each one is a simple on/off toggle,
so you only run what you need.

Features:

* **Clean <head> & disable XML-RPC** — remove generator, RSD, WLW manifest,
  feeds, shortlink and asset version strings; disable XML-RPC.
* **Lock the REST API** — restrict the REST API to authenticated users, with an
  admin-configurable whitelist of public route prefixes (oEmbed stays open).
* **Security headers** — send hardened HTTP headers (X-Frame-Options,
  Referrer-Policy, Permissions-Policy, …) and mask X-Powered-By.
* **Generic login errors** — hide whether the username or the password was wrong
  on a failed login (anti-enumeration).
* **File integrity monitoring** — once a day, hash every executable file across
  WordPress core, plugins, mu-plugins and the active theme (SHA-256) and alert
  on any added, modified or removed file via e-mail, a log file and a dismissible
  admin notice. A "Scan now" button is available on the settings screen.

The file integrity scanner derives its scan roots from WordPress itself
(`ABSPATH`, `WP_CONTENT_DIR`, `WPMU_PLUGIN_DIR`, `get_theme_root()`), so it works
unchanged on a classic single-folder install and on split layouts such as
Bedrock. The uploads directory is always excluded.

== Privacy ==

The plugin does not collect or transmit any visitor data.

* File integrity monitoring stores a baseline manifest and a log file in
  `wp-content/uploads/xyo-security/` (protected from direct web access) and, when
  a change is detected, sends a report e-mail to the site admin address. Both
  only contain file paths and hashes from your own installation.
* No data is sent to any third party.

== Installation ==

1. Upload the plugin folder to `wp-content/plugins/` and activate it.
2. Go to Settings > Security by Xyo and toggle the features you want.
3. For file integrity monitoring, click "Scan now" to record the initial
   baseline, or wait for the first daily run.

== Frequently Asked Questions ==

= Will locking the REST API break my site? =

It can, if your theme or other plugins rely on anonymous REST access. Review the
public-route whitelist on the settings screen before enabling it.

= The daily integrity scan never runs. =

If `DISABLE_WP_CRON` is set, WordPress will not fire the scheduled job on its
own. Make sure a real system cron triggers `wp-cron.php`, or use the "Scan now"
button. The settings screen warns you when this is the case.

== Changelog ==

= 3.0.0 =
* Per-feature toggle settings screen (WordPress Settings API).
* REST API lock with an admin-configurable public-route whitelist.
* New file integrity monitoring: daily SHA-256 scan with e-mail, log and admin
  notice alerts, "Scan now" button and DISABLE_WP_CRON warning.
* Fixed early textdomain loading (WordPress 6.7 notice).

== Upgrade Notice ==

= 3.0.0 =
All features default to on. Review Settings > Security by Xyo after upgrading —
locking the REST API may affect anonymous API access.
