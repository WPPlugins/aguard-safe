=== AGuard Safe ===
Contributors: aguard
Tags: security, file integrity, two-factor, malware, audit log
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.9.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Watches a WordPress site for signs of a break-in and tells the owner by e-mail: changed core files, new administrators, cloaking, PHP in uploads.

== Description ==

AGuard Safe is a monitoring plugin written by people who clean hacked WordPress sites for a living. It does not try to be a firewall. It watches the things that change when a site is compromised and reports them in plain language.

**What it watches**

* WordPress core files, compared with the official checksums.
* System files in the site root: `wp-config.php`, `.htaccess`, `index.php`, drop-ins and must-use plugins.
* The list of administrator accounts, role changes, password resets and application passwords.
* Plugin and theme installs, updates, activation and removal.
* PHP files appearing in the uploads, cache and upgrade folders.
* Cloaking: whether the home page shows Googlebot something different from what a visitor sees.
* Administrator logins, failed login bursts and XML-RPC abuse.
* Changes to critical options such as the site address, the administrator e-mail and open registration.

**What it can do, if you turn it on**

* Ask administrators for a one-time code sent by e-mail after the password.
* Move the login page to an address of your choice.
* Block PHP execution in the uploads folder with an `.htaccess` rule.
* Move a suspicious file to quarantine (`uploads/aguard-safe/quarantine`, closed to direct access). Nothing is deleted and the file can be restored.
* Show who is logged in as an administrator and sign a user out everywhere.
* Read-only file browser and log viewer for investigating an incident. Both are off until an administrator enables them in Settings.

Notifications go to the site administrator's e-mail address. You can change the address in Settings.

== External services ==

The plugin contacts WordPress.org to check file integrity:

* `api.wordpress.org` to download the official checksums of the installed WordPress version. The WordPress version and locale are sent.
* `downloads.wordpress.org` to download the official checksums of installed plugins. The plugin slug and version are sent.

Both services are provided by WordPress.org: [terms](https://wordpress.org/about/tos/), [privacy policy](https://wordpress.org/about/privacy/).

For the cloaking check and the self-tests the plugin requests pages of your own site from your own server. No data is sent to the plugin author or to any other third party.

== Installation ==

1. Install the plugin and activate it.
2. Open AGuard Safe in the admin menu. The first full check starts when you press "Check now".
3. In Settings, confirm the e-mail address for notifications and send a test message.

== Frequently Asked Questions ==

= Does it replace a firewall plugin? =

No. It works alongside one. A firewall tries to stop an attack, AGuard Safe tells you when something on the site has changed anyway.

= Will it slow the site down? =

The hourly check reads a short list of system files and looks for PHP files in the uploads and cache folders. The full check compares all core files and runs every six hours, or when you start it by hand.

= Why are Settings locked? =

Changing the notification address or turning protection off is the first thing an intruder with an administrator session would do. Settings open after you enter a code sent to the notification address.

= Does the plugin send anything to its author? =

No.

= What stays after I delete the plugin? =

Settings, the event log and the file baseline are removed. Two things are left on purpose: the `uploads/aguard-safe` folder with the files you moved to quarantine (and a copy of your previous `.htaccess`), and the rule that blocks PHP in the uploads folder if you turned it on. Remove them by hand if you no longer need them.

= Can I translate the plugin? =

Yes. The plugin is translation-ready and translations are managed on translate.wordpress.org.

= Where is the source code? =

All of it is in the plugin. The JavaScript and CSS files in the `assets` folder are the human-readable sources: nothing is minified or compiled and no build tools are used.

== Changelog ==

= 1.9.3 =
* First release in the WordPress.org plugin directory.
