=== AGuard Safe – Login Security, 2FA, Malware Scan ===
Contributors: aguard
Tags: security, malware scanner, 2fa, login security, activity log
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.10.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Malware scanner, two-factor authentication, file change detection, scan for suspicious and extra files, login and activity monitoring.

== Description ==

https://www.youtube.com/watch?v=-1VoR4xdJZ8

= Security plugin for WordPress: malware scanner, file change detection, login protection =

AGuard Safe is a security plugin for WordPress. It scans the site for malware, compares WordPress and plugin files with the official originals, protects the login with two-factor authentication and brute force protection, records what administrators do, and checks the installed plugins for known vulnerabilities. When something changes, it sends you an e-mail.

The plugin is made by AGuard, a company that cleans up hacked WordPress sites. Most hacked sites are not noticed by their owners: a customer, Google or the hosting company notices first, often weeks later. AGuard Safe closes that gap. It remembers what the site looked like yesterday, compares it with today and reports the difference.

**AGuard Safe includes a malware scanner, file change detection with one-button repair, two-factor authentication, brute force protection, an activity log and a vulnerability check for your plugins.** It is free: there is no account to create and no paid version.

= Malware scanner =

* **Code scan.** Looks through `wp-content` for backdoor and injected-loader patterns.
* **PHP where it should not be.** Finds PHP files in the uploads, cache and upgrade folders.
* **Files that are not WordPress.** Finds extra files in the WordPress core folders that are not part of the official release.
* **Cloaking check.** Loads the home page as a visitor and as Googlebot and compares the two. This finds SEO spam, pharma and casino hacks that are hidden from the owner.
* **Quarantine.** Moves a file out of reach of the site. The plugin then checks that WordPress still loads and puts the file back if it does not.
* **PHP block in uploads.** One switch closes the most common malware route.
* **Runs by itself.** Quick scan every hour, full scan every 6 hours, and a "Check now" button for a manual scan.

= File change detection and repair =

* **Every WordPress core file** is compared with the official checksums from WordPress.org.
* **Plugins from the directory** are compared with their official checksums.
* **Replace with the original.** One button downloads the official file from WordPress.org, accepts it only when the checksum matches and keeps the previous file in quarantine.
* **Show what was changed.** Only the changed lines, next to the original.
* **System files every hour:** `wp-config.php`, `.htaccess`, `index.php`, drop-ins and must-use plugins.
* **Changed in the last 48 hours:** one list of every file that moved.
* **PHP snippets** kept by snippet plugins (WPCode, Code Snippets, Woody Code Snippets, Header Footer Code Manager, Insert PHP Code Snippet, FluentSnippets): a new or changed snippet is reported.
* The baseline is refreshed automatically after a WordPress update, so updates do not raise false alarms.

= Two-factor authentication and login security =

* **Two-factor authentication** for administrators: a one-time code by e-mail after the password. Nothing to install on a phone.
* **Trusted browsers.** The code is not asked again on a remembered device; one button forgets all of them.
* **Brute force protection.** An address is blocked for 30 minutes after the number of failed logins that you set. It sees a notice instead of the login form.
* **Leaked password check**, optional: tells you when an administrator password is on the lists of leaked passwords. The password itself never leaves your server.
* **Custom login URL** instead of `wp-login.php`, with a trial mode where both addresses work, and an option to answer "404" on the old one.
* **Failed login counter** with an alert threshold you set.
* **XML-RPC abuse alert:** 50 or more calls an hour.

= Login and activity monitoring =

* **Every administrator login**, with IP address and browser. A login from a new IP is reported by e-mail.
* **Who is signed in right now**, per device, with a "Sign out everywhere" button.
* **Accounts:** new administrators, role changes, password resets, new application passwords.
* **Plugins and themes:** installs, updates, activations and removals.
* **Site settings:** changes to the site address, administrator e-mail and open registration.
* Everything goes into one feed, grouped by day, in three levels of importance.

= Plugin updates and vulnerabilities =

* **Waiting updates** for the installed plugins in one list.
* **Known vulnerabilities (CVE)**, optional, checked once a day.
* Each finding shows the CVE, the CVSS score, what an attacker needs and the version that fixes it.
* Findings are split into **"Urgent"** and **"Not urgent"**, so you know which ones cannot wait. Urgent ones are reported by e-mail.
* **Closed plugins:** plugins that have been closed on WordPress.org are marked.

= E-mail alerts =

* Sent to the site administrator's address or to an address of your choice.
* Extra recipients who receive incidents only.
* Test e-mail button.
* A limit of 10 messages an hour.

= Locked settings =

* Settings, quarantine restore and the file baseline open only with a code sent to the notification e-mail.
* The one-time first-run button only turns protection on and does not need the code; the change is reported by e-mail.

= Dashboard and incident tools =

* **Security score** from 0 to 100 on the Overview and in a widget on the WordPress dashboard.
* **"What to do" list:** every note leads to the exact file or check, not to a general page.
* **Read-only file viewer** with line numbers; the lines the scan pointed at are marked.
* **Read-only log viewer.**
* Each viewer can be turned off in Settings.

= What it is not =

AGuard Safe is not a firewall. It does not filter traffic and works alongside a firewall, not instead of one. Its job is to make sure that if somebody does get in, you learn about it the same day.

= Your data =

Out of the box the plugin talks only to WordPress.org, to compare your files with the originals. Two optional checks (plugin vulnerabilities and leaked passwords) use our service and stay off until you turn them on. What exactly is sent is listed under "External services" below.

= Support =

Is the site already hacked? We remove malware, find how the attacker got in and close that door: [aguard.lt](https://aguard.lt/en). There is also a [free site check](https://aguard.lt/en/check).

== External services ==

The plugin contacts WordPress.org to check file integrity:

* `api.wordpress.org` to download the official checksums of the installed WordPress version. The WordPress version and locale are sent.
* `downloads.wordpress.org` to download the official checksums of installed plugins. The plugin slug and version are sent.

When an administrator presses "Replace with the original" or "Show what was changed" for a changed file, that one file is downloaded from `core.svn.wordpress.org` (WordPress) or `plugins.svn.wordpress.org` (a plugin). The WordPress or plugin version and the file path are part of the address.

These services are provided by WordPress.org: [terms](https://wordpress.org/about/tos/), [privacy policy](https://wordpress.org/about/privacy/).

The plugin vulnerability check is off until an administrator turns it on: with the "Agree and turn on" button shown on the Overview after installation, or in the Plugins tab. When it is on, the plugin sends one request to `data.aguard.lt`: when the check is turned on, once a day, within about an hour after the list of installed plugins or their versions changes, and when you press "Check now" (after a failed request it tries again at the next hourly check). The request contains the folder names (slugs) and versions of all installed plugins, including premium and private ones. As with any request, the service sees the IP address of your server. The site address is not sent. The answer is the list of known vulnerabilities for those plugins. The service is run by the plugin author, AGuard: [terms](https://aguard.lt/en/terms), [privacy policy](https://aguard.lt/en/privacy). Vulnerability data from WPVulnerability (CC0) and the CISA Known Exploited Vulnerabilities catalogue.

The check of administrator passwords is off until an administrator turns it on (the "Agree and turn on" button on the Overview, or Settings). When it is on, after a correct administrator login the plugin sends the first 5 characters of the SHA-1 hash of the password to `data.aguard.lt`, receives the list of leaked hashes that start with those characters and compares on your server. The password itself, its full hash and the user name are never sent. This happens once per password and at most once a week per administrator. `data.aguard.lt` is run by the plugin author, AGuard ([terms](https://aguard.lt/en/terms), [privacy policy](https://aguard.lt/en/privacy)); it passes those 5 characters, without the address of your server, to Pwned Passwords by Have I Been Pwned ([terms](https://haveibeenpwned.com/TermsOfUse), [privacy policy](https://haveibeenpwned.com/Privacy)) and returns the answer.

The optional footer notice (off by default) only prints a link to the plugin author's site; it loads nothing from it.

For the cloaking check and the self-tests the plugin requests pages of your own site from your own server.

== Installation ==

1. Install the plugin and activate it.
2. Open AGuard Safe in the admin menu. The first full check starts when you press "Check now".
3. In Settings, confirm the e-mail address for notifications and send a test message.

== Frequently Asked Questions ==

= Does it replace a firewall plugin? =

No. It works alongside one. A firewall tries to stop an attack; AGuard Safe tells you when something on the site has changed anyway.

= Can I use it together with another security plugin? =

Yes. It does not block requests and does not rewrite your server rules, apart from one optional rule in the uploads folder. If two plugins both ask for a login code, turn that feature on in one of them only, or signing in becomes a quest.

= My site is already hacked. Will this fix it? =

It will show you what was changed, put original WordPress and plugin files back and move the intruder's files to quarantine. That is often most of the work. A hacked site, however, usually has more than one door open: a stolen password, an old plugin, a second backdoor. If the problem comes back, the door is still open. That is the part we do by hand: [aguard.lt](https://aguard.lt/en).

= Will it slow the site down? =

The hourly check reads a short list of system files and looks for PHP files in the uploads and cache folders. The full check compares all core files and runs every six hours, or when you start it by hand. Visitors do not wait for any of it.

= Will it e-mail me every five minutes? =

No. There is a limit of 10 messages an hour, updates of WordPress do not raise alarms, and you choose who receives what. We want you to read the one e-mail that matters.

= Can I lock myself out with the brute force protection? =

It is hard to do. An address that an administrator signed in from during the last 30 days is never blocked, the block lasts 30 minutes, and the password reset keeps working. If you manage it anyway, add `define('AGUARD_SAFE_LOCKOUT_OFF', true);` to `wp-config.php` and the block is off.

= Why are Settings locked? =

Changing the notification address or turning protection off is the first thing an intruder with an administrator session would do. Settings open after you enter a code sent to the notification address.

= I lost access to the notification mailbox. Now what? =

Prove that the site is yours the old way: through the files. Add `define('AGUARD_SAFE_MASTER', true);` to `wp-config.php`, open Settings without the code, change the address and remove the line again.

= Is the two-factor code sent by e-mail safe enough? =

It stops the most common case: a password that leaked or was guessed. It needs nothing installed on a phone, so it actually gets turned on. If the administrator's mailbox itself is compromised, no plugin on the site will save the day; protect the mailbox first.

= What is sent to your server? =

Nothing, until you turn on one of the two optional checks. The vulnerability check sends the folder names and versions of your plugins. The password check sends the first 5 characters of a hash, never the password. The site address is not sent. Details are under "External services".

= Is there a paid version? =

No. Everything the plugin does is in this free version. We earn our living by cleaning up hacked sites, and we would honestly prefer that you never need us.

= What stays after I delete the plugin? =

Settings, the event log and the file baseline are removed. Two things are left on purpose: the `uploads/aguard-safe` folder with the files you moved to quarantine (and a copy of your previous `.htaccess`), and the rule that blocks PHP in the uploads folder if you turned it on. Remove them by hand if you no longer need them.

= Can I translate the plugin? =

Yes. The plugin is translation-ready and translations are managed on translate.wordpress.org.

= Where is the source code? =

All of it is in the plugin. The JavaScript and CSS files in the `assets` folder are the human-readable sources: nothing is minified or compiled and no build tools are used.

== Screenshots ==

1. Overview: the security score, what needs your attention and where it leads.
2. Scan: every check has its own card; the ring shows how many need attention.
3. A changed plugin file: "Replace with the original" and the changed lines next to the original.
4. Activity: logins, accounts, plugins and settings in one feed, in three levels of importance.
5. Plugins: waiting updates and known vulnerabilities, split into "Urgent" and "Not urgent".
6. Settings: notifications, brute force protection, login address and two-factor authentication.
7. The widget on the WordPress dashboard.
8. The login code e-mail.
9. What an address sees after too many failed logins.

== Credits ==

The plugin name in the header is set in a typeface by TypeTogether (Veronika Burian, José Scaglione), SIL Open Font License 1.1. The font file `assets/wordmark.woff` is a renamed subset that contains only the letters of the name.

== Changelog ==

= 1.10.1 =
* Fewer e-mails. What an administrator does from an address they have signed in from during the last 30 days goes to the log only: settings, quarantine, allowlist, installing, activating, deactivating and deleting plugins, theme and profile changes. From an unknown address the e-mail is still sent.
* No e-mail for a blocked address, a password reset request or a WordPress update; password guessing and XML-RPC abuse are reported once a day.
* Remote access tools that were already on the site at the first check are not reported by e-mail, only the ones that appear later. A file manager plugin is no longer treated as one.
* Notification e-mails have the same look as the login code e-mail, with a plain-text copy inside.
* In e-mails "anonymous", "cron" and "wp-cli" are replaced with plain words.
* Suggested text for the site's privacy policy (Settings > Privacy > Policy Guide), following the checks that are turned on.
* The "viewer is turned off" notice is a link to the setting.
* More space in the first-run window.

= 1.10.0 =
* New "Plugins" tab: waiting updates, known vulnerabilities of the installed plugins and plugins closed on WordPress.org. The vulnerability check is optional and off by default.
* New look of all screens: one layout everywhere, sections with named screens, events as a feed by day.
* First-run step on the Overview: one button turns on the PHP block in the uploads folder and the vulnerability check.
* Scan: every single check has its own card; new card "Remote access tools".
* File viewer: line numbers, the lines the code scan pointed at are marked, a file name in the findings opens the file.
* Brute force protection: an address is blocked for 30 minutes after 10 failed logins (the number can be changed).
* Optional check of administrator passwords against lists of leaked passwords.
* Login code and unlock code e-mails have a new look.
* "Show what was changed": the changed lines of a file next to its original.
* New widget on the WordPress dashboard: the score, what to do and the last events.
* Every note on the Overview leads to the exact file or check; an unknown file can be added to the allowlist from the file screen.
* PHP snippets are watched in six snippet plugins, not only in Code Snippets.
* A changed file of WordPress or of a plugin from the directory can be replaced with the original: downloaded from WordPress.org, accepted only when the checksum matches, the previous file is kept in quarantine.
* Quarantine: the screen tells what the file belongs to; after the move the plugin checks that WordPress still loads (a request that a page cache cannot answer) and puts the file back if the site answers with an error.
* On new installs the read-only file and log viewers are on; on updated sites they stay as they were.
* New optional setting: a one-line notice with a link in the footer of the site. Off by default.

= 1.9.3 =
* First release in the WordPress.org plugin directory.
