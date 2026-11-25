<?php
/**
 * Removes the plugin's settings and logs when the plugin is deleted.
 *
 * Quarantined files and the PHP block rules in .htaccess are left in place on purpose:
 * removing them silently would put suspicious files back within reach.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) exit;

wp_clear_scheduled_hook('aguard_safe_scan');

$aguard_safe_options = [
    'aguard_safe', 'aguard_safe_events', 'aguard_safe_baseline', 'aguard_safe_quarantine',
    'aguard_safe_alert_sigs', 'aguard_safe_cloak_state', 'aguard_safe_core_sig', 'aguard_safe_fail_hist',
    'aguard_safe_known_logins', 'aguard_safe_last_scan', 'aguard_safe_remote_sig', 'aguard_safe_remote_known', 'aguard_safe_mail_ok', 'aguard_safe_snippets',
    'aguard_safe_uploads_sig', 'aguard_safe_vulns', 'aguard_safe_lockouts', 'aguard_safe_snippet_src',
];
foreach ($aguard_safe_options as $aguard_safe_option) {
    delete_option($aguard_safe_option);
}

delete_metadata('user', 0, 'aguard_safe_trusted', '', true);
delete_metadata('user', 0, 'aguard_safe_pw', '', true);
delete_metadata('user', 0, 'aguard_safe_review', '', true);
