<?php
/**
 * Plugin Name: AGuard Safe – Login Security, 2FA, Malware Scan
 * Description: Watches the site for signs of a break-in and reports them by e-mail: changed core files, new administrators, cloaking, PHP in uploads. Optional e-mail login confirmation, custom login address and file quarantine.
 * Version:     1.10.0
 * Author:      AGuard
 * Author URI:  https://aguard.lt
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Text Domain: aguard-safe
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) exit;

final class AGuard_Safe {

    const VERSION      = '1.10.0';
    const OPT          = 'aguard_safe';
    const OPT_EVENTS   = 'aguard_safe_events';
    const OPT_BASELINE = 'aguard_safe_baseline';
    const CRON         = 'aguard_safe_scan';
    const MAX_EVENTS   = 400;
    const OPT_Q        = 'aguard_safe_quarantine';
    const OPT_VULNS    = 'aguard_safe_vulns';
    const FEED_URL     = 'https://data.aguard.lt/v1/check';
    const HT_BEGIN     = '# BEGIN AGuard Safe';
    const HT_END       = '# END AGuard Safe';

    private static $opts = null;
    private static $login_slug = '';

    /* ------------------------------------------------------------ bootstrap */

    public static function init() {
        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
        register_deactivation_hook(__FILE__, [__CLASS__, 'deactivate']);

        // users
        add_action('user_register',   [__CLASS__, 'on_user_register'], 10, 1);
        add_action('set_user_role',   [__CLASS__, 'on_set_user_role'], 10, 3);
        add_action('add_user_role',   [__CLASS__, 'on_add_user_role'], 10, 2);
        add_action('deleted_user',    [__CLASS__, 'on_deleted_user'], 10, 1);
        add_action('retrieve_password', [__CLASS__, 'on_retrieve_password'], 10, 1);
        add_action('after_password_reset', [__CLASS__, 'on_password_reset'], 10, 1);
        add_action('profile_update',  [__CLASS__, 'on_profile_update'], 10, 2);

        // plugins / themes / core
        add_action('activated_plugin',   [__CLASS__, 'on_plugin_activated'], 10, 1);
        add_action('deactivated_plugin', [__CLASS__, 'on_plugin_deactivated'], 10, 1);
        add_action('deleted_plugin',     [__CLASS__, 'on_plugin_deleted'], 10, 2);
        add_action('upgrader_process_complete', [__CLASS__, 'on_upgrader'], 10, 2);
        add_action('_core_updated_successfully', [__CLASS__, 'on_core_updated'], 10, 1); // ir automatiniai branduolio atnaujinimai
        add_action('switch_theme',       [__CLASS__, 'on_switch_theme'], 10, 1);

        // logins / attacks
        add_action('wp_login',        [__CLASS__, 'on_login'], 10, 2);
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed'], 10, 1);
        add_filter('authenticate', [__CLASS__, 'pw_check'], 90, 3);
        add_filter('authenticate', [__CLASS__, 'lockout_authenticate'], 99, 3);
        add_action('login_init', [__CLASS__, 'lockout_login_page'], 1);
        add_action('xmlrpc_call',     [__CLASS__, 'on_xmlrpc'], 10, 1);
        add_action('application_password_did_save', [__CLASS__, 'on_app_password'], 10, 2);
        // two-factor by e-mail for administrators (see twofa_*)
        add_filter('authenticate', [__CLASS__, 'twofa_authenticate'], 100, 3);
        add_action('login_form_aguard2fa', [__CLASS__, 'twofa_page']);
        add_action('after_password_reset', function ($u) { self::twofa_revoke($u instanceof WP_User ? $u->ID : (int) $u); }, 20, 1);
        add_action('wp_set_password', function ($pw, $uid) { self::twofa_revoke((int) $uid); }, 20, 2);

        // critical options
        add_action('updated_option', [__CLASS__, 'on_updated_option'], 10, 3);

        // file edits through wp-admin editors
        add_action('wp_ajax_edit-theme-plugin-file', [__CLASS__, 'on_editor_save'], 1);
        add_action('wp_ajax_aguard_safe_scan_step', [__CLASS__, 'ajax_scan_step']);

        // cron
        add_action(self::CRON, [__CLASS__, 'cron_scan']);
        add_filter('cron_schedules', function ($s) {
            if (!isset($s['aguard_hourly'])) $s['aguard_hourly'] = ['interval' => HOUR_IN_SECONDS, 'display' => 'AGuard Safe hourly'];
            return $s;
        });
        if (!wp_next_scheduled(self::CRON)) wp_schedule_event(time() + 300, 'aguard_hourly', self::CRON);

        // admin UI
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'admin_assets']);
        add_action('wp_dashboard_setup', [__CLASS__, 'dashboard_widget_register'], 999);
        // Fires only on this plugin's own admin page.
        add_action('wp_ajax_nopriv_aguard_safe_ping', [__CLASS__, 'probe_ping']);
        add_action('wp_ajax_aguard_safe_ping', [__CLASS__, 'probe_ping']);
        add_action('send_headers', [__CLASS__, 'probe_header']);
        add_action('load-toplevel_page_aguard-safe', [__CLASS__, 'handle_download']);
        add_action('load-toplevel_page_aguard-safe', [__CLASS__, 'handle_json']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) { array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=aguard-safe')) . '">' . __('Settings', 'aguard-safe') . '</a>'); return $links; });
        self::login_boot();
        // Public footer notice: only when the site owner has switched it on (off by default).
        if (!empty(self::opts()['credit'])) {
            add_action('wp_enqueue_scripts', [__CLASS__, 'credit_assets']);
            add_action('wp_footer', [__CLASS__, 'credit'], 99);
        }
        if (!empty(self::opts()['lockdown'])) {
            add_filter('file_mod_allowed', '__return_false', 99);
            add_filter('pre_option_users_can_register', '__return_zero', 99);
            add_action('admin_notices', [__CLASS__, 'lockdown_notice']);
            add_action('network_admin_notices', [__CLASS__, 'lockdown_notice']);
        }
    }

    public static function credit_html() {
        $url = strpos((string) get_locale(), 'lt') === 0 ? 'https://aguard.lt/' : 'https://aguard.lt/en';
        /* translators: %s: the plugin name "AGuard Safe" as a link to the plugin author's site */
        return sprintf(esc_html__('This site is watched by %s', 'aguard-safe'), '<a href="' . esc_url($url) . '">AGuard Safe</a>');
    }

    public static function credit_assets() {
        wp_enqueue_style('aguard-safe-credit', plugin_dir_url(__FILE__) . 'assets/credit.css', [], self::VERSION);
    }

    public static function credit() {
        echo '<p class="aguard-safe-credit">' . wp_kses(self::credit_html(), ['a' => ['href' => true]]) . '</p>';
    }

    /* ---------- Plugins: updates and known vulnerabilities ---------- */

    /** Installed plugins: slug => [file, name, version, active, update]. */
    public static function installed_plugins() {
        if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $up = get_site_transient('update_plugins'); $out = [];
        foreach (get_plugins() as $file => $p) {
            $slug = dirname($file); if ($slug === '.') $slug = basename($file, '.php');
            $slug = strtolower($slug);
            if (!preg_match('/^[a-z0-9][a-z0-9._-]{0,190}$/', $slug)) continue;
            $new = (is_object($up) && isset($up->response[$file]) && is_object($up->response[$file]) && !empty($up->response[$file]->new_version)) ? (string) $up->response[$file]->new_version : '';
            $out[$slug] = ['file' => $file, 'name' => (string) ($p['Name'] ?? $slug), 'version' => (string) ($p['Version'] ?? ''), 'active' => is_plugin_active($file) || is_plugin_active_for_network($file), 'update' => $new];
        }
        return $out;
    }

    /** The stored answer of the last check; anything of the wrong shape is dropped. */
    public static function vuln_data() {
        $d = get_option(self::OPT_VULNS, []); if (!is_array($d)) return [];
        $plugins = [];
        foreach ((isset($d['plugins']) && is_array($d['plugins'])) ? $d['plugins'] : [] as $slug => $row) {
            if (!is_array($row) || !isset($row['status'], $row['version']) || !is_scalar($row['status']) || !is_scalar($row['version'])) continue;
            $vs = [];
            foreach ((isset($row['vulns']) && is_array($row['vulns'])) ? $row['vulns'] : [] as $v) {
                if (!is_array($v)) continue;
                $x = ['cvss' => (isset($v['cvss']) && is_numeric($v['cvss'])) ? (float) $v['cvss'] : null, 'epss' => (isset($v['epss']) && is_numeric($v['epss'])) ? (float) $v['epss'] : null];
                foreach (['urgent', 'kev', 'unfixed'] as $k) $x[$k] = empty($v[$k]) ? 0 : 1;
                foreach (['cve', 'needs', 'fixed_in', 'fixed_after', 'title', 'url'] as $k) $x[$k] = (isset($v[$k]) && is_scalar($v[$k])) ? (string) $v[$k] : '';
                $vs[] = $x;
            }
            $plugins[(string) $slug] = ['status' => (string) $row['status'], 'version' => (string) $row['version'], 'closed' => empty($row['closed']) ? 0 : 1, 'closed_date' => (isset($row['closed_date']) && is_scalar($row['closed_date'])) ? (string) $row['closed_date'] : '', 'vulns' => $vs];
        }
        return ['t' => (int) ($d['t'] ?? 0), 'tried' => (int) ($d['tried'] ?? 0), 'sig' => (isset($d['sig']) && is_string($d['sig'])) ? $d['sig'] : '', 'at' => (int) ($d['at'] ?? 0), 'plugins' => $plugins, 'alerted' => array_values(array_filter((isset($d['alerted']) && is_array($d['alerted'])) ? $d['alerted'] : [], 'is_string')), 'error' => (isset($d['error']) && is_scalar($d['error'])) ? (string) $d['error'] : ''];
    }

    /** Link to the description of a vulnerability: only the known reference sites, otherwise the CVE record. */
    private static function vuln_link($url, $cve) {
        $host = strtolower((string) wp_parse_url((string) $url, PHP_URL_HOST));
        if (strpos((string) $url, 'https://') === 0 && in_array($host, ['www.wordfence.com', 'wordfence.com', 'patchstack.com', 'wpscan.com', 'www.cve.org', 'nvd.nist.gov', 'www.wpvulnerability.com', 'www.wpvulnerability.net'], true)) return esc_url_raw((string) $url, ['https']);
        return $cve ? 'https://www.cve.org/CVERecord?id=' . $cve : '';
    }

    /**
     * Asks data.aguard.lt which of the installed plugins have known vulnerabilities.
     * Runs only after an administrator has turned the check on in the Plugins tab.
     * Sent: the plugin slugs and their versions, with the plugin's own User-Agent (no site address).
     */
    public static function vuln_refresh($force = false) {
        if (empty(self::opts()['vuln_check'])) return null;
        $list = []; foreach (self::installed_plugins() as $slug => $p) $list[$slug] = $p['version'];
        if (!$list) return null;
        ksort($list); $sig = md5((string) wp_json_encode($list));
        $d = self::vuln_data(); $now = time();
        if (!$force && $now - (int) ($d['tried'] ?? 0) < 50 * MINUTE_IN_SECONDS) return $d;
        if (!$force && ($d['sig'] ?? '') === $sig && $now - (int) ($d['t'] ?? 0) < 20 * HOUR_IN_SECONDS) return $d;
        $d['tried'] = $now;
        $r = wp_remote_post(self::FEED_URL, ['timeout' => 15, 'redirection' => 0, 'limit_response_size' => 512 * KB_IN_BYTES, 'user-agent' => 'AGuard Safe/' . self::VERSION, 'headers' => ['Content-Type' => 'application/json'], 'body' => wp_json_encode(['plugins' => $list])]);
        $code = is_wp_error($r) ? 0 : (int) wp_remote_retrieve_response_code($r);
        $j = $code === 200 ? json_decode((string) wp_remote_retrieve_body($r), true) : null;
        if (!is_array($j) || !isset($j['plugins']) || !is_array($j['plugins'])) {
            $d['error'] = is_wp_error($r) ? $r->get_error_message() : ($code === 200 ? __('the answer could not be read', 'aguard-safe') : 'HTTP ' . $code);
            update_option(self::OPT_VULNS, $d, false);
            return $d;
        }
        // The answer is treated as untrusted text: every field is checked and cut before it is stored.
        $str = function ($x, $max) { return is_scalar($x) ? substr((string) $x, 0, $max) : ''; };
        $plugins = [];
        foreach ($j['plugins'] as $slug => $row) {
            $slug = (string) $slug; // json_decode turns an all-digit key into a number
            if (!isset($list[$slug]) || !is_array($row)) continue;
            $vs = [];
            foreach (array_slice((isset($row['vulns']) && is_array($row['vulns'])) ? $row['vulns'] : [], 0, 25) as $v) {
                if (!is_array($v)) continue;
                $cve = $str($v['cve'] ?? '', 30); if (!preg_match('/^CVE-\d{4}-\d{3,8}$/', $cve)) $cve = '';
                $ver = function ($k) use ($v, $str) { return (string) preg_replace('/[^0-9A-Za-z.+-]/', '', $str($v[$k] ?? '', 30)); };
                $vs[] = [
                    'cve' => $cve,
                    'cvss' => (isset($v['cvss']) && is_numeric($v['cvss'])) ? round(min(10, max(0, (float) $v['cvss'])), 1) : null,
                    'epss' => (isset($v['epss']) && is_numeric($v['epss'])) ? round(min(1, max(0, (float) $v['epss'])), 3) : null,
                    'urgent' => empty($v['urgent']) ? 0 : 1,
                    'kev' => empty($v['kev']) ? 0 : 1,
                    'unfixed' => empty($v['unfixed']) ? 0 : 1,
                    'needs' => (string) preg_replace('/[^lhuca]/', '', $str($v['needs'] ?? '', 10)),
                    'fixed_in' => $ver('fixed_in'),
                    'fixed_after' => $ver('fixed_after'),
                    'title' => sanitize_text_field(mb_substr($str($v['title'] ?? '', 800), 0, 160)),
                    'url' => self::vuln_link($str($v['url'] ?? '', 300), $cve),
                ];
            }
            $st = $str($row['status'] ?? '', 20); if (!in_array($st, ['vulnerable', 'ok', 'none', 'pending'], true)) $st = 'none';
            if ($st === 'vulnerable' && !$vs) $st = 'ok';
            $plugins[$slug] = ['status' => $st, 'version' => $list[$slug], 'closed' => empty($row['closed']) ? 0 : 1, 'closed_date' => (string) preg_replace('/[^0-9-]/', '', $str($row['closed_date'] ?? '', 10)), 'vulns' => $vs];
        }
        // One e-mail about urgent findings that have not been reported yet.
        // Reported findings are remembered while that plugin version stays installed, also when an answer comes back empty for a while.
        $seen = array_values(array_filter((array) ($d['alerted'] ?? []), function ($k) use ($list) { $p = explode('|', (string) $k, 3); return count($p) === 3 && isset($list[$p[0]]) && (string) $list[$p[0]] === $p[1]; }));
        $new = []; $fresh = [];
        foreach ($plugins as $slug => $row) {
            foreach ($row['vulns'] as $v) {
                if (!$v['urgent']) continue;
                $k = $slug . '|' . $row['version'] . '|' . ($v['cve'] ?: md5($v['title']));
                if (!in_array($k, $seen, true)) { $new[$slug][] = $v; $fresh[] = $k; }
            }
        }
        $d = ['t' => $now, 'tried' => $now, 'sig' => $sig, 'at' => (int) ($j['at'] ?? 0), 'plugins' => $plugins, 'alerted' => $seen, 'error' => ''];
        if ($new) {
            $names = self::installed_plugins(); $info = [];
            foreach ($new as $slug => $vs) {
                $parts = [];
                foreach (array_slice($vs, 0, 5) as $v) {
                    /* translators: %s: plugin version number */
                    $parts[] = ($v['cve'] ?: $v['title']) . ($v['fixed_in'] ? ' (' . sprintf(__('fixed in %s', 'aguard-safe'), $v['fixed_in']) . ')' : '');
                }
                $info[($names[$slug]['name'] ?? $slug) . ' ' . ($names[$slug]['version'] ?? '')] = implode(', ', $parts);
            }
            sort($fresh);
            $e = self::event('vuln', __('Plugins with a vulnerability that needs an urgent update:', 'aguard-safe') . ' ' . count($new), $info, true, 'vuln_' . md5(implode(',', $fresh)), DAY_IN_SECONDS);
            // Only the hourly e-mail limit makes the next check report the finding again.
            if (empty($e['data']['_note'])) $d['alerted'] = array_slice(array_merge($seen, $fresh), -500);
        }
        update_option(self::OPT_VULNS, $d, false);
        return $d;
    }

    /** Installed plugins joined with the last answer of the vulnerability check, worst first. */
    public static function plugin_rows() {
        $d = self::vuln_data(); $on = !empty(self::opts()['vuln_check']); $rows = [];
        foreach (self::installed_plugins() as $slug => $p) {
            $v = $d['plugins'][$slug] ?? null;
            // An answer about another version of the plugin is out of date: wait for the next check.
            if (!$on) $state = 'off'; elseif (!is_array($v) || (string) $v['version'] !== (string) $p['version']) $state = 'wait'; else $state = $v['status'];
            $vs = ($state === 'vulnerable') ? $v['vulns'] : [];
            $urgent = 0; foreach ($vs as $x) $urgent += $x['urgent'];
            $closed = (is_array($v) && $on) ? (int) $v['closed'] : 0;
            $rank = $urgent ? 0 : ($vs ? 1 : ($closed ? 2 : ($p['update'] ? 3 : 4)));
            $rows[] = ['slug' => $slug, 'name' => $p['name'], 'version' => $p['version'], 'active' => $p['active'], 'update' => $p['update'], 'state' => $state, 'vulns' => $vs, 'urgent' => $urgent, 'closed' => $closed, 'closed_date' => $closed ? (string) $v['closed_date'] : '', 'rank' => $rank];
        }
        usort($rows, function ($a, $b) { return $a['rank'] <=> $b['rank'] ?: strcasecmp($a['name'], $b['name']); });
        return $rows;
    }

    public static function vuln_counts() {
        $c = ['urgent' => 0, 'vulnerable' => 0, 'closed' => 0, 'updates' => 0];
        foreach (self::plugin_rows() as $r) { if ($r['urgent']) $c['urgent']++; if ($r['vulns']) $c['vulnerable']++; if ($r['closed']) $c['closed']++; if ($r['update']) $c['updates']++; }
        return $c;
    }

    /** What an attacker needs, from the letters the feed sends. */
    private static function vuln_needs($s) {
        $m = ['l' => __('needs a signed-in user', 'aguard-safe'), 'h' => __('needs an administrator account', 'aguard-safe'), 'u' => __('needs an action by a user', 'aguard-safe'), 'c' => __('hard to exploit', 'aguard-safe'), 'a' => __('not reachable over the network', 'aguard-safe')];
        $out = []; foreach (str_split((string) $s) as $ch) if (isset($m[$ch])) $out[] = $m[$ch];
        return implode(', ', $out);
    }

    public static function activate() {
        if (!wp_next_scheduled(self::CRON)) wp_schedule_event(time() + 300, 'aguard_hourly', self::CRON);
        $fresh = get_option(self::OPT, null) === null; // a new install, not an update of a site that already has settings
        $o = self::opts();
        if ($fresh) { $o['tool_files'] = (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) ? 0 : 1; $o['tool_logs'] = 1; }
        if (empty($o['installed']) || $fresh) { if (empty($o['installed'])) $o['installed'] = time(); update_option(self::OPT, $o, true); self::$opts = null; }
        self::build_baseline();
        self::event('plugin', __('AGuard Safe activated', 'aguard-safe'), [], false);
    }

    public static function deactivate() {
        wp_clear_scheduled_hook(self::CRON);
        self::event('plugin', __('AGuard Safe deactivated', 'aguard-safe'), [], true);
    }

    /* ------------------------------------------------------------ helpers */

    /** Notifications go to the site administrator unless another address is set in Settings. */
    public static function default_mail() {
        return (string) get_option('admin_email');
    }

    /** Optional read-only tools (file browser, log viewer). Off until an administrator enables them in Settings. */
    public static function tool_on($tab) {
        $o = self::opts();
        if ($tab === 'files') return !empty($o['tool_files']);
        if ($tab === 'logs') return !empty($o['tool_logs']);
        return true;
    }

    /** A sanitized $_SERVER value. */
    private static function srv($k) {
        return isset($_SERVER[$k]) ? sanitize_text_field(wp_unslash($_SERVER[$k])) : '';
    }

    private static function srv_uri() {
        return isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
    }

    public static function opts() {
        if (self::$opts === null) {
            $d = ['email' => self::default_mail(), 'notify_cc' => '', 'notify' => 1, 'notify_admin_login' => 1, 'failed_threshold' => 20, 'cloak_check' => 1, 'whitelist' => ['service-worker.js'], 'block_php_uploads' => 0, 'lockdown' => 0, 'login_slug' => '', 'login_mode' => 'off', 'twofa' => 0, 'tool_files' => 0, 'tool_logs' => 0, 'credit' => 0, 'vuln_check' => 0, 'setup_done' => 0, 'lockout' => 1, 'lockout_after' => 10, 'pw_check' => 0];
            $o = get_option(self::OPT, []);
            self::$opts = is_array($o) ? array_merge($d, $o) : $d;
        }
        return self::$opts;
    }

    private static function ip() {
        $ip = self::srv('REMOTE_ADDR');
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $h) {
            if (!empty($_SERVER[$h])) { $ip .= ' (' . $h . ': ' . substr(sanitize_text_field(wp_unslash($_SERVER[$h])), 0, 80) . ')'; break; }
        }
        return $ip;
    }

    private static function who() {
        $u = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        $s = ($u && $u->ID) ? $u->user_login . ' (#' . $u->ID . ')' : (defined('DOING_CRON') && DOING_CRON ? 'cron' : (defined('WP_CLI') && WP_CLI ? 'wp-cli' : 'anonymous'));
        return $s . ' | IP ' . self::ip() . ' | ' . (isset($_SERVER['REQUEST_URI']) ? substr(esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])), 0, 120) : '');
    }

    private static function ua() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 160) : '';
    }

    /** Record an event and (optionally) e-mail it. $mail: true/false; rate-limited per $key. */
    public static function event($type, $title, $data = [], $mail = true, $key = null, $ttl = 600) {
        $events = get_option(self::OPT_EVENTS, []);
        if (!is_array($events)) $events = [];
        if (!is_array($data)) $data = ($data === null || $data === '') ? [] : ['info' => is_scalar($data) ? (string) $data : (string) wp_json_encode($data)]; // details are always stored as a list
        if (strlen((string) wp_json_encode($data)) > 10000) { $data = ['_note' => __('data truncated (too large for the log)', 'aguard-safe'), 'summary' => mb_substr((string) wp_json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 0, 4000)]; }
        $e = ['t' => time(), 'type' => $type, 'title' => $title, 'data' => $data, 'who' => self::who(), 'ua' => self::ua(), 'mailed' => false];
        if ($mail && !empty(self::opts()['notify'])) {
            $key = 'aguard_safe_rl_' . md5($key === null ? $type . '|' . $title : $key);
            $hour = 'aguard_safe_mails_' . wp_date('YmdH'); $sent = (int) get_transient($hour);
            if (!get_transient($key) && $sent < 10) {
                set_transient($key, 1, max(60, (int) $ttl));
                set_transient($hour, $sent + 1, HOUR_IN_SECONDS);
                $e['mailed'] = self::mail($type, $title, $data, $e);
            } elseif ($sent >= 10) {
                $e['data']['_note'] = __('e-mail not sent: limit of 10 messages per hour reached', 'aguard-safe');
            }
        }
        array_unshift($events, $e);
        if (count($events) > self::MAX_EVENTS) $events = array_slice($events, 0, self::MAX_EVENTS);
        update_option(self::OPT_EVENTS, $events, false);
        return $e;
    }

    private static function mail($type, $title, $data, $e) {
        $o = self::opts(); $to = $o['email'];
        if (!is_email($to)) return false;
        // Papildomi adresai (užsakovas) gauna tik incidentus – ne techninį srautą; ne daugiau 5 laiškų per parą.
        $critical = self::is_critical($type, $title, $data);
        $cc = [];
        if ($critical) {
            $cc = array_values(array_filter(array_map('trim', explode(',', (string) ($o['notify_cc'] ?? ''))), 'is_email'));
            if ($cc) { $dk = 'aguard_safe_cc_' . wp_date('Ymd'); $n = (int) get_transient($dk); if ($n >= 5) { $cc = []; } else { set_transient($dk, $n + 1, DAY_IN_SECONDS); } }
        }
        $site = wp_parse_url(home_url(), PHP_URL_HOST);
        $subj = '[AGuard Safe] ' . $site . ': ' . ($critical ? __('IMPORTANT –', 'aguard-safe') . ' ' : '') . $title;
        $lines = [__('Site:', 'aguard-safe') . ' ' . home_url(), __('Time:', 'aguard-safe') . ' ' . wp_date('Y-m-d H:i:s T'), __('Type:', 'aguard-safe') . ' ' . $type, __('Event:', 'aguard-safe') . ' ' . $title, __('Who:', 'aguard-safe') . ' ' . $e['who'], __('Browser:', 'aguard-safe') . ' ' . $e['ua'], ''];
        foreach ((array) $data as $k => $v) {
            $lines[] = $k . ': ' . (is_scalar($v) ? $v : wp_json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
        $lines[] = '';
        $lines[] = __('View:', 'aguard-safe') . ' ' . admin_url('admin.php?page=aguard-safe');
        $lines[] = '— AGuard Safe ' . self::VERSION;
        return (bool) wp_mail(array_merge([$to], $cc), $subj, implode("\n", $lines), ['Content-Type: text/plain; charset=UTF-8']);
    }

    /** Incidentai, apie kuriuos verta pranešti užsakovui; visa kita – tik techniniam adresui ir žurnalui. */
    public static function is_critical($type, $title, $data = []) {
        if (in_array($type, ['lockdown', 'quarantine', 'attack', 'file', 'theme', 'option', 'vuln'], true)) return true;
        if ($type === 'scan') return strpos($title, __('no changes found', 'aguard-safe')) === false;
        if ($type === 'user') { foreach ([__('NEW ADMINISTRATOR:', 'aguard-safe'), __('ADMINISTRATOR ROLE ADDED:', 'aguard-safe'), __('ROLE CHANGED TO ADMINISTRATOR:', 'aguard-safe'), __('User deleted: #', 'aguard-safe'), __('Application password created for user #', 'aguard-safe'), __('Administrator password changed:', 'aguard-safe')] as $mark) { if (strpos($title, $mark) !== false) return true; } return false; }
        if ($type === 'login') return !empty($data['new_ip']);
        if ($type === 'plugin') return strpos($title, __('INSTALLED', 'aguard-safe')) !== false || strpos($title, __('AGuard Safe deactivated', 'aguard-safe')) !== false;
        return false;
    }

    private static function user_brief($id) {
        $u = get_userdata($id);
        if (!$u) return ['id' => $id];
        return ['id' => $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'roles' => implode(',', (array) $u->roles), 'registered' => $u->user_registered, 'display' => $u->display_name];
    }

    /* ------------------------------------------------------------ user hooks */

    public static function on_user_register($id) {
        $b = self::user_brief($id);
        $roles = array_filter(explode(',', $b['roles'] ?? ''));
        $admin = in_array('administrator', $roles, true);
        self::event('user', ($admin ? __('NEW ADMINISTRATOR:', 'aguard-safe') . ' ' : __('New user:', 'aguard-safe') . ' ') . ($b['login'] ?? $id), $b, $admin || (bool) array_diff($roles, ['customer', 'subscriber']), 'user_register_' . $id);
    }

    /** Ką tik sukurtas naudotojas (per 2 min): apie jį jau pranešta vienu įvykiu „NAUJAS ADMINISTRATORIUS“, rolės/slaptažodžio laiškai – dublikatai. */
    private static function just_created($id) {
        $u = get_userdata((int) $id);
        return $u && (time() - strtotime($u->user_registered . ' UTC')) < 120;
    }
    public static function on_set_user_role($id, $role, $old) {
        if (self::just_created($id)) return;
        $b = self::user_brief($id);
        $b['new_role'] = $role; $b['old_roles'] = implode(',', (array) $old);
        $hot = $role === 'administrator' || in_array('administrator', (array) $old, true) || in_array($role, ['editor', 'shop_manager'], true);
        if ($role === 'customer' && (empty($old) || $old === ['customer'])) return; // WooCommerce churn
        self::event('user', ($role === 'administrator' ? __('ROLE CHANGED TO ADMINISTRATOR:', 'aguard-safe') . ' ' : __('User role changed:', 'aguard-safe') . ' ') . ($b['login'] ?? $id) . ' → ' . $role, $b, $hot, 'set_role_' . $id . $role);
    }

    public static function on_add_user_role($id, $role) {
        if ($role === 'administrator' && !self::just_created($id)) {
            self::event('user', __('ADMINISTRATOR ROLE ADDED:', 'aguard-safe') . ' ' . (($b = self::user_brief($id))['login'] ?? '#' . (int) $id), $b, true, 'add_role_' . $id);
        }
    }

    public static function on_deleted_user($id) {
        self::event('user', __('User deleted: #', 'aguard-safe') . $id, ['id' => $id], true, 'deleted_user_' . $id);
    }

    public static function on_retrieve_password($login) {
        $u = get_user_by('login', $login) ?: get_user_by('email', $login);
        if ($u && user_can($u, 'manage_options') && !self::just_created($u->ID)) self::event('user', __('Administrator password reset requested:', 'aguard-safe') . ' ' . $u->user_login, self::user_brief($u->ID), true, 'retrieve_' . $u->ID);
    }

    public static function on_password_reset($user) {
        if ($user instanceof WP_User && user_can($user, 'manage_options')) self::event('user', __('Administrator password changed:', 'aguard-safe') . ' ' . $user->user_login, self::user_brief($user->ID), true, 'reset_' . $user->ID);
    }

    public static function on_profile_update($id, $old) {
        $u = get_userdata($id);
        if (!$u || !($old instanceof WP_User)) return;
        $changes = [];
        if ($u->user_email !== $old->user_email) $changes['email'] = $old->user_email . ' → ' . $u->user_email;
        if ($u->user_pass !== $old->user_pass) $changes['password'] = __('changed', 'aguard-safe');
        if ($changes && user_can($u, 'manage_options')) self::event('user', __('Administrator account changed:', 'aguard-safe') . ' ' . $u->user_login, $changes + self::user_brief($id), true, 'profile_' . $id . implode(',', array_keys($changes)));
    }

    /* ------------------------------------------------------------ plugin / theme hooks */

    private static function plugin_name($file) {
        if (!function_exists('get_plugin_data')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $p = self::plugins_dir() . '/' . $file;
        $d = file_exists($p) ? get_plugin_data($p, false, false) : [];
        return ($d['Name'] ?? $file) . ' ' . ($d['Version'] ?? '') . ' (' . $file . ')';
    }

    public static function on_plugin_activated($file)   { self::event('plugin', __('Plugin activated:', 'aguard-safe') . ' ' . self::plugin_name($file), ['file' => $file], true, 'act_' . $file); }
    public static function on_plugin_deactivated($file) { self::event('plugin', __('Plugin deactivated:', 'aguard-safe') . ' ' . self::plugin_name($file), ['file' => $file], true, 'deact_' . $file); }
    public static function on_plugin_deleted($file, $ok) { self::event('plugin', __('Plugin deleted:', 'aguard-safe') . ' ' . $file, ['file' => $file, 'deleted' => $ok ? 'yes' : 'no'], true, 'del_' . $file); }

    public static function on_core_updated($new_version) {
        delete_transient('aguard_safe_sums');
        self::build_baseline();
        update_option(self::OPT . '_core_sig', '', false);
        self::event('plugin', __('WordPress updated to', 'aguard-safe') . ' ' . $new_version . ' ' . __('(system files changed legitimately, the baseline has been updated)', 'aguard-safe'), ['version' => $new_version], true, 'core_' . $new_version, DAY_IN_SECONDS);
    }
    public static function on_upgrader($upgrader, $extra) {
        $type = $extra['type'] ?? '?'; $action = $extra['action'] ?? '?';
        $items = $extra['plugins'] ?? ($extra['themes'] ?? []);
        if ($type === 'plugin' && $action === 'install' && is_object($upgrader) && method_exists($upgrader, 'plugin_info') && !empty($upgrader->plugin_info())) $items = [$upgrader->plugin_info()];
        if ($type === 'theme' && $action === 'install' && is_object($upgrader) && method_exists($upgrader, 'theme_info') && !empty($upgrader->theme_info())) $items = [$upgrader->theme_info()->get_stylesheet()];
        $title = ($action === 'install' ? __('INSTALLED', 'aguard-safe') : __('Updated', 'aguard-safe')) . ' (' . $type . '): ' . implode(', ', (array) $items);
        self::event('plugin', $title, ['type' => $type, 'action' => $action, 'items' => $items], $action === 'install' || $type === 'core', 'upg_' . $type . $action . implode(',', (array) $items));
        // Bet koks baigtas atnaujinimas/diegimas teisėtai keičia sargybinius failus (advanced-cache.php, wordfence-waf.php, šakniniai failai) – atskaitos taškas perstatomas, kad kita patikra nekeltų klaidingo aliarmo.
        self::build_baseline();
        if ($type === 'core') update_option(self::OPT . '_core_sig', '', false);
    }

    public static function on_switch_theme($name) { self::event('theme', __('Theme changed:', 'aguard-safe') . ' ' . $name, ['theme' => $name], true); }

    public static function on_editor_save() {
        // Runs before the core handler, so the request is verified here the same way core verifies it.
        $nonce = isset($_POST['nonce']) ? sanitize_text_field(wp_unslash($_POST['nonce'])) : '';
        $f = isset($_POST['file']) ? sanitize_text_field(wp_unslash($_POST['file'])) : '';
        if ($nonce === '' || $f === '') return;
        if (!empty($_POST['plugin'])) {
            $t = sanitize_text_field(wp_unslash($_POST['plugin']));
            if (!current_user_can('edit_plugins') || !wp_verify_nonce($nonce, 'edit-plugin_' . $f)) return;
        } elseif (!empty($_POST['theme'])) {
            $t = sanitize_text_field(wp_unslash($_POST['theme']));
            if (!current_user_can('edit_themes') || !wp_verify_nonce($nonce, 'edit-theme_' . $t . '_' . $f)) return;
        } else {
            return;
        }
        self::event('file', __('File edited in the wp-admin editor:', 'aguard-safe') . ' ' . $t . '/' . $f, ['file' => $f, 'target' => $t], true, 'editor_' . $t . $f);
    }

    /* ------------------------------------------------------------ login / attack hooks */

    public static function on_login($login, $user) {
        if ($user instanceof WP_User && user_can($user, 'manage_options')) {
            $o = self::opts();
            // Laiškas tik kai administratorius jungiasi iš IP, iš kurio per 30 d. nesijungė (nauja vieta/įrenginys);
            // įprasti kasdieniai prisijungimai iš žinomo IP – tik į žurnalą.
            $ip = (self::srv('HTTP_CF_CONNECTING_IP') ?: self::srv('REMOTE_ADDR'));
            $known = get_option(self::OPT . '_known_logins', []); if (!is_array($known)) $known = [];
            $now = time(); $seen = isset($known[$login][$ip]) && ($now - (int) $known[$login][$ip]) < 30 * DAY_IN_SECONDS;
            $known[$login][$ip] = $now;
            foreach ($known as $u => $ips) { foreach ($ips as $k => $t) { if ($now - (int) $t > 30 * DAY_IN_SECONDS) unset($known[$u][$k]); } if (empty($known[$u])) unset($known[$u]); }
            update_option(self::OPT . '_known_logins', $known, false);
            $title = $seen ? __('Administrator signed in:', 'aguard-safe') . ' ' . $login : __('Administrator signed in from a NEW IP:', 'aguard-safe') . ' ' . $login;
            self::event('login', $title, ['ip' => self::ip(), 'ua' => self::ua(), 'new_ip' => !$seen], !$seen && !empty($o['notify_admin_login']), 'login_' . $login . '_' . md5($ip) . '_' . wp_date('Y-m-d'), 12 * HOUR_IN_SECONDS);
        }
    }

    /** Is $ip inside one of the $ranges (CIDR, IPv4 or IPv6)? */
    private static function ip_in($ip, $ranges) {
        $b = @inet_pton($ip); if ($b === false) return false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a malformed address is simply not in any range.
        foreach ($ranges as $r) {
            list($net, $bits) = explode('/', $r); $n = @inet_pton($net); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            if ($n === false || strlen($n) !== strlen($b)) continue;
            $bits = (int) $bits; $full = intdiv($bits, 8); $rest = $bits % 8;
            if ($full && substr($b, 0, $full) !== substr($n, 0, $full)) continue;
            if ($rest && ((ord($b[$full]) ^ ord($n[$full])) & (0xFF << (8 - $rest) & 0xFF))) continue;
            return true;
        }
        return false;
    }

    /**
     * The visitor's address for counting and blocking. The Cloudflare header is believed only when the request really comes
     * from Cloudflare; otherwise anybody could send that header and get a new "address" for every attempt.
     */
    public static function client_ip() {
        $ip = self::srv('REMOTE_ADDR'); $cf = self::srv('HTTP_CF_CONNECTING_IP');
        if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP) && self::ip_in($ip, ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'])) return $cf;
        return $ip;
    }

    /** Emergency switch for the IP block, the same way as for the login address and the code by e-mail. */
    public static function lockout_killed() {
        if (defined('AGUARD_SAFE_LOCKOUT_OFF') && AGUARD_SAFE_LOCKOUT_OFF) return 'AGUARD_SAFE_LOCKOUT_OFF';
        if (file_exists(self::content_dir() . '/AGUARD-LOCKOUT-OFF')) return basename(self::content_dir()) . '/AGUARD-LOCKOUT-OFF';
        return '';
    }

    /** Until when signing in from this address is paused (0 = not paused). */
    public static function lockout_until($ip = null) {
        if (empty(self::opts()['lockout']) || self::lockout_killed() !== '') return 0;
        $u = (int) get_transient('aguard_safe_lock_' . md5($ip === null ? self::client_ip() : $ip));
        return $u > time() ? $u : 0;
    }

    /** Addresses paused right now: ip => until. */
    public static function lockouts() {
        $l = get_option(self::OPT . '_lockouts', []); if (!is_array($l)) $l = [];
        return array_filter($l, function ($u) { return (int) $u > time(); });
    }

    /** An address an administrator signed in from during the last 30 days is never paused: an attacker behind the same proxy must not lock the owner out. */
    private static function ip_of_admin($ip) {
        $known = get_option(self::OPT . '_known_logins', []);
        foreach ((array) $known as $ips) { if (is_array($ips) && isset($ips[$ip]) && (time() - (int) $ips[$ip]) < 30 * DAY_IN_SECONDS) return true; }
        return false;
    }

    public static function on_login_failed($login) {
        $cip = self::client_ip();
        if (self::lockout_until($cip)) return; // already paused: attempts are not even checked, nothing to count
        $ipk = 'aguard_safe_fail_' . md5($cip);
        $n = (int) get_transient($ipk) + 1;
        set_transient($ipk, $n, 15 * MINUTE_IN_SECONDS);
        $day = 'aguard_safe_fail_day_' . wp_date('Ymd');
        $t = (int) get_transient($day) + 1; set_transient($day, $t, DAY_IN_SECONDS);
        $h = get_option(self::OPT . '_fail_hist', []); if (!is_array($h)) $h = []; $k = wp_date('Y-m-d'); $h[$k] = ($h[$k] ?? 0) + 1; if (count($h) > 14) $h = array_slice($h, -14, null, true); update_option(self::OPT . '_fail_hist', $h, false);
        $o = self::opts(); $th = (int) $o['failed_threshold']; $after = max(3, (int) ($o['lockout_after'] ?? 10));
        if (!empty($o['lockout']) && self::lockout_killed() === '' && $n >= $after && !self::ip_of_admin($cip)) {
            $until = time() + 30 * MINUTE_IN_SECONDS;
            set_transient('aguard_safe_lock_' . md5($cip), $until, 30 * MINUTE_IN_SECONDS);
            $l = self::lockouts(); $l[$cip] = $until; if (count($l) > 200) $l = array_slice($l, -200, null, true); update_option(self::OPT . '_lockouts', $l, false);
            delete_transient($ipk);
            /* translators: 1: IP address, 2: number of attempts */
            self::event('attack', sprintf(__('Address %1$s blocked for 30 minutes after %2$d failed attempts', 'aguard-safe'), $cip, $n), ['last_login_tried' => $login, 'today_total' => $t], true, 'lockout_' . $cip, HOUR_IN_SECONDS);
            return;
        }
        if ($n === $th || ($n > $th && $n % 100 === 0)) {
            self::event('attack', __('Password guessing:', 'aguard-safe') . ' ' . $n . ' ' . __('failed attempts in 15 min from', 'aguard-safe') . ' ' . self::ip(), ['last_login_tried' => $login, 'today_total' => $t], true, 'bruteforce_' . $cip);
        }
    }

    /** While an address is paused, no password is checked for it at all (browser form, XML-RPC, REST). */
    public static function lockout_authenticate($user, $username = '', $password = '') {
        if ($username === '' && $password === '') return $user;
        $until = self::lockout_until();
        if (!$until) return $user;
        /* translators: %d: minutes */
        return new WP_Error('aguard_locked', sprintf(__('Access blocked: too many failed sign-in attempts from your address. The address is recorded. Blocked for %d more minutes.', 'aguard-safe'), max(1, (int) ceil(($until - time()) / 60))));
    }

    /** The login page for a paused address: a plain page instead of the form. */
    public static function lockout_login_page() {
        $until = self::lockout_until();
        if (!$until) return;
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only decides which screen is shown.
        if (in_array($action, ['logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'confirmaction', 'postpass'], true)) return; // password reset and sign-out keep working
        $min = max(1, (int) ceil(($until - time()) / 60)); $base = plugin_dir_url(__FILE__) . 'assets/';
        status_header(429); nocache_headers(); header('Retry-After: ' . max(60, $until - time())); header('Content-Type: text/html; charset=UTF-8');
        echo '<!doctype html><html lang="' . esc_attr(get_bloginfo('language')) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' . esc_html__('Access blocked', 'aguard-safe') . '</title>';
        echo '<link rel="stylesheet" href="' . esc_url($base . 'block.css?ver=' . self::VERSION) . '"></head><body class="ag-block"><main><div class="ag-block-card">'; // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet -- a standalone page shown instead of wp-login.php, the enqueue system is not running here.
        echo '<img src="' . esc_url($base . 'knight-emergency.png') . '" alt="" width="150" height="178"><div><p class="ag-block-k">' . esc_html(wp_parse_url(home_url(), PHP_URL_HOST)) . '</p><h1>' . esc_html__('Access blocked', 'aguard-safe') . '</h1>';
        echo '<p>' . esc_html__('Too many failed sign-in attempts came from your address. The address has been blocked and recorded.', 'aguard-safe') . '</p>';
        echo '<dl><dt>' . esc_html__('Your address', 'aguard-safe') . '</dt><dd>' . esc_html(self::client_ip()) . '</dd><dt>' . esc_html__('Recorded', 'aguard-safe') . '</dt><dd>' . esc_html(wp_date('Y-m-d H:i')) . '</dd><dt>' . esc_html__('Blocked until', 'aguard-safe') . '</dt><dd>' . esc_html(wp_date('H:i', $until)) . '</dd></dl>';
        echo '<p class="ag-block-w">' . esc_html__('Every attempt from this address is logged and reported to the administrator of this site.', 'aguard-safe') . '</p>';
        echo '<p class="ag-block-n">' . esc_html__('Are you the owner and forgot the password?', 'aguard-safe') . ' <a href="' . esc_url(wp_lostpassword_url()) . '">' . esc_html__('Reset the password', 'aguard-safe') . '</a></p>';
        echo '</div></div><p class="ag-block-f">' . esc_html__('Protected by AGuard Safe', 'aguard-safe') . '</p></main></body></html>';
        exit;
    }

    /** Looks the password up in the Pwned Passwords list (through data.aguard.lt) without sending it: only the first 5 characters of its SHA-1 hash leave the site. Returns how many times it was seen in breaches, or -1 when the service did not answer. */
    public static function pwned_count($password) {
        $h = strtoupper(sha1($password)); $pre = substr($h, 0, 5); $suf = substr($h, 5);
        $r = wp_remote_get('https://data.aguard.lt/v1/pw/' . $pre, ['timeout' => 5, 'redirection' => 0, 'user-agent' => 'AGuard Safe/' . self::VERSION, 'limit_response_size' => 512 * KB_IN_BYTES]);
        if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) return -1;
        foreach (explode("\n", (string) wp_remote_retrieve_body($r)) as $line) { $p = explode(':', trim($line)); if (count($p) === 2 && $p[0] === $suf) return (int) $p[1]; }
        return 0;
    }

    /** After a correct administrator password: is this password in known breaches? Once per password and at most once a week. */
    public static function pw_check($user, $username = '', $password = '') {
        try {
            if (!($user instanceof WP_User) || $password === '' || empty(self::opts()['pw_check']) || !user_can($user, 'manage_options')) return $user;
            $sig = substr(md5($user->user_pass), 0, 12); $m = get_user_meta($user->ID, 'aguard_safe_pw', true);
            if (is_array($m) && ($m['sig'] ?? '') === $sig && (time() - (int) ($m['t'] ?? 0)) < WEEK_IN_SECONDS) return $user;
            $n = self::pwned_count($password);
            if ($n < 0) return $user;
            update_user_meta($user->ID, 'aguard_safe_pw', ['sig' => $sig, 't' => time(), 'n' => $n]);
            /* translators: %s: user login */
            if ($n > 0) self::event('user', sprintf(__('The password of administrator %s is in a list of leaked passwords – change it', 'aguard-safe'), $user->user_login), ['seen_in_breaches' => $n], true, 'pwned_' . $user->ID, DAY_IN_SECONDS);
        } catch (\Throwable $e) { return $user; }
        return $user;
    }

    /** Administrators whose current password was found in the leaked list. */
    public static function pwned_admins() {
        $out = [];
        foreach (get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_pass']]) as $u) { $m = get_user_meta($u->ID, 'aguard_safe_pw', true); if (is_array($m) && !empty($m['n']) && ($m['sig'] ?? '') === substr(md5($u->user_pass), 0, 12)) $out[] = $u->user_login; }
        return $out;
    }

    public static function on_xmlrpc($name) {
        $k = 'aguard_safe_xmlrpc_hour';
        $n = (int) get_transient($k) + 1; set_transient($k, $n, HOUR_IN_SECONDS);
        if ($n === 50) self::event('attack', __('XML-RPC: 50+ calls per hour (', 'aguard-safe') . $name . ')', ['ip' => self::ip()], true, 'xmlrpc_' . wp_date('YmdH'));
    }

    public static function on_app_password($user_id, $item) {
        self::event('user', __('Application password created for user #', 'aguard-safe') . $user_id, self::user_brief($user_id) + ['name' => $item['name'] ?? ''], true, 'apppass_' . $user_id);
    }

    public static function on_updated_option($name, $old, $new) {
        static $watch = ['siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'active_plugins', 'template', 'stylesheet', 'permalink_structure', 'blog_public'];
        if (!in_array($name, $watch, true) || $old === $new) return;
        $fmt = function ($v) { return is_scalar($v) ? (string) $v : wp_json_encode($v, JSON_UNESCAPED_SLASHES); };
        if ($name === 'active_plugins') {
            $added = array_values(array_diff((array) $new, (array) $old)); $removed = array_values(array_diff((array) $old, (array) $new));
            if (!$added && !$removed) return;
            self::event('plugin', __('List of active plugins changed', 'aguard-safe'), ['added' => $added, 'removed' => $removed], false);
            return;
        }
        self::event('option', __('System option changed:', 'aguard-safe') . ' ' . $name, ['old' => $fmt($old), 'new' => $fmt($new)], true, 'opt_' . $name);
    }

    /* ------------------------------------------------------------ paths & file tools (read-only) */

    /** Root of what the read-only tools may show: the WordPress folder and nothing above it. */
    public static function base_dir() { return self::wp_root(); }

    /**
     * Locations of WordPress itself, taken from the WordPress filesystem API (WP_Filesystem_Base::abspath(),
     * wp_content_dir(), wp_plugins_dir(), wp_lang_dir()). The plugin's own files are located with plugin_dir_path( __FILE__ ),
     * uploads with wp_upload_dir(). These folders are only read (integrity checks); the plugin's data is written to uploads.
     */
    public static function wp_root() { static $d = null; return $d ?? ($d = self::real_dir(self::fs()->abspath())); }
    public static function content_dir() { static $d = null; return $d ?? ($d = self::real_dir(self::fs()->wp_content_dir())); }
    public static function lang_dir() { static $d = null; return $d ?? ($d = self::real_dir(self::fs()->wp_lang_dir())); }
    public static function plugins_dir() { static $d = null; return $d ?? ($d = self::real_dir(self::fs()->wp_plugins_dir())); }
    /** Folder of the must-use plugins: where WordPress loads them from, or its default place when there are none yet. */
    public static function mu_plugins_dir() { $f = wp_get_mu_plugins(); return $f ? self::real_dir(pathinfo($f[0], PATHINFO_DIRNAME)) : self::content_dir() . '/mu-plugins'; }
    /** Normalised path without a trailing slash; symlinks are resolved when the folder exists, so all comparisons use the same form. */
    private static function lower($s) { return function_exists('mb_strtolower') ? mb_strtolower((string) $s) : strtolower((string) $s); }
    private static function real_dir($path) { $r = realpath((string) $path); return rtrim(wp_normalize_path($r === false ? (string) $path : $r), '/'); }

    /** Certificate check for requests the site makes to itself: the same core filter WordPress uses for its own loopback requests. */
    private static function local_sslverify() {
        return apply_filters('https_local_ssl_verify', false); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter for loopback requests.
    }

    /** True when $path (after resolving symlinks and ../) is $dir itself or lies inside it. */
    private static function is_inside($path, $dir) {
        $r = realpath($path); $d = realpath($dir);
        if ($r === false || $d === false) return false;
        $r = rtrim(wp_normalize_path($r), '/'); $d = rtrim(wp_normalize_path($d), '/');
        return $r === $d || strpos($r, $d . '/') === 0;
    }

    /** Uploads directory as WordPress reports it (it can be moved out of wp-content). */
    public static function uploads_dir() {
        $up = wp_upload_dir(null, false);
        return self::real_dir($up['basedir']);
    }

    /** Path of a WordPress directory relative to $root (absolute when it lives elsewhere). */
    private static function rel_to($root, $path) {
        $path = rtrim(wp_normalize_path($path), '/');
        return strpos($path, $root . '/') === 0 ? substr($path, strlen($root) + 1) : $path;
    }

    public static function safe_path($rel) {
        $base = self::base_dir();
        $rel = str_replace("\0", '', (string) $rel);
        $p = wp_normalize_path($base . '/' . ltrim($rel, '/'));
        $r = realpath($p);
        if ($r === false) return false;
        $r = wp_normalize_path($r);
        if ($r !== $base && strpos($r, $base . '/') !== 0) return false;
        return $r;
    }

    public static function rel($abs) {
        $base = self::base_dir();
        $abs = wp_normalize_path($abs);
        if ($abs === $base) return '';
        return strpos($abs, $base . '/') === 0 ? substr($abs, strlen($base) + 1) : $abs; // outside the WordPress folder (moved uploads): shown as is
    }

    private static function file_row($path) {
        $st = @stat($path);
        $row = ['name' => basename($path), 'rel' => self::rel($path), 'dir' => is_dir($path), 'size' => $st ? $st['size'] : null, 'mtime' => $st ? $st['mtime'] : null, 'ctime' => $st ? $st['ctime'] : null, 'perms' => $st ? substr(sprintf('%o', $st['mode']), -4) : null, 'uid' => $st ? $st['uid'] : null, 'link' => is_link($path) ? @readlink($path) : null];
        if (function_exists('posix_getpwuid') && $st) { $pw = @posix_getpwuid($st['uid']); $row['owner'] = $pw['name'] ?? $st['uid']; }
        return $row;
    }

    public static function list_dir($rel, $with_hash = false) {
        $dir = self::safe_path($rel);
        if (!$dir || !is_dir($dir)) return new WP_Error('nodir', __('Folder not found or outside the allowed area:', 'aguard-safe') . ' ' . $rel);
        $out = [];
        $h = @opendir($dir);
        if (!$h) return new WP_Error('noread', __('Cannot read:', 'aguard-safe') . ' ' . $rel);
        while (($n = readdir($h)) !== false) {
            if ($n === '.' || $n === '..') continue;
            $p = $dir . '/' . $n;
            $row = self::file_row($p);
            if ($with_hash && !$row['dir'] && $row['size'] !== null && $row['size'] < 50 * MB_IN_BYTES && is_readable($p)) $row['sha256'] = hash_file('sha256', $p);
            $out[] = $row;
        }
        closedir($h);
        usort($out, function ($a, $b) { return ($b['dir'] <=> $a['dir']) ?: strcasecmp($a['name'], $b['name']); });
        return $out;
    }

    public static function read_file($rel, $offset = 0, $max = 2 * MB_IN_BYTES) {
        $f = self::safe_path($rel);
        if (!$f || !is_file($f)) return new WP_Error('nofile', __('File not found or outside the allowed area:', 'aguard-safe') . ' ' . $rel);
        if (!is_readable($f)) return new WP_Error('noread', __('File is not readable:', 'aguard-safe') . ' ' . $rel);
        $size = filesize($f);
        $data = ($size - $offset > 0) ? (string) file_get_contents($f, false, null, max(0, (int) $offset), min($max, max(1, $size - (int) $offset))) : '';
        return ['rel' => $rel, 'size' => $size, 'offset' => (int) $offset, 'length' => strlen($data), 'sha256' => $size < 100 * MB_IN_BYTES ? hash_file('sha256', $f) : null, 'mtime' => filemtime($f), 'data' => $data];
    }

    public static function tail_file($rel, $lines = 200, $grep = '', $first = false, $start = 0) {
        $f = self::safe_path($rel);
        if (!$f || !is_file($f) || !is_readable($f)) return new WP_Error('nofile', __('File not found or not readable:', 'aguard-safe') . ' ' . $rel);
        if (!in_array(self::rel($f), array_column(self::log_candidates(), 'rel'), true)) return new WP_Error('nofile', __('File not found or not readable:', 'aguard-safe') . ' ' . $rel); // only the log files listed on this tab
        $lines = max(1, min(5000, (int) $lines));
        $out = [];
        if ($grep !== '') {
            if (function_exists('set_time_limit')) @set_time_limit(300); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a full file scan can take longer than the default limit.
            $fh = new SplFileObject($f, 'rb'); $n = 0; $max = $first ? $lines : 20000; $scanned = 0; $t0 = microtime(true); $stopped = false;
            if ($start > 0) $fh->fseek((int) $start);
            $re = '~' . str_replace('~', '\~', $grep) . '~i'; $use_re = @preg_match($re, '') !== false;
            while (!$fh->eof() && ($l = $fh->fgets()) !== false) {
                if ($l === '' && $fh->eof()) break;
                $scanned++;
                if (($scanned & 4095) === 0 && microtime(true) - $t0 > 240) { $stopped = true; break; }
                if (stripos($l, $grep) !== false || ($use_re && preg_match($re, $l))) { $out[] = rtrim($l, "\r\n"); if (++$n >= $max) break; }
            }
            $pos = $fh->ftell(); $fh = null;
            if (!$first && count($out) > $lines) $out = array_slice($out, -$lines);
            return ['rel' => $rel, 'lines' => $out, 'scanned_lines' => $scanned, 'grep' => $grep, 'first' => $first, 'start' => (int) $start, 'next_offset' => $pos, 'timed_out' => $stopped, 'size' => filesize($f)];
        }
        // tail without loading the whole file
        $fh = new SplFileObject($f, 'rb'); $pos = filesize($f); $buf = ''; $chunk = 65536;
        while ($pos > 0 && substr_count($buf, "\n") <= $lines) {
            $read = min($chunk, $pos); $pos -= $read; $fh->fseek($pos); $buf = $fh->fread($read) . $buf;
            if (strlen($buf) > 20 * MB_IN_BYTES) break;
        }
        $fh = null;
        $arr = explode("\n", rtrim($buf, "\n"));
        return ['rel' => $rel, 'lines' => array_slice($arr, -$lines), 'size' => filesize($f)];
    }

    public static function log_candidates() {
        $base = self::base_dir();
        $c = [];
        foreach ([$base . '/logs', $base . '/log', self::content_dir() . '/debug.log', self::wp_root() . '/error_log', self::wp_root() . '/wp-admin/error_log', self::uploads_dir() . '/wc-logs', self::content_dir() . '/updraft'] as $p) {
            $p = wp_normalize_path($p);
            if (is_dir($p)) { foreach ((@scandir($p) ?: []) as $n) { if ($n[0] !== '.' && is_file($p . '/' . $n)) $c[] = self::file_row($p . '/' . $n); } }
            elseif (is_file($p)) $c[] = self::file_row($p);
        }
        return $c;
    }

    /* ------------------------------------------------------------ scans */

    /** Files whose change matters most: WP root, wp-content root (drop-ins), mu-plugins, .htaccess, wp-config. */
    public static function sentinel_files() {
        $files = [];
        $root = self::wp_root();
        foreach ((@scandir($root) ?: []) as $n) { if ($n[0] !== '.' && is_file("$root/$n") && preg_match('~\.(php|html?|txt|ini|json)$~i', $n)) $files[] = "$root/$n"; }
        foreach (['.htaccess', '.user.ini', 'php.ini', 'wp-config.php', '.htpasswd'] as $n) { if (is_file("$root/$n")) $files[] = "$root/$n"; }
        $wc = self::content_dir();
        foreach ((@scandir($wc) ?: []) as $n) { if ($n[0] !== '.' && is_file("$wc/$n")) $files[] = "$wc/$n"; }
        if (is_file("$wc/.htaccess")) $files[] = "$wc/.htaccess";
        $mu = self::mu_plugins_dir();
        foreach ([$mu, self::uploads_dir(), self::plugins_dir(), rtrim(wp_normalize_path(get_theme_root()), '/'), "$root/wp-includes", "$root/wp-admin"] as $d) { if (is_file("$d/.htaccess")) $files[] = "$d/.htaccess"; }
        if (is_dir($mu)) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($mu, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
            foreach ($it as $f) { if ($f->isFile()) $files[] = wp_normalize_path($f->getPathname()); }
        }
        $files = (array) apply_filters('aguard_safe_sentinel_files', $files);
        return array_values(array_unique(array_filter($files, 'is_string')));
    }

    public static function build_baseline() {
        global $wp_version;
        $b = ['t' => time(), 'wp' => (string) $wp_version, 'files' => [], 'admins' => []];
        foreach (self::sentinel_files() as $f) { if (is_readable($f)) $b['files'][$f] = ['h' => hash_file('sha256', $f), 'm' => filemtime($f), 's' => filesize($f)]; }
        foreach (get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_email']]) as $u) $b['admins'][$u->ID] = $u->user_login . ' <' . $u->user_email . '>';
        update_option(self::OPT_BASELINE, $b, false);
        return $b;
    }

    /** The plugin changed a watched file itself: record its new state so the next check does not report it. */
    private static function baseline_touch($f) {
        $b = get_option(self::OPT_BASELINE, []);
        if (empty($b['files']) || !is_array($b['files'])) return;
        if (is_readable($f)) $b['files'][$f] = ['h' => hash_file('sha256', $f), 'm' => filemtime($f), 's' => filesize($f)]; else unset($b['files'][$f]);
        update_option(self::OPT_BASELINE, $b, false);
    }

    public static function check_sentinels() {
        $b = get_option(self::OPT_BASELINE, []);
        if (empty($b['files'])) return ['changed' => [], 'added' => [], 'removed' => [], 'baseline' => null];
        $now = [];
        foreach (self::sentinel_files() as $f) { if (is_readable($f)) $now[$f] = ['h' => hash_file('sha256', $f), 'm' => filemtime($f), 's' => filesize($f)]; }
        $changed = $added = $removed = [];
        foreach ($now as $f => $i) {
            if (!isset($b['files'][$f])) $added[] = $f . ' (' . $i['s'] . ' B, ' . wp_date('Y-m-d H:i', $i['m']) . ')';
            elseif ($b['files'][$f]['h'] !== $i['h']) $changed[] = $f . ' (' . $b['files'][$f]['s'] . '→' . $i['s'] . ' B, ' . wp_date('Y-m-d H:i', $i['m']) . ')';
        }
        foreach ($b['files'] as $f => $i) { if (!isset($now[$f])) $removed[] = $f; }
        return ['changed' => $changed, 'added' => $added, 'removed' => $removed, 'baseline' => $b['t']];
    }

    public static function check_admins() {
        $b = get_option(self::OPT_BASELINE, []);
        $now = [];
        foreach (get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_email']]) as $u) $now[$u->ID] = $u->user_login . ' <' . $u->user_email . '>';
        $added = array_diff_key($now, (array) ($b['admins'] ?? [])); $removed = array_diff_key((array) ($b['admins'] ?? []), $now);
        return ['now' => $now, 'added' => $added, 'removed' => $removed];
    }

    /** Core files vs. official checksums (wp-admin, wp-includes, root). */
    public static function check_core($limit_seconds = 40) {
        global $wp_version;
        if (!function_exists('get_core_checksums')) require_once ABSPATH . 'wp-admin/includes/update.php';
        $locale = get_locale();
        $ck = md5($wp_version . '|' . $locale); $cached = get_transient('aguard_safe_sums'); $sums = (is_array($cached) && ($cached['k'] ?? '') === $ck) ? $cached['sums'] : false;
        $fallback = false;
        if (!$sums) { $sums = get_core_checksums($wp_version, $locale); if (!$sums && $locale !== 'en_US') { $sums = get_core_checksums($wp_version, 'en_US'); $fallback = true; } if ($sums) set_transient('aguard_safe_sums', ['k' => $ck, 'sums' => $sums], $fallback ? HOUR_IN_SECONDS : DAY_IN_SECONDS); }
        if (!$sums) return new WP_Error('nosums', __('Could not get WordPress', 'aguard-safe') . ' ' . $wp_version . ' ' . __('checksums from api.wordpress.org', 'aguard-safe'));
        if ($locale !== 'en_US') unset($sums['wp-includes/version.php']); // lokalizuotame pakete version.php turi $wp_local_package eilutę – lyginti su en_US suma beprasmiška
        $start = microtime(true); $modified = $missing = []; $checked = 0;
        foreach ($sums as $file => $md5) {
            if (strpos($file, 'wp-content/') === 0) continue; // name used inside the official checksum list for bundled themes and plugins
            $p = self::wp_root() . '/' . $file;
            if (!file_exists($p)) { if (!in_array($file, ['readme.html', 'license.txt', 'wp-config-sample.php'], true)) $missing[] = $file; continue; } // readme/licence are commonly removed or renamed (e.g. by Wordfence)
            if (md5_file($p) !== $md5) $modified[] = $file . ' (' . wp_date('Y-m-d H:i', filemtime($p)) . ')';
            $checked++;
            if (microtime(true) - $start > $limit_seconds) { $modified[] = __('… stopped after', 'aguard-safe') . ' ' . $limit_seconds . ' s (' . $checked . ' ' . __('files)', 'aguard-safe'); break; }
        }
        // extra files that are not part of core
        $extra = [];
        foreach (['', 'wp-admin', 'wp-includes', 'wp-admin/includes', 'wp-includes/js', 'wp-admin/js', 'wp-admin/css', 'wp-includes/css'] as $d) {
            $dir = rtrim(self::wp_root() . '/' . $d, '/');
            foreach ((@scandir($dir) ?: []) as $n) {
                if ($n[0] === '.' || is_dir("$dir/$n")) continue;
                $rel = ltrim("$d/$n", '/');
                if (preg_match('~\.(log|txt|bak|gz|zip|tmp)$~i', $n) || $n === 'error_log' || preg_match('~^readme\.[0-9a-f]{32}\.html$~', $n)) continue; // Wordfence renames readme.html to hide the version
                if (!isset($sums[$rel]) && !in_array($rel, ['wp-config.php', 'wp-config-sample.php', 'robots.txt', 'favicon.ico', '.htaccess', 'error_log', 'wp-admin/error_log', 'php.ini', '.user.ini', 'sitemap.xml', 'wp-includes/version.php'], true)) $extra[] = $rel . ' (' . filesize("$dir/$n") . ' B, ' . wp_date('Y-m-d H:i', filemtime("$dir/$n")) . ')';
            }
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::wp_root() . '/wp-includes', FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
        $n = 0;
        foreach ($it as $f) {
            if (++$n > 30000) break;
            $rel = 'wp-includes/' . ltrim(str_replace(wp_normalize_path(self::wp_root() . '/wp-includes'), '', wp_normalize_path($f->getPathname())), '/');
            if ($f->isFile() && !isset($sums[$rel]) && $rel !== 'wp-includes/version.php' && preg_match('~\.(php|phtml|php\d|phar|inc|ico|txt)$~i', $rel)) $extra[] = $rel . ' (' . $f->getSize() . ' B, ' . wp_date('Y-m-d H:i', $f->getMTime()) . ')';
        }
        $wl = (array) (self::opts()['whitelist'] ?? []);
        $extra = array_values(array_filter(array_unique($extra), function ($e) use ($wl) { $rel = preg_replace('~ \(.*$~', '', $e); return !in_array($rel, $wl, true); }));
        return ['version' => $wp_version, 'checked' => $checked, 'modified' => $modified, 'missing' => $missing, 'extra' => $extra, 'whitelisted' => $wl];
    }

    /** Installed plugins vs. the official wordpress.org checksums (premium/custom plugins are reported as unverifiable). */
    public static function check_plugins($limit_seconds = 120) {
        if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        if (function_exists('set_time_limit')) @set_time_limit(300); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a full file scan can take longer than the default limit.
        $out = []; $start = microtime(true);
        foreach (get_plugins() as $file => $data) {
            $slug = dirname($file); if ($slug === '.') $slug = basename($file, '.php');
            $ver = $data['Version'] ?? '';
            $row = ['plugin' => $file, 'name' => $data['Name'] ?? '', 'version' => $ver, 'status' => 'unverified'];
            $r = wp_remote_get('https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($ver) . '.json', ['timeout' => 20]);
            if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) { $row['status'] = 'no-checksums (not on wordpress.org or version unknown)'; $out[] = $row; continue; }
            $j = json_decode(wp_remote_retrieve_body($r), true);
            if (empty($j['files'])) { $row['status'] = 'no-checksums'; $out[] = $row; continue; }
            $dir = self::plugins_dir() . '/' . $slug; $modified = $missing = []; $known = [];
            foreach ($j['files'] as $rel => $sums) {
                $known[$rel] = true; $p = $dir . '/' . $rel;
                if (!file_exists($p)) { $missing[] = $rel; continue; }
                $md5 = $sums['md5'] ?? null; $sha = $sums['sha256'] ?? null;
                if (($sha && hash_file('sha256', $p) !== $sha) || (!$sha && $md5 && md5_file($p) !== $md5)) $modified[] = $rel . ' (' . wp_date('Y-m-d H:i', filemtime($p)) . ')';
            }
            $extra = [];
            if (is_dir($dir)) {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
                foreach ($it as $f) {
                    $rel = ltrim(str_replace(wp_normalize_path($dir), '', wp_normalize_path($f->getPathname())), '/');
                    if ($f->isFile() && !isset($known[$rel]) && preg_match('~\.(php|phtml|php\d|phar|inc|htaccess)$~i', $rel)) $extra[] = $rel . ' (' . $f->getSize() . ' B, ' . wp_date('Y-m-d H:i', $f->getMTime()) . ')';
                }
            }
            $row['status'] = ($modified || $extra) ? 'MISMATCH' : 'ok'; $row['checked'] = count($known); $row['modified'] = $modified; $row['missing_count'] = count($missing); $row['extra'] = $extra;
            $out[] = $row;
            if (microtime(true) - $start > $limit_seconds) { $out[] = ['plugin' => '…', 'status' => 'stopped after ' . $limit_seconds . ' s']; break; }
        }
        return $out;
    }

    /** Signature scan for obfuscated / backdoor-style PHP under a directory of the WordPress installation. */
    public static function scan_suspicious($dir = '', $limit = 400, $limit_seconds = 150) {
        $root = self::wp_root();
        if ($dir === '') $dir = self::rel_to($root, self::content_dir());
        // The folder may come from the request. It is resolved (../ and symlinks) and must lie inside WordPress, wp-content or uploads.
        $base = preg_match('~^(/|[A-Za-z]:[\\\\/])~', $dir) ? wp_normalize_path($dir) : $root . '/' . ltrim($dir, '/');
        if (!file_exists($base)) return new WP_Error('nodir', __('Folder not found:', 'aguard-safe') . ' ' . $dir);
        if (!self::is_inside($base, $root) && !self::is_inside($base, self::content_dir()) && !self::is_inside($base, self::uploads_dir())) return new WP_Error('nodir', __('Folder outside the allowed area:', 'aguard-safe') . ' ' . $dir);
        $base = rtrim(wp_normalize_path(realpath($base)), '/');
        if (!is_dir($base)) return new WP_Error('nodir', __('Folder not found:', 'aguard-safe') . ' ' . $dir);
        return self::scan_dir($base, $root, $dir, $limit, $limit_seconds);
    }

    /** Signs the code scan looks for: name => pattern. The file viewer marks the same lines. */
    public static function code_signs() {
        return [
            'eval(' => '~\beval\s*\(~', 'base64_decode(' => '~\bbase64_decode\s*\(~', 'gzinflate/gzuncompress' => '~\bgz(inflate|uncompress|decode)\s*\(~', 'str_rot13' => '~\bstr_rot13\s*\(~', 'hex2bin' => '~\bhex2bin\s*\(~',
            'wp_set_auth_cookie(' => '~\bwp_set_auth_cookie\s*\(~', 'wp_signon(' => '~\bwp_signon\s*\(~', 'wp_set_current_user(' => '~\bwp_set_current_user\s*\(~', 'passwordless/one-time login' => '~one[_-]?time[_-]?login|auto[_-]?login|login[_-]?as[_-]?admin|passwordless~i', 'get_users(role=administrator)' => '~get_users\s*\([^;]{0,80}administrator~',
            'create_function' => '~\bcreate_function\s*\(~', 'assert(' => '~\bassert\s*\(~', 'preg_replace /e' => '~preg_replace\s*\(\s*[\'"][^\'"]*/[a-z]*e[a-z]*[\'"]~i', 'system/exec/shell' => '~\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(~',
            'variable function from request' => '~\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(~', 'dynamic call $x($y)' => '~\$[a-zA-Z_]\w*\s*\(\s*\$[a-zA-Z_]\w*\s*\(~', 'long hex string' => '~[\'"][0-9a-f]{120,}[\'"]~', 'chr() chain' => '~(chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}~', 'googlebot check' => '~googlebot~i', 'curl POST to http' => '~CURLOPT_URL~',
        ];
    }

    /** The scan itself. $base is an already validated absolute folder; paths in the result are shown relative to $root. */
    public static function scan_dir($base, $root, $dir, $limit = 400, $limit_seconds = 150) {
        if (function_exists('set_time_limit')) @set_time_limit(300); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a full file scan can take longer than the default limit.
        $sig = self::code_signs();
        $wc = self::rel_to($root, self::content_dir());
        $skip = ["$wc/cache", "$wc/updraft", "$wc/upgrade", self::rel_to($root, self::uploads_dir()) . '/wc-logs', self::rel_to($root, self::lang_dir()), self::rel_to($root, plugin_dir_path(__FILE__))];
        $findings = []; $start = microtime(true); $n = 0;
        $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS), function ($f) use ($root, $skip) {
            $rel = self::rel_to($root, $f->getPathname());
            foreach ($skip as $s) { if (strpos($rel, $s) === 0) return false; }
            return true;
        }), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
        foreach ($it as $f) {
            if (!$f->isFile() || !preg_match('~\.(php|phtml|php\d|phar|inc|ico|htaccess)$~i', $f->getFilename()) && $f->getFilename() !== '.htaccess') continue;
            if (++$n % 200 === 0 && microtime(true) - $start > $limit_seconds) { $findings[] = ['file' => '… stopped after ' . $limit_seconds . ' s (' . $n . ' files)']; break; }
            if ($f->getSize() > 3 * MB_IN_BYTES) continue;
            $c = @file_get_contents($f->getPathname()); if ($c === false) continue;
            $hits = [];
            foreach ($sig as $label => $re) { if (preg_match($re, $c)) $hits[] = $label; }
            if (!$hits) continue;
            $score = count($hits) + (in_array('eval(', $hits, true) ? 2 : 0) + (in_array('long hex string', $hits, true) ? 2 : 0) + (in_array('googlebot check', $hits, true) ? 2 : 0) + (in_array('variable function from request', $hits, true) ? 3 : 0);
            $findings[] = ['file' => self::rel_to($root, $f->getPathname()), 'size' => $f->getSize(), 'mtime' => wp_date('Y-m-d H:i', $f->getMTime()), 'score' => $score, 'hits' => $hits];
            if (count($findings) >= $limit) break;
        }
        usort($findings, function ($a, $b) { return ($b['score'] ?? 0) <=> ($a['score'] ?? 0); });
        return ['dir' => $dir, 'files_scanned' => $n, 'findings' => $findings];
    }

    /** PHP-like files where they should never be (uploads, cache, updraft). */
    public static function scan_uploads($limit_seconds = 40, $light = false) {
        $dirs = [self::uploads_dir(), self::content_dir() . '/cache', self::content_dir() . '/updraft', self::lang_dir(), self::content_dir() . '/upgrade'];
        $qdir = self::quarantine_dir(false) . '/'; $cache = self::content_dir() . '/cache/';
        $found = []; $start = microtime(true); $n = 0;
        $prev = get_option(self::OPT . '_last_scan'); $since = ($light && is_array($prev) && !empty($prev['t'])) ? (int) $prev['t'] - 2 * HOUR_IN_SECONDS : 0; // lengvoje patikroje turinys tikrinamas tik naujesniems failams
        foreach ($dirs as $d) {
            if (!is_dir($d)) continue;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD);
            foreach ($it as $f) {
                if (++$n % 500 === 0 && microtime(true) - $start > $limit_seconds) { $found[] = __('… stopped after', 'aguard-safe') . ' ' . $limit_seconds . ' s'; break 2; }
                if ($since && $f->isFile() && $f->getMTime() < $since && !preg_match('~\.(php\d?|phtml|phar)$~i', $f->getFilename())) continue;
                $name = $f->getFilename();
                if (!$f->isFile()) continue;
                $path = wp_normalize_path($f->getPathname());
                if (strpos($path, $qdir) === 0) continue; // our own quarantine
                // WP Super Cache keeps cached pages as PHP files; LiteSpeed/W3TC keep their own caches too
                if ((strpos($path, $cache) === 0 && preg_match('~^(supercache|blogs|litespeed|object|db|page_enhanced|minify)/~', substr($path, strlen($cache)))) || preg_match('~^(meta-)?wp-cache-[0-9a-f]{32}\.php$~', $name)) continue;
                // ordinary protective stubs and translation files are not findings
                if ($name === '.htaccess' && $f->getSize() < 1200) continue;
                if ($name === 'index.php' && $f->getSize() < 120) continue;
                if (substr($name, -9) === '.l10n.php' && strpos($path, '/languages/') !== false) continue;
                if ((preg_match('~\.(php|phtml|php\d|phar|inc|cgi|pl|py|sh|suspected)(\.|$)~i', $name) || (preg_match('~\.(ico|txt|jpg|png|gif|svg|css|js)$~i', $name) && $f->getSize() < 300000 && self::looks_like_php($f->getPathname())))) {
                    $found[] = self::rel(wp_normalize_path($f->getPathname())) . ' (' . $f->getSize() . ' B, ' . wp_date('Y-m-d H:i', $f->getMTime()) . ')';
                }
            }
        }
        return ['scanned' => $n, 'found' => $found];
    }

    private static function looks_like_php($p) {
        $h = @file_get_contents($p, false, null, 0, 4096);
        return $h !== false && strpos($h, '<?php') !== false;
    }

    /** Files modified in the last N hours under the site (excluding noisy dirs). */
    public static function recent_files($hours = 48, $limit = 300, $limit_seconds = 40) {
        $since = time() - $hours * HOUR_IN_SECONDS; $out = []; $start = microtime(true); $n = 0;
        $root = self::wp_root();
        $wc = self::rel_to($root, self::content_dir()); $up = self::rel_to($root, self::uploads_dir());
        $skip = ["$wc/cache", "$wc/updraft", "$up/wc-logs", "$up/woocommerce_transient_files", "$wc/upgrade", "$wc/et-cache", "$wc/litespeed"];
        $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), function ($f) use ($root, $skip) {
            $rel = self::rel_to($root, $f->getPathname());
            foreach ($skip as $s) { if (strpos($rel, $s) === 0) return false; }
            return true;
        }), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD);
        foreach ($it as $f) {
            if (++$n % 1000 === 0 && microtime(true) - $start > $limit_seconds) { $out[] = ['rel' => __('… stopped after', 'aguard-safe') . ' ' . $limit_seconds . ' s', 'mtime' => 0]; break; }
            if ($f->isFile() && $f->getMTime() >= $since && !preg_match('~\.(log|jpe?g|png|gif|webp|svg|woff2?|ttf|mp4|pdf|zip|gz|avif)$~i', $f->getFilename())) {
                $out[] = ['rel' => self::rel(wp_normalize_path($f->getPathname())), 'size' => $f->getSize(), 'mtime' => $f->getMTime()];
                if (count($out) >= $limit) break;
            }
        }
        usort($out, function ($a, $b) { return $b['mtime'] <=> $a['mtime']; });
        return $out;
    }

    /** Does the site show different content to Google's crawler? */
    public static function check_cloaking() {
        $url = home_url('/?aguard_safe=' . wp_rand(1000, 9999));
        $get = function ($ua) use ($url) {
            $r = wp_remote_get($url, ['timeout' => 25, 'redirection' => 3, 'user-agent' => $ua, 'sslverify' => self::local_sslverify(), 'headers' => ['Cache-Control' => 'no-cache']]);
            if (is_wp_error($r)) return ['error' => $r->get_error_message()];
            $b = (string) wp_remote_retrieve_body($r);
            preg_match('~<title[^>]*>(.*?)</title>~is', $b, $m);
            $code = (int) wp_remote_retrieve_response_code($r); $mit = (string) wp_remote_retrieve_header($r, 'cf-mitigated');
            $out = ['code' => $code, 'title' => trim(html_entity_decode($m[1] ?? '')), 'length' => strlen($b), 'ctype' => wp_remote_retrieve_header($r, 'content-type')];
            if ($code !== 200 || $mit !== '' || stripos($b, 'Just a moment') !== false) $out['error'] = __('response is not 200 or a Cloudflare check (', 'aguard-safe') . $code . ($mit ? ' ' . $mit : '') . __(') – cannot compare', 'aguard-safe');
            return $out;
        };
        $human = $get('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36');
        $gbot  = $get('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $cloaked = empty($human['error']) && empty($gbot['error']) && $human['title'] !== '' && $gbot['title'] !== '' && self::lower($human['title']) !== self::lower($gbot['title']);
        return ['human' => $human, 'googlebot' => $gbot, 'cloaked' => $cloaked];
    }

    /** Kiekvienas žingsnis atskirai: vienas sugedęs (pvz., neskaitomas katalogas) nenutraukia kitų; laiko limitas nustatomas prieš kiekvieną. */
    /** Scan results with failed steps (stored as WP_Error) removed, for code that reads them as arrays. */
    private static function plain($r) {
        if (!is_array($r)) return [];
        foreach ($r as $k => $v) { if (is_object($v)) unset($r[$k]); }
        return $r;
    }
    private static function step($r, $key, $fn) {
        if (function_exists('set_time_limit')) @set_time_limit(120); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a full file scan can take longer than the default limit.
        try { $r[$key] = $fn(); } catch (\Throwable $e) { $r[$key] = new WP_Error('step', get_class($e) . ': ' . $e->getMessage()); }
        return $r;
    }
    public static function run_scan($full = true) {
        $r = ['t' => time()];
        $r = self::step($r, 'sentinels', function () { return self::check_sentinels(); });
        $r = self::step($r, 'admins', function () { return self::check_admins(); });
        $r = self::step($r, 'uploads', function () use ($full) { return self::scan_uploads(40, !$full); });
        if ($full) { $r = self::step($r, 'core', function () { return self::check_core(); }); $r = self::step($r, 'recent', function () { return self::recent_files(48, 100, 30); }); }
        if ($full && !empty(self::opts()['cloak_check'])) $r = self::step($r, 'cloaking', function () { return self::check_cloaking(); });
        $r = self::step($r, 'snippets', function () { return self::check_snippets(); });
        $r = self::step($r, 'remote_admin', function () { return self::check_remote_admin(); });
        if (!empty(self::opts()['block_php_uploads'])) $r = self::step($r, 'uploads_guard', function () { return self::uploads_guard_check(); });
        if (!$full) { $prev = get_option(self::OPT . '_last_scan', []); foreach (['core', 'recent', 'cloaking'] as $k) if (isset($prev[$k]) && !isset($r[$k])) $r[$k] = $prev[$k]; $r['full_t'] = (int) ($prev['full_t'] ?? 0); } else $r['full_t'] = $r['t']; // lengva patikra neištrina paskutinio pilno branduolio rezultato
        update_option(self::OPT . '_last_scan', $r, false);
        return $r;
    }

    /** Rankinė patikra žingsniais iš naršyklės: kiekvienas žingsnis – atskira užklausa (matosi eiga, neužstringa viena ilga užklausa), tarpiniai rezultatai transiente, „finish“ išsaugo ir apdoroja kaip cron. */
    public static function scan_steps() {
        $o = self::opts();
        $st = ['sentinels' => [__('System files (wp-config.php, .htaccess, index.php…)', 'aguard-safe'), 'vientisumas'], 'admins' => [__('List of administrator accounts', 'aguard-safe'), 'prisijungimai'], 'uploads' => [__('PHP files in the upload and cache folders', 'aguard-safe'), 'ugniasiene'], 'core' => [__('WordPress core – every file is compared with the original', 'aguard-safe'), 'vientisumas'], 'recent' => [__('Files changed in the last 48 hours', 'aguard-safe'), 'skenavimas']];
        if (!empty($o['cloak_check'])) $st['cloaking'] = [__('Content for Google\'s crawler and for a regular visitor', 'aguard-safe'), 'srautas'];
        if (self::snippets_present()) $st['snippets'] = [__('PHP snippets (code kept by snippet plugins)', 'aguard-safe'), 'valymas']; // shown only on sites that use such a plugin
        $st['remote_admin'] = [__('Remote management and auto-login tools', 'aguard-safe'), 'pavojaus_signalai'];
        if (!empty($o['block_php_uploads'])) $st['uploads_guard'] = [__('PHP block rules in the upload folders', 'aguard-safe'), 'ugniasiene'];
        return $st;
    }
    private static function nf($n) { return number_format((int) $n, 0, ',', ' '); } // paprastas tarpas – tekstas eina per JSON į textContent
    private static function step_text($k, $v) {
        if (is_wp_error($v)) return ['risk', __('failed:', 'aguard-safe') . ' ' . $v->get_error_message()];
        if (!is_array($v)) return ['info', __('no result', 'aguard-safe')];
        switch ($k) {
            case 'sentinels': if (empty($v['baseline'])) return ['info', __('baseline not created yet', 'aguard-safe')]; $n = count($v['changed']) + count($v['added']) + count($v['removed']); return $n ? ['warn', __('files changed:', 'aguard-safe') . ' ' . $n] : ['ok', __('no changes', 'aguard-safe')];
            case 'admins': $n = count($v['added']) + count($v['removed']); return $n ? ['warn', __('changed: +', 'aguard-safe') . count($v['added']) . ' / −' . count($v['removed'])] : ['ok', __('list unchanged (', 'aguard-safe') . count($v['now'] ?? []) . ')'];
            case 'uploads': return !empty($v['found']) ? ['risk', __('PHP files found:', 'aguard-safe') . ' ' . count($v['found'])] : ['ok', __('no PHP files found, checked', 'aguard-safe') . ' ' . self::nf((int) $v['scanned'])];
            case 'core': $bad = count($v['modified']) + count($v['missing']); if ($bad) return ['risk', __('modified:', 'aguard-safe') . ' ' . count($v['modified']) . __(', missing', 'aguard-safe') . ' ' . count($v['missing']) . __(', unknown', 'aguard-safe') . ' ' . count($v['extra'])]; return $v['extra'] ? ['warn', self::nf((int) $v['checked']) . ' ' . __('files match, unknown:', 'aguard-safe') . ' ' . count($v['extra'])] : ['ok', self::nf((int) $v['checked']) . ' ' . __('files match the original', 'aguard-safe')];
            case 'recent': return ['info', __('modified files:', 'aguard-safe') . ' ' . count($v) . ' ' . __('(Scan → Files)', 'aguard-safe')];
            case 'cloaking': if (!empty($v['human']['error']) || !empty($v['googlebot']['error'])) return ['warn', __('could not compare:', 'aguard-safe') . ' ' . ($v['human']['error'] ?? $v['googlebot']['error'])]; return !empty($v['cloaked']) ? ['risk', __('the crawler is shown different content!', 'aguard-safe')] : ['ok', __('content matches', 'aguard-safe')];
            case 'snippets': if (empty($v['table'])) return ['info', __('no snippet plugin on this site', 'aguard-safe')]; return $v['changed'] ? ['warn', __('snippets changed:', 'aguard-safe') . ' ' . count($v['changed'])] : ['ok', (int) $v['count'] . ' ' . __('snippets, no changes', 'aguard-safe')];
            case 'remote_admin': return !empty($v['found']) ? ['warn', __('found:', 'aguard-safe') . ' ' . implode(', ', array_slice($v['found'], 0, 3))] : ['ok', __('none found', 'aguard-safe')];
            case 'uploads_guard': return !empty($v['missing_real']) ? ['warn', __('rules missing:', 'aguard-safe') . ' ' . count($v['missing_real']) . ' ' . __('(being restored)', 'aguard-safe')] : ['ok', __('rules in place', 'aguard-safe')];
        }
        return ['info', __('done', 'aguard-safe')];
    }
    public static function ajax_scan_step() {
        if (!current_user_can(self::cap()) || !check_ajax_referer('aguard_safe_scan', 'nonce', false)) wp_send_json_error(['msg' => __('no permission or the security key has expired – reload the page', 'aguard-safe')], 403);
        $step = sanitize_key($_POST['step'] ?? ''); $key = 'aguard_safe_scan_' . get_current_user_id(); $t0 = microtime(true);
        if ($step === 'start') {
            global $wp_version; $bl = get_option(self::OPT_BASELINE, []);
            if (!empty($bl['files']) && (string) ($bl['wp'] ?? '') !== (string) $wp_version) self::on_core_updated((string) $wp_version);
            set_transient($key, ['t' => time()], HOUR_IN_SECONDS);
            wp_send_json_success(['step' => 'start', 'state' => 'info', 'text' => __('started', 'aguard-safe') . ' ' . wp_date('H:i:s'), 'ms' => 0]);
        }
        $r = get_transient($key); if (!is_array($r)) wp_send_json_error(['msg' => __('check session not found – start again', 'aguard-safe')]);
        if ($step === 'finish') {
            $r['full_t'] = $r['t']; update_option(self::OPT . '_last_scan', $r, false); delete_transient($key);
            self::process_scan($r, __('Manual check', 'aguard-safe')); $d = self::dashboard(); $n = count($d['issues']);
            wp_send_json_success(['step' => 'finish', 'state' => $d['grade'], 'todo' => $n, 'text' => __('Score', 'aguard-safe') . ' ' . (int) $d['score'] . ' / 100 · ' . ($n ? sprintf(/* translators: %d: number of things to do */ _n('%d thing needs your attention', '%d things need your attention', $n, 'aguard-safe'), $n) : __('no issues found', 'aguard-safe')), 'ms' => (int) round((microtime(true) - $t0) * 1000)]);
        }
        $fns = ['sentinels' => function () { return self::check_sentinels(); }, 'admins' => function () { return self::check_admins(); }, 'uploads' => function () { return self::scan_uploads(40, false); }, 'core' => function () { return self::check_core(); }, 'recent' => function () { return self::recent_files(48, 100, 30); }, 'cloaking' => function () { return self::check_cloaking(); }, 'snippets' => function () { return self::check_snippets(); }, 'remote_admin' => function () { return self::check_remote_admin(); }, 'uploads_guard' => function () { return self::uploads_guard_check(); }];
        if (!isset($fns[$step])) wp_send_json_error(['msg' => __('unknown step', 'aguard-safe')]);
        $r = self::step($r, $step, $fns[$step]); set_transient($key, $r, HOUR_IN_SECONDS);
        [$state, $text] = self::step_text($step, $r[$step]);
        $where = ['admins' => ['tab' => 'sessions'], 'uploads_guard' => ['tab' => 'settings'], 'remote_admin' => ['tab' => 'scan', 'what' => 'remote']];
        $open = in_array($state, ['warn', 'risk'], true) ? html_entity_decode(self::url($where[$step] ?? ['tab' => 'scan', 'what' => $step]), ENT_QUOTES) . ($step === 'uploads_guard' ? '#ag-s-files' : '') : ''; // url() is escaped for HTML, JSON needs the plain address
        wp_send_json_success(['step' => $step, 'state' => $state, 'text' => $text, 'open' => $open, 'ms' => (int) round((microtime(true) - $t0) * 1000)]);
    }

    public static function cron_scan($full = null) {
        global $wp_version;
        $bl = get_option(self::OPT_BASELINE, []);
        if (!empty($bl['files']) && (string) ($bl['wp'] ?? '') !== (string) $wp_version) { self::on_core_updated((string) $wp_version); } // atnaujinimas įvyko be mūsų kabliuko – nekelti aliarmo dėl branduolio failų
        $r = self::run_scan($full === null ? ((int) wp_date('G')) % 6 === 0 : (bool) $full); // pilna patikra (branduolys, nauji failai, cloaking) kas 6 val.; kitomis valandomis – lengva; rankinis mygtukas – visada pilna
        self::process_scan($r);
        self::vuln_refresh();
    }

    /** Patikros rezultatų apdorojimas (pranešimai, parašai, įvykis) – bendras cron'ui ir rankinei patikrai žingsniais. */
    public static function process_scan($r, $label = null) {
        if ($label === null) $label = __('Hourly check', 'aguard-safe');
        $alerts = [];
        foreach (['sentinels', 'admins', 'uploads', 'snippets', 'remote_admin'] as $k) { if (isset($r[$k]) && is_wp_error($r[$k])) { $alerts[__('A check step failed:', 'aguard-safe') . ' ' . $k] = $r[$k]->get_error_message(); } }
        $r = self::plain($r);
        if (is_array($r['sentinels'] ?? null) && ($r['sentinels']['changed'] || $r['sentinels']['added'] || $r['sentinels']['removed'])) {
            $alerts[__('System files changed', 'aguard-safe')] = $r['sentinels'];
            self::build_baseline(); // report each change once
        }
        if (is_array($r['admins'] ?? null) && ($r['admins']['added'] || $r['admins']['removed'])) { $alerts[__('The list of administrators changed', 'aguard-safe')] = ['added' => $r['admins']['added'], 'removed' => $r['admins']['removed']]; }
        if (is_array($r['uploads'] ?? null) && !empty($r['uploads']['found'])) {
            $sig = md5(implode('|', $r['uploads']['found']));
            if (get_option(self::OPT . '_uploads_sig') !== $sig) { $alerts[__('PHP files in the upload/cache folders', 'aguard-safe')] = $r['uploads']['found']; update_option(self::OPT . '_uploads_sig', $sig, false); }
        }
        if (!empty($r['core']) && !is_wp_error($r['core']) && ($r['core']['modified'] || $r['core']['extra'] || $r['core']['missing'])) {
            $sig = md5(wp_json_encode([$r['core']['modified'], $r['core']['extra'], $r['core']['missing']]));
            if (get_option(self::OPT . '_core_sig') !== $sig) { $alerts[__('WordPress core files do not match the original', 'aguard-safe')] = ['modified' => $r['core']['modified'], 'extra' => $r['core']['extra'], 'missing' => $r['core']['missing']]; update_option(self::OPT . '_core_sig', $sig, false); }
        }
        if (!empty($r['cloaking']['cloaked'])) {
            $alerts[__('Search crawlers are shown different content than visitors (cloaking)', 'aguard-safe')] = $r['cloaking'];
        } elseif (isset($r['cloaking']) && get_option(self::OPT . '_cloak_state') === 'cloaked' && empty($r['cloaking']['human']['error']) && empty($r['cloaking']['googlebot']['error'])) {
            $alerts[__('Cloaking is no longer detected', 'aguard-safe')] = $r['cloaking'];
        }
        if (isset($r['cloaking']) && empty($r['cloaking']['human']['error']) && empty($r['cloaking']['googlebot']['error'])) update_option(self::OPT . '_cloak_state', $r['cloaking']['cloaked'] ? 'cloaked' : 'clean', false);
        if (is_array($r['snippets'] ?? null) && !empty($r['snippets']['table']) && $r['snippets']['changed']) { $alerts[__('PHP snippets changed', 'aguard-safe')] = $r['snippets']['changed']; }
        if (is_array($r['remote_admin'] ?? null) && !empty($r['remote_admin']['found'])) {
            $sig = md5(wp_json_encode($r['remote_admin']['found']));
            if (get_option(self::OPT . '_remote_sig') !== $sig) { $alerts[__('Remote management or auto-login tool detected', 'aguard-safe')] = $r['remote_admin']['found']; update_option(self::OPT . '_remote_sig', $sig, false); }
        } elseif (isset($r['remote_admin']) && is_array($r['remote_admin'])) update_option(self::OPT . '_remote_sig', '', false);
        if (!empty($r['uploads_guard']) && is_array($r['uploads_guard']) && $r['uploads_guard']['missing']) { self::uploads_guard_apply(true, true); if ($r['uploads_guard']['missing_real']) $alerts[__('The PHP execution block in the uploads folder was removed – restored', 'aguard-safe')] = $r['uploads_guard']['missing_real']; }
        $seen = get_option(self::OPT . '_alert_sigs', []); if (!is_array($seen)) $seen = [];
        foreach ($alerts as $title => $data) {
            $sig = md5($title . '|' . wp_json_encode($data));
            $fresh = !isset($seen[$title]) || $seen[$title]['sig'] !== $sig || time() - $seen[$title]['t'] > DAY_IN_SECONDS;
            $e = self::event('scan', $title, $data, $fresh, 'scan_' . $title, DAY_IN_SECONDS);
            if ($e['mailed']) $seen[$title] = ['sig' => $sig, 't' => time()];
        }
        update_option(self::OPT . '_alert_sigs', $seen, false);
        if (!$alerts) self::event('scan', $label . __(': no changes found', 'aguard-safe'), ['sentinel_files' => count(get_option(self::OPT_BASELINE)['files'] ?? [])], false);
    }

    /** Login sessions of privileged users: when, from which IP, which browser (WordPress keeps them up to 14 days). */
    /** "Chrome · Windows" iš User-Agent eilutės. */
    public static function ua_human($ua) {
        if ($ua === '') return __('unknown device', 'aguard-safe');
        $os = __('other OS', 'aguard-safe');
        if (preg_match('~iPhone~', $ua)) $os = 'iPhone'; elseif (preg_match('~iPad~', $ua)) $os = 'iPad'; elseif (preg_match('~Android~', $ua)) $os = 'Android'; elseif (preg_match('~Windows~', $ua)) $os = 'Windows'; elseif (preg_match('~Mac OS X~', $ua)) $os = 'Mac'; elseif (preg_match('~CrOS~', $ua)) $os = 'ChromeOS'; elseif (preg_match('~Linux~', $ua)) $os = 'Linux';
        $br = __('other browser', 'aguard-safe');
        if (preg_match('~Edg/~', $ua)) $br = 'Edge'; elseif (preg_match('~OPR/|Opera~', $ua)) $br = 'Opera'; elseif (preg_match('~SamsungBrowser~', $ua)) $br = 'Samsung Internet'; elseif (preg_match('~Firefox/~', $ua)) $br = 'Firefox'; elseif (preg_match('~Chrome/|CriOS~', $ua)) $br = 'Chrome'; elseif (preg_match('~Safari/~', $ua)) $br = 'Safari'; elseif (preg_match('~curl|python|wp-cli|Go-http~i', $ua)) $br = __('application (not a browser)', 'aguard-safe');
        $mob = preg_match('~Mobile|Android|iPhone~', $ua) ? ' ' . __('· phone', 'aguard-safe') : '';
        return $br . ' · ' . $os . $mob;
    }
    public static function role_human($roles) {
        $map = ['administrator' => __('Administrator', 'aguard-safe'), 'editor' => __('Editor', 'aguard-safe'), 'shop_manager' => __('Shop manager', 'aguard-safe'), 'author' => __('Author', 'aguard-safe'), 'contributor' => __('Contributor', 'aguard-safe'), 'subscriber' => __('Subscriber', 'aguard-safe'), 'customer' => __('Customer', 'aguard-safe')];
        return implode(', ', array_map(function ($r) use ($map) { return $map[$r] ?? $r; }, (array) $roles));
    }
    public static function admin_sessions() {
        $out = [];
        $cur_hash = function_exists('wp_get_session_token') ? (function_exists('hash') ? hash('sha256', wp_get_session_token()) : sha1(wp_get_session_token())) : '';
        foreach (get_users(['role__in' => ['administrator', 'editor', 'shop_manager', 'author']]) as $u) {
            $raw = get_user_meta($u->ID, 'session_tokens', true);
            $sess = [];
            foreach ((array) $raw as $hash => $sdata) {
                if (!is_array($sdata)) continue;
                if (!empty($sdata['expiration']) && (int) $sdata['expiration'] < time()) continue; // pasibaigusios sesijos – tik WordPress dar nespėjo jų išvalyti
                $sess[] = ['login' => isset($sdata['login']) ? wp_date('Y-m-d H:i:s', $sdata['login']) : null, 'login_t' => (int) ($sdata['login'] ?? 0), 'expiration' => isset($sdata['expiration']) ? wp_date('Y-m-d H:i:s', $sdata['expiration']) : null, 'expiration_t' => (int) ($sdata['expiration'] ?? 0), 'ip' => $sdata['ip'] ?? null, 'ua' => $sdata['ua'] ?? null, 'device' => self::ua_human((string) ($sdata['ua'] ?? '')), 'current' => ($u->ID === get_current_user_id() && $hash === $cur_hash)];
            }
            usort($sess, function ($a, $b) { return strcmp((string) $b['login'], (string) $a['login']); });
            $out[] = ['id' => $u->ID, 'login' => $u->user_login, 'display' => $u->display_name, 'email' => $u->user_email, 'roles' => implode(',', (array) $u->roles), 'role_h' => self::role_human($u->roles), 'registered' => $u->user_registered, 'sessions' => $sess];
        }
        return $out;
    }


    /* ------------------------------------------------------------ response: quarantine, uploads guard, lockdown, extra checks */

    /** Direct filesystem access through the WordPress filesystem class. */
    private static function fs() {
        static $fs = null;
        if ($fs === null) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
            $fs = new WP_Filesystem_Direct(null);
        }
        return $fs;
    }

    /** Writes a file with an explicit mode, so no global filesystem constant is needed. */
    private static function put($file, $contents) {
        $mode = defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : ((int) @fileperms(self::wp_root() . '/index.php') & 0777 | 0644);
        return self::fs()->put_contents($file, $contents, $mode);
    }

    /** Move a file with an explicit mode; never depends on the FS_CHMOD_* constants. */
    private static function mv($from, $to, $mode = 0644) {
        $ok = false;
        try { $ok = (bool) self::fs()->move($from, $to, false); } catch (\Throwable $e) { $ok = false; }
        if (!$ok && is_file($from) && !file_exists($to)) {
            try { $ok = (bool) self::fs()->copy($from, $to, false, $mode); } catch (\Throwable $e) { $ok = false; }
        }
        if ($ok && is_file($to) && file_exists($from)) self::rm($from); // the move fell back to a copy: remove the source
        if (is_file($to) && file_exists($from)) { self::rm($to); return false; } // the source cannot be removed (permissions): undo, report failure
        return $ok && is_file($to);
    }

    private static function rm($f) {
        wp_delete_file($f);
        return !file_exists($f);
    }

    /** Quarantine directory: uploads/aguard-safe/quarantine, closed to direct access. Files are stored with a .quarantine suffix so they cannot be executed. */
    public static function quarantine_dir($create = true) {
        $dir = self::uploads_dir() . '/aguard-safe/quarantine';
        if ($create && !is_dir($dir)) {
            wp_mkdir_p($dir);
            self::put($dir . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n");
            self::put($dir . '/index.php', "<?php // Silence is golden.\n");
            self::put(dirname($dir) . '/index.php', "<?php // Silence is golden.\n");
        }
        return $dir;
    }

    /** May this file be moved to quarantine? true or a reason string. */
    public static function quarantinable($rel) {
        $abs = self::safe_path($rel);
        if (!$abs || !is_file($abs)) return __('File not found.', 'aguard-safe');
        $root = self::wp_root();
        $protected = ["$root/wp-config.php", "$root/wp-load.php", "$root/wp-settings.php", "$root/wp-blog-header.php", "$root/index.php", "$root/.htaccess", "$root/.user.ini"];
        if (in_array($abs, $protected, true)) return __('The site needs this file – restore it from the original instead of quarantining it.', 'aguard-safe');
        if (strpos($abs, $root . '/') !== 0) return __('Only files of the site (the WordPress folder) can be quarantined.', 'aguard-safe');
        if (strpos($abs, self::real_dir(plugin_dir_path(__FILE__)) . '/') === 0) return __('This is an AGuard Safe file.', 'aguard-safe');
        if (strpos($abs, self::quarantine_dir(false) . '/') === 0) return __('The file is already in quarantine.', 'aguard-safe');
        return true;
    }

    /** What a file belongs to: tells the administrator how risky it is to take the file away. */
    public static function file_owner($rel) {
        $abs = self::safe_path($rel); if (!$abs) return ['kind' => 'other', 'name' => '', 'live' => false];
        $in = function ($dir) use ($abs) { $dir = self::real_dir((string) $dir); return ($dir !== '' && strpos($abs, $dir . '/') === 0) ? substr($abs, strlen($dir) + 1) : null; };
        if ($in(self::mu_plugins_dir()) !== null) return ['kind' => 'mu', 'name' => '', 'live' => true];
        $c = $in(self::content_dir()); if ($c !== null && strpos($c, '/') === false && substr($c, -4) === '.php') return ['kind' => 'mu', 'name' => $c, 'live' => true]; // drop-ins: object-cache.php, db.php, advanced-cache.php…
        $r = $in(self::plugins_dir());
        if ($r !== null) {
            $slug = explode('/', $r)[0]; $name = $slug; $live = false;
            if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
            foreach (get_plugins() as $file => $pl) { if ($file === $r || strpos($file, $slug . '/') === 0) { $name = (string) $pl['Name']; if (is_plugin_active($file) || (is_multisite() && is_plugin_active_for_network($file))) $live = true; } }
            return ['kind' => 'plugin', 'name' => $name, 'live' => $live];
        }
        $r = $in(get_theme_root());
        if ($r !== null) { $slug = explode('/', $r)[0]; $t = wp_get_theme($slug); return ['kind' => 'theme', 'name' => $t->exists() ? (string) $t->get('Name') : $slug, 'live' => in_array($slug, [get_stylesheet(), get_template()], true)]; }
        if ($in(self::uploads_dir()) !== null) return ['kind' => 'uploads', 'name' => '', 'live' => false];
        $root = self::wp_root(); $r = $in($root);
        if ($r !== null && (strpos($r, 'wp-admin/') === 0 || strpos($r, 'wp-includes/') === 0 || (strpos($r, '/') === false && preg_match('~^(wp-[a-z-]+|xmlrpc)\.php$~', $r)))) return ['kind' => 'core', 'name' => 'WordPress', 'live' => true];
        return ['kind' => 'other', 'name' => '', 'live' => false];
    }

    /** Answers the self-test with the random value it sent. A page cache cannot fake that, so the answer proves that PHP and all plugins really loaded. */
    public static function probe_ping() {
        $t = isset($_POST['t']) ? substr(sanitize_key(wp_unslash($_POST['t'])), 0, 32) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- a public echo of a random value, changes nothing.
        wp_die('ag:' . esc_html($t), '', ['response' => 200]);
    }

    /** Marks a self-test request of the home page, so a copy served from a cache can be told apart from a live answer. */
    public static function probe_header() {
        if (isset($_GET['aguard_safe']) && !headers_sent()) header('X-AGuard-Probe: ' . (string) absint(wp_unslash($_GET['aguard_safe']))); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- echoes digits of a self-test marker.
    }

    /**
     * Is the site alive? Two requests that a page cache cannot answer for PHP:
     * 'core' – POST to admin-ajax.php, WordPress with all plugins and the theme functions must load and echo a random value;
     * 'home' – the home page with a random marker; 'home_live' is true only when the answer carries the marker back (not a cached copy).
     * Codes: 200 = fine, 0 = no answer.
     */
    public static function site_probe() {
        $args = ['timeout' => 15, 'redirection' => 2, 'user-agent' => 'Mozilla/5.0 AGuardSafe-selftest', 'sslverify' => self::local_sslverify(), 'headers' => ['Cache-Control' => 'no-cache', 'Pragma' => 'no-cache'], 'cookies' => []];
        $t = strtolower(wp_generate_password(16, false));
        $r = wp_remote_post(admin_url('admin-ajax.php'), $args + ['body' => ['action' => 'aguard_safe_ping', 't' => $t]]);
        $core = is_wp_error($r) ? 0 : (int) wp_remote_retrieve_response_code($r);
        if ($core === 200 && strpos((string) wp_remote_retrieve_body($r), 'ag:' . $t) === false) $core = 1; // answered, but not by this WordPress
        $m = (string) wp_rand(100000, 999999);
        $r = wp_remote_get(home_url('/?aguard_safe=' . $m), $args);
        $home = is_wp_error($r) ? 0 : (int) wp_remote_retrieve_response_code($r);
        return ['core' => $core, 'home' => $home, 'home_live' => !is_wp_error($r) && (string) wp_remote_retrieve_header($r, 'x-aguard-probe') === $m];
    }

    /** Compares the self-test before and after a change: 'broken' – it worked and now answers with an error; 'ok' – a live answer both times; 'unknown' – nothing could be proved. */
    public static function probe_verdict($before, $after) {
        foreach (['core', 'home'] as $k) { if ($before[$k] === 200 && $after[$k] >= 500) return 'broken'; } // a fatal error answers 500; a timeout or a rate limit is not proof
        $core_ok = $before['core'] === 200 && $after['core'] === 200;
        $home_ok = $before['home'] === 200 && $after['home'] === 200 && $after['home_live'];
        return ($core_ok && $home_ok) ? 'ok' : ($core_ok ? 'core_only' : 'unknown');
    }

    /**
     * The official original of a file, when there is one: WordPress core or a plugin from the WordPress.org directory.
     * Returns null for anything else. 'same' tells whether the file on the site already matches the original.
     */
    public static function original_info($rel) {
        $abs = self::safe_path($rel); if (!$abs || !is_file($abs)) return null;
        $own = self::file_owner($rel);
        if ($own['kind'] === 'core') {
            global $wp_version;
            if (!function_exists('get_core_checksums')) require_once ABSPATH . 'wp-admin/includes/update.php';
            $path = ltrim(substr($abs, strlen(self::wp_root())), '/');
            $ck = 'aguard_safe_osum_' . md5($wp_version); $sums = get_transient($ck);
            if (!is_array($sums)) { $sums = get_core_checksums($wp_version, 'en_US'); if (is_array($sums)) set_transient($ck, $sums, DAY_IN_SECONDS); }
            if (!is_array($sums) || empty($sums[$path])) return null;
            return ['of' => 'WordPress ' . $wp_version, 'url' => 'https://core.svn.wordpress.org/tags/' . rawurlencode($wp_version) . '/' . str_replace('%2F', '/', rawurlencode($path)), 'algo' => 'md5', 'sums' => [(string) $sums[$path]], 'same' => md5_file($abs) === $sums[$path]];
        }
        if ($own['kind'] !== 'plugin') return null;
        if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $r = ltrim(substr($abs, strlen(self::plugins_dir())), '/'); $slug = explode('/', $r)[0]; $path = substr($r, strlen($slug) + 1);
        if ($path === '' || $path === false) return null;
        $ver = ''; foreach (get_plugins() as $file => $pl) { if (strpos($file, $slug . '/') === 0) $ver = (string) $pl['Version']; }
        if ($ver === '' || !preg_match('~^[A-Za-z0-9._-]+$~', $ver)) return null;
        $ck = 'aguard_safe_osum_' . md5($slug . '|' . $ver); $files = get_transient($ck);
        if (!is_array($files)) {
            $res = wp_remote_get('https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($ver) . '.json', ['timeout' => 15]);
            $j = (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) ? json_decode(wp_remote_retrieve_body($res), true) : null;
            $files = is_array($j['files'] ?? null) ? $j['files'] : [];
            set_transient($ck, $files, $files ? DAY_IN_SECONDS : 10 * MINUTE_IN_SECONDS);
        }
        if (empty($files[$path])) return null;
        $algo = !empty($files[$path]['sha256']) ? 'sha256' : 'md5'; $sums = array_map('strval', (array) ($files[$path][$algo] ?? []));
        if (!$sums) return null;
        return ['of' => $own['name'] . ' ' . $ver, 'url' => 'https://plugins.svn.wordpress.org/' . rawurlencode($slug) . '/tags/' . rawurlencode($ver) . '/' . str_replace('%2F', '/', rawurlencode($path)), 'algo' => $algo, 'sums' => $sums, 'same' => in_array(hash_file($algo, $abs), $sums, true)];
    }

    /** Downloads the official original and returns its text only when the checksum matches the one published by WordPress.org. */
    /** Side-by-side table of the changed places only, with three lines around each. */
    public static function diff_table($left, $right) {
        if (!class_exists('WP_Text_Diff_Renderer_Table', false)) require ABSPATH . WPINC . '/wp-diff.php';
        $l = explode("\n", str_replace(["\r\n", "\r"], "\n", (string) $left));
        $r = explode("\n", str_replace(["\r\n", "\r"], "\n", (string) $right));
        $renderer = new class(['show_split_view' => true, 'leading_context_lines' => 3, 'trailing_context_lines' => 3]) extends WP_Text_Diff_Renderer_Table {
            public function _startBlock($header) {
                $n = preg_match('/[acd](\d+)/', (string) $header, $m) ? (int) $m[1] : 0;
                /* translators: %d: line number in the file */
                return '<tr><td colspan="2" class="ag-diff-at">' . esc_html(sprintf(__('From line %d', 'aguard-safe'), $n)) . "</td></tr>\n";
            }
        };
        $rows = $renderer->render(new Text_Diff($l, $r));
        if (!$rows) return '';
        return '<table class="diff is-split-view"><tbody>' . $rows . '</tbody></table>';
    }

    public static function original_fetch($o) {
        $res = wp_remote_get($o['url'], ['timeout' => 30, 'redirection' => 0, 'limit_response_size' => 8 * MB_IN_BYTES]);
        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) return new WP_Error('q', __('Could not download the original from WordPress.org. The file was left as it is.', 'aguard-safe'));
        $body = (string) wp_remote_retrieve_body($res);
        if (!in_array(hash($o['algo'], $body), $o['sums'], true)) return new WP_Error('q', __('The downloaded file does not match the official checksum, so it was not used. The file was left as it is.', 'aguard-safe'));
        return $body;
    }

    /**
     * Replaces a changed file with the official original. The download is accepted only when its checksum matches the one published by WordPress.org.
     * The current file is not deleted: it goes to quarantine and can be restored.
     */
    public static function replace_with_original($rel) {
        $o = self::original_info($rel);
        if (!$o) return new WP_Error('q', __('There is no official original for this file.', 'aguard-safe'));
        if ($o['same']) return new WP_Error('q', __('The file already matches the original.', 'aguard-safe'));
        $body = self::original_fetch($o);
        if (is_wp_error($body)) return $body;
        $abs = self::safe_path($rel); $mode = (int) @fileperms($abs) & 0777; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable permissions fall back to the default below.
        $before = self::site_probe();
        $q = self::quarantine_file($rel);
        if (is_wp_error($q)) return $q;
        if (!self::put($abs, $body)) { self::restore_quarantined($q['id']); return new WP_Error('q', __('Could not write the original (permissions?). The file was left as it is.', 'aguard-safe')); }
        if ($mode) self::fs()->chmod($abs, $mode);
        if (function_exists('opcache_invalidate')) @opcache_invalidate($abs, true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- opcache may be restricted on the host.
        self::baseline_touch($abs);
        $after = self::site_probe(); $v = self::probe_verdict($before, $after);
        if ($v === 'broken') { self::rm($abs); $back = self::restore_quarantined($q['id']); return new WP_Error('q', __('With the original in place the site started answering with an error, so the previous file was put back.', 'aguard-safe') . (is_wp_error($back) ? ' ' . $back->get_error_message() : '')); }
        self::event('quarantine', __('File replaced with the original from WordPress.org:', 'aguard-safe') . ' ' . $q['rel'], ['original_of' => $o['of'], 'previous_file_kept' => $q['dest'], 'previous_sha256' => $q['sha256']], true, 'r_' . $q['id']);
        return ['rel' => $q['rel'], 'of' => $o['of'], 'verdict' => $v];
    }

    public static function quarantine_file($rel) {
        $ok = self::quarantinable($rel);
        if ($ok !== true) return new WP_Error('q', $ok);
        $abs = self::safe_path($rel); $qdir = self::quarantine_dir(true);
        if (!is_dir($qdir) || !wp_is_writable($qdir)) return new WP_Error('q', __('The quarantine folder is not writable:', 'aguard-safe') . ' ' . $qdir);
        $id = wp_date('Ymd-His') . '-' . substr(md5($abs . microtime(true)), 0, 6);
        $dest = $qdir . '/' . $id . '__' . preg_replace('~[^A-Za-z0-9._-]+~', '_', self::rel($abs)) . '.quarantine';
        $entry = ['id' => $id, 'orig' => $abs, 'rel' => self::rel($abs), 'dest' => $dest, 'sha256' => hash_file('sha256', $abs), 'size' => filesize($abs), 'mtime' => filemtime($abs), 'perms' => substr(sprintf('%o', fileperms($abs)), -4), 't' => time(), 'who' => self::who()];
        if (!self::mv($abs, $dest, 0600)) return new WP_Error('q', __('Could not move the file (permissions?).', 'aguard-safe'));
        self::fs()->chmod($dest, 0600);
        $list = get_option(self::OPT_Q, []); if (!is_array($list)) $list = [];
        $list[$id] = $entry; update_option(self::OPT_Q, $list, false);
        self::event('quarantine', __('File moved to quarantine:', 'aguard-safe') . ' ' . $entry['rel'], ['sha256' => $entry['sha256'], 'size' => $entry['size'], 'dest' => $dest], true, 'q_' . $id);
        return $entry;
    }

    public static function restore_quarantined($id) {
        $list = get_option(self::OPT_Q, []); $q = $list[$id] ?? null;
        if (!$q) return new WP_Error('q', __('Entry not found.', 'aguard-safe'));
        if (!is_file($q['dest'])) return new WP_Error('q', __('The quarantined file no longer exists.', 'aguard-safe'));
        $orig = wp_normalize_path((string) $q['orig']);
        if (strpos($orig, self::wp_root() . '/') !== 0 || strpos($orig, '/../') !== false) return new WP_Error('q', __('Only files of the site (the WordPress folder) can be quarantined.', 'aguard-safe'));
        if (file_exists($q['orig'])) return new WP_Error('q', __('A file already exists at the original location – remove it first.', 'aguard-safe'));
        if (hash_file('sha256', $q['dest']) !== $q['sha256']) return new WP_Error('q', __('The checksum of the quarantined file does not match – the file was changed.', 'aguard-safe'));
        wp_mkdir_p(dirname($q['orig']));
        $mode = (int) octdec((string) ($q['perms'] ?? '')) & 0777; if (!$mode) $mode = 0644;
        if (!self::mv($q['dest'], $q['orig'], $mode)) return new WP_Error('q', __('Could not restore the file.', 'aguard-safe'));
        self::fs()->chmod($q['orig'], $mode);
        $list[$id]['restored'] = time(); update_option(self::OPT_Q, $list, false);
        self::event('quarantine', __('File restored from quarantine:', 'aguard-safe') . ' ' . $q['rel'], ['sha256' => $q['sha256']], true, 'qr_' . $id);
        return $q;
    }

    /** Directories that must never execute PHP. */
    public static function uploads_guard_targets() {
        $out = [];
        foreach ((array) apply_filters('aguard_safe_guard_targets', [self::uploads_dir()]) as $d) { if (is_string($d) && is_dir($d)) $out[] = rtrim(wp_normalize_path($d), '/'); }
        return $out;
    }

    private static function uploads_guard_block() {
        return self::HT_BEGIN . "\n# No PHP/CGI execution in this directory (managed by AGuard Safe)\n<FilesMatch \"\\.(php|phtml|php[0-9]|phar|pl|py|cgi|sh)(\\.|$)\">\n  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n  <IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n  </IfModule>\n</FilesMatch>\n" . self::HT_END . "\n";
    }

    /** Add or remove our .htaccess block in the uploads folder (existing rules are preserved; the original is copied to the quarantine folder). */
    public static function uploads_guard_apply($on, $silent = false) {
        $res = [];
        foreach (self::uploads_guard_targets() as $d) {
            $f = "$d/.htaccess"; $cur = is_file($f) ? (string) file_get_contents($f) : '';
            $has = strpos($cur, self::HT_BEGIN) !== false;
            if ($on && !$has) {
                if ($cur !== '') @copy($f, self::quarantine_dir(true) . '/' . wp_date('Ymd-His') . '__' . preg_replace('~[^A-Za-z0-9._-]+~', '_', self::rel($f)) . '.bak');
                $ok = self::put($f, self::uploads_guard_block() . ($cur !== '' ? "\n" . ltrim($cur) : ''));
                $res[self::rel($f)] = $ok ? __('written', 'aguard-safe') : __('FAILED to write', 'aguard-safe');
            } elseif (!$on && $has) {
                $new = preg_replace('~' . preg_quote(self::HT_BEGIN, '~') . '.*?' . preg_quote(self::HT_END, '~') . "\n?~s", '', $cur);
                $ok = trim($new) === '' ? self::rm($f) : self::put($f, ltrim($new));
                $res[self::rel($f)] = $ok ? __('removed', 'aguard-safe') : __('FAILED to remove', 'aguard-safe');
            } else $res[self::rel($f)] = $on ? __('already there', 'aguard-safe') : __('was not there', 'aguard-safe');
            self::baseline_touch($f);
        }
        if (!$silent) self::event('settings', ($on ? __('Enabled', 'aguard-safe') : __('Disabled', 'aguard-safe')) . ' ' . __('PHP execution block in the uploads folder', 'aguard-safe'), $res, true);
        return $res;
    }

    public static function uploads_guard_check() {
        $present = $missing = [];
        foreach (self::uploads_guard_targets() as $d) { $f = "$d/.htaccess"; if (is_file($f) && strpos((string) file_get_contents($f), self::HT_BEGIN) !== false) $present[] = self::rel($f); else $missing[] = self::rel($f); }
        // wp-content/upgrade is emptied by WordPress on every update – a missing rule there is expected and re-added silently
        $real = array_values(array_filter($missing, function ($f) { return strpos($f, '/upgrade/') === false; }));
        return ['enabled' => !empty(self::opts()['block_php_uploads']), 'present' => $present, 'missing' => $missing, 'missing_real' => $real];
    }

    /** Drop a harmless PHP file into uploads and try to execute it over HTTP: proves whether the guard works on this server. */
    public static function uploads_guard_verify() {
        $up = wp_upload_dir(); $name = 'aguard-safe-test-' . wp_generate_password(10, false) . '.php';
        $dir = self::uploads_dir() . '/aguard-safe'; wp_mkdir_p($dir);
        $path = $dir . '/' . $name;
        if (!self::put($path, "<?php echo 'AGS_EXEC_' . 'OK';")) return ['blocked' => null, 'error' => esc_html__('could not create the test file', 'aguard-safe')];
        $url = rtrim($up['baseurl'], '/') . '/aguard-safe/' . $name;
        $r = wp_remote_get($url, ['timeout' => 15, 'sslverify' => self::local_sslverify(), 'redirection' => 0, 'headers' => ['Cache-Control' => 'no-cache']]);
        self::rm($path);
        if (is_wp_error($r)) return ['blocked' => null, 'url' => $url, 'error' => $r->get_error_message()];
        $code = wp_remote_retrieve_response_code($r); $body = (string) wp_remote_retrieve_body($r);
        $executed = strpos($body, 'AGS_EXEC_OK') !== false;
        return ['blocked' => !$executed, 'executed' => $executed, 'http' => $code, 'url' => $url];
    }

    /**
     * PHP and script snippets kept in the database or in files by the snippet plugins: Code Snippets, WPCode, Woody Code Snippets,
     * Header Footer Code Manager, Insert PHP Code Snippet, FluentSnippets. Such code runs on every page and is a common hiding place.
     * Returns [source names, items]; an item key is "Source:id".
     */
    private static function snippet_items() {
        static $res = null; if ($res !== null) return $res;
        global $wpdb; $src = []; $items = [];
        $pick = function ($row, $names) { foreach ($names as $n) { if (array_key_exists($n, $row)) return (string) $row[$n]; } return ''; };
        foreach (['snippets' => 'Code Snippets', 'hfcm_scripts' => 'Header Footer Code Manager', 'xyz_ips_short_code' => 'Insert PHP Code Snippet'] as $t => $label) {
            $table = $wpdb->prefix . $t;
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) continue; // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one lookup per request, nothing to cache.
            $src[] = $label;
            foreach ($wpdb->get_results($wpdb->prepare('SELECT * FROM %i LIMIT 2000', $table), ARRAY_A) ?: [] as $row) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read for comparison with the previous check.
                $id = $pick($row, ['id', 'script_id']); $code = $pick($row, ['code', 'snippet', 'content']);
                $items[$label . ':' . $id] = ['name' => $pick($row, ['name', 'title']), 'active' => $pick($row, ['active', 'status']), 'h' => md5($code), 'len' => strlen($code)];
            }
        }
        foreach (['wpcode' => 'WPCode', 'wbcr-snippets' => 'Woody Code Snippets'] as $pt => $label) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT ID, post_title, post_status, MD5(post_content) AS h, LENGTH(post_content) AS len FROM {$wpdb->posts} WHERE post_type = %s AND post_status NOT IN ('auto-draft', 'inherit') LIMIT 2000", $pt), ARRAY_A) ?: []; // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read for comparison with the previous check.
            if (!$rows && !post_type_exists($pt)) continue;
            $src[] = $label;
            foreach ($rows as $row) $items[$label . ':' . $row['ID']] = ['name' => (string) $row['post_title'], 'active' => $row['post_status'] === 'publish' ? '1' : '0', 'h' => (string) $row['h'], 'len' => (int) $row['len']];
        }
        $fdir = self::content_dir() . '/fluent-snippets';
        if (is_dir($fdir)) {
            $src[] = 'FluentSnippets';
            foreach (glob($fdir . '/*.php') ?: [] as $f) { if (basename($f) === 'index.php') continue; $items['FluentSnippets:' . basename($f)] = ['name' => basename($f), 'active' => '1', 'h' => (string) md5_file($f), 'len' => (int) filesize($f)]; }
        }
        return $res = [$src, $items];
    }

    /** Does this site keep code in a snippet plugin? Without one the step has nothing to check and is not shown. */
    public static function snippets_present() {
        return (bool) self::snippet_items()[0];
    }

    public static function check_snippets() {
        [$src, $now] = self::snippet_items();
        if (!$src) return ['table' => null, 'changed' => []];
        $prev = get_option(self::OPT . '_snippets', null);
        // up to 1.9 only Code Snippets was watched and the keys were bare ids
        if (is_array($prev)) { $up = []; foreach ($prev as $id => $r) $up[strpos((string) $id, ':') === false ? 'Code Snippets:' . $id : (string) $id] = $r; $prev = $up; }
        $known = get_option(self::OPT . '_snippet_src', null); if (!is_array($known)) $known = is_array($prev) ? ['Code Snippets'] : [];
        $changed = [];
        if (is_array($prev)) {
            foreach ($now as $id => $r) {
                $sname = strstr((string) $id, ':', true);
                if (!isset($prev[$id])) { if (in_array($sname, $known, true)) $changed[] = __('NEW', 'aguard-safe') . " $id {$r['name']} (active={$r['active']}, {$r['len']} B)"; } // a source seen for the first time is only remembered
                elseif ($prev[$id]['h'] !== $r['h']) $changed[] = __('CHANGED', 'aguard-safe') . " $id {$r['name']} ({$prev[$id]['len']}→{$r['len']} B, active={$r['active']})";
                elseif ((string) $prev[$id]['active'] !== (string) $r['active']) $changed[] = __('STATUS', 'aguard-safe') . " $id {$r['name']}: active {$prev[$id]['active']}→{$r['active']}";
            }
            foreach ($prev as $id => $r) { if (!isset($now[$id])) $changed[] = __('DELETED', 'aguard-safe') . " $id {$r['name']}"; }
        }
        update_option(self::OPT . '_snippets', $now, false); update_option(self::OPT . '_snippet_src', $src, false);
        return ['table' => implode(', ', $src), 'count' => count($now), 'active' => count(array_filter($now, function ($r) { return (string) $r['active'] === '1'; })), 'changed' => $changed, 'first_run' => !is_array($prev)];
    }

    /** Plugins/options that let someone log in as administrator without a password (remote management panels, auto-login tools). */
    public static function check_remote_admin() {
        $found = [];
        $pat = ['iwp-client' => 'InfiniteWP client', 'worker/init.php' => 'ManageWP Worker', 'mainwp-child' => 'MainWP Child', 'wp-remote' => 'WP Remote', 'autologin' => __('auto-login plugin', 'aguard-safe'), 'temporary-login' => __('temporary login plugin', 'aguard-safe'), 'one-time-login' => __('one-time login plugin', 'aguard-safe'), 'login-as' => __('login-as plugin', 'aguard-safe'), 'user-switching' => 'User Switching', 'wp-file-manager' => __('WP File Manager (file manager in the browser)', 'aguard-safe'), 'backwpup' => null];
        foreach ((array) get_option('active_plugins', []) as $p) { foreach ($pat as $k => $label) { if ($label && stripos($p, $k) !== false) $found[] = "$label ($p)"; } }
        $uc = get_option('updraft_central_localkeys'); if (is_array($uc) && $uc) $found[] = __('UpdraftCentral remote control (', 'aguard-safe') . count($uc) . ' ' . __('key(s))', 'aguard-safe');
        $jp = get_option('jetpack_options'); if (is_array($jp) && !empty($jp['id'])) $found[] = __('Jetpack connected to WordPress.com (SSO/remote management possible)', 'aguard-safe');
        return ['found' => array_values(array_unique($found))];
    }

    /** Lockdown: kick everyone else out, force password resets, freeze plugin/theme changes and registration. */
    public static function lockdown($on) {
        $o = self::opts();
        if ($on) {
            $me = get_current_user_id(); $kicked = []; $reset = [];
            foreach (get_users(['role__in' => ['administrator', 'editor', 'shop_manager', 'author', 'contributor']]) as $u) {
                if ($u->ID === $me) continue;
                WP_Session_Tokens::get_instance($u->ID)->destroy_all(); delete_user_meta($u->ID, 'aguard_safe_trusted'); $kicked[] = $u->user_login;
                if (in_array('administrator', (array) $u->roles, true) && function_exists('retrieve_password')) { $r = retrieve_password($u->user_login); $reset[] = $u->user_login . (is_wp_error($r) ? ' ' . __('(e-mail failed)', 'aguard-safe') : ''); }
            }
            $o['lockdown'] = ['t' => time(), 'by' => self::who()];
            update_option(self::OPT, $o, true); self::$opts = null;
            $res = ['sessions_destroyed' => $kicked, 'password_reset_sent' => $reset];
            self::event('lockdown', __('LOCKDOWN enabled', 'aguard-safe'), $res, true, 'lockdown_on_' . time());
            return $res;
        }
        $o['lockdown'] = 0; update_option(self::OPT, $o, true); self::$opts = null;
        self::event('lockdown', __('LOCKDOWN disabled', 'aguard-safe'), [], true, 'lockdown_off_' . time());
        return true;
    }

    public static function lockdown_notice() {
        if (!current_user_can(self::cap())) return;
        echo '<div class="notice notice-error"><p><strong>AGuard Safe LOCKDOWN</strong>' . esc_html__(': installing, updating and editing plugins/themes and registration are temporarily disabled.', 'aguard-safe') . ' <a href="' . esc_url(admin_url('admin.php?page=aguard-safe')) . '">' . esc_html__('Manage', 'aguard-safe') . '</a></p></div>';
    }


    /* ------------------------------------------------------------ overview (plain-language dashboard) */

    /** Skydelio kortelė šalia Wordfence: būklė, paskutinė patikra, prisijungimai, 3 paskutiniai įvykiai. */
    public static function dashboard_widget_register() {
        if (!current_user_can(self::cap())) return;
        wp_add_dashboard_widget('aguard_safe_widget', 'AGuard Safe', [__CLASS__, 'dashboard_widget'], null, null, 'normal', 'high');
        // First in the left column, also when other plugins add their own "high" widgets. An order the user set by dragging is kept by WordPress.
        global $wp_meta_boxes;
        if (isset($wp_meta_boxes['dashboard']['normal']['high']['aguard_safe_widget'])) { $mine = $wp_meta_boxes['dashboard']['normal']['high']['aguard_safe_widget']; unset($wp_meta_boxes['dashboard']['normal']['high']['aguard_safe_widget']); $wp_meta_boxes['dashboard']['normal']['high'] = ['aguard_safe_widget' => $mine] + $wp_meta_boxes['dashboard']['normal']['high']; } // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- only the order of the dashboard widgets is changed.
    }
    public static function dashboard_widget() {
        try {
            $d = self::dashboard(); $o = self::opts();
            $g = $d['grade']; $last = (int) $d['last_scan']; $f = $d['files']; $a = $d['access']; $n = count($d['issues']);
            $home = self::url([]);
            /* translators: %d: number of things */
            $head = $n ? sprintf(_n('%d thing needs your attention', '%d things need your attention', $n, 'aguard-safe'), $n) : __('Protection is working', 'aguard-safe');
            /* translators: %s: time span, e.g. 5 mins */
            $when = $last ? sprintf(__('Last check %s ago', 'aguard-safe'), human_time_diff($last)) : __('No automatic check has run yet', 'aguard-safe');
            // hero: score, headline, the knight
            echo '<div class="agw-hero"><div class="agw-score agw-' . esc_attr($g) . '" style="--agw-p:' . (int) $d['score'] . '%"><b>' . (int) $d['score'] . '</b></div><div class="agw-ht"><b>' . esc_html($head) . '</b><span>' . esc_html($when) . ' · ' . esc_html__('score out of 100', 'aguard-safe') . '</span><a class="agw-btn" href="' . esc_url($home) . '">' . esc_html__('Open AGuard Safe', 'aguard-safe') . '</a></div><img class="agw-knight" src="' . esc_url(plugin_dir_url(__FILE__) . 'assets/knight-overview.png') . '" alt="" width="101" height="120"></div>';
            // four numbers
            $fv = $f['status'] === 'ok' ? __('match', 'aguard-safe') : ($f['status'] === 'risk' ? __('changed', 'aguard-safe') : (!empty($f['checked']) ? (int) $f['extra'] . ' ' . __('unknown', 'aguard-safe') : '–'));
            $vc = empty($o['vuln_check']) ? null : self::vuln_counts(); $locks = count(self::lockouts());
            $tiles = [
                [__('WordPress files', 'aguard-safe'), $fv, $f['status'], self::url(['tab' => 'scan'])],
                [__('Failed logins today', 'aguard-safe'), (string) (int) $a['failed_today'], $a['status'], self::url(['tab' => 'events', 'type' => 'other'])],
                [__('Addresses blocked now', 'aguard-safe'), (string) $locks, $locks ? 'warn' : 'ok', self::url(['tab' => 'settings'])],
                $vc === null ? [__('Signed-in devices', 'aguard-safe'), (string) (int) $a['sessions'], 'ok', self::url(['tab' => 'sessions'])] : [__('Plugins to update urgently', 'aguard-safe'), (string) (int) $vc['urgent'], $vc['urgent'] ? 'risk' : 'ok', self::url(['tab' => 'plugins'])],
            ];
            echo '<div class="agw-tiles">';
            foreach ($tiles as $t) echo '<a class="agw-tile agw-t-' . esc_attr($t[2]) . '" href="' . esc_url($t[3]) . '"><span>' . esc_html($t[0]) . '</span><b>' . esc_html($t[1]) . '</b></a>';
            echo '</div>';
            // seven days
            $max = 1; foreach ($d['days'] as $day) $max = max($max, (int) $day['events'] + (int) $day['fails']);
            echo '<div class="agw-week"><div class="agw-wh"><b>' . esc_html__('Last 7 days', 'aguard-safe') . '</b><span><i class="agw-k1"></i>' . esc_html__('events', 'aguard-safe') . '<i class="agw-k2"></i>' . esc_html__('failed logins', 'aguard-safe') . '</span></div><div class="agw-bars">';
            foreach ($d['days'] as $date => $day) { $ev = (int) $day['events']; $fl = (int) $day['fails']; $tot = $ev + $fl; echo '<div class="agw-day" title="' . esc_attr($date . ': ' . $ev . ' / ' . $fl) . '"><em>' . ($tot ? (int) $tot : '') . '</em><div class="agw-col"><i class="agw-b2" style="height:' . (int) round($fl / $max * 56) . 'px"></i><i class="agw-b1" style="height:' . (int) round($ev / $max * 56) . 'px"></i></div><span>' . esc_html(wp_date('D', strtotime($date))) . '</span></div>'; }
            echo '</div></div>';
            // what to do
            if ($n) {
                echo '<div class="agw-sec"><b>' . esc_html__('What to do', 'aguard-safe') . '</b>';
                foreach (array_slice($d['issues'], 0, 3) as $it) { $pp = self::issue_parts($it); $lk = self::issue_link($it); echo '<a class="agw-row" href="' . esc_url($lk ? $lk[1] : $home) . '"><i class="agw-dot agw-d-' . esc_attr($it[0]) . '"></i><span>' . esc_html($pp[0]) . '</span><em>→</em></a>'; }
                echo '</div>';
            }
            // recent events
            $events = get_option(self::OPT_EVENTS, []); $events = is_array($events) ? array_values(array_filter($events, function ($e) { return is_array($e) && !empty($e['t']) && (($e['type'] ?? '') !== 'scan' || !empty($e['mailed']) || stripos((string) ($e['title'] ?? ''), __('no changes found', 'aguard-safe')) === false); })) : [];
            usort($events, function ($x, $y) { return (int) $y['t'] <=> (int) $x['t']; });
            if ($events) {
                $emb = ['login' => 'login', 'scan' => 'scan', 'user' => 'user', 'plugin' => 'plugins', 'theme' => 'theme', 'settings' => 'settings', 'quarantine' => 'emergency', 'tools' => 'activity', 'test' => 'settings'];
                echo '<div class="agw-sec"><b>' . esc_html__('Recent events', 'aguard-safe') . '</b>';
                foreach (array_slice($events, 0, 4) as $e) { $ty = (string) ($e['type'] ?? ''); $crit = self::is_critical($ty, (string) ($e['title'] ?? ''), (array) ($e['data'] ?? [])) && !in_array($ty, ['plugin', 'login', 'settings'], true); echo '<div class="agw-row"><span class="agw-sh' . ($crit ? ' agw-sh-risk' : '') . '">' . wp_kses(self::shield($emb[$ty] ?? 'alert', 22), self::svg_kses()) . '</span><span>' . esc_html(function_exists('mb_substr') ? mb_substr((string) $e['title'], 0, 90) : substr((string) $e['title'], 0, 90)) . '</span><time>' . esc_html(wp_date(wp_date('Y-m-d') === wp_date('Y-m-d', (int) $e['t']) ? 'H:i' : 'j M', (int) $e['t'])) . '</time></div>'; }
                echo '<a class="agw-all" href="' . esc_url(self::url(['tab' => 'events'])) . '">' . esc_html__('All events', 'aguard-safe') . ' →</a></div>';
            }
        } catch (\Throwable $e) { echo '<p>' . esc_html__('AGuard Safe: could not show the status (', 'aguard-safe') . esc_html($e->getMessage()) . ').</p>'; }
    }
    public static function dashboard() {
        $last = self::plain(get_option(self::OPT . '_last_scan', [])); $o = self::opts();
        $issues = []; $score = 100;
        $core = $last['core'] ?? null;
        if (is_array($core)) {
            if ($core['modified'] || $core['missing']) { $issues[] = ['risk', __('Modified or missing WordPress core files:', 'aguard-safe') . ' ' . count($core['modified']) . ' / ' . count($core['missing']) . __('. Check them and restore from the original.', 'aguard-safe'), 30, ['tab' => 'scan', 'what' => 'core']]; $score -= 30; }
            if (!empty($core['extra'])) { $issues[] = ['warn', __('The core folders contain', 'aguard-safe') . ' ' . count($core['extra']) . ' ' . __('unknown files:', 'aguard-safe') . ' ' . implode(', ', array_slice($core['extra'], 0, 3)) . (count($core['extra']) > 3 ? '…' : '') . __('. If you know the file, add it to the allowlist.', 'aguard-safe'), 20, count($core['extra']) === 1 ? ['tab' => 'files', 'file' => preg_replace('~ \(.*$~', '', (string) $core['extra'][0])] : ['tab' => 'scan', 'what' => 'core']]; $score -= 20; }
        }
        if (!empty($last['uploads']['found'])) { $issues[] = ['risk', __('Executable PHP files found in the upload/cache folders:', 'aguard-safe') . ' ' . count($last['uploads']['found']) . '.', 20, ['tab' => 'scan', 'what' => 'uploads']]; $score -= 20; }
        if (!empty($last['cloaking']['cloaked'])) { $issues[] = ['risk', __('Google\'s crawler is shown different content than visitors (cloaking) – the site is infected.', 'aguard-safe'), 30, ['tab' => 'scan', 'what' => 'cloaking']]; $score -= 30; }
        if (!empty($last['sentinels']['changed']) || !empty($last['sentinels']['added'])) { $issues[] = ['warn', __('System files changed:', 'aguard-safe') . ' ' . implode(', ', array_slice(array_merge($last['sentinels']['changed'], $last['sentinels']['added']), 0, 3)) . '.', 10, ['tab' => 'scan', 'what' => 'sentinels']]; $score -= 10; }
        if (!empty($last['snippets']['changed'])) { $issues[] = ['warn', __('PHP snippets changed:', 'aguard-safe') . ' ' . implode('; ', array_slice($last['snippets']['changed'], 0, 3)) . '.', 10, 'scan']; $score -= 10; }
        $remote = self::check_remote_admin()['found']; // live – reacts immediately when a plugin is removed
        if ($remote) { $issues[] = ['warn', __('Tools are active that allow managing the site without a password or changing files in the browser:', 'aguard-safe') . ' ' . implode('; ', $remote) . __('. If you do not use them, turn them off.', 'aguard-safe'), 10, 'scan']; $score -= 10; }
        $guard = self::uploads_guard_check();
        if (empty($o['block_php_uploads'])) { $issues[] = ['info', __('PHP execution in the uploads folder is not blocked. Turn it on in Settings – it closes the most common malware route.', 'aguard-safe'), 10, 'settings']; $score -= 10; }
        elseif ($guard['missing_real']) { $issues[] = ['warn', __('The PHP block rule is gone from:', 'aguard-safe') . ' ' . implode(', ', $guard['missing_real']) . ' ' . __('(it will be restored automatically).', 'aguard-safe'), 10, 'scan']; $score -= 10; }
        $pw = empty($o['pw_check']) ? [] : self::pwned_admins();
        /* translators: %s: user logins */
        if ($pw) { $issues[] = ['risk', sprintf(__('An administrator password is in a list of leaked passwords: %s. Change it: attackers try such passwords first.', 'aguard-safe'), implode(', ', $pw)), 20, '']; $score -= 20; }
        $vc = empty(self::opts()['vuln_check']) ? ['urgent' => 0, 'closed' => 0] : self::vuln_counts();
        if ($vc['urgent']) { $issues[] = ['risk', sprintf(/* translators: %d: number of plugins */ _n('%d plugin has a vulnerability that needs an urgent update. Open Plugins.', '%d plugins have vulnerabilities that need an urgent update. Open Plugins.', $vc['urgent'], 'aguard-safe'), $vc['urgent']), 20, 'plugins']; $score -= 20; }
        elseif ($vc['closed']) { $issues[] = ['warn', sprintf(/* translators: %d: number of plugins */ _n('%d installed plugin has been closed on WordPress.org and will get no more updates. Open Plugins.', '%d installed plugins have been closed on WordPress.org and will get no more updates. Open Plugins.', $vc['closed'], 'aguard-safe'), $vc['closed']), 10, 'plugins']; $score -= 10; }
        $last_t = (int) ($last['t'] ?? 0);
        if (!$last_t || time() - $last_t > 3 * HOUR_IN_SECONDS) { $issues[] = ['warn', ($last_t ? sprintf(/* translators: %s: time span */ __('The automatic check has not run for %s', 'aguard-safe'), human_time_diff($last_t)) : __('The automatic check has never run', 'aguard-safe')) . __('. Press “Check now” or check WP-Cron.', 'aguard-safe'), 15, '']; $score -= 15; }
        $admins = count(get_users(['role' => 'administrator', 'fields' => 'ID']));
        $fail_hist = get_option(self::OPT . '_fail_hist', []); if (!is_array($fail_hist)) $fail_hist = [];
        $today = (int) get_transient('aguard_safe_fail_day_' . wp_date('Ymd'));
        $events = get_option(self::OPT_EVENTS, []); $days = [];
        for ($i = 6; $i >= 0; $i--) { $d = wp_date('Y-m-d', time() - $i * DAY_IN_SECONDS); $days[$d] = ['events' => 0, 'alerts' => 0, 'fails' => (int) ($fail_hist[$d] ?? 0)]; }
        $tk = wp_date('Y-m-d'); if (isset($days[$tk])) $days[$tk]['fails'] = max($days[$tk]['fails'], $today); // the per-day transient counted before the 7-day history existed
        foreach ((array) $events as $e) { $d = wp_date('Y-m-d', $e['t']); if (isset($days[$d])) { $days[$d]['events']++; if (!empty($e['mailed'])) $days[$d]['alerts']++; } }
        $sessions = 0; foreach (self::admin_sessions() as $u) $sessions += count($u['sessions']);
        $score = max(0, min(100, $score));
        return ['score' => $score, 'grade' => $score >= 90 ? 'ok' : ($score >= 70 ? 'warn' : 'risk'), 'issues' => $issues, 'last_scan' => $last_t, 'next_scan' => wp_next_scheduled(self::CRON),
            'files' => ['status' => is_array($core) ? (($core['modified'] || $core['missing']) ? 'risk' : ($core['extra'] ? 'warn' : 'ok')) : 'warn', 'checked' => $core['checked'] ?? 0, 'modified' => count($core['modified'] ?? []), 'extra' => count($core['extra'] ?? [])],
            'access' => ['admins' => $admins, 'sessions' => $sessions, 'failed_today' => $today, 'status' => $today >= (int) $o['failed_threshold'] ? 'warn' : 'ok'],
            'protection' => ['guard' => !empty($o['block_php_uploads']) && !$guard['missing_real'], 'lockdown' => !empty($o['lockdown']), 'remote' => count($remote), 'cloak_clean' => empty($last['cloaking']['cloaked']), 'status' => (!empty($o['block_php_uploads']) && !$remote) ? 'ok' : 'warn'],
            'days' => $days, 'quarantine' => count(get_option(self::OPT_Q, []) ?: [])];
    }

    private static function plural($n, $f1, $f2, $f10) { $n = (int) $n; $m = $n % 10; $h = $n % 100; return ($m === 1 && $h !== 11) ? $f1 : (($m >= 2 && $m <= 9 && ($h < 10 || $h > 19)) ? $f2 : $f10); }
    /** Is the first-run step still waiting for an answer? */
    public static function setup_pending() {
        $o = self::opts();
        return empty($o['setup_done']) && (empty($o['block_php_uploads']) || empty($o['vuln_check']) || empty($o['pw_check']));
    }

    /** The first-run step: as a card on the Overview and, until answered, as a window on the plugin screens (again after 12 hours when postponed). */
    public static function setup_card($modal) {
        if (!self::setup_pending()) return;
        $so = self::opts(); $id = $modal ? 'ag-setup-m' : 'ag-setup-c';
        if ($modal) echo '<div class="ag-modal" id="ag-setup-modal" role="dialog" aria-modal="true" aria-labelledby="' . esc_attr($id) . '">';
        echo '<form method="post" class="ag-setup">'; wp_nonce_field('aguard_safe_settings', '_wpnonce', true, true);
        echo '<img class="ag-setup-k" src="' . esc_url(plugin_dir_url(__FILE__) . 'assets/knight-setup.png') . '" alt="" width="169" height="240">';
        echo '<div class="ag-setup-t"><b id="' . esc_attr($id) . '">' . esc_html__('One step to finish the setup', 'aguard-safe') . '</b><span>' . esc_html__('Press the button once and the full protection is on. Each item can be changed later in Settings.', 'aguard-safe') . '</span><ul>';
        if (empty($so['block_php_uploads'])) echo '<li>' . esc_html__('Block PHP execution in the uploads folder', 'aguard-safe') . '</li>';
        if (empty($so['vuln_check'])) echo '<li>' . esc_html__('Check the installed plugins for known vulnerabilities once a day. For that the folder names (slugs) of all installed plugins and their versions are sent to data.aguard.lt.', 'aguard-safe') . '</li>';
        if (empty($so['pw_check'])) echo '<li>' . esc_html__('Check administrator passwords against lists of leaked passwords. The password itself is never sent anywhere.', 'aguard-safe') . '</li>';
        echo '</ul><div class="ag-setup-a"><button class="button button-primary" name="aguard_setup_all" value="1">' . esc_html__('Agree and turn on', 'aguard-safe') . '</button>' . ($modal ? '<button class="button" name="aguard_setup_later" value="1" id="ag-setup-later">' . esc_html__('Remind me later', 'aguard-safe') . '</button>' : '') . '<button class="button-link" name="aguard_setup_skip" value="1">' . esc_html__('Continue without these', 'aguard-safe') . '</button></div>';
        if (empty($so['vuln_check']) || empty($so['pw_check'])) echo '<p class="ag-setup-terms">' . esc_html__('By pressing “Agree and turn on” you accept the', 'aguard-safe') . ' <a href="https://aguard.lt/en/terms" target="_blank" rel="noopener">' . esc_html__('terms', 'aguard-safe') . '</a> ' . esc_html__('and the', 'aguard-safe') . ' <a href="https://aguard.lt/en/privacy" target="_blank" rel="noopener">' . esc_html__('privacy policy', 'aguard-safe') . '</a> ' . esc_html__('of the data.aguard.lt service.', 'aguard-safe') . '</p>';
        echo '</div></form>';
        if ($modal) echo '</div>';
    }

    public static function render_home($d) {
        $word = ['ok' => __('Protection is working', 'aguard-safe'), 'warn' => __('Needs attention', 'aguard-safe'), 'risk' => __('Action required', 'aguard-safe')];
        $g = $d['grade']; $last = (int) $d['last_scan']; $f = $d['files']; $a = $d['access']; $p = $d['protection']; $n = count($d['issues']);
        echo '<div class="ag-home">';
        // status headline
        $sub = ($last ? __('Last check', 'aguard-safe') . ' ' . wp_date('Y-m-d H:i', $last) . ' (' . sprintf(/* translators: %s: time span */ __('%s ago', 'aguard-safe'), human_time_diff($last)) . ')' : __('No automatic check has run yet', 'aguard-safe')) . ($d['next_scan'] ? ', ' . sprintf(/* translators: %s: time span */ __('next in %s', 'aguard-safe'), human_time_diff($d['next_scan'])) : '') . '. ' . ($n ? $n . ' ' . _n('note', 'notes', $n, 'aguard-safe') . (' ' . __('below.', 'aguard-safe')) : __('No issues found.', 'aguard-safe'));
        $tabs = ['scan' => 'scan', 'settings' => 'settings', 'plugins' => 'plugins'];
        /* translators: %d: the security score, 0 to 100 */
        $pop = '<div class="ag-score-pop" id="ag-score-pop" role="tooltip"><b>' . esc_html(sprintf(__('Security score: %d of 100', 'aguard-safe'), (int) $d['score'])) . '</b><p>' . esc_html($n ? __('100 means nothing needs attention. Points taken off:', 'aguard-safe') : __('100 means nothing needs attention.', 'aguard-safe')) . '</p>';
        if ($n) {
            $pop .= '<ul>';
            foreach ($d['issues'] as $it) {
                [$head] = self::issue_parts($it); $to = self::issue_link($it);
                $pop .= '<li><span class="ag-dot ag-dot-' . esc_attr(in_array($it[0], ['warn', 'risk'], true) ? $it[0] : 'idle') . '"></span>' . ($to ? '<a href="' . esc_url($to[1]) . '">' . esc_html($head) . '</a>' : '<span>' . esc_html($head) . '</span>') . '<em>−' . (int) ($it[2] ?? 0) . '</em></li>';
            }
            $pop .= '</ul>';
        }
        $pop .= '</div>';
        echo '<div class="ag-card ag-status"><div class="ag-score-wrap" tabindex="0" aria-describedby="ag-score-pop"><div class="ag-score ag-score-' . esc_attr($g) . '" style="--ag-p:' . (int) max(0, min(100, $d['score'])) . '%"><b>' . (int) $d['score'] . '</b></div><span class="ag-score-cap">' . esc_html__('Score out of 100', 'aguard-safe') . '</span>' . wp_kses_post($pop) . '</div><div><h2>' . esc_html($n ? sprintf(/* translators: %d: number of things to do */ _n('%d thing needs your attention', '%d things need your attention', $n, 'aguard-safe'), $n) : ($word[$g] ?? '')) . '</h2><p>' . esc_html($sub) . '</p></div>';
        echo '<div class="ag-act">' . ($n ? '<a class="button button-primary" id="ag-todo-btn" href="#ag-todo">' . esc_html__('Details', 'aguard-safe') . '</a>' : '') . '<button type="button" class="button' . ($n ? '' : ' button-primary') . '" id="ag-scan-btn">' . esc_html__('Check now', 'aguard-safe') . '</button></div><img class="ag-knight ag-knight-home" src="' . esc_url(plugin_dir_url(__FILE__) . 'assets/knight-overview.png') . '" alt="" width="136" height="140"></div>';
        // scan dialog: what will be checked, progress per step, result
        $ls = self::plain(get_option(self::OPT . '_last_scan', [])); $fullt = (int) ($ls['full_t'] ?? 0);
        echo '<div class="ag-modal" id="ag-scan" hidden><div class="ag-dialog ag-scanbox" role="dialog" aria-modal="true" aria-labelledby="ag-scan-h"><img class="ag-scan-knight" src="' . esc_url(plugin_dir_url(__FILE__) . 'assets/knight-scan.png') . '" alt="" width="96" height="114"><h3 id="ag-scan-h">' . esc_html__('Full check', 'aguard-safe') . '</h3>';
        echo '<p>' . esc_html__('The check goes through', 'aguard-safe') . ' ' . (!empty($f['checked']) ? esc_html(number_format_i18n((int) $f['checked'])) . ' ' . esc_html__('WordPress files,', 'aguard-safe') . ' ' : '') . esc_html__('the upload folders, settings and accounts. It takes from a dozen seconds to a few minutes and the server works harder meanwhile, so it only starts when you press “Start”. A light check runs automatically every hour, a full one every 6 hours.', 'aguard-safe') . ($fullt ? ' ' . esc_html__('Last full check:', 'aguard-safe') . ' ' . esc_html(wp_date('m-d H:i', $fullt)) . '.' : '') . '</p><ul class="ag-steps">';
        foreach (self::scan_steps() as $k => $st) echo '<li data-step="' . esc_attr($k) . '">' . wp_kses(self::icon($st[1], 18), self::svg_kses()) . '<span class="ag-sn">' . esc_html($st[0]) . '</span><span class="ag-sr">' . esc_html__('waiting', 'aguard-safe') . '</span></li>';
        echo '</ul><div class="ag-acts"><button type="button" class="button button-primary" id="ag-scan-go">' . esc_html__('Start the check', 'aguard-safe') . '</button><button type="button" class="button" id="ag-scan-close">' . esc_html__('Close', 'aguard-safe') . '</button><span class="ag-res" id="ag-scan-res"></span></div></div></div>';
        // script: assets/admin.js (enqueued in admin_assets)
        self::setup_card(false);
        // KPI strip
        $fv = !empty($f['checked']) ? ($f['modified'] ? $f['modified'] . ' ' . _n('modified', 'modified', $f['modified'], 'aguard-safe') : ($f['extra'] ? $f['extra'] . ' ' . _n('unknown', 'unknown', $f['extra'], 'aguard-safe') : __('Matches the original', 'aguard-safe'))) : __('Not checked yet', 'aguard-safe');
        if (!empty($f['checked']) && $f['status'] === 'risk' && !$f['modified'] && !$f['extra']) $fv = __('Files are missing', 'aguard-safe');
        $kpi = [
            ['vientisumas', __('WordPress files', 'aguard-safe'), $fv, !empty($f['checked']) ? __('files checked:', 'aguard-safe') . ' ' . number_format_i18n((int) $f['checked']) : __('waiting for a full check', 'aguard-safe'), $f['status'], self::url(['tab' => 'scan'])],
            ['pavojaus_signalai', __('Failed logins', 'aguard-safe'), (string) (int) $a['failed_today'], $a['failed_today'] ? __('today · alert from', 'aguard-safe') . ' ' . (int) self::opts()['failed_threshold'] : __('none today', 'aguard-safe'), $a['status'], self::url(['tab' => 'events'])],
            ['prisijungimai', __('Signed-in devices', 'aguard-safe'), (string) (int) $a['sessions'], __('administrator accounts:', 'aguard-safe') . ' ' . (int) $a['admins'], 'info', self::url(['tab' => 'sessions'])],
            ['valymas', __('Quarantine', 'aguard-safe'), (string) (int) $d['quarantine'], $d['quarantine'] ? _n('isolated file', 'isolated files', $d['quarantine'], 'aguard-safe') : __('no isolated files', 'aguard-safe'), $d['quarantine'] ? 'warn' : 'info', self::url(['tab' => 'quarantine'])],
        ];
        if (!empty(self::opts()['vuln_check'])) {
            $vc = self::vuln_counts();
            /* translators: %d: number of plugins */
            $kpi[3] = ['vientisumas', __('Plugins', 'aguard-safe'), $vc['urgent'] ? sprintf(_n('%d urgent', '%d urgent', $vc['urgent'], 'aguard-safe'), $vc['urgent']) : (string) (int) $vc['vulnerable'], $vc['urgent'] ? __('updates available:', 'aguard-safe') . ' ' . (int) $vc['updates'] : __('with known vulnerabilities:', 'aguard-safe') . ' ' . (int) $vc['vulnerable'] . ' · ' . __('updates available:', 'aguard-safe') . ' ' . (int) $vc['updates'], $vc['urgent'] ? 'risk' : ($vc['vulnerable'] ? 'warn' : 'info'), self::url(['tab' => 'plugins'])];
        }
        echo '<div class="ag-grid">';
        foreach ($kpi as $k) echo '<a class="ag-card ag-kpi" href="' . esc_url($k[5]) . '"><div class="ag-l">' . wp_kses(self::icon($k[0], 20), self::svg_kses()) . esc_html($k[1]) . '</div><div class="ag-v' . esc_attr($k[4] === 'info' ? '' : ' ag-' . $k[4]) . '">' . esc_html($k[2]) . '</div><div class="ag-s">' . esc_html($k[3]) . '</div></a>';
        echo '</div>';
        // what to do
        if ($n) {
            $go = ['scan' => [__('Open Scan', 'aguard-safe'), 'scan'], 'settings' => [__('Open Settings', 'aguard-safe'), 'settings'], 'plugins' => [__('Open Plugins', 'aguard-safe'), 'plugins']];
            echo '<div class="ag-rows ag-todo" id="ag-todo"><div class="ag-rows-h">' . esc_html__('What to do', 'aguard-safe') . '</div>';
            foreach ($d['issues'] as $it) {
                // the first sentence is the headline, the rest is the explanation
                [$head, $rest] = self::issue_parts($it);
                $to = self::issue_link($it);
                echo '<div class="ag-row ag-row-todo"><span class="ag-dot ag-dot-' . esc_attr(in_array($it[0], ['warn', 'risk'], true) ? $it[0] : 'idle') . '"></span><div><b>' . esc_html($head) . '</b>' . ($rest !== '' ? '<span>' . esc_html($rest) . '</span>' : '') . '</div>' . ($to ? '<a class="button" href="' . esc_url($to[1]) . '">' . esc_html($to[0]) . '</a>' : '<span></span>') . '</div>';
            }
            echo '</div>';
        }
        // modules
        $login = []; if (self::twofa_enabled()) $login[] = __('e-mail confirmation', 'aguard-safe'); if (self::login_mode() !== 'off') $login[] = __('custom login address', 'aguard-safe'); if ($p['lockdown']) $login[] = 'LOCKDOWN';
        $mods = [
            ['vientisumas', __('File integrity', 'aguard-safe'), __('The WordPress core is compared with the official checksums every 6 hours; between checks, new and changed files are tracked.', 'aguard-safe'), $f['status'], $fv],
            ['prisijungimai', __('Login protection', 'aguard-safe'), __('Administrator logins, failed attempts, e-mail confirmation, the login address of the site.', 'aguard-safe'), $login ? 'ok' : 'warn', $login ? __('Enabled:', 'aguard-safe') . ' ' . implode(', ', $login) : __('Standard wp-login without extra protection', 'aguard-safe')],
            ['ugniasiene', __('Upload and code protection', 'aguard-safe'), __('PHP block in the upload folders, remote management tools, comparison of the content with what Google sees.', 'aguard-safe'), $p['status'], ($p['guard'] ? __('PHP block enabled', 'aguard-safe') : __('PHP block disabled', 'aguard-safe')) . ($p['remote'] ? ' · ' . (int) $p['remote'] . ' ' . _n('risky tool', 'risky tools', $p['remote'], 'aguard-safe') : '') . ($p['cloak_clean'] ? '' : ' ' . __('· cloaking!', 'aguard-safe'))],
        ];
        $on = __('on', 'aguard-safe'); $off = __('off', 'aguard-safe');
        $rows = [
            [__('File checks', 'aguard-safe'), $f['status'], ($f['status'] === 'risk' || $f['status'] === 'warn') ? __('needs attention', 'aguard-safe') : __('every hour', 'aguard-safe')],
            [__('Login alerts', 'aguard-safe'), !empty(self::opts()['notify_admin_login']) ? 'ok' : 'warn', !empty(self::opts()['notify_admin_login']) ? $on : $off],
            [__('PHP block in uploads', 'aguard-safe'), $p['guard'] ? 'ok' : 'warn', $p['guard'] ? $on : $off],
            [__('Two-factor code', 'aguard-safe'), self::twofa_enabled() ? 'ok' : 'warn', self::twofa_enabled() ? $on : $off],
            [__('Googlebot sees the same content', 'aguard-safe'), $p['cloak_clean'] ? 'ok' : 'risk', $p['cloak_clean'] ? __('yes', 'aguard-safe') : __('no', 'aguard-safe')],
        ];
        $prot = '<div class="ag-rows ag-prot"><div class="ag-rows-h">' . esc_html__('Protection', 'aguard-safe') . '</div>';
        foreach ($rows as $m) $prot .= '<div class="ag-row ag-row-prot"><span class="ag-dot ag-dot-' . esc_attr(in_array($m[1], ['ok', 'warn', 'risk'], true) ? $m[1] : 'idle') . '"></span><b>' . esc_html($m[0]) . '</b><span>' . esc_html($m[2]) . '</span></div>';
        $prot .= '</div>';
        // 7-day chart: plain bars
        $max = 1; foreach ($d['days'] as $v) $max = max($max, (int) $v['fails'] + (int) $v['events']);
        echo '<div class="ag-cols"><div class="ag-card ag-chart"><div class="ag-card-h"><b>' . esc_html__('Last 7 days', 'aguard-safe') . '</b><div class="ag-legend"><i class="ag-bar-e"></i>' . esc_html__('recorded events', 'aguard-safe') . '<i class="ag-bar-f"></i>' . esc_html__('failed logins', 'aguard-safe') . '</div></div><div class="ag-bars">';
        foreach ($d['days'] as $day => $v) {
            // one bar a day: events, with failed logins stacked on top
            $ev = (int) $v['events']; $fl = (int) $v['fails']; $sum = $ev + $fl; $ts = strtotime($day . ' 12:00:00');
            $h = $sum ? max(4, (int) round(118 * $sum / $max)) : 2; $hf = $fl ? max(3, (int) round($h * $fl / $sum)) : 0;
            echo '<div class="ag-day" title="' . esc_attr($day . ' · ' . __('recorded events', 'aguard-safe') . ': ' . $ev . ' · ' . __('failed logins', 'aguard-safe') . ': ' . $fl) . '"><div class="ag-day-bars"><div class="ag-stack' . ($sum ? '' : ' ag-stack-0') . '" style="height:' . (int) $h . 'px">' . ($sum ? '<em>' . (int) $sum . '</em>' : '') . ($hf ? '<span class="ag-bar-f" style="height:' . (int) $hf . 'px"></span>' : '') . '</div></div><b>' . esc_html(wp_date('D', $ts)) . '</b></div>';
        }
        echo '</div></div>' . wp_kses_post($prot) . '</div>';
        // what is checked, when there is nothing to do
        if (!$n) echo '<div class="ag-card"><div class="ag-card-h"><b>' . esc_html__('What is checked', 'aguard-safe') . '</b></div><p style="margin:4px 0;color:var(--ag-text2)">' . esc_html__('Files match the originals, no foreign code found, Google sees the same content as visitors, PHP does not run in the upload folders. Next automatic check', 'aguard-safe') . ' ' . ($d['next_scan'] ? esc_html(sprintf(/* translators: %s: time span */ __('in %s', 'aguard-safe'), human_time_diff($d['next_scan']))) : esc_html__('not scheduled', 'aguard-safe')) . '.</p></div>';
        self::review_card($d);
        echo '<p class="ag-foot">' . esc_html__('Notifications are sent to', 'aguard-safe') . ' ' . esc_html(self::mask_email(self::opts()['email'])) . ' ' . esc_html__('· AGuard Safe v', 'aguard-safe') . esc_html(self::VERSION) . ' · <a href="https://aguard.lt" target="_blank" rel="noopener">aguard.lt</a></p></div>';
    }

    public static function prune_events($kw) {
        $events = get_option(self::OPT_EVENTS, []); if (!is_array($events)) return 0;
        $keep = []; $n = 0; $kwl = self::lower($kw);
        foreach ($events as $e) { if (strpos(self::lower((string) wp_json_encode($e, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)), $kwl) !== false) { $n++; continue; } $keep[] = $e; }
        update_option(self::OPT_EVENTS, $keep, false);
        $last = self::plain(get_option(self::OPT . '_last_scan', []));
        if (is_array($last) && strpos(self::lower((string) wp_json_encode($last, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)), $kwl) !== false) { self::run_scan(true); }
        self::event('settings', __('Removed from the log', 'aguard-safe') . ' ' . $n . ' ' . __('events by keyword', 'aguard-safe'), ['keyword' => $kw], true, 'prune_' . time());
        return $n;
    }

    /* ------------------------------------------------------------ login URL (own address instead of wp-login.php) */
    /** Why: bots hammer /wp-login.php; customers never use it (WooCommerce logs in / registers on its own pages). Everything is wrapped in try/catch so a bug degrades to "feature off", never to a white screen. */
    /* ===================== Dviejų veiksnių patvirtinimas el. paštu (administratoriams) ===================== */
    public static function twofa_killed() {
        if (defined('AGUARD_SAFE_2FA_OFF') && AGUARD_SAFE_2FA_OFF) return 'AGUARD_SAFE_2FA_OFF';
        if (file_exists(self::content_dir() . '/AGUARD-2FA-OFF')) return basename(self::content_dir()) . '/AGUARD-2FA-OFF'; // išlieka ir atnaujinus įskiepį
        return '';
    }
    /** Pamiršti visas prisimintas naršykles (slaptažodžio keitimas, LOCKDOWN, 2FA perjungimas, mygtukas). */
    public static function twofa_revoke($uid = 0) {
        if ($uid) { delete_user_meta((int) $uid, 'aguard_safe_trusted'); return; }
        foreach (get_users(['role' => 'administrator', 'fields' => 'ID']) as $id) delete_user_meta((int) $id, 'aguard_safe_trusted');
    }
    private static function twofa_ip_known($uid, $login) {
        $known = get_option(self::OPT . '_known_logins', []); $ip = self::twofa_client_ip();
        return is_array($known) && isset($known[$login][$ip]) && (time() - (int) $known[$login][$ip]) < 30 * DAY_IN_SECONDS;
    }
    private static function twofa_login_url_base() {
        return wp_login_url(); // the plugin's own address, when enabled, is applied through the login_url filter
    }
    public static function twofa_enabled() { return self::twofa_killed() === '' && !empty(self::opts()['twofa']); }
    private static function twofa_client_ip() { return (self::srv('HTTP_CF_CONNECTING_IP') ?: self::srv('REMOTE_ADDR')); }
    /** Patikimų naršyklių slapukas: 30 d.; raktas saugomas tik maišytas (hash) naudotojo meta. */
    private static $twofa_why = '';
    private static function twofa_device_ok($uid) {
        $c = sanitize_text_field(wp_unslash($_COOKIE['aguard_safe_trust'] ?? '')); if ($c === '' || strpos($c, ':') === false) { self::$twofa_why = __('browser not remembered (no cookie)', 'aguard-safe'); return false; }
        [$cuid, $rand] = explode(':', $c, 2); if ((int) $cuid !== (int) $uid || strlen($rand) < 20) { self::$twofa_why = __('the cookie belongs to another user', 'aguard-safe'); return false; }
        $list = get_user_meta($uid, 'aguard_safe_trusted', true); if (!is_array($list)) { self::$twofa_why = __('the list of remembered browsers is empty (forgotten)', 'aguard-safe'); return false; }
        $h = hash_hmac('sha256', $rand, wp_salt('auth'));
        if (!isset($list[$h])) { self::$twofa_why = __('the cookie is no longer valid (forgotten or the password was changed)', 'aguard-safe'); return false; }
        if ((int) $list[$h] <= time()) { self::$twofa_why = __('the remembered period has ended (30 days)', 'aguard-safe'); return false; }
        return true;
    }
    private static function twofa_trust_device($uid) {
        $rand = wp_generate_password(40, false, false);
        $list = get_user_meta($uid, 'aguard_safe_trusted', true); if (!is_array($list)) $list = [];
        foreach ($list as $k => $exp) { if ((int) $exp < time()) unset($list[$k]); }
        $list[hash_hmac('sha256', $rand, wp_salt('auth'))] = time() + 30 * DAY_IN_SECONDS;
        update_user_meta($uid, 'aguard_safe_trusted', $list);
        setcookie('aguard_safe_trust', $uid . ':' . $rand, ['expires' => time() + 30 * DAY_IN_SECONDS, 'path' => '/', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']);
    }
    /**
     * A code e-mail in the look of the plugin: HTML with the knight embedded in the message itself (nothing is loaded from the internet) and a plain-text copy.
     * $rows: label => value, $warn: the "if this was not you" paragraph.
     */
    private static function mail_code($to, $subject, $title, $lead, $code, $rows, $warn, $plain) {
        $e = 'esc_html'; $ink = '#0f1f45'; $mint = '#3fb9a8';
        $tr = ''; foreach ($rows as $k => $v) $tr .= '<tr><td style="padding:7px 0;border-top:1px solid #e8edf2;color:#64748b;font-size:13px;width:38%">' . $e($k) . '</td><td style="padding:7px 0;border-top:1px solid #e8edf2;color:#101827;font-size:13px;font-weight:600;word-break:break-all">' . $e($v) . '</td></tr>';
        $html = '<!doctype html><html><body style="margin:0;padding:0;background:#eef1f6">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f6"><tr><td align="center" style="padding:28px 12px">'
            . '<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            . '<tr><td style="background:' . $ink . ';border-radius:12px 12px 0 0;padding:16px 26px;color:#fff;font-size:18px;font-weight:800;letter-spacing:.01em">AGuard Safe<span style="float:right;font-size:12px;font-weight:500;color:#c7cfe2;line-height:24px">' . $e(wp_parse_url(home_url(), PHP_URL_HOST)) . '</span></td></tr>'
            . '<tr><td style="background:' . $mint . ';height:5px;line-height:5px;font-size:0">&nbsp;</td></tr>'
            . '<tr><td style="background:#fff;padding:26px 26px 8px">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="vertical-align:top"><div style="font-size:21px;font-weight:700;color:' . $ink . ';line-height:1.25">' . $e($title) . '</div><div style="margin-top:6px;font-size:14px;color:#475569;line-height:1.5">' . $e($lead) . '</div></td><td width="96" style="vertical-align:top;text-align:right"><img src="cid:aguardknight" width="84" alt="" style="display:block;margin-left:auto;border:0"></td></tr></table>'
            . '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:18px 0 6px"><tr><td style="background:' . $mint . ';border-radius:10px;padding:0 5px 5px 0"><div style="background:#fff;border:2px solid ' . $ink . ';border-radius:10px;padding:12px 26px;font-family:Menlo,Consolas,monospace;font-size:32px;font-weight:700;letter-spacing:.22em;color:' . $ink . '">' . $e($code) . '</div></td></tr></table>'
            . '<div style="font-size:13px;color:#64748b;margin:0 0 16px">' . $e(__('Valid for 10 minutes, for one use.', 'aguard-safe')) . '</div>'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">' . $tr . '</table>'
            . '</td></tr>'
            . '<tr><td style="background:#fff;border-radius:0 0 12px 12px;padding:8px 26px 24px"><div style="border-left:3px solid #d62828;padding:8px 0 8px 14px;font-size:13px;color:#101827;line-height:1.5">' . $e($warn) . '</div></td></tr>'
            . '<tr><td style="padding:14px 6px 0;font-size:12px;color:#64748b;text-align:center">' . $e(__('Sent by the AGuard Safe plugin of this site.', 'aguard-safe')) . '</td></tr>'
            . '</table></td></tr></table></body></html>';
        $knight = plugin_dir_path(__FILE__) . 'assets/knight-emergency.png';
        $hook = function ($m) use ($plain, $knight) { $m->AltBody = $plain; if (is_readable($knight)) { try { $m->addEmbeddedImage($knight, 'aguardknight', 'knight.png', 'base64', 'image/png'); } catch (\Throwable $e) { unset($e); } } };
        add_action('phpmailer_init', $hook, 99);
        $ok = (bool) wp_mail($to, $subject, $html, ['Content-Type: text/html; charset=UTF-8']);
        remove_action('phpmailer_init', $hook, 99);
        return $ok;
    }

    private static function twofa_send($user, $code) {
        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $body = __('Your login confirmation code:', 'aguard-safe') . ' ' . $code . "\n\n" . __('The code is valid for 10 minutes and for one login only.', 'aguard-safe') . "\n\n" . __('Site:', 'aguard-safe') . ' ' . home_url() . "\n" . __('Username:', 'aguard-safe') . ' ' . $user->user_login . "\n" . __('From: IP', 'aguard-safe') . ' ' . self::twofa_client_ip() . "\n\n" . __('If this was not you, do nothing, do not tell the code to anyone and inform the administrator: somebody knows your password.', 'aguard-safe') . "\n";
        return self::mail_code($user->user_email, '[' . $site . __('] Login code:', 'aguard-safe') . ' ' . $code, __('Your login code', 'aguard-safe'), __('Enter it on the sign-in page to finish signing in.', 'aguard-safe'), $code, [__('Site', 'aguard-safe') => home_url(), __('Username', 'aguard-safe') => $user->user_login, __('Requested from', 'aguard-safe') => 'IP ' . self::twofa_client_ip()], __('If this was not you, do nothing, do not tell the code to anyone and inform the administrator: somebody knows your password.', 'aguard-safe'), $body);
    }
    /** Po teisingo slaptažodžio: administratoriui be patikimos naršyklės išsiunčiamas kodas ir rodoma kodo forma. */
    public static function twofa_authenticate($user, $username = '', $password = '') {
        try {
            if (!($user instanceof WP_User) || $username === '' || $password === '') return $user;
            if (!self::twofa_enabled() || !user_can($user, 'manage_options')) return $user;
            if (did_action('application_password_did_authenticate') || wp_doing_cron()) return $user; // programų slaptažodžiai – kitas kanalas, čia 2FA netaikoma
            if (self::twofa_device_ok($user->ID)) return $user;
            if ((defined('REST_REQUEST') && REST_REQUEST) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || wp_doing_ajax()) {
                // Slaptažodžiu per XML-RPC / REST / AJAX administratorius be patikimos naršyklės neįleidžiamas – kitaip tai būtų 2FA apėjimas.
                return new WP_Error('aguard2fa', __('Administrator login requires e-mail confirmation – sign in using a browser.', 'aguard-safe'));
            }
            $sk = 'aguard_safe_2fa_sends_' . $user->ID; $sends = (int) get_transient($sk);
            if ((int) get_transient('aguard_safe_2fa_block_' . $user->ID) > 0) return new WP_Error('aguard2fa', __('Too many attempts. Try again in an hour or contact the administrator.', 'aguard-safe'));
            if ($sends >= 5) { self::event('attack', __('2FA: too many code requests (5 per 15 min):', 'aguard-safe') . ' ' . $user->user_login, ['ip' => self::ip(), 'ua' => self::ua()], true, '2fa_sends_' . $user->ID, 900); return new WP_Error('aguard2fa', __('Too many code requests. Try again in 15 minutes.', 'aguard-safe')); }
            set_transient($sk, $sends + 1, 15 * MINUTE_IN_SECONDS);
            $code = str_pad((string) wp_rand(0, 999999), 6, '0', STR_PAD_LEFT);
            $token = wp_generate_password(32, false, false);
            $redirect = isset($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : (isset($_POST['redirect']) ? esc_url_raw(wp_unslash($_POST['redirect'])) : admin_url()); // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            $interim = !empty($_REQUEST['interim-login']); // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            set_transient('aguard_safe_2fa_' . $token, ['uid' => $user->ID, 'hash' => wp_hash($code), 'tries' => 0, 'remember' => !empty($_POST['rememberme']), 'redirect' => $redirect, 'ip' => self::twofa_client_ip(), 'interim' => $interim], 10 * MINUTE_IN_SECONDS); // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            if (!self::twofa_send($user, $code)) {
                // Pašto klaida: iš žinomo IP (iš kurio jungtasi per 30 d.) įleidžiame be kodo ir pranešame; iš nežinomo – ne.
                if (self::twofa_ip_known($user->ID, $user->user_login)) {
                    self::event('login', __('IMPORTANT: could not send the 2FA code (mail error) –', 'aguard-safe') . ' ' . $user->user_login . ' ' . __('let in without a code from a known IP', 'aguard-safe'), ['ip' => self::ip(), 'ua' => self::ua(), 'new_ip' => true], true, '2fa_mailfail_' . $user->ID, 3600);
                    return $user;
                }
                self::event('login', __('IMPORTANT: could not send the 2FA code (mail error) –', 'aguard-safe') . ' ' . $user->user_login . ' ' . __('NOT let in from an unknown IP', 'aguard-safe'), ['ip' => self::ip(), 'ua' => self::ua(), 'new_ip' => true], true, '2fa_mailfail_' . $user->ID, 3600);
                return new WP_Error('aguard2fa', __('Could not send the confirmation code by e-mail. Contact the administrator.', 'aguard-safe'));
            }
            self::event('login', __('2FA code sent:', 'aguard-safe') . ' ' . $user->user_login, ['ip' => self::ip(), 'why' => self::$twofa_why], false);
            $args = ['action' => 'aguard2fa', 't' => $token]; if ($interim) $args['interim-login'] = '1';
            wp_safe_redirect(add_query_arg($args, self::twofa_login_url_base())); exit;
        } catch (\Throwable $e) { self::event('error', '2FA: ' . $e->getMessage(), [], false); return $user; }
    }
    /** Kodo forma (wp-login.php?action=aguard2fa&t=…), rodoma per standartinį prisijungimo puslapio rėmą. */
    public static function twofa_page() {
        // Jau prisijungęs (pvz., dukart paspausta „Patvirtinti“ arba grįžta atgal) – tiesiog į valdymo skydą, be klaidos.
        if (is_user_logged_in()) { wp_safe_redirect(admin_url()); exit; }
        $token = preg_replace('/[^a-zA-Z0-9]/', '', sanitize_text_field(wp_unslash($_REQUEST['t'] ?? ''))); // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
        $key = 'aguard_safe_2fa_' . $token; $st = $token !== '' ? get_transient($key) : false; $msg = ''; $err = null;
        if (!is_array($st)) { $err = new WP_Error('aguard2fa', __('The code has expired or the link is wrong.', 'aguard-safe') . ' <a href="' . esc_url(wp_login_url()) . '">' . __('Sign in again', 'aguard-safe') . '</a>.'); }
        elseif (isset($_GET['resend']) && $st['tries'] < 5 && (int) get_transient('aguard_safe_2fa_sends_' . $st['uid']) < 5) { // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            set_transient('aguard_safe_2fa_sends_' . $st['uid'], (int) get_transient('aguard_safe_2fa_sends_' . $st['uid']) + 1, 15 * MINUTE_IN_SECONDS);
            $code = str_pad((string) wp_rand(0, 999999), 6, '0', STR_PAD_LEFT); $st['hash'] = wp_hash($code); $st['tries']++; set_transient($key, $st, 10 * MINUTE_IN_SECONDS);
            $u = get_userdata($st['uid']); if ($u) self::twofa_send($u, $code);
            $msg = '<p class="message">' . __('A new code has been sent.', 'aguard-safe') . '</p>';
        } elseif (self::srv('REQUEST_METHOD') === 'POST' && isset($_POST['aguard_code'])) { // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            $c = preg_replace('/\D/', '', sanitize_text_field(wp_unslash($_POST['aguard_code']))); $st['tries']++; // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
            $fk = 'aguard_safe_2fa_fails_' . $st['uid']; $fails = (int) get_transient($fk);
            if ($st['tries'] > 5 || $fails >= 15) {
                delete_transient($key); $u = get_userdata($st['uid']);
                if ($fails >= 15) set_transient('aguard_safe_2fa_block_' . $st['uid'], 1, HOUR_IN_SECONDS);
                self::event('attack', __('2FA: too many wrong codes – login stopped:', 'aguard-safe') . ' ' . ($u ? $u->user_login : $st['uid']), ['ip' => self::ip(), 'ua' => self::ua()], true, '2fa_fail_' . $st['uid'], 600);
                $err = new WP_Error('aguard2fa', __('Too many wrong codes.', 'aguard-safe') . ' <a href="' . esc_url(wp_login_url()) . '">' . __('Sign in again', 'aguard-safe') . '</a>.');
            } elseif ($c !== '' && hash_equals((string) $st['hash'], wp_hash($c))) {
                delete_transient($key); delete_transient($fk); $u = get_userdata($st['uid']);
                if ($u) {
                    wp_set_auth_cookie($u->ID, !empty($st['remember']));
                    if (!empty($_POST['aguard_trust'])) self::twofa_trust_device($u->ID); // phpcs:ignore WordPress.Security.NonceVerification -- login screen: the visitor is not signed in yet, the request is bound to a one-time random token.
                    do_action('wp_login', $u->user_login, $u); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core hook, fired after the second login step.
                    if (!empty($st['interim'])) { $GLOBALS['interim_login'] = 'success'; login_header('', '<p class="message">' . __('Signed in. You can continue working.', 'aguard-safe') . '</p>'); echo '</div></body></html>'; exit; }
                    $to = !empty($st['redirect']) ? (string) $st['redirect'] : admin_url();
                    wp_safe_redirect($to); exit;
                }
                $err = new WP_Error('aguard2fa', __('User not found.', 'aguard-safe'));
            } else { set_transient($key, $st, 10 * MINUTE_IN_SECONDS); set_transient($fk, $fails + 1, HOUR_IN_SECONDS); $uu = get_userdata($st['uid']); do_action('wp_login_failed', $uu ? $uu->user_login : '', new WP_Error('aguard2fa', __('wrong code', 'aguard-safe'))); $err = new WP_Error('aguard2fa', __('Wrong code. Attempts left:', 'aguard-safe') . ' ' . (5 - $st['tries']) . '.'); } // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core hook, fired after the second login step.
        }
        nocache_headers();
        login_header(__('Confirm your login', 'aguard-safe'), $msg, $err);
        if (is_array($st)) {
            $u = get_userdata($st['uid']); $mask = $u ? preg_replace('/^(.).*(@.*)$/u', '$1***$2', $u->user_email) : '';
            $action = add_query_arg(array_merge(['action' => 'aguard2fa', 't' => $token], !empty($st['interim']) ? ['interim-login' => '1'] : []), self::twofa_login_url_base());
            echo '<form name="aguard2fa" id="loginform" method="post" action="' . esc_url($action) . '">';
            echo '<p style="margin-bottom:12px">' . esc_html__('A 6-digit code has been sent to', 'aguard-safe') . ' <strong>' . esc_html($mask) . '</strong> ' . esc_html__('. Enter it here.', 'aguard-safe') . '</p>';
            echo '<p><label for="aguard_code">' . esc_html__('Code from the e-mail', 'aguard-safe') . '</label><input type="text" name="aguard_code" id="aguard_code" class="input" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" autofocus style="font-size:24px;letter-spacing:6px;text-align:center"></p>';
            echo '<p class="forgetmenot"><label><input type="checkbox" name="aguard_trust" value="1" checked> ' . esc_html__('Remember this browser for 30 days', 'aguard-safe') . '</label></p>';
            echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__('Confirm', 'aguard-safe') . '" id="aguard2fa_submit"></p>';
            echo '</form>';
            wp_print_inline_script_tag('document.getElementById("loginform").addEventListener("submit",function(){var b=document.getElementById("aguard2fa_submit");if(b.disabled){return false;}b.disabled=true;b.value=' . wp_json_encode(__('Checking…', 'aguard-safe')) . ';});');
            echo '<p id="nav"><a href="' . esc_url(add_query_arg('resend', '1', $action)) . '">' . esc_html__('Send the code again', 'aguard-safe') . '</a> &nbsp;|&nbsp; <a href="' . esc_url(wp_login_url()) . '">' . esc_html__('Back', 'aguard-safe') . '</a></p>';
        }
        login_footer('aguard_code'); exit;
    }

    public static function login_killed() {
        if (defined('AGUARD_SAFE_LOGIN_OFF') && AGUARD_SAFE_LOGIN_OFF) return 'AGUARD_SAFE_LOGIN_OFF';
        if (file_exists(self::content_dir() . '/AGUARD-LOGIN-OFF')) return basename(self::content_dir()) . '/AGUARD-LOGIN-OFF'; // outside the plugin folder: survives updates, nothing is edited inside the plugin
        return '';
    }
    public static function login_slug_valid($s) {
        $s = (string) $s;
        if (!preg_match('~^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$~', $s)) return false;
        return !in_array($s, ['wp-admin', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-json', 'admin', 'login', 'prisijungti', 'prisijungimas', 'feed', 'index.php', 'xmlrpc.php', 'wp-cron.php'], true);
    }
    public static function login_mode() {
        if (self::login_killed() !== '') return 'off';
        $o = self::opts(); $m = $o['login_mode'] ?? 'off';
        if (!in_array($m, ['soft', 'strict'], true) || !self::login_slug_valid($o['login_slug'] ?? '')) return 'off';
        return $m;
    }
    public static function login_info() {
        $o = self::opts(); $mode = self::login_mode(); $slug = (string) ($o['login_slug'] ?? '');
        return ['mode' => $mode, 'slug' => $slug, 'url' => $mode !== 'off' ? home_url('/' . $slug . '/') : wp_login_url(), 'killed' => self::login_killed(), 'saved_mode' => $o['login_mode'] ?? 'off'];
    }
    private static function login_req_path() {
        $p = (string) wp_parse_url(self::srv_uri(), PHP_URL_PATH);
        $home = rtrim((string) wp_parse_url(home_url('/'), PHP_URL_PATH), '/');
        $core = rtrim((string) wp_parse_url(site_url('/'), PHP_URL_PATH), '/'); // differs from home when WordPress lives in a subdirectory
        if ($core !== '' && $core !== $home && strpos($p . '/', $core . '/') === 0) $p = substr($p, strlen($core));
        elseif ($home !== '' && strpos($p . '/', $home . '/') === 0) $p = substr($p, strlen($home));
        return trim(rawurldecode($p), '/');
    }
    public static function login_boot() {
        try {
            $mode = self::login_mode(); if ($mode === 'off') return;
            self::login_hook_filters((string) self::opts()['login_slug']);
            $path = self::login_req_path();
            if ($path === self::$login_slug) {
                $GLOBALS['pagenow'] = 'wp-login.php';
                if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- constant read by page-cache plugins: the login page must not be cached.
                add_action('wp_loaded', [__CLASS__, 'login_serve'], 1);
            } elseif ($mode === 'strict') {
                if ($path === 'wp-login.php') add_action('wp_loaded', [__CLASS__, 'login_404'], 1);
                add_action('init', [__CLASS__, 'login_guard_admin'], 1);
            }
        } catch (\Throwable $e) { self::event('error', 'login_boot: ' . $e->getMessage(), [], false); }
    }
    private static function login_hook_filters($slug) {
        self::$login_slug = $slug;
        if (has_filter('site_url', [__CLASS__, 'login_filter_site_url'])) return;
        add_filter('site_url', [__CLASS__, 'login_filter_site_url'], 10, 2);
        add_filter('network_site_url', [__CLASS__, 'login_filter_site_url'], 10, 2);
        add_filter('wp_redirect', [__CLASS__, 'login_rewrite_url'], 10, 1);
        foreach (['login_url', 'logout_url', 'lostpassword_url', 'register_url'] as $f) add_filter($f, [__CLASS__, 'login_rewrite_url'], 99, 1);
    }
    /** Address of wp-login.php as WordPress core builds it, without this plugin's rewrite (core may live in a subdirectory). */
    private static function login_core_url() {
        $slug = self::$login_slug; self::$login_slug = '';
        $u = wp_login_url();
        self::$login_slug = $slug;
        return $u;
    }
    public static function login_filter_site_url($url, $path = '') {
        return (is_string($path) && strpos($path, 'wp-login.php') !== false) ? self::login_rewrite_url($url) : $url;
    }
    public static function login_rewrite_url($url) {
        try {
            if (self::$login_slug === '' || !is_string($url) || strpos($url, 'wp-login.php') === false) return $url;
            $h = (string) wp_parse_url($url, PHP_URL_HOST);
            if ($h !== '') { $home = (string) wp_parse_url(home_url(), PHP_URL_HOST); $norm = function ($x) { return strtolower(preg_replace('~^www\.~', '', $x)); }; if ($norm($h) !== $norm($home)) return $url; }
            return preg_replace('~(?:/' . preg_quote(self::$login_slug, '~') . ')?/wp-login\.php(?=[?#]|$)~', '/' . self::$login_slug, $url, 1);
        } catch (\Throwable $e) { return $url; }
    }
    public static function login_serve() {
        global $pagenow, $error, $errors, $interim_login, $action, $user_login, $redirect_to, $rememberme, $secure_cookie, $user, $requested_redirect_to, $customize_login, $lostpassword_redirect, $login_link_separator;
        $pagenow = 'wp-login.php';
        nocache_headers();
        require_once self::wp_root() . '/wp-login.php';
        exit;
    }
    public static function login_404() {
        status_header(404); nocache_headers(); header('Content-Type: text/html; charset=UTF-8');
        wp_register_style('aguard-safe-notfound', false, [], self::VERSION);
        wp_add_inline_style('aguard-safe-notfound', 'body{font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#333;margin:12vh auto;max-width:520px;padding:0 20px}h1{font-size:22px}a{color:#0a5}');
        echo '<!DOCTYPE html><html lang="' . esc_attr(get_bloginfo('language')) . '"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>' . esc_html__('Page not found', 'aguard-safe') . '</title>';
        wp_print_styles(['aguard-safe-notfound']);
        echo '</head><body><h1>' . esc_html__('Page not found', 'aguard-safe') . '</h1><p>' . esc_html__('This page does not exist.', 'aguard-safe') . ' <a href="' . esc_url(home_url('/')) . '">' . esc_html__('Back to the home page', 'aguard-safe') . '</a></p></body></html>';
        exit;
    }
    public static function login_guard_admin() {
        try {
            if (!is_admin() || is_user_logged_in() || wp_doing_ajax() || wp_doing_cron()) return;
            $script = basename((string) wp_parse_url(self::srv_uri(), PHP_URL_PATH));
            if (in_array($script, ['admin-ajax.php', 'admin-post.php', 'async-upload.php'], true)) return;
            self::login_404();
        } catch (\Throwable $e) { /* never break the request */ }
    }
    /** Opens the site's own pages from the server and reports what it saw. */
    public static function login_selftest() {
        $o = self::opts(); $mode = self::login_mode(); $slug = (string) ($o['login_slug'] ?? '');
        $get = function ($url) {
            $r = wp_remote_get($url, ['timeout' => 25, 'redirection' => 0, 'user-agent' => 'Mozilla/5.0 AGuardSafe-selftest', 'sslverify' => self::local_sslverify(), 'headers' => ['Cache-Control' => 'no-cache'], 'cookies' => []]);
            if (is_wp_error($r)) return ['code' => 0, 'err' => $r->get_error_message()];
            $b = (string) wp_remote_retrieve_body($r);
            return ['code' => (int) wp_remote_retrieve_response_code($r), 'form' => strpos($b, 'id="loginform"') !== false || strpos($b, 'name="log"') !== false, 'len' => strlen($b)];
        };
        $t = ['mode' => $mode, 'ok' => true];
        $r = wp_rand(1000, 9999);
        $t['home'] = $get(home_url('/?aguard_safe=' . $r)); if ($t['home']['code'] !== 200) $t['ok'] = false;
        if (function_exists('wc_get_page_permalink')) { $acc = wc_get_page_permalink('myaccount'); if ($acc) { $t['account'] = $get(add_query_arg('aguard_safe', $r, $acc)); if ($t['account']['code'] !== 200) $t['ok'] = false; } }
        if ($mode !== 'off') {
            $t['new_url'] = $get(home_url('/' . $slug . '/?aguard_safe=' . $r)); if ($t['new_url']['code'] !== 200 || empty($t['new_url']['form'])) $t['ok'] = false;
            $t['old_url'] = $get(add_query_arg('aguard_safe', $r, self::login_core_url()));
            if ($mode === 'strict' && $t['old_url']['code'] !== 404) $t['ok'] = false;
            if ($mode === 'soft' && ($t['old_url']['code'] !== 200 || empty($t['old_url']['form']))) $t['ok'] = false;
            $t['generated_login_url'] = wp_login_url(); if (strpos($t['generated_login_url'], '/' . $slug) === false) $t['ok'] = false;
            $t['generated_logout_url'] = wp_logout_url();
        } else {
            $t['old_url'] = $get(add_query_arg('aguard_safe', $r, self::login_core_url())); if ($t['old_url']['code'] !== 200) $t['ok'] = false;
        }
        return $t;
    }
    /** Saves mode+slug, self-tests from the server, and rolls back automatically if anything does not answer as expected. */
    public static function login_apply($mode, $slug) {
        $mode = in_array($mode, ['off', 'soft', 'strict'], true) ? $mode : 'off';
        $o = self::opts(); $prev = ['login_mode' => $o['login_mode'] ?? 'off', 'login_slug' => $o['login_slug'] ?? ''];
        if ($mode !== 'off') {
            if (!self::login_slug_valid($slug)) return ['ok' => false, 'msg' => __('Invalid address: 3–40 characters, lowercase letters, digits and hyphens; words such as “login” and “admin” are not allowed.', 'aguard-safe')];
            if (get_page_by_path($slug, OBJECT, ['page', 'post', 'product']) || url_to_postid(home_url('/' . $slug . '/'))) return ['ok' => false, 'msg' => __('This address is already used on the site (a page or a post). Choose another one.', 'aguard-safe')];
            if (self::login_killed() !== '') return ['ok' => false, 'msg' => __('The emergency switch is on (', 'aguard-safe') . esc_html(self::login_killed()) . __('): remove it first.', 'aguard-safe')];
        }
        $o['login_mode'] = $mode; $o['login_slug'] = $mode !== 'off' ? $slug : ($o['login_slug'] ?? '');
        update_option(self::OPT, $o, true); self::$opts = null;
        // the running request already booted with the old mode; the test opens fresh requests, which see the new option
        if ($mode !== 'off') self::login_hook_filters($slug); // so the URLs generated in this very request already use the new address
        $t = self::login_selftest();
        if ($mode !== 'off' && (empty($t['new_url']) || $t['new_url']['code'] !== 200 || empty($t['new_url']['form']) || $t['home']['code'] !== 200 || (isset($t['account']) && $t['account']['code'] !== 200) || ($mode === 'strict' && $t['old_url']['code'] !== 404))) {
            $o['login_mode'] = $prev['login_mode']; $o['login_slug'] = $prev['login_slug']; update_option(self::OPT, $o, true); self::$opts = null;
            self::event('settings', __('Login address change CANCELLED – the self-test failed', 'aguard-safe'), ['wanted' => $mode . ' /' . $slug, 'test' => $t], true, 'login_fail_' . time());
            return ['ok' => false, 'msg' => __('The self-test failed and the setting was reverted. The site works as before.', 'aguard-safe'), 'test' => $t];
        }
        $url = $mode !== 'off' ? home_url('/' . $slug . '/') : wp_login_url();
        self::event('settings', __('Login address:', 'aguard-safe') . ' ' . ($mode === 'off' ? __('the standard /wp-login.php restored', 'aguard-safe') : ($mode === 'soft' ? __('trial mode, new address', 'aguard-safe') . ' ' . $url : __('ONLY the new address', 'aguard-safe') . ' ' . $url . ' ' . __('(wp-login.php shows 404)', 'aguard-safe'))), ['mode' => $mode, 'url' => $url, 'test' => $t], true, 'login_' . time());
        return ['ok' => true, 'msg' => ($mode === 'off' ? __('The standard login address has been restored.', 'aguard-safe') : __('Saved and tested. Login address:', 'aguard-safe') . ' <a href="' . esc_url($url) . '" target="_blank">' . esc_html($url) . '</a>' . ($mode === 'soft' ? ' ' . __('(the old /wp-login.php still works for now).', 'aguard-safe') : __('. The old /wp-login.php no longer works – tell the address to everyone who signs in.', 'aguard-safe'))) . ' ' . __('The address has been sent to the notification e-mail.', 'aguard-safe'), 'test' => $t];
    }

    /* ------------------------------------------------------------ settings lock (code to the current alert address) */

    public static function mask_email($e) { $p = explode('@', (string) $e); return isset($p[1]) ? substr($p[0], 0, 2) . str_repeat('*', max(1, strlen($p[0]) - 2)) . '@' . $p[1] : '***'; }
    private static function unlock_key() { return 'aguard_safe_unlocked_' . get_current_user_id(); }
    public static function is_unlocked() {
        if (defined('AGUARD_SAFE_MASTER') && AGUARD_SAFE_MASTER) return true;
        return (bool) get_transient(self::unlock_key());
    }
    public static function unlock_request() {
        $rk = 'aguard_safe_unlockreq_' . get_current_user_id(); $nreq = (int) get_transient($rk) + 1; set_transient($rk, $nreq, 15 * MINUTE_IN_SECONDS);
        if ($nreq > 3) { self::event('settings', __('Too many unlock code requests (3 per 15 min)', 'aguard-safe'), ['ip' => self::ip()], true, 'unlockflood_' . get_current_user_id(), 900); return false; }
        $code = (string) wp_rand(100000, 999999);
        set_transient('aguard_safe_code_' . get_current_user_id(), ['h' => hash_hmac('sha256', $code, wp_salt('auth')), 't' => time(), 'tries' => 0], 10 * MINUTE_IN_SECONDS);
        $to = self::opts()['email'];
        $body = __('AGuard Safe settings unlock code:', 'aguard-safe') . ' ' . $code . "\n" . __('Valid for 10 minutes.', 'aguard-safe') . "\n\n" . __('Site:', 'aguard-safe') . ' ' . home_url() . "\n" . __('Requested by:', 'aguard-safe') . ' ' . self::who() . "\n\n" . __('If this was not you, somebody with administrator permissions is trying to change the security settings. Change the passwords and turn LOCKDOWN on.', 'aguard-safe');
        $ok = self::mail_code($to, '[AGuard Safe] ' . wp_parse_url(home_url(), PHP_URL_HOST) . __(': settings unlock code', 'aguard-safe'), __('Settings unlock code', 'aguard-safe'), __('Enter it in AGuard Safe → Settings to change the security settings.', 'aguard-safe'), $code, [__('Site', 'aguard-safe') => home_url(), __('Requested by', 'aguard-safe') => self::who()], __('If this was not you, somebody with administrator permissions is trying to change the security settings. Change the passwords and turn LOCKDOWN on.', 'aguard-safe'), $body);
        self::event('settings', __('Settings unlock code requested', 'aguard-safe'), ['sent_to' => self::mask_email($to), 'mail_ok' => $ok ? 'yes' : 'no'], false);
        return (bool) $ok;
    }
    public static function unlock_verify($code) {
        $k = 'aguard_safe_code_' . get_current_user_id(); $c = get_transient($k);
        if (!is_array($c)) return false;
        $c['tries'] = ($c['tries'] ?? 0) + 1;
        if ($c['tries'] > 5) { delete_transient($k); self::event('settings', __('Too many wrong unlock codes – the code has been cancelled', 'aguard-safe'), [], true); return false; }
        if (!hash_equals($c['h'], hash_hmac('sha256', preg_replace('~\D~', '', $code), wp_salt('auth')))) { set_transient($k, $c, 10 * MINUTE_IN_SECONDS); return false; }
        delete_transient($k); set_transient(self::unlock_key(), 1, 15 * MINUTE_IN_SECONDS);
        self::event('settings', __('Settings unlocked with a code', 'aguard-safe'), [], true, 'unlock_' . time());
        return true;
    }

    /* ------------------------------------------------------------ admin UI */

    /* ------------------------------------------------------------ prekės ženklas: AG ženklas (vektorizuotas iš aguard.lt/brand/aguard-logo.png) ir funkcinės ikonos (64×64, linija 4.4, rašalas = currentColor, akcentas #0A8E89) */
    private static function icon_src($name) {
        static $i = null;
        if ($i === null) $i = [
            'apzvalga' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M9 12 H36 V34 H9 Z M43 12 H55 V23 H43 Z M43 30 H55 V52 H43 Z M9 41 H35 V52 H9 Z"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M15 29 L23 21 L30 25 M46 45 H52"/>',
            'skenavimas' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M8 24 V11 H24 M40 11 H53 V24 M53 40 V53 H40 M24 53 H11 L8 50 V40"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M21 32 H43 M32 21 V43"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M13 41 L41 13"/><path fill="#0A8E89" d="M45 32 L50 27 L55 32 L50 37 Z"/>',
            'ugniasiene' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M11 12 H51 L56 17 V24 H11 Z"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M11 28 H27 M39 28 H53 V40 H11 V34"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M11 45 H51 V54 H11 Z"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M32 17 V47 M27 42 L32 47 L37 42"/>',
            'vientisumas' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M16 8 H40 L52 20 V55 H16 Z M40 8 V21 H52"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M23 28 H41 M23 36 H35 M23 44 H30"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M34 45 L39 50 L51 37"/>',
            'prisijungimai' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M12 25 V16 L20 8 H44 L52 16 V25 M12 40 V51 L19 56 H45 L52 49 V40"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M8 32 H26 M38 32 H56"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M31 23 V40 L38 47"/><path fill="#0A8E89" d="M27 19 H35 V25 H27 Z"/>',
            'srautas' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M8 16 H23 L33 26 H48 M8 48 H23 L33 38 H48"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M10 32 H24 M41 32 H54"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M43 20 L49 26 L43 32 M43 32 L49 38 L43 44"/><path fill="#0A8E89" d="M7 28 H13 V36 H7 Z"/>',
            'pavojaus_signalai' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M31 7 L53 29 V37 L35 55 H27 L9 37 V29 Z"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M31 19 V38"/><path fill="#0A8E89" d="M27 44 H35 V51 H27 Z"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M13 13 L19 19 M49 13 L43 19"/>',
            'valymas' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M10 14 H46 M10 25 H33 M10 36 H26 M10 47 H23"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M51 10 L24 54 M37 42 L45 50 L56 38"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M47 17 H54 V24"/>',
            'nustatymai' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M10 16 H31 M43 16 H54 M10 32 H17 M29 32 H54 M10 48 H36 M48 48 H54"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M32 10 L42 16 L32 22 L22 16 Z"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M19 26 L29 32 L19 38 L9 32 Z"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M38 42 L48 48 L38 54 L28 48 Z"/>',
            'ataskaitos' => '<path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M12 9 H43 L53 19 V55 H12 Z M43 9 V20 H53"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M20 25 H36 M20 32 H30"/><path fill="none" stroke="currentColor" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M21 47 V41 M31 47 V37 M41 47 V30"/><path fill="none" stroke="#0A8E89" stroke-width="4.4" stroke-linejoin="miter" stroke-linecap="butt" d="M20 51 H45"/>',
            'mark' => '<g transform="translate(0,984) scale(0.1,-0.1)"><path class="ag-a" d="M3835 9173 c-49 -30 -110 -68 -135 -83 -25 -15 -117 -71 -205 -125 -88 -54 -191 -117 -230 -140 -38 -23 -131 -79 -205 -125 -74 -45 -252 -153 -395 -240 -419 -253 -976 -592 -1315 -800 -401 -246 -610 -374 -683 -418 l-58 -35 4 -1391 c4 -1516 1 -1423 62 -1745 96 -498 332 -1031 648 -1463 229 -314 580 -669 905 -915 148 -114 328 -234 336 -226 3 4 6 250 6 548 l0 542 -158 160 c-567 573 -862 1195 -898 1896 l-7 127 214 1 c164 1 1207 0 1289 -1 13 0 15 -206 15 -1796 0 -1584 2 -1797 15 -1808 38 -32 879 -526 896 -526 2 0 4 1940 4 4310 0 2371 -3 4310 -7 4310 -5 0 -48 -26 -98 -57z m-806 -2480 c0 -489 -2 -916 -5 -950 l-6 -63 -754 -2 -754 -3 0 500 0 500 432 260 c238 143 577 347 753 453 176 105 323 192 326 192 4 0 7 -399 8 -887z"/><path class="ag-g" d="M4310 4919 c0 -4030 1 -4311 17 -4305 24 10 395 220 623 354 721 423 1198 776 1585 1173 527 541 846 1104 1014 1789 78 320 104 601 99 1080 l-3 285 -906 3 -907 2 -5 -22 c-3 -13 -6 -220 -7 -460 l-1 -438 461 0 c435 0 461 -1 456 -18 -2 -9 -12 -55 -21 -102 -86 -443 -272 -843 -560 -1202 -214 -267 -469 -511 -785 -747 l-135 -102 -3 1346 c-1 740 -1 1950 0 2689 l3 1343 165 -100 c335 -204 1069 -645 1207 -726 l143 -84 2 -309 3 -309 238 0 c130 1 332 1 447 1 l210 0 0 573 0 572 -67 41 c-74 45 -226 137 -668 409 -441 271 -462 283 -1535 935 -311 188 -628 381 -705 428 -305 186 -348 212 -356 212 -5 0 -9 -1868 -9 -4311z"/></g>',
        ];
        return $i[$name] ?? '';
    }
    /** Inline SVG ikona. $class 'ag-two' – dviejų spalvų AG ženklas (A – teksto spalva, G – akcentas). */
    /** Allowed markup for the plugin's own inline SVG icons. */
    /** A note of the overview split into a headline and an explanation. */
    /**
     * One quiet request for a review at the bottom of the Overview: not before a week of use, not while something is wrong,
     * closed for good with one button. Nothing is promised for a review and nothing is sent anywhere when the link is pressed.
     */
    private static function review_card($d) {
        $o = self::opts(); $uid = get_current_user_id(); $m = get_user_meta($uid, 'aguard_safe_review', true);
        if ($m === 'done' || (is_numeric($m) && (int) $m > time())) return;
        if (empty($o['installed']) || time() - (int) $o['installed'] < WEEK_IN_SECONDS || ($d['grade'] ?? '') === 'risk' || self::setup_pending()) return;
        $n = wp_nonce_field('aguard_safe_review', '_wpnonce', true, false);
        echo '<form method="post" class="ag-review">' . wp_kses($n, ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<div class="ag-review-s" aria-hidden="true">★★★★★</div><div class="ag-review-t"><b>' . esc_html__('Is AGuard Safe useful to you?', 'aguard-safe') . '</b><span>' . esc_html__('The plugin is made by one person. An honest review on WordPress.org, good or critical, helps other site owners decide and shows what to improve.', 'aguard-safe') . '</span></div>';
        echo '<div class="ag-review-a"><a class="button button-primary" href="https://wordpress.org/support/plugin/aguard-safe/reviews/#new-post" target="_blank" rel="noopener noreferrer">' . esc_html__('Write a review', 'aguard-safe') . '</a><button class="button-link" name="aguard_review" value="later">' . esc_html__('Later', 'aguard-safe') . '</button><button class="button-link" name="aguard_review" value="done">' . esc_html__('Do not show again', 'aguard-safe') . '</button></div></form>';
    }

    /** Where an Overview note leads: [button label, address], or null. The 4th element of a note is a tab name or the address arguments of the exact place. */
    private static function issue_link($it) {
        $to = $it[3] ?? '';
        if (is_array($to)) return [isset($to['file']) ? __('Open the file', 'aguard-safe') : __('Open the check', 'aguard-safe'), self::url($to)];
        $go = ['scan' => __('Open Scan', 'aguard-safe'), 'settings' => __('Open Settings', 'aguard-safe'), 'plugins' => __('Open Plugins', 'aguard-safe')];
        return isset($go[(string) $to]) ? [$go[(string) $to], self::url(['tab' => (string) $to])] : null;
    }

    private static function issue_parts($it) {
        $tx = (string) ($it[1] ?? '');
        if (preg_match('/^(.{8,90}?)(?:: |\. | – )(.+)$/us', $tx, $mm)) return [rtrim($mm[1], '.'), $mm[2]];
        return [rtrim($tx, '.'), ''];
    }

    /** The two-colour shield of a section tab, with the section's emblem. */
    private static function shield($group, $w = 22) {
        $e = [
            'overview' => '<path class="ag-sf" d="M8.2 9.5h3v3h-3zM12.8 9.5h3v3h-3zM8.2 14h3v3h-3zM12.8 14h3v3h-3z"/>',
            'scan' => '<path class="ag-se" d="M8.2 12a3.1 3.1 0 1 0 6.2 0a3.1 3.1 0 1 0-6.2 0M13.6 14.4l2.6 2.8"/>',
            'activity' => '<path class="ag-se" d="M6.900 12.600c1.500-2.400 3.200-3.500 5.100-3.500s3.600 1.100 5.100 3.500c-1.500 2.400-3.200 3.500-5.100 3.500s-3.600-1.100-5.100-3.500z"/><path class="ag-sf" d="M10.700 12.600a1.300 1.300 0 1 0 2.600 0a1.300 1.300 0 1 0-2.600 0"/>',
            'plugins' => '<path class="ag-se" d="M10 8.300v2.500M14 8.300v2.500M8.600 10.800h6.800v1.700a3.400 3.400 0 0 1-6.800 0zM12 15.900v2.300"/>',
            'settings' => '<path class="ag-se" d="M8 10.5h8M8 14.8h8"/><path class="ag-sf" d="M8.8 10.5a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0M12.4 14.8a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0"/>',
            'emergency' => '<path class="ag-sf" d="M8.700 11.800h6.600v5h-6.600z"/><path class="ag-se" d="M10 11.800v-1.400a2 2 0 0 1 4 0v1.400"/>',
            'login' => '<path class="ag-se" d="M7.700 11.300a2.300 2.300 0 1 0 4.600 0a2.300 2.300 0 1 0-4.600 0M11.700 13l4.300 4.300M14.200 15.500l1.500-1.500"/>',
            'user' => '<path class="ag-sf" d="M9.900 10.400a2.100 2.100 0 1 0 4.200 0a2.100 2.100 0 1 0-4.200 0M7.900 18c.4-2.700 1.900-4 4.100-4s3.700 1.300 4.100 4z"/>',
            'theme' => '<path class="ag-sf" d="M8 9.300h8v3.200H8zM8 14h3.400v3.400H8zM12.900 14H16v3.400h-3.100z"/>',
            'alert' => '<path class="ag-se" d="M12 8.600v5.400"/><path class="ag-sf" d="M10.900 16.800a1.100 1.100 0 1 0 2.200 0a1.100 1.100 0 1 0-2.200 0"/>',
        ];
        return '<svg class="ag-shield" width="' . (int) $w . '" height="' . (int) round($w * 26 / 24) . '" viewBox="0 0 24 26" aria-hidden="true" focusable="false"><path class="ag-sl" d="M12 1.500 2.500 5v8.200c0 5.300 3.700 9 9.500 11.300z"/><path class="ag-sr" d="M12 1.500 21.500 5v8.200c0 5.300-3.700 9-9.500 11.300z"/>' . ($e[$group] ?? '') . '</svg>';
    }

    /**
     * The number in a ring for the summary card. With $total > 1 the ring is cut into $total parts and the first $bad of them take the colour of $tone:
     * "4 of 8 checks" is seen before it is read. Only paths, so it passes svg_kses().
     */
    private static function dial($label, $tone = 'ok', $total = 1, $bad = 0) {
        $total = max(1, min(24, (int) $total)); $bad = max(0, min($total, (int) $bad)); $r = 31; $c = 40; $gap = $total > 1 ? 7 : 0; $seg = '';
        for ($i = 0; $i < $total; $i++) {
            $a0 = deg2rad(-90 + $i * 360 / $total + $gap / 2); $a1 = deg2rad(-90 + ($i + 1) * 360 / $total - $gap / 2);
            if ($total === 1) { $d = 'M40 9a31 31 0 1 1-.01 0'; }
            else { $d = sprintf('M%.2F %.2FA%d %d 0 %d 1 %.2F %.2F', $c + $r * cos($a0), $c + $r * sin($a0), $r, $r, ($a1 - $a0) > M_PI ? 1 : 0, $c + $r * cos($a1), $c + $r * sin($a1)); }
            $seg .= '<path class="' . (($total === 1 && $tone !== 'ok') || $i < $bad ? 'ag-dial-b' : 'ag-dial-g') . '" d="' . $d . '"/>';
        }
        // the core: a navy disc on a coloured one, shifted like every "printed" block of the plugin
        $svg = '<svg width="80" height="80" viewBox="0 0 80 80" aria-hidden="true" focusable="false">' . $seg . '<path class="ag-dial-s" d="M42.5 20.5a22 22 0 1 1-.01 0"/><path class="ag-dial-c" d="M40 18a22 22 0 1 1-.01 0"/></svg>';
        return '<span class="ag-dial ag-dial-' . esc_attr(in_array($tone, ['ok', 'warn', 'risk'], true) ? $tone : 'ok') . '">' . wp_kses($svg, self::svg_kses()) . '<b>' . esc_html((string) $label) . '</b></span>';
    }

    public static function svg_kses() {
        $p = ['d' => true, 'fill' => true, 'class' => true, 'stroke' => true, 'stroke-width' => true, 'stroke-linecap' => true, 'stroke-linejoin' => true, 'transform' => true];
        return ['svg' => ['class' => true, 'width' => true, 'height' => true, 'viewbox' => true, 'fill' => true, 'aria-hidden' => true, 'focusable' => true], 'g' => $p, 'path' => $p];
    }

    /** Allowed markup for the plugin's own tables and detail blocks. */
    public static function html_kses() {
        $a = ['class' => true, 'style' => true, 'title' => true, 'colspan' => true];
        $k = wp_kses_allowed_html('post');
        foreach (['table', 'thead', 'tbody', 'tr', 'th', 'td', 'colgroup', 'col', 'div', 'p', 'span', 'pre', 'code', 'b', 'br', 'details', 'summary', 'a'] as $t) $k[$t] = array_merge($k[$t] ?? [], $a);
        $k['a']['href'] = true; $k['details']['open'] = true;
        return $k;
    }

    public static function icon($name, $size = 18, $class = '') {
        $src = self::icon_src($name); if ($src === '') return '';
        $mark = $name === 'mark'; $w = $mark ? (int) round($size * 825 / 984) : (int) $size;
        return '<svg class="ag-ic' . ($class ? ' ' . esc_attr($class) : '') . '" width="' . $w . '" height="' . (int) $size . '" viewBox="' . ($mark ? '0 0 825 984' : '0 0 64 64') . '" fill="currentColor" aria-hidden="true" focusable="false">' . $src . '</svg>';
    }
    /** Meniu ikona: AG ženklas, A white, G mint. Single quotes on purpose: WordPress svg-painter repaints only fill="…" in double quotes, so the two colours stay. */
    public static function menu_icon() {
        return 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="-30 0 885 984">' . str_replace(['class="ag-a"', 'class="ag-g"'], ["fill='#fff'", "fill='#3fb9a8'"], self::icon_src('mark')) . '</svg>');
    }
    /** Bendras administravimo CSS (aguard.lt paletė: rašalas #0D1B2A, akcentas #0A8E89, būsenos žalia/gintaro/raudona be ryškių „hakerio“ atspalvių). */
    public static function admin_assets($hook) {
        $base = plugin_dir_url(__FILE__) . 'assets/';
        $ver = function ($f) { $t = @filemtime(plugin_dir_path(__FILE__) . 'assets/' . $f); return self::VERSION . ($t ? '.' . $t : ''); }; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the browser must not keep an old copy after the file changes.
        if ($hook === 'index.php' && current_user_can(self::cap())) wp_enqueue_style('aguard-safe-widget', $base . 'widget.css', [], $ver('widget.css'));
        if ($hook !== 'toplevel_page_aguard-safe') return;
        wp_enqueue_style('aguard-safe-admin', $base . 'admin.css', [], $ver('admin.css'));
        wp_enqueue_script('aguard-safe-admin', $base . 'admin.js', [], $ver('admin.js'), true);
        wp_localize_script('aguard-safe-admin', 'aguardSafe', ['scanNonce' => wp_create_nonce('aguard_safe_scan'), 'checking' => __('checking…', 'aguard-safe'), 'refresh' => __('Refresh the overview', 'aguard-safe'), 'todo' => __('Details', 'aguard-safe'), 'busy' => __('Checking… The result opens here when the check is done. Do not close the page.', 'aguard-safe'), 'open' => __('Open', 'aguard-safe'), 'failed' => __('The check was interrupted, you can try again.', 'aguard-safe'), 'waiting' => __('waiting', 'aguard-safe'), 'serverError' => __('server error', 'aguard-safe'), 'stepFailed' => __('failed:', 'aguard-safe'), 'seconds' => __('s', 'aguard-safe'),
            /* translators: %d: number of seconds */
            'finished' => __('Finished in %d s.', 'aguard-safe')]);
    }

    public static function admin_menu() {
        add_menu_page('AGuard Safe', 'AGuard Safe', self::cap(), 'aguard-safe', [__CLASS__, 'page'], self::menu_icon(), 81);
    }

    /** True when the request carries a valid nonce of this plugin. */
    private static function verified() {
        static $ok = null;
        if ($ok === null) {
            $ok = isset($_GET['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'aguard_safe') && current_user_can(self::cap());
        }
        return $ok;
    }

    /** A request parameter. Without a valid nonce every parameter is ignored and the default is returned. */
    private static function req($k, $d = '') {
        if (!self::verified()) return $d;
        return isset($_GET[$k]) ? sanitize_text_field(wp_unslash($_GET[$k])) : $d; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified() above checks the nonce.
    }

    /** Who may use the plugin: administrators; on a multisite network only network administrators (the tools read files shared by all sites). */
    public static function cap() { return is_multisite() ? 'manage_network_options' : 'manage_options'; }

    private static function check_access() {
        if (!current_user_can(self::cap())) wp_die(esc_html__('You do not have permission.', 'aguard-safe'));
    }

    /** For the download and JSON endpoints: the nonce is required. */
    private static function require_nonce() {
        self::check_access();
        if (!self::verified()) wp_die(esc_html__('The security key is missing or has expired. Open the page from the menu again.', 'aguard-safe'), '', ['response' => 403]);
    }

    public static function handle_download() {
        if (!isset($_GET['aguard_download'])) return; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only detects the request; require_nonce() follows.
        self::require_nonce();
        if (!self::tool_on('files') && !self::tool_on('logs')) wp_die(esc_html__('This tool is turned off.', 'aguard-safe'));
        $req = self::req('aguard_download');
        if (self::req('b64') !== '' && ($dec = base64_decode(strtr($req, '-_', '+/'), true)) !== false) $req = sanitize_text_field($dec);
        $f = self::safe_path($req);
        if (!$f || !is_file($f) || !is_readable($f)) wp_die(esc_html__('File not found.', 'aguard-safe'));
        if (!self::tool_on('files') && !in_array(self::rel($f), array_column(self::log_candidates(), 'rel'), true)) wp_die(esc_html__('This tool is turned off.', 'aguard-safe'));
        self::event('tools', __('File downloaded:', 'aguard-safe') . ' ' . self::rel($f), [], false);
        nocache_headers();
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . rawurlencode(basename($f)) . '"');
        header('Content-Length: ' . filesize($f));
        readfile($f); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streams a file download to the administrator without loading it into memory.
        exit;
    }

    private static function url($args = []) {
        return wp_nonce_url(add_query_arg(array_merge(['page' => 'aguard-safe'], $args), admin_url('admin.php')), 'aguard_safe');
    }

    /** Data for a tab (shared by the HTML page and the JSON endpoint). Returns [title, data]. */
    private static function collect($tab) {
        $g = function ($k, $d = '') {
            $v64 = self::req($k . '64', null);
            if ($v64 !== null) { $v = base64_decode(strtr($v64, '-_', '+/'), true); if ($v !== false) return sanitize_text_field($v); }
            return self::req($k, $d);
        };
        $n = function ($k, $d, $min, $max) use ($g) { return max($min, min($max, (int) $g($k, $d))); };
        $data = null; $title = '';
        switch ($tab) {
            case 'files':
                $path = $g('path'); $file = $g('file');
                if ($file !== '') { $title = __('File:', 'aguard-safe') . ' ' . $file; $data = self::read_file($file, $n('offset', 0, 0, 2147483647)); }
                else { $title = __('Folder: /', 'aguard-safe') . $path; $data = self::list_dir($path, $g('hash') === '1'); }
                break;
            case 'logs':
                $file = $g('file');
                if ($file !== '') { $title = __('Log:', 'aguard-safe') . ' ' . $file; $data = self::tail_file($file, $n('lines', 200, 1, 5000), $g('q'), $g('first') === '1', $n('start', 0, 0, 2147483647)); }
                else { $title = __('Logs', 'aguard-safe'); $data = self::log_candidates(); }
                break;
            case 'scan':
                $title = __('Checks', 'aguard-safe');
                $what = $g('what', '');
                if ($what === 'core') $data = self::check_core(60);
                elseif ($what === 'uploads') $data = self::scan_uploads(60);
                elseif ($what === 'recent') $data = self::recent_files($n('hours', 48, 1, 8760), $n('limit', 300, 1, 2000), 60);
                elseif ($what === 'cloaking') $data = self::check_cloaking();
                elseif ($what === 'sentinels') $data = self::check_sentinels();
                elseif ($what === 'plugins') $data = self::check_plugins();
                elseif ($what === 'suspicious') $data = self::scan_suspicious($g('dir', ''), $n('limit', 400, 1, 2000));
                elseif ($what === 'snippets') $data = self::check_snippets();
                elseif ($what === 'remote') $data = self::check_remote_admin();
                elseif ($what === 'uploads_guard') $data = ['state' => self::uploads_guard_check(), 'verify' => self::uploads_guard_verify()];
                elseif ($what === 'all') $data = self::run_scan(true);
                else { $data = get_option(self::OPT . '_last_scan', null); }
                break;
            case 'events':
                $title = __('Events', 'aguard-safe'); $data = get_option(self::OPT_EVENTS, []);
                break;
            case 'sessions':
                $title = __('Administrator sessions', 'aguard-safe'); $data = self::admin_sessions();
                break;
            case 'plugins':
                $title = __('Plugins: updates and known vulnerabilities', 'aguard-safe'); $data = ['on' => !empty(self::opts()['vuln_check']), 'rows' => self::plugin_rows(), 'state' => self::vuln_data()];
                break;
            case 'home':
                $title = __('Overview', 'aguard-safe'); $data = self::dashboard();
                break;
            case 'settings':
                $title = __('Settings', 'aguard-safe'); $data = ['settings' => self::opts(), 'unlocked' => self::is_unlocked(), 'uploads_guard' => self::uploads_guard_check(), 'login' => self::login_info()];
                break;
            case 'response':
                $title = __('Incident response', 'aguard-safe'); $data = ['lockdown' => !empty(self::opts()['lockdown']) ? self::opts()['lockdown'] : 0, 'quarantine' => count(get_option(self::OPT_Q, []) ?: []), 'remote_admin' => self::check_remote_admin()];
                break;
            case 'quarantine':
                $title = __('Quarantine', 'aguard-safe'); $data = ['dir' => self::quarantine_dir(false), 'items' => array_values(get_option(self::OPT_Q, []) ?: [])];
                break;
            default:
                $title = __('Status', 'aguard-safe'); $data = self::status();
        }

        return [$title, $data];
    }

    public static function handle_json() {
        if (!isset($_GET['format'])) return; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only detects the request; require_nonce() follows.
        self::require_nonce();
        if (self::req('format') !== 'json') return;
        $tab = sanitize_key(self::req('tab', 'home'));
        if (!in_array($tab, ['home', 'status', 'events', 'scan', 'files', 'logs', 'sessions', 'plugins', 'quarantine', 'settings', 'response'], true)) $tab = 'status';
        if (!self::tool_on($tab)) { list($title, $data) = ['', new WP_Error('off', __('This viewer is turned off. Turn it on in Settings → Tools.', 'aguard-safe'))]; } else { list($title, $data) = self::collect($tab); }
        nocache_headers(); header('Content-Type: application/json; charset=UTF-8');
        echo wp_json_encode(is_wp_error($data) ? ['error' => $data->get_error_message()] : $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        exit;
    }

    public static function page() {
        self::check_access();
        $tab = sanitize_key(self::req('tab', 'home'));

        if (isset($_POST['aguard_unlock_request']) && check_admin_referer('aguard_safe_settings')) { $r = self::unlock_request(); echo '<div class="notice notice-' . ($r ? 'info' : 'error') . '"><p>' . ($r ? esc_html__('The unlock code has been sent to', 'aguard-safe') . ' ' . esc_html(self::mask_email(self::opts()['email'])) . esc_html__('. Valid for 10 minutes.', 'aguard-safe') : esc_html__('Could not send the code.', 'aguard-safe')) . '</p></div>'; $tab = 'settings'; }
        if (isset($_POST['aguard_unlock_code']) && check_admin_referer('aguard_safe_settings')) { $ok = self::unlock_verify(sanitize_text_field(wp_unslash($_POST['aguard_unlock_code']))); echo '<div class="notice notice-' . ($ok ? 'success' : 'error') . '"><p>' . ($ok ? esc_html__('Settings are unlocked for 15 minutes.', 'aguard-safe') : esc_html__('Wrong or expired code.', 'aguard-safe')) . '</p></div>'; $tab = 'settings'; }
        if (isset($_POST['aguard_lock']) && check_admin_referer('aguard_safe_settings')) { delete_transient(self::unlock_key()); echo '<div class="notice notice-success"><p>' . esc_html__('Settings locked.', 'aguard-safe') . '</p></div>'; $tab = 'settings'; }
        if (isset($_POST['aguard_logout_user']) && check_admin_referer('aguard_safe_q') && current_user_can(self::cap())) {
            $uid = (int) $_POST['aguard_logout_user']; $tu = get_userdata($uid);
            if ($tu) { $m = WP_Session_Tokens::get_instance($uid); if ($uid === get_current_user_id()) $m->destroy_others(wp_get_session_token()); else $m->destroy_all(); self::event('settings', __('All sessions of the user signed out:', 'aguard-safe') . ' ' . $tu->user_login, ['ip' => self::ip(), 'by' => wp_get_current_user()->user_login], true, 'logout_' . $uid . '_' . time()); echo '<div class="notice notice-success"><p>' . esc_html($tu->user_login) . esc_html__(': all devices signed out', 'aguard-safe') . ($uid === get_current_user_id() ? esc_html__(', except this one', 'aguard-safe') : '') . esc_html__('. Signing in again will require the password.', 'aguard-safe') . '</p></div>'; }
            $tab = 'sessions';
        }
        if (isset($_POST['aguard_setup_all']) && check_admin_referer('aguard_safe_settings') && empty(self::opts()['setup_done'])) {
            // First-run setup, once: it only turns protection ON, so it does not need the unlock code. Afterwards these switches live in Settings.
            $o = self::opts(); $done = []; $failed = false;
            if (empty($o['block_php_uploads'])) { $res = self::uploads_guard_apply(true, true); if (in_array(__('FAILED to write', 'aguard-safe'), (array) $res, true)) $failed = true; else { $o['block_php_uploads'] = 1; $done[] = 'block_php_uploads'; } }
            if (empty($o['vuln_check'])) { $o['vuln_check'] = 1; $done[] = 'vuln_check'; }
            if (empty($o['pw_check'])) { $o['pw_check'] = 1; $done[] = 'pw_check'; }
            $o['setup_done'] = 1; update_option(self::OPT, $o, true); self::$opts = null;
            self::event('settings', __('Recommended protection turned on', 'aguard-safe'), ['ip' => self::ip(), 'turned_on' => implode(', ', $done)], true);
            self::vuln_refresh(true);
            echo '<div class="notice notice-' . ($failed ? 'warning' : 'success') . '"><p>' . esc_html($failed ? __('The vulnerability check is on, but the PHP block could not be written to the uploads folder. Try again in Settings.', 'aguard-safe') : __('Recommended protection is on. You can change each item in Settings.', 'aguard-safe')) . '</p></div>';
        }
        if (isset($_POST['aguard_unblock']) && check_admin_referer('aguard_safe_settings') && self::is_unlocked()) {
            foreach (array_keys(self::lockouts()) as $bip) delete_transient('aguard_safe_lock_' . md5($bip));
            update_option(self::OPT . '_lockouts', [], false); unset($_POST['aguard_save']);
            self::event('settings', __('All blocked addresses were unblocked', 'aguard-safe'), ['ip' => self::ip()], false);
            echo '<div class="notice notice-success"><p>' . esc_html__('All addresses are unblocked.', 'aguard-safe') . '</p></div>';
        }
        if (isset($_POST['aguard_setup_later']) && check_admin_referer('aguard_safe_settings')) set_transient('aguard_safe_setup_later_' . get_current_user_id(), 1, 12 * HOUR_IN_SECONDS);
        if (isset($_POST['aguard_setup_skip']) && check_admin_referer('aguard_safe_settings')) {
            $o = self::opts(); $o['setup_done'] = 1; update_option(self::OPT, $o, true); self::$opts = null;
        }
        if (isset($_POST['aguard_vuln_on']) && check_admin_referer('aguard_safe_settings')) {
            $o = self::opts(); $o['vuln_check'] = 1; update_option(self::OPT, $o, true); self::$opts = null;
            self::event('settings', __('Plugin vulnerability check turned on', 'aguard-safe'), ['ip' => self::ip()], false);
            $vd = self::vuln_refresh(true);
            echo '<div class="notice notice-' . (empty($vd['error']) ? 'success' : 'warning') . '"><p>' . (empty($vd['error']) ? esc_html__('The vulnerability check is on. The plugins have been checked.', 'aguard-safe') : esc_html__('The vulnerability check is on, but the first request failed:', 'aguard-safe') . ' ' . esc_html((string) $vd['error'])) . '</p></div>';
            $tab = 'plugins';
        }
        if (isset($_POST['aguard_vuln_off']) && check_admin_referer('aguard_safe_settings')) {
            if (!self::is_unlocked()) echo '<div class="notice notice-error"><p>' . esc_html__('The vulnerability check can be turned off only when Settings are unlocked with the code from the e-mail.', 'aguard-safe') . '</p></div>';
            else {
                $o = self::opts(); $o['vuln_check'] = 0; update_option(self::OPT, $o, true); self::$opts = null; delete_option(self::OPT_VULNS);
                self::event('settings', __('Plugin vulnerability check turned off', 'aguard-safe'), ['ip' => self::ip()], true, 'vuln_off_' . time());
                echo '<div class="notice notice-success"><p>' . esc_html__('The vulnerability check is off. Nothing is sent to data.aguard.lt.', 'aguard-safe') . '</p></div>';
            }
            $tab = 'plugins';
        }
        if (isset($_POST['aguard_vuln_check']) && check_admin_referer('aguard_safe_settings')) {
            $vd = self::vuln_refresh(true);
            if ($vd === null) echo '<div class="notice notice-error"><p>' . esc_html__('The vulnerability check is turned off.', 'aguard-safe') . '</p></div>';
            elseif (!empty($vd['error'])) echo '<div class="notice notice-warning"><p>' . esc_html__('The check could not reach data.aguard.lt:', 'aguard-safe') . ' ' . esc_html((string) $vd['error']) . '</p></div>';
            else echo '<div class="notice notice-success"><p>' . esc_html__('The plugins have been checked.', 'aguard-safe') . '</p></div>';
            $tab = 'plugins';
        }
        if (isset($_POST['aguard_run_scan']) && check_admin_referer('aguard_safe_settings')) { self::cron_scan(true); echo '<div class="notice notice-success"><p>' . esc_html__('Check finished.', 'aguard-safe') . '</p></div>'; }
        if (isset($_POST['aguard_prune']) && check_admin_referer('aguard_safe_settings')) {
            $kw = trim(sanitize_text_field(wp_unslash($_POST['aguard_prune_kw'] ?? '')));
            if (!self::is_unlocked()) echo '<div class="notice notice-error"><p>' . esc_html__('Events can be removed only when Settings are unlocked.', 'aguard-safe') . '</p></div>';
            elseif (mb_strlen($kw) < 4) echo '<div class="notice notice-error"><p>' . esc_html__('The keyword is too short.', 'aguard-safe') . '</p></div>';
            else { $n = self::prune_events($kw); echo '<div class="notice notice-success"><p>' . esc_html__('Events removed:', 'aguard-safe') . ' ' . (int) $n . '.</p></div>'; }
            $tab = 'settings';
        }
        if (isset($_POST['aguard_save']) && check_admin_referer('aguard_safe_settings') && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('Settings are locked. Unlock them first with the code from the e-mail.', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_save']); $tab = 'settings'; }
        if (isset($_POST['aguard_rebaseline']) && check_admin_referer('aguard_safe_settings') && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('The baseline can be updated only when Settings are unlocked.', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_rebaseline']); }
        if (isset($_POST['aguard_restore']) && check_admin_referer('aguard_safe_q') && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('Restoring from quarantine is possible only when Settings are unlocked.', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_restore']); }
        if (isset($_POST['aguard_save']) && check_admin_referer('aguard_safe_settings')) {
            $o = self::opts();
            $o['email'] = sanitize_email(wp_unslash($_POST['email'] ?? self::default_mail())) ?: self::default_mail();
            $o['notify_cc'] = implode(', ', array_unique(array_filter(array_map('sanitize_email', preg_split('/[\s,;]+/', sanitize_text_field(wp_unslash($_POST['notify_cc'] ?? '')))))));
            $o['notify'] = empty($_POST['notify']) ? 0 : 1;
            $o['notify_admin_login'] = empty($_POST['notify_admin_login']) ? 0 : 1;
            $o['cloak_check'] = empty($_POST['cloak_check']) ? 0 : 1;
            $o['tool_files'] = empty($_POST['tool_files']) ? 0 : 1;
            $o['tool_logs'] = empty($_POST['tool_logs']) ? 0 : 1;
            $o['credit'] = empty($_POST['credit']) ? 0 : 1;
            $o['failed_threshold'] = max(5, min(100000, absint(wp_unslash($_POST['failed_threshold'] ?? 20))));
            $o['lockout'] = empty($_POST['lockout']) ? 0 : 1;
            $o['lockout_after'] = max(3, min(1000, absint(wp_unslash($_POST['lockout_after'] ?? 10))));
            $o['pw_check'] = empty($_POST['pw_check']) ? 0 : 1;
            $o['whitelist'] = array_values(array_filter(array_map('trim', explode("\n", sanitize_textarea_field(wp_unslash($_POST['whitelist'] ?? ''))))));
            $want = empty($_POST['block_php_uploads']) ? 0 : 1;
            if ($want !== (int) ($o['block_php_uploads'] ?? 0)) { $res = self::uploads_guard_apply((bool) $want); $o['block_php_uploads'] = $want; echo '<div class="notice notice-info"><p>' . esc_html__('PHP block in uploads:', 'aguard-safe') . ' ' . esc_html(wp_json_encode($res, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</p></div>'; }
            update_option(self::OPT, $o, true); self::$opts = null;
            self::event('settings', __('Settings changed', 'aguard-safe'), ['email' => $o['email'], 'notify' => $o['notify'], 'whitelist' => $o['whitelist'], 'block_php_uploads' => $o['block_php_uploads'], 'credit' => $o['credit']], true, 'settings_' . time());
            echo '<div class="notice notice-success"><p>' . esc_html__('Saved.', 'aguard-safe') . '</p></div>'; $tab = 'settings';
        }
        if (isset($_POST['aguard_test_mail']) && check_admin_referer('aguard_safe_settings')) {
            $e = self::event('test', __('Test notification', 'aguard-safe'), ['php' => PHP_VERSION], true, 'test_' . time());
            echo '<div class="notice notice-' . ($e['mailed'] ? 'success' : 'error') . '"><p>' . ($e['mailed'] ? esc_html__('E-mail sent to', 'aguard-safe') . ' ' . esc_html(self::opts()['email']) : esc_html__('wp_mail() returned an error – check the mail settings.', 'aguard-safe')) . '</p></div>';
        }
        if (isset($_POST['aguard_rebaseline']) && check_admin_referer('aguard_safe_settings')) { self::build_baseline(); echo '<div class="notice notice-success"><p>' . esc_html__('Baseline updated.', 'aguard-safe') . '</p></div>'; }
        if (isset($_POST['aguard_uploads_verify']) && check_admin_referer('aguard_safe_settings')) { $v = self::uploads_guard_verify(); echo '<div class="notice notice-' . (!empty($v['blocked']) ? 'success' : 'warning') . '"><p>' . esc_html__('PHP execution test in the uploads folder:', 'aguard-safe') . ' ' . esc_html(wp_json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</p></div>'; }
        if (isset($_POST['aguard_lockdown_on']) && check_admin_referer('aguard_safe_settings')) { $r = self::lockdown(true); echo '<div class="notice notice-warning"><p>' . esc_html__('LOCKDOWN enabled:', 'aguard-safe') . ' ' . esc_html(wp_json_encode($r, JSON_UNESCAPED_UNICODE)) . '</p></div>'; }
        if (isset($_POST['aguard_lockdown_off']) && check_admin_referer('aguard_safe_settings')) { self::lockdown(false); echo '<div class="notice notice-success"><p>' . esc_html__('LOCKDOWN disabled.', 'aguard-safe') . '</p></div>'; }
        if (isset($_POST['aguard_replace']) && check_admin_referer('aguard_safe_q')) {
            if (!self::is_unlocked()) echo '<div class="notice notice-error"><p>' . esc_html__('Replacing files is locked: unlock Settings first with the code from the e-mail (Settings).', 'aguard-safe') . '</p></div>';
            else {
                $r = self::replace_with_original(sanitize_text_field(wp_unslash($_POST['aguard_replace'])));
                if (is_wp_error($r)) echo '<div class="notice notice-error"><p>' . esc_html($r->get_error_message()) . '</p></div>';
                /* translators: 1: file path, 2: what the original belongs to, e.g. "Elementor 3.5.0" */
                else echo '<div class="notice notice-' . ($r['verdict'] === 'ok' ? 'success' : 'warning') . '"><p>' . esc_html(sprintf(__('%1$s is now the original from %2$s. The previous file is kept in Scan → Quarantine.', 'aguard-safe'), $r['rel'], $r['of'])) . ' ' . esc_html($r['verdict'] === 'ok' ? __('The site answered live after the change.', 'aguard-safe') : __('The plugin could not fully check the site by itself, so open it in a private window and look at it.', 'aguard-safe')) . '</p></div>';
            }
        }
        if (isset($_POST['aguard_review']) && check_admin_referer('aguard_safe_review')) update_user_meta(get_current_user_id(), 'aguard_safe_review', sanitize_key(wp_unslash($_POST['aguard_review'])) === 'done' ? 'done' : time() + 30 * DAY_IN_SECONDS);
        if (isset($_POST['aguard_allow']) && check_admin_referer('aguard_safe_q')) {
            $arel = ltrim(sanitize_text_field(wp_unslash($_POST['aguard_allow'])), '/');
            if (!self::is_unlocked()) echo '<div class="notice notice-error"><p>' . esc_html__('The allowlist is locked: unlock Settings with the code from the e-mail first.', 'aguard-safe') . '</p></div>';
            elseif ($arel !== '' && strpos($arel, '..') === false && strlen($arel) < 400) {
                $o = self::opts(); $wl = array_values(array_filter((array) ($o['whitelist'] ?? []))); if (!in_array($arel, $wl, true)) $wl[] = $arel; $o['whitelist'] = $wl; update_option(self::OPT, $o, true); self::$opts = null;
                $ls = get_option(self::OPT . '_last_scan', []);
                if (is_array($ls) && !empty($ls['core']['extra'])) { $ls['core']['extra'] = array_values(array_filter((array) $ls['core']['extra'], function ($x) use ($arel) { return preg_replace('~ \(.*$~', '', (string) $x) !== $arel; })); update_option(self::OPT . '_last_scan', $ls, false); }
                self::event('settings', __('File added to the allowlist:', 'aguard-safe') . ' ' . $arel, ['whitelist' => $wl], true, 'allow_' . md5($arel));
                echo '<div class="notice notice-success"><p>' . esc_html__('Added to the allowlist. The file will not be reported again.', 'aguard-safe') . '</p></div>';
            }
        }
        if (isset($_POST['aguard_quarantine']) && check_admin_referer('aguard_safe_q') && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('Quarantine is locked: unlock Settings first with the code from the e-mail (Settings).', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_quarantine']); }
        if (isset($_POST['aguard_quarantine']) && check_admin_referer('aguard_safe_q')) {
            $before = self::site_probe(); // does the site answer now? Without that the check after the move proves nothing.
            $r = self::quarantine_file(sanitize_text_field(wp_unslash($_POST['aguard_quarantine'])));
            if (is_wp_error($r)) echo '<div class="notice notice-error"><p>' . esc_html($r->get_error_message()) . '</p></div>';
            else {
                if (function_exists('opcache_invalidate')) @opcache_invalidate($r['orig'], true); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- opcache may be restricted on the host; the check below still runs.
                $after = self::site_probe(); $v = self::probe_verdict($before, $after);
                $codes = ['core_before' => $before['core'], 'core_after' => $after['core'], 'home_before' => $before['home'], 'home_after' => $after['home'], 'home_from_cache' => !$after['home_live']];
                if ($v === 'broken') {
                    $back = self::restore_quarantined($r['id']);
                    if (is_wp_error($back)) { echo '<div class="notice notice-error"><p>' . esc_html__('Without this file the site stopped answering, and the file could not be put back automatically:', 'aguard-safe') . ' ' . esc_html($back->get_error_message()) . ' ' . esc_html__('Restore it now in Scan → Quarantine.', 'aguard-safe') . '</p></div>'; $tab = 'quarantine'; }
                    else {
                        echo '<div class="notice notice-warning"><p><strong>' . esc_html__('The file was put back.', 'aguard-safe') . '</strong> ' . esc_html__('Without it the site started answering with an error, so the move was undone. The site needs this file: replace it with a clean copy (reinstall the plugin or theme) instead of removing it.', 'aguard-safe') . '</p></div>';
                        self::event('quarantine', __('Quarantine undone, the site needs the file:', 'aguard-safe') . ' ' . $r['rel'], $codes, false);
                    }
                } else {
                    $say = ['ok' => __('WordPress and the home page answered live after the move. The file can be restored here at any time.', 'aguard-safe'), 'core_only' => __('WordPress with all plugins still loads. The home page could not be checked live (it came from a cache or did not answer), so open the site in a private window and look at it. The file can be restored here at any time.', 'aguard-safe'), 'unknown' => __('The plugin could not check the site by itself, so open the site in a private window and make sure it works. The file can be restored here at any time.', 'aguard-safe')][$v];
                    echo '<div class="notice notice-' . ($v === 'ok' ? 'success' : 'warning') . '"><p>' . esc_html__('Moved to quarantine:', 'aguard-safe') . ' ' . esc_html($r['rel']) . '. ' . esc_html($say) . '</p></div>';
                    $tab = 'quarantine';
                }
            }
        }
        if (isset($_POST['aguard_restore']) && check_admin_referer('aguard_safe_q')) {
            $r = self::restore_quarantined(sanitize_text_field(wp_unslash($_POST['aguard_restore'])));
            echo '<div class="notice notice-' . (is_wp_error($r) ? 'error' : 'success') . '"><p>' . esc_html(is_wp_error($r) ? $r->get_error_message() : esc_html__('Restored:', 'aguard-safe') . ' ' . $r['orig']) . '</p></div>';
        }

        if (isset($_POST['aguard_login_save']) && check_admin_referer('aguard_safe_settings') && !self::is_unlocked() && (sanitize_key(wp_unslash($_POST['login_mode'] ?? '')) !== (self::opts()['login_mode'] ?? 'off') || sanitize_title((string) wp_unslash($_POST['login_slug'] ?? '')) !== (string) (self::opts()['login_slug'] ?? ''))) { echo '<div class="notice notice-error"><p>' . esc_html__('Changing the login address is locked: unlock Settings first with the code from the e-mail.', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_login_save']); $tab = 'settings'; }
        if (isset($_POST['aguard_login_save']) && check_admin_referer('aguard_safe_settings')) {
            { $r = self::login_apply(sanitize_key(wp_unslash($_POST['login_mode'] ?? 'off')), sanitize_title(wp_unslash($_POST['login_slug'] ?? ''))); echo '<div class="notice notice-' . ($r['ok'] ? 'success' : 'error') . '"><p>' . wp_kses_post($r['msg']) . '</p>' . (!empty($r['test']) ? '<p style="font-size:12px;color:#555">' . esc_html__('Test:', 'aguard-safe') . ' ' . esc_html(wp_json_encode($r['test'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</p>' : '') . '</div>'; }
            $tab = 'settings';
        }
        if (isset($_POST['aguard_2fa_forget']) && check_admin_referer('aguard_safe_settings')) { self::twofa_revoke(); self::event('settings', __('2FA: all remembered browsers forgotten', 'aguard-safe'), ['ip' => self::ip()], true, '2fa_forget_' . time()); echo '<div class="notice notice-success"><p>' . esc_html__('All remembered browsers have been forgotten – next time every administrator will enter a code.', 'aguard-safe') . '</p></div>'; $tab = 'settings'; }
        if (isset($_POST['aguard_2fa_save']) && check_admin_referer('aguard_safe_settings')) {
            $o = self::opts(); $want = empty($_POST['twofa']) ? 0 : 1; $was = (int) ($o['twofa'] ?? 0);
            if ($want === 0 && $was === 1 && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('The confirmation can be turned off only when Settings are unlocked with the code from the e-mail (above).', 'aguard-safe') . '</p></div>'; $tab = 'settings'; }
            else {
                $o['twofa'] = $want; update_option(self::OPT, $o, true); self::$opts = null;
                if ($want !== $was) { self::twofa_revoke(); self::event('settings', __('E-mail confirmation (2FA)', 'aguard-safe') . ' ' . ($want ? __('ENABLED', 'aguard-safe') : __('DISABLED', 'aguard-safe')) . ' ' . __('for administrators', 'aguard-safe'), ['ip' => self::ip()], true, '2fa_' . time()); }
                $test = '';
                if ($want && $want !== $was) { $me = wp_get_current_user(); $ok = self::twofa_send($me, '000000'); $test = $ok ? ' ' . __('A test e-mail has been sent to', 'aguard-safe') . ' ' . esc_html(self::mask_email($me->user_email)) . (' ' . __('– if it does not arrive within a few minutes, turn the confirmation off.', 'aguard-safe')) : ' ' . __('WARNING: the test e-mail could not be sent – check the site\'s mail before relying on this.', 'aguard-safe'); }
                echo '<div class="notice notice-success"><p>' . esc_html__('E-mail confirmation', 'aguard-safe') . ' ' . ($want ? esc_html__('enabled: from the next login administrators will enter a code from the e-mail after the password.', 'aguard-safe') : esc_html__('disabled.', 'aguard-safe')) . wp_kses_post($test) . '</p></div>'; $tab = 'settings';
            }
        }
        if (isset($_POST['aguard_login_test']) && check_admin_referer('aguard_safe_settings')) { $t = self::login_selftest(); echo '<div class="notice notice-' . ($t['ok'] ? 'success' : 'warning') . '"><p>' . esc_html__('Login address self-test:', 'aguard-safe') . ' ' . ($t['ok'] ? esc_html__('everything works.', 'aguard-safe') : esc_html__('problems found.', 'aguard-safe')) . '</p><p style="font-size:12px;color:#555">' . esc_html(wp_json_encode($t, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</p></div>'; $tab = 'settings'; }

        if (!in_array($tab, ['home', 'status', 'events', 'scan', 'files', 'logs', 'sessions', 'plugins', 'quarantine', 'settings', 'response'], true)) $tab = 'status';
        if (!self::tool_on($tab)) { $title = $tab === 'files' ? __('Files', 'aguard-safe') : __('Logs', 'aguard-safe'); $data = new WP_Error('off', __('This viewer is turned off. Turn it on in Settings → Tools.', 'aguard-safe')); }
        else { list($title, $data) = self::collect($tab); }
        self::render($tab, $title, $data);
    }

    public static function status() {
        global $wp_version, $wpdb;
        $b = get_option(self::OPT_BASELINE, []);
        $mu = []; $wc = self::content_dir();
        $mud = self::mu_plugins_dir();
        if (is_dir($mud)) foreach ((@scandir($mud) ?: []) as $n) { if ($n[0] !== '.' && is_file("$mud/$n")) { $r = self::file_row("$mud/$n"); $r['sha256'] = hash_file('sha256', "$mud/$n"); $mu[] = $r; } }
        $drop = [];
        foreach ((@scandir($wc) ?: []) as $n) { if ($n[0] !== '.' && is_file("$wc/$n")) { $r = self::file_row("$wc/$n"); $r['sha256'] = hash_file('sha256', "$wc/$n"); $drop[] = $r; } }
        $admins = [];
        foreach (get_users(['role' => 'administrator']) as $u) $admins[] = ['id' => $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'registered' => $u->user_registered, 'display' => $u->display_name];
        return [
            'plugin' => self::VERSION, 'wp' => $wp_version, 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'server' => self::srv('SERVER_SOFTWARE'), 'os' => (function_exists('php_uname') ? php_uname() : PHP_OS),
            'abspath' => self::wp_root() . '/', 'base_dir' => self::base_dir(), 'user' => function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? posix_geteuid()) : get_current_user(),
            'db' => ['server' => $wpdb->db_server_info(), 'prefix' => $wpdb->prefix, 'name' => DB_NAME, 'host' => DB_HOST],
            'consts' => ['WP_CACHE' => defined('WP_CACHE') ? WP_CACHE : null, 'DISALLOW_FILE_EDIT' => defined('DISALLOW_FILE_EDIT') ? DISALLOW_FILE_EDIT : null, 'DISALLOW_FILE_MODS' => defined('DISALLOW_FILE_MODS') ? DISALLOW_FILE_MODS : null, 'WP_DEBUG' => defined('WP_DEBUG') ? WP_DEBUG : null, 'DISABLE_WP_CRON' => defined('DISABLE_WP_CRON') ? DISABLE_WP_CRON : null],
            'php_ini' => ['disable_functions' => ini_get('disable_functions'), 'open_basedir' => ini_get('open_basedir'), 'auto_prepend_file' => ini_get('auto_prepend_file'), 'auto_append_file' => ini_get('auto_append_file'), 'error_log' => ini_get('error_log')],
            'included_files_before_plugins' => self::early_includes(),
            'admins' => $admins, 'admin_count' => count($admins), 'users_total' => count_users()['total_users'] ?? null,
            'mu_plugins' => $mu, 'dropins' => $drop,
            'baseline_time' => $b['t'] ?? null, 'baseline_files' => count($b['files'] ?? []),
            'next_scan' => wp_next_scheduled(self::CRON), 'last_scan' => (get_option(self::OPT . '_last_scan')['t'] ?? null),
            'settings' => self::opts(),
            'quarantine' => ['dir' => self::quarantine_dir(false), 'count' => count(get_option(self::OPT_Q, []) ?: [])],
            'uploads_guard' => self::uploads_guard_check(),
            'remote_admin' => self::check_remote_admin(),
            'lockdown' => !empty(self::opts()['lockdown']) ? self::opts()['lockdown'] : 0,
            'login' => self::login_info(),
        ];
    }

    /** PHP files already loaded that are not WP core, plugins or themes: the place where early hooks hide. */
    private static function early_includes() {
        $out = [];
        $abs = self::wp_root() . '/'; $root = rtrim($abs, '/');
        $own = '~^(' . preg_quote(self::rel_to($root, self::plugins_dir()), '~') . '|' . preg_quote(self::rel_to($root, get_theme_root()), '~') . ')/~';
        foreach (get_included_files() as $f) {
            $f = wp_normalize_path($f);
            $rel = strpos($f, $abs) === 0 ? substr($f, strlen($abs)) : $f;
            if (preg_match($own, $rel) || preg_match($own, $f) || preg_match('~^(wp-admin/|wp-includes/|wp-settings\.php$|wp-load\.php$|wp-config\.php$|index\.php$|wp-blog-header\.php$|wp-cron\.php$|wp-login\.php$|xmlrpc\.php$|wp-admin/.*)~', $rel)) continue;
            $out[] = $rel;
        }
        return $out;
    }

    /* ------------------------------------------------------------ žmogui skaitomi duomenų vaizdai (JSON lieka po „Techninės detalės“) */
    private static function key_h($k) {
        $m = ['plugin' => __('Plugin', 'aguard-safe'), 'wp' => 'WordPress', 'php' => 'PHP', 'sapi' => __('PHP mode', 'aguard-safe'), 'server' => __('Server', 'aguard-safe'), 'os' => __('Operating system', 'aguard-safe'), 'abspath' => __('Site folder', 'aguard-safe'), 'base_dir' => __('Folder the tools may read', 'aguard-safe'), 'user' => __('System user', 'aguard-safe'), 'db' => __('Database', 'aguard-safe'), 'prefix' => __('Table prefix', 'aguard-safe'), 'name' => __('Name', 'aguard-safe'), 'host' => __('Address', 'aguard-safe'), 'consts' => __('Constants (wp-config.php)', 'aguard-safe'), 'php_ini' => __('PHP settings', 'aguard-safe'), 'included_files_before_plugins' => __('Non-core files loaded early', 'aguard-safe'), 'users_total' => __('Users in total', 'aguard-safe'), 'admin_count' => __('Administrators', 'aguard-safe'), 'baseline_time' => __('File baseline', 'aguard-safe'), 'baseline_files' => __('Files in the baseline', 'aguard-safe'), 'next_scan' => __('Next automatic check', 'aguard-safe'), 'last_scan' => __('Last check', 'aguard-safe'), 'login' => __('Login address', 'aguard-safe'), 'mode' => __('Mode', 'aguard-safe'), 'slug' => __('Address', 'aguard-safe'), 'url' => __('Link', 'aguard-safe'), 'killed' => __('Turned off by the emergency file', 'aguard-safe'), 'saved_mode' => __('Saved mode', 'aguard-safe'), 'checked' => __('Files checked', 'aguard-safe'), 'modified' => __('Modified', 'aguard-safe'), 'missing' => __('Missing', 'aguard-safe'), 'missing_count' => __('Missing', 'aguard-safe'), 'extra' => __('Unknown', 'aguard-safe'), 'found' => __('Found', 'aguard-safe'), 'scanned' => __('Checked', 'aguard-safe'), 'changed' => __('Changed', 'aguard-safe'), 'added' => __('Added', 'aguard-safe'), 'removed' => __('Removed', 'aguard-safe'), 'version' => __('Version', 'aguard-safe'), 'whitelisted' => __('Allowlist', 'aguard-safe'), 'count' => __('Count', 'aguard-safe'), 'ms' => __('Duration, ms', 'aguard-safe'), 'rows' => __('Lines', 'aguard-safe'), 't' => __('Time', 'aguard-safe'), 'full_t' => __('Full check', 'aguard-safe'), 'human' => __('Visitor', 'aguard-safe'), 'googlebot' => 'Googlebot', 'cloaked' => __('The crawler is shown different content', 'aguard-safe'), 'title' => __('Page title', 'aguard-safe'), 'code' => __('HTTP code', 'aguard-safe'), 'length' => __('Size, B', 'aguard-safe'), 'ctype' => __('Content type', 'aguard-safe'), 'error' => __('Error', 'aguard-safe'), 'table' => __('Table', 'aguard-safe'), 'active' => __('Active', 'aguard-safe'), 'first_run' => __('First run', 'aguard-safe'), 'enabled' => __('Enabled', 'aguard-safe'), 'present' => __('Present', 'aguard-safe'), 'missing_real' => __('Missing (not counting those removed by WP)', 'aguard-safe'), 'blocked' => __('Blocked', 'aguard-safe'), 'executed' => __('Executed', 'aguard-safe'), 'http' => 'HTTP', 'dir' => __('Folder', 'aguard-safe'), 'files_scanned' => __('Files checked', 'aguard-safe'), 'findings' => __('Findings', 'aguard-safe'), 'status' => __('Status', 'aguard-safe'), 'file' => __('File', 'aguard-safe'), 'size' => __('Size, B', 'aguard-safe'), 'mtime' => __('Changed', 'aguard-safe'), 'score' => __('Score', 'aguard-safe'), 'hits' => __('Signs', 'aguard-safe'), 'rel' => __('File', 'aguard-safe'), 'ip' => 'IP', 'by' => __('Who', 'aguard-safe'), 'now' => __('Now', 'aguard-safe'), 'baseline' => __('Baseline', 'aguard-safe'), 'uploads_guard' => __('PHP block in the upload folders', 'aguard-safe'), 'remote_admin' => __('Remote management tools', 'aguard-safe'), 'sentinels' => __('System files', 'aguard-safe'), 'admins' => __('Administrators', 'aguard-safe'), 'uploads' => __('PHP files in the upload folders', 'aguard-safe'), 'core' => __('WordPress core', 'aguard-safe'), 'recent' => __('Recently changed files', 'aguard-safe'), 'cloaking' => __('Content for the crawler and for a visitor', 'aguard-safe'), 'snippets' => 'Code Snippets', 'state' => __('Status', 'aguard-safe'), 'verify' => __('Check', 'aguard-safe'), 'query' => __('Query', 'aguard-safe'), 'note' => __('Note', 'aguard-safe'), 'email' => __('E-mail', 'aguard-safe'), 'login_t' => __('Signed in', 'aguard-safe'), 'expiration_t' => __('Valid until', 'aguard-safe'), 'ua' => __('Browser', 'aguard-safe'), 'device' => __('Device', 'aguard-safe'), 'quarantine' => __('Quarantine', 'aguard-safe'), 'lockdown' => 'LOCKDOWN', 'settings' => __('Settings', 'aguard-safe'), 'items' => __('Entries', 'aguard-safe'), 'id' => 'ID', 'roles' => __('Roles', 'aguard-safe'), 'registered' => __('Registered', 'aguard-safe'), 'display' => __('Name', 'aguard-safe'), 'perms' => __('Permissions', 'aguard-safe'), 'sha256' => 'SHA-256', 'link' => __('Link', 'aguard-safe'), 'php_files' => __('PHP files', 'aguard-safe'), 'ctime' => __('Created', 'aguard-safe'), 'restored' => __('Restored', 'aguard-safe'), 'dest' => __('Quarantined file', 'aguard-safe'), 'who' => __('Who', 'aguard-safe'), 'type' => __('Type', 'aguard-safe'), 'mailed' => __('E-mail sent', 'aguard-safe'), 'data' => __('Data', 'aguard-safe')];
        return $m[$k] ?? ucfirst(str_replace('_', ' ', (string) $k));
    }
    private static function scalar($v, $k = '') {
        if (is_bool($v)) return $v ? __('yes', 'aguard-safe') : __('no', 'aguard-safe');
        if ($v === null || $v === '') return '—';
        if (is_int($v) && $v > 1000000000 && in_array($k, ['t', 'full_t', 'next_scan', 'last_scan', 'baseline_time', 'mtime', 'ctime', 'login_t', 'expiration_t', 'restored', 'baseline'], true)) return wp_date('Y-m-d H:i:s', $v);
        if (is_array($v)) return wp_json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return (string) $v;
    }
    /** Masyvas → lentelė raktas/reikšmė; skaliarų sąrašas → per kablelį; eilučių sąrašas → lentelė su stulpeliais. */
    /** The core check as lists of files: every file is a row that leads to the place where something can be done with it. */
    public static function core_view($d) {
        if (!is_array($d)) return self::kv($d);
        $split = function ($s) { return preg_match('~^(.*?) \((.*)\)$~', (string) $s, $m) ? [$m[1], $m[2]] : [(string) $s, '']; };
        $block = function ($title, $note, $items, $kind) use ($split) {
            if (!$items) return '';
            $h = '<div class="ag-flist ag-flist-' . esc_attr($kind) . '"><div class="ag-flist-h"><b>' . esc_html($title) . ' <i>' . count($items) . '</i></b><span>' . $note . '</span></div>';
            foreach (array_slice($items, 0, 200) as $it) {
                [$rel, $meta] = $split($it); $abs = self::wp_root() . '/' . $rel;
                if ($kind === 'missing' || !@is_file($abs)) { $h .= '<div class="ag-frow"><b>' . esc_html($rel) . '</b><span>' . esc_html($meta) . '</span><em></em></div>'; continue; } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a path outside open_basedir is simply shown without a link.
                $url = $kind === 'modified' ? self::url(['tab' => 'files', 'file' => $rel, 'diff' => '1']) . '#ag-diff' : self::url(['tab' => 'files', 'file' => $rel]);
                $h .= '<a class="ag-frow" href="' . esc_url($url) . '"><b>' . esc_html($rel) . '</b><span>' . esc_html($meta) . '</span><em>' . esc_html($kind === 'modified' ? __('Show what was changed', 'aguard-safe') : __('Open the file', 'aguard-safe')) . ' →</em></a>';
            }
            if (count($items) > 200) $h .= '<div class="ag-frow"><span>… ' . (int) (count($items) - 200) . '</span></div>';
            return $h . '</div>';
        };
        $h = $block(__('Unknown files', 'aguard-safe'), esc_html__('They are not part of this WordPress version. Open a file to read its code; there you can move it to quarantine or, if you know the file, add it to the allowlist.', 'aguard-safe'), (array) ($d['extra'] ?? []), 'extra');
        $h .= $block(__('Modified files', 'aguard-safe'), esc_html__('They differ from the official WordPress files. Open a file to see what was changed and to replace it with the original.', 'aguard-safe'), (array) ($d['modified'] ?? []), 'modified');
        $h .= $block(__('Missing files', 'aguard-safe'), esc_html__('WordPress expects these files. To put them back, reinstall the same version:', 'aguard-safe') . ' <a href="' . esc_url(self_admin_url('update-core.php')) . '">' . esc_html__('Dashboard → Updates → Re-install', 'aguard-safe') . '</a>', (array) ($d['missing'] ?? []), 'missing');
        $rest = $d; unset($rest['extra'], $rest['modified'], $rest['missing']);
        return $h . self::kv($rest);
    }

    public static function kv($data, $depth = 0, $k = '') {
        if (is_wp_error($data)) return '<span class="ag-risk">' . esc_html($data->get_error_message()) . '</span>';
        if (!is_array($data)) return esc_html(self::scalar($data, $k));
        if (!$data) return '<span class="ag-muted">' . __('none', 'aguard-safe') . '</span>';
        $list = array_keys($data) === range(0, count($data) - 1);
        if ($list && !array_filter($data, 'is_array')) return esc_html(implode(', ', array_map(function ($v) { return self::scalar($v); }, $data)));
        if ($list && is_array($data[0]) && array_keys($data[0]) !== range(0, count($data[0]) - 1)) return self::rows_table($data);
        if ($depth >= 1 && !$list && count($data) <= 6 && !array_filter($data, 'is_array')) { $p = []; foreach ($data as $key => $v) $p[] = '<span class="ag-muted">' . esc_html(self::key_h($key)) . ':</span> ' . esc_html(self::scalar($v, (string) $key)); return implode('<br>', $p); }
        if ($depth > 3) return '<pre class="ag-pre">' . esc_html(wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</pre>';
        $h = '<table class="ag-kv">';
        foreach ($data as $key => $v) $h .= '<tr><th>' . esc_html(self::key_h($key)) . '</th><td>' . self::kv($v, $depth + 1, (string) $key) . '</td></tr>';
        return $h . '</table>';
    }
    /** Vienodų eilučių sąrašas → lentelė. $cols: raktas => antraštė (tuščia – iš pirmos eilutės). */
    public static function rows_table($rows, $cols = [], $limit = 500, $open = '') {
        $rows = array_values(array_filter((array) $rows, 'is_array')); if (!$rows) return '<span class="ag-muted">' . __('none', 'aguard-safe') . '</span>';
        if (!$cols) { foreach (array_slice($rows, 0, 20) as $r) foreach ($r as $k => $v) if (!isset($cols[$k])) $cols[$k] = self::key_h($k); }
        $h = '<table class="widefat striped ag-tbl"><thead><tr>'; foreach ($cols as $l) $h .= '<th>' . esc_html($l) . '</th>'; $h .= '</tr></thead><tbody>';
        foreach (array_slice($rows, 0, $limit) as $r) {
            $h .= '<tr>';
            foreach ($cols as $k => $l) { $v = $r[$k] ?? null; $cls = is_string($v) ? ($v === 'ok' ? ' class="ag-ok"' : (strtoupper($v) === 'MISMATCH' ? ' class="ag-risk"' : '')) : ''; $txt = is_array($v) ? self::kv($v, 1, (string) $k) : esc_html(self::scalar($v, (string) $k)); if ($open !== '' && $k === $open && is_string($v) && $v !== '' && ($ap = self::safe_path($v)) && is_file($ap)) $txt = '<a href="' . esc_url(self::url(['tab' => 'files', 'file' => $v, 'hl' => '1'])) . '" title="' . esc_attr__('Open the file and show the marked lines', 'aguard-safe') . '">' . $txt . '</a>'; $h .= '<td' . $cls . '>' . $txt . '</td>'; }
            $h .= '</tr>';
        }
        if (count($rows) > $limit) $h .= '<tr><td colspan="' . count($cols) . '" class="ag-muted">' . __('… more', 'aguard-safe') . ' ' . (count($rows) - $limit) . '</td></tr>';
        return $h . '</tbody></table>';
    }
    public static function json_details($data, $label = null) {
        if ($label === null) $label = __('Technical details (JSON)', 'aguard-safe');
        return '<details class="ag-json"><summary>' . esc_html($label) . '</summary><pre class="ag-pre">' . esc_html(wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR)) . '</pre></details>';
    }
    /** Skirtuko „Patikra“ rezultatas žmogui: santrauka + lentelės pagal patikros rūšį. */
    private static function scan_view($what, $data) {
        if (is_wp_error($data)) return '<p class="ag-sum ag-risk">' . esc_html($data->get_error_message()) . '</p>';
        if (!is_array($data)) return '<div class="ag-top">' . self::dial('–') . '<div class="ag-top-text"><b>' . esc_html__('No check has run yet', 'aguard-safe') . '</b><span>' . esc_html__('The first automatic check starts within an hour. You can run it now.', 'aguard-safe') . '</span></div><a class="button button-primary" data-ag-busy="1" href="' . esc_url(self::url(['tab' => 'scan', 'what' => 'all'])) . '">' . esc_html__('Full check', 'aguard-safe') . '</a></div>';
        $sum = function ($k, $v) { [$st, $tx] = self::step_text($k, $v); return '<p class="ag-sum ag-' . $st . '">' . esc_html($tx) . '</p>'; };
        $out = '';
        switch ($what) {
            case '': case 'all':
                if (!empty($data['_note'])) $out .= '<p class="ag-note">' . esc_html($data['_note']) . '</p>';
                $steps = self::scan_steps() + ['admins' => [__('List of administrator accounts', 'aguard-safe'), 'prisijungimai'], 'cloaking' => [__('Content for Google\'s crawler and for a visitor', 'aguard-safe'), 'srautas'], 'uploads_guard' => [__('PHP block rules', 'aguard-safe'), 'ugniasiene']];
                $rows = ''; $bad = 0; $n = 0; $rerun = ['sentinels', 'core', 'uploads', 'recent', 'cloaking'];
                foreach ($steps as $k => $st) {
                    if (!array_key_exists($k, $data)) continue;
                    [$state, $tx] = self::step_text($k, $data[$k]);
                    $dot = in_array($state, ['ok', 'warn', 'risk'], true) ? $state : 'idle'; $n++; if ($dot === 'warn' || $dot === 'risk') $bad++;
                    $head = '<span class="ag-dot ag-dot-' . $dot . '"></span><div class="ag-row-name"><b>' . esc_html($st[0]) . '</b></div><div class="ag-row-res ag-res-' . $dot . '">' . esc_html($tx) . '</div>';
                    if (!is_array($data[$k]) || !$data[$k]) { $rows .= '<div class="ag-row ag-row-chk">' . $head . '<span></span></div>'; continue; }
                    $rows .= '<details class="ag-row-d"' . ($dot === 'risk' ? ' open' : '') . '><summary class="ag-row ag-row-chk">' . $head . '<span class="ag-row-more">' . esc_html__('Details', 'aguard-safe') . '</span></summary><div class="ag-row-open ag-row-kv">' . ($k === 'core' ? self::core_view($data[$k]) : self::kv($data[$k], 1, $k)) . (in_array($k, $rerun, true) ? '<p><a class="button" href="' . esc_url(self::url(['tab' => 'scan', 'what' => $k])) . '">' . esc_html__('Run this check again', 'aguard-safe') . '</a></p>' : '') . '</div></details>';
                }
                $when = !empty($data['t']) ? __('Check time:', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) $data['t'])) . (!empty($data['full_t']) ? ' ' . __('· last full check:', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) $data['full_t'])) : '') : '';
                /* translators: 1: number of checks that need attention, 2: number of all checks */
                $big = $bad ? sprintf(__('%1$d of %2$d checks need attention', 'aguard-safe'), $bad, $n) : __('All checks passed', 'aguard-safe');
                $out .= '<div class="ag-top">' . self::dial($bad ? (int) $bad : (int) $n, $bad ? 'warn' : 'ok', (int) $n, (int) $bad) . '<div class="ag-top-text"><b>' . esc_html($big) . '</b><span>' . $when . '</span></div><a class="button button-primary" data-ag-busy="1" href="' . esc_url(self::url(['tab' => 'scan', 'what' => 'all'])) . '">' . esc_html__('Full check', 'aguard-safe') . '</a></div><div class="ag-rows">' . $rows . '</div>';
                break;
            case 'core': case 'uploads': case 'sentinels': case 'cloaking': case 'snippets':
                $out .= $sum($what, $data) . '<div class="ag-card ag-sec">' . ($what === 'core' ? self::core_view($data) : self::kv($data)) . '</div>'; break;
            case 'remote':
                $out .= $sum('remote_admin', $data) . '<div class="ag-card ag-sec">' . self::kv($data) . '</div>'; break;
            case 'uploads_guard':
                $out .= $sum('uploads_guard', $data['state'] ?? []) . '<div class="ag-card ag-sec">' . self::kv($data) . '</div>'; break;
            case 'recent':
                $out .= '<p class="ag-sum">' . __('Files changed in the selected period:', 'aguard-safe') . ' ' . count($data) . '</p><div class="ag-card ag-sec">' . self::rows_table($data, ['rel' => __('File', 'aguard-safe'), 'size' => __('Size, B', 'aguard-safe'), 'mtime' => __('Changed', 'aguard-safe')]) . '</div>'; break;
            case 'plugins':
                $bad = count(array_filter($data, function ($r) { return strtoupper((string) ($r['status'] ?? '')) === 'MISMATCH'; }));
                $out .= '<p class="ag-sum ag-' . ($bad ? 'risk' : 'ok') . '">' . ($bad ? __('Plugins whose files differ from wordpress.org:', 'aguard-safe') . ' ' . $bad : __('All checked plugins match the wordpress.org copies', 'aguard-safe')) . '</p><div class="ag-card ag-sec">' . self::rows_table($data, ['name' => __('Plugin', 'aguard-safe'), 'version' => __('Version', 'aguard-safe'), 'status' => __('Status', 'aguard-safe'), 'checked' => __('Checked', 'aguard-safe'), 'modified' => __('Modified', 'aguard-safe'), 'extra' => __('Unknown', 'aguard-safe')]) . '</div>'; break;
            case 'suspicious':
                $f = $data['findings'] ?? [];
                $out .= '<p class="ag-sum ag-' . ($f ? 'warn' : 'ok') . '">' . __('Files checked:', 'aguard-safe') . ' ' . (int) ($data['files_scanned'] ?? 0) . ' (' . esc_html((string) ($data['dir'] ?? '')) . __(') · findings:', 'aguard-safe') . ' ' . count($f) . '</p><p class="ag-note">' . __('Findings are not a verdict but signs (encoded code, eval, remote requests). The higher the score, the more worthwhile it is to look at the file. Click a file name to open it with the found lines marked.', 'aguard-safe') . '</p><div class="ag-card ag-sec">' . self::rows_table($f, ['file' => __('File', 'aguard-safe'), 'score' => __('Score', 'aguard-safe'), 'hits' => __('Signs', 'aguard-safe'), 'size' => __('Size, B', 'aguard-safe'), 'mtime' => __('Changed', 'aguard-safe')], 500, self::tool_on('files') ? 'file' : '') . '</div>'; break;
            default:
                $out .= '<div class="ag-card ag-sec">' . self::kv($data) . '</div>';
        }
        return $out;
    }

    private static function render($tab, $title, $data) {
        // Six sections; a section with several screens gets a second row of tabs.
        $groups = [
            'overview' => [__('Overview', 'aguard-safe'), ['home' => __('Overview', 'aguard-safe')]],
            'scan' => [__('Scan', 'aguard-safe'), ['scan' => __('Checks', 'aguard-safe'), 'files' => __('Files', 'aguard-safe'), 'quarantine' => __('Quarantine', 'aguard-safe')]],
            'activity' => [__('Activity', 'aguard-safe'), ['events' => __('Events', 'aguard-safe'), 'sessions' => __('Logins', 'aguard-safe'), 'logs' => __('Logs', 'aguard-safe')]],
            'plugins' => [__('Plugins', 'aguard-safe'), ['plugins' => __('Plugins', 'aguard-safe')]],
            'settings' => [__('Settings', 'aguard-safe'), ['settings' => __('Settings', 'aguard-safe'), 'status' => __('Site information', 'aguard-safe')]],
            'emergency' => [__('Emergency', 'aguard-safe'), ['response' => __('Emergency', 'aguard-safe')]],
        ];
        // a tool that is turned off stays visible in its section, so it can be found
        $off = []; foreach (['files', 'logs'] as $t) { if (!self::tool_on($t)) $off[$t] = 1; }
        $about = [
            'scan' => __('Results of every check', 'aguard-safe'), 'files' => __('Read-only file viewer', 'aguard-safe'), 'quarantine' => __('Files moved out of reach of the site', 'aguard-safe'),
            'events' => __('Everything that happened on the site', 'aguard-safe'), 'sessions' => __('Who is signed in right now', 'aguard-safe'), 'logs' => __('Read-only log viewer', 'aguard-safe'),
            'settings' => __('Notifications, login, files, tools', 'aguard-safe'), 'status' => __('WordPress, PHP, server and plugin versions', 'aguard-safe'),
        ];
        $cur = 'overview'; foreach ($groups as $g => $def) { if (isset($def[1][$tab])) $cur = $g; }
        $urgent = empty(self::opts()['vuln_check']) ? 0 : (int) self::vuln_counts()['urgent'];
        echo '<div class="wrap aguard"><h1 class="screen-reader-text">AGuard Safe</h1><div class="ag-head">' . wp_kses(self::icon('mark', 44, 'ag-two'), self::svg_kses()) . '<div class="ag-h1">AGuard <span>Safe</span></div><span class="ag-meta">' . esc_html(wp_parse_url(home_url(), PHP_URL_HOST)) . ' · v' . esc_html(self::VERSION) . '</span></div><nav class="ag-tabs">';
        foreach ($groups as $g => $def) {
            echo '<a class="ag-t-' . esc_attr($g) . ($cur === $g ? ' on' : '') . '" href="' . esc_url(self::url(['tab' => (string) array_key_first($def[1])])) . '">' . wp_kses(self::shield($g), self::svg_kses()) . '<span>' . esc_html($def[0]) . '</span>' . (($g === 'plugins' && $urgent) ? '<b class="ag-count">' . (int) $urgent . '</b>' : '') . '</a>';
        }
        echo '</nav>';
        if (self::setup_pending() && !get_transient('aguard_safe_setup_later_' . get_current_user_id())) self::setup_card(true);
        echo '<div class="ag-body">';
        if (count($groups[$cur][1]) > 1) {
            echo '<nav class="ag-sub">';
            foreach ($groups[$cur][1] as $k => $l) {
                if (isset($off[$k])) { echo '<a class="ag-sub-off" href="' . esc_url(self::url(['tab' => 'settings']) . '#ag-s-tools') . '"><b>' . esc_html($l) . '</b><span>' . esc_html__('Off. Turn it on in Settings', 'aguard-safe') . '</span></a>'; continue; }
                echo '<a class="' . ($tab === $k ? 'on' : '') . '" href="' . esc_url(self::url(['tab' => $k])) . '"><b>' . esc_html($l) . '</b><span>' . esc_html($about[$k] ?? '') . '</span></a>';
            }
            echo '</nav>';
        }
        if ($tab === 'home') echo '<div class="ag-band"><h2 class="ag-title">' . esc_html__('Overview', 'aguard-safe') . '</h2></div>';
        else echo '<div class="ag-band"><h2 class="ag-title">' . esc_html($title) . '</h2><img class="ag-knight" src="' . esc_url(plugin_dir_url(__FILE__) . 'assets/knight-' . $cur . '.png') . '" alt="" width="118" height="140"></div>';
        // screens without their own summary get a plain one, so every screen starts the same way
        $intro = [
            'status' => [__('What this site runs on', 'aguard-safe'), __('WordPress, PHP, server and plugin versions.', 'aguard-safe')],
            'quarantine' => [__('Files moved out of reach of the site', 'aguard-safe'), __('A file in quarantine no longer runs. It can be restored.', 'aguard-safe')],
            'files' => [__('Read-only file viewer', 'aguard-safe'), __('Nothing can be changed here.', 'aguard-safe')],
            'logs' => [__('Read-only log viewer', 'aguard-safe'), __('Nothing can be changed here.', 'aguard-safe')],
            'response' => [__('If the site has been broken into', 'aguard-safe'), __('Actions for an emergency.', 'aguard-safe')],
        ];
        $one = $tab === 'scan' ? sanitize_key(self::req('what')) : '';
        if ($one !== '' && $one !== 'all') echo '<div class="ag-top"><div class="ag-top-text"><b>' . esc_html__('Result of one check, run just now', 'aguard-safe') . '</b><span>' . esc_html__('The other checks were not run again.', 'aguard-safe') . '</span></div><a class="button" href="' . esc_url(self::url(['tab' => 'scan'])) . '">← ' . esc_html__('All checks', 'aguard-safe') . '</a></div>';
        if (isset($intro[$tab])) echo '<div class="ag-top"><div class="ag-top-text"><b>' . esc_html($intro[$tab][0]) . '</b><span>' . esc_html($intro[$tab][1]) . '</span></div></div>';
        if (is_wp_error($data)) { echo '<div class="notice notice-error"><p>' . esc_html($data->get_error_message()) . '</p></div></div></div>'; return; }
        $esc = 'esc_html';
        switch ($tab) {
            case 'status':
                echo '<h3>' . esc_html__('Administrators (', 'aguard-safe') . (int) $data['admin_count'] . ')</h3><table class="widefat striped"><colgroup><col style="width:60px"><col style="width:140px"><col><col style="width:170px"><col></colgroup><thead><tr><th>ID</th><th>Login</th><th>' . esc_html__('E-mail', 'aguard-safe') . '</th><th>' . esc_html__('Registered', 'aguard-safe') . '</th><th>' . esc_html__('Name', 'aguard-safe') . '</th></tr></thead><tbody>';
                foreach ($data['admins'] as $a) echo '<tr><td>' . (int) $a['id'] . '</td><td>' . esc_html($a['login']) . '</td><td>' . esc_html($a['email']) . '</td><td>' . esc_html($a['registered']) . '</td><td>' . esc_html($a['display']) . '</td></tr>';
                echo '</tbody></table>';
                foreach (['mu_plugins' => __('Must-use plugins (mu-plugins)', 'aguard-safe'), 'dropins' => __('wp-content files (drop-ins)', 'aguard-safe')] as $k => $l) {
                    echo '<h3>' . esc_html($l) . '</h3><table class="widefat striped"><thead><tr><th>' . esc_html__('File', 'aguard-safe') . '</th><th>' . esc_html__('Size', 'aguard-safe') . '</th><th>' . esc_html__('Changed', 'aguard-safe') . '</th><th>' . esc_html__('Permissions', 'aguard-safe') . '</th></tr></thead><tbody>';
                    foreach ($data[$k] as $r) echo '<tr><td><a href="' . esc_url(self::url(['tab' => 'files', 'file' => $r['rel']])) . '">' . esc_html($r['rel']) . '</a></td><td>' . (int) $r['size'] . '</td><td>' . esc_html(wp_date('Y-m-d H:i:s', $r['mtime'])) . '</td><td>' . esc_html($r['perms']) . '</td></tr>';
                    echo '</tbody></table>';
                }
                echo '<h3>' . esc_html__('Non-core PHP files loaded early', 'aguard-safe') . '</h3><p>' . ($data['included_files_before_plugins'] ? '<code>' . implode('</code>, <code>', array_map('esc_html', $data['included_files_before_plugins'])) . '</code>' : esc_html__('none', 'aguard-safe')) . '</p>';
                unset($data['admins'], $data['mu_plugins'], $data['dropins'], $data['settings'], $data['quarantine'], $data['uploads_guard'], $data['remote_admin'], $data['lockdown']);
                echo '<h3>' . esc_html__('Environment', 'aguard-safe') . '</h3><div class="ag-card ag-sec">' . wp_kses(self::kv($data), self::html_kses()) . '</div>' . wp_kses(self::json_details($data), self::html_kses());
                break;
            case 'home':
                self::render_home($data);
                break;
            case 'settings':
                $o = $data['settings']; $un = $data['unlocked']; $dis = $un ? '' : ' disabled';
                $nonce = wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]);
                // One setting = one row: the name and a short note on the left, the control on the right.
                $row = function ($title, $note, $ctl) { $ctl = preg_replace('~<(input|textarea) ~', '<$1 aria-label="' . esc_attr($title) . '" ', $ctl, 1); echo '<div class="ag-set"><div class="ag-set-t"><b>' . esc_html($title) . '</b>' . ($note !== '' ? '<span>' . esc_html($note) . '</span>' : '') . '</div><div class="ag-set-c">' . $ctl . '</div></div>'; }; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $ctl is built below from escaped parts.
                $sw = function ($name, $on, $form, $off = '') { return '<label class="ag-sw"><input type="checkbox" name="' . esc_attr($name) . '" form="' . esc_attr($form) . '" ' . checked((bool) $on, true, false) . esc_attr($off) . '><span></span></label>'; };
                // lock
                echo '<form method="post" class="ag-top ag-lock' . ($un ? ' ag-lock-open' : '') . '">' . $nonce; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with wp_kses above.
                if ($un) echo '<p><b>' . esc_html__('Unlocked', 'aguard-safe') . '</b><span>' . esc_html__('15 min. Changes are reported by e-mail to the current address.', 'aguard-safe') . '</span></p><button class="button" name="aguard_lock" value="1">' . esc_html__('Lock now', 'aguard-safe') . '</button>';
                /* translators: %s: masked e-mail address */
                elseif (!get_transient('aguard_safe_code_' . get_current_user_id())) echo '<p><b>' . esc_html__('Settings are locked', 'aguard-safe') . '</b><span>' . esc_html(sprintf(__('To change them, first get a one-time code by e-mail. It goes to %s', 'aguard-safe'), self::mask_email($o['email']))) . '</span></p><button class="button button-primary" name="aguard_unlock_request" value="1">' . esc_html__('Send me the code', 'aguard-safe') . '</button>';
                /* translators: %s: masked e-mail address */
                else echo '<p><b>' . esc_html__('Enter the code from the e-mail', 'aguard-safe') . '</b><span>' . esc_html(sprintf(__('The 6-digit code was sent to %s. It is valid for 10 minutes.', 'aguard-safe'), self::mask_email($o['email']))) . '</span></p><input type="text" name="aguard_unlock_code" inputmode="numeric" placeholder="' . esc_attr__('6-digit code', 'aguard-safe') . '" aria-label="' . esc_attr__('Code from the e-mail', 'aguard-safe') . '" autocomplete="one-time-code" autofocus><button class="button button-primary">' . esc_html__('Unlock', 'aguard-safe') . '</button><button class="button-link" name="aguard_unlock_request" value="1">' . esc_html__('Send the code again', 'aguard-safe') . '</button>';
                echo '</form>';
                if (!$un) echo '<details class="ag-how ag-lock-help"><summary>' . esc_html__('No access to this mailbox?', 'aguard-safe') . '</summary><p>' . esc_html__('Then the code cannot reach you, and that is on purpose: a stranger with an administrator session must not be able to change the address. The owner of the site can still get in through the files: add the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_MASTER\', true);</code> ' . esc_html__('to wp-config.php (through the hosting file manager or FTP). Settings then open without a code. Change the notification e-mail, save, and remove the line again.', 'aguard-safe') . '</p></details>';
                echo '<div class="ag-cols-set"><nav class="ag-side"><a href="#ag-s-notify">' . esc_html__('Notifications', 'aguard-safe') . '</a><a href="#ag-s-brute">' . esc_html__('Password guessing', 'aguard-safe') . '</a><a href="#ag-s-login">' . esc_html__('Login protection', 'aguard-safe') . '</a><a href="#ag-s-files">' . esc_html__('File protection', 'aguard-safe') . '</a><a href="#ag-s-tools">' . esc_html__('Tools', 'aguard-safe') . '</a><a class="ag-side-out" href="' . esc_url(self::url(['tab' => 'status'])) . '">' . esc_html__('Site information', 'aguard-safe') . ' →</a></nav><div>';
                echo '<form method="post" id="ag-f-main">' . $nonce . '</form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with wp_kses above.
                $save = '<button class="button button-primary" name="aguard_save" value="1" form="ag-f-main"' . esc_attr($dis) . '>' . esc_html__('Save', 'aguard-safe') . '</button>';
                // notifications
                echo '<div class="ag-rows ag-sec2" id="ag-s-notify"><div class="ag-rows-h">' . esc_html__('Notifications', 'aguard-safe') . '<small>' . esc_html__('Where alerts go and what is reported.', 'aguard-safe') . '</small></div>';
                $row(__('Notification e-mail', 'aguard-safe'), __('All alerts and unlock codes', 'aguard-safe'), '<input type="email" name="email" form="ag-f-main" value="' . esc_attr($o['email']) . '"' . esc_attr($dis) . '>');
                $row(__('Extra recipients', 'aguard-safe'), __('Comma separated. Incidents only, no more than 5 e-mails a day; unlock codes are not sent to them', 'aguard-safe'), '<input type="text" name="notify_cc" form="ag-f-main" value="' . esc_attr($o['notify_cc'] ?? '') . '"' . esc_attr($dis) . '>');
                $row(__('Send notifications', 'aguard-safe'), '', $sw('notify', $o['notify'], 'ag-f-main', $dis));
                $row(__('Report administrator logins', 'aguard-safe'), __('An e-mail when an administrator signs in from a new IP', 'aguard-safe'), $sw('notify_admin_login', $o['notify_admin_login'], 'ag-f-main', $dis));
                $row(__('Failed login threshold', 'aguard-safe'), __('Failed attempts an hour before an alert is sent', 'aguard-safe'), '<input type="number" class="ag-num" name="failed_threshold" form="ag-f-main" value="' . esc_attr($o['failed_threshold']) . '" min="5"' . esc_attr($dis) . '>');
                echo '<div class="ag-set-foot"><span>' . esc_html__('Changes are reported to the notification e-mail.', 'aguard-safe') . '</span>' . $save . '<button class="button" name="aguard_test_mail" value="1" form="ag-f-main">' . esc_html__('Test e-mail', 'aguard-safe') . '</button></div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $save is built from escaped parts.
                // password guessing
                $lk = self::lockout_killed(); $locks = self::lockouts();
                echo '<div class="ag-rows ag-sec2" id="ag-s-brute"><div class="ag-rows-h">' . esc_html__('Password guessing', 'aguard-safe') . '<small>' . esc_html__('What happens when somebody tries passwords one after another.', 'aguard-safe') . '</small></div>';
                $row(__('Block the address after failed attempts', 'aguard-safe'), ($lk !== '' ? __('turned off by the emergency switch (', 'aguard-safe') . $lk . '). ' : '') . __('The address is blocked for 30 minutes and sees a notice instead of the sign-in form. An address an administrator signed in from during the last 30 days is never blocked.', 'aguard-safe'), $sw('lockout', !empty($o['lockout']), 'ag-f-main', $dis));
                $row(__('Failed attempts before the block', 'aguard-safe'), __('From one address within 15 minutes', 'aguard-safe'), '<input type="number" class="ag-num" name="lockout_after" form="ag-f-main" value="' . esc_attr((int) ($o['lockout_after'] ?? 10)) . '" min="3"' . esc_attr($dis) . '>');
                /* translators: %d: number of addresses */
                $row(__('Blocked right now', 'aguard-safe'), $locks ? implode(', ', array_slice(array_keys($locks), 0, 8)) . (count($locks) > 8 ? ' …' : '') : __('nobody', 'aguard-safe'), '<b class="ag-num-b">' . (int) count($locks) . '</b>' . ($locks ? '<button class="button" name="aguard_unblock" value="1" form="ag-f-main"' . esc_attr($dis) . '>' . esc_html__('Unblock all', 'aguard-safe') . '</button>' : ''));
                $row(__('Check administrator passwords against leaked lists', 'aguard-safe'), __('After a correct sign-in. The password itself is never sent anywhere.', 'aguard-safe'), $sw('pw_check', !empty($o['pw_check']), 'ag-f-main', $dis));
                echo '<details class="ag-how"><summary>' . esc_html__('How it works', 'aguard-safe') . '</summary><p>' . esc_html__('Leaked passwords: the plugin sends only the first 5 characters of the SHA-1 hash of the password to data.aguard.lt, receives all leaked hashes that start with them and compares on your server. The list is Pwned Passwords by Have I Been Pwned.', 'aguard-safe') . '</p><p>' . esc_html__('Emergency switch without signing in: the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_LOCKOUT_OFF\', true);</code> ' . esc_html__('in wp-config.php or an empty file', 'aguard-safe') . ' <code>AGUARD-LOCKOUT-OFF</code> ' . esc_html__('in the wp-content folder (it survives plugin updates).', 'aguard-safe') . '</p></details>';
                echo '<div class="ag-set-foot"><span></span>' . $save . '</div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $save is built from escaped parts.
                // login protection
                $li = $data['login']; $fails_today = (int) get_transient('aguard_safe_fail_day_' . wp_date('Ymd')); $m = $o['login_mode'] ?? 'off';
                $k2 = self::twofa_killed(); $tf = (int) ($o['twofa'] ?? 0);
                echo '<form method="post" id="ag-f-login">' . $nonce . '</form><form method="post" id="ag-f-2fa">' . $nonce . '</form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with wp_kses above.
                echo '<div class="ag-rows ag-sec2" id="ag-s-login"><div class="ag-rows-h">' . esc_html__('Login protection', 'aguard-safe') . '<small>' . esc_html__('The standard address', 'aguard-safe') . ' /wp-login.php ' . esc_html__('is guessed by bots all the time (failed attempts today:', 'aguard-safe') . ' ' . (int) $fails_today . ')</small></div>';
                $seg = '<div class="ag-seg">';
                foreach (['off' => __('Standard', 'aguard-safe'), 'soft' => __('Trial: both', 'aguard-safe'), 'strict' => __('New only', 'aguard-safe')] as $k => $l) $seg .= '<label><input type="radio" name="login_mode" form="ag-f-login" value="' . esc_attr($k) . '" ' . checked($m, $k, false) . '><span>' . esc_html($l) . '</span></label>';
                $seg .= '</div>';
                $now = $li['mode'] === 'off' ? __('standard address', 'aguard-safe') : ($li['mode'] === 'soft' ? __('trial mode – both addresses work', 'aguard-safe') : __('new address only', 'aguard-safe'));
                $row(__('Login address', 'aguard-safe'), __('Now:', 'aguard-safe') . ' ' . $now . ($li['mode'] !== 'off' ? ' · ' . $li['url'] : '') . ($li['killed'] ? ' · ' . __('turned off by the emergency switch (', 'aguard-safe') . $li['killed'] . ')' : ''), $seg);
                $row(__('New address:', 'aguard-safe'), home_url('/') . '… ' . __('lowercase letters, digits, hyphen; not “login” or “admin”', 'aguard-safe'), '<input type="text" name="login_slug" form="ag-f-login" value="' . esc_attr($o['login_slug'] ?? '') . '" placeholder="' . esc_attr__('e.g. team-entrance', 'aguard-safe') . '" pattern="[a-z0-9][a-z0-9-]{1,38}[a-z0-9]">');
                echo '<details class="ag-how"><summary>' . esc_html__('How it works', 'aguard-safe') . '</summary><p>' . esc_html__('Trial –', 'aguard-safe') . ' ' . esc_html__('both', 'aguard-safe') . ' ' . esc_html__('addresses work, links on the site already point to the new one (safe to try, nobody gets locked out)', 'aguard-safe') . '. ' . esc_html__('New address only –', 'aguard-safe') . ' <code>/wp-login.php</code> ' . esc_html__('and', 'aguard-safe') . ' <code>/wp-admin</code> ' . esc_html__('show “404” to visitors who are not signed in (bots no longer see the login form)', 'aguard-safe') . '.</p><p>' . esc_html__('When the address is changed,', 'aguard-safe') . ' <strong>' . esc_html__('nothing changes for customers', 'aguard-safe') . '</strong>' . esc_html__(': their login, registration at checkout and password reset happen on the shop pages (', 'aguard-safe') . '<code>/my-account/</code>' . esc_html__(', checkout), which do not use wp-login.php. The new address is needed only by administrators and staff – tell it to them. Every change is reported to the notification e-mail.', 'aguard-safe') . '</p><p>' . esc_html__('After saving, the plugin opens the new address, the home page and the account page by itself; if any of them does not answer “200”, the setting is reverted automatically. The new address is sent to the notification e-mail. Emergency switch without signing in: the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_LOGIN_OFF\', true);</code> ' . esc_html__('in wp-config.php or an empty file', 'aguard-safe') . ' <code>AGUARD-LOGIN-OFF</code> ' . esc_html__('in the wp-content folder (it survives plugin updates).', 'aguard-safe') . '</p></details>';
                echo '<div class="ag-set-foot"><span></span><button class="button button-primary" name="aguard_login_save" value="1" form="ag-f-login">' . esc_html__('Save and test', 'aguard-safe') . '</button><button class="button" name="aguard_login_test" value="1" form="ag-f-login">' . esc_html__('Check now', 'aguard-safe') . '</button></div>';
                $row(__('E-mail confirmation (2FA)', 'aguard-safe'), ($k2 !== '' ? __('turned off by the emergency switch (', 'aguard-safe') . $k2 . '). ' : '') . __('After the correct password, a 6-digit code is sent to the administrator\'s e-mail; signing in is not possible without it. The browser can be remembered for 30 days, so the code is not asked every day. Customers and non-administrators are not affected.', 'aguard-safe'), $sw('twofa', $tf, 'ag-f-2fa'));
                echo '<details class="ag-how"><summary>' . esc_html__('How it works', 'aguard-safe') . '</summary><p>' . esc_html__('If the e-mail cannot be sent (mail error), an administrator from a usual IP (used to sign in during the last 30 days) is let in without a code and this is reported; from an unknown IP – not. The confirmation can be turned off only when Settings are unlocked with a code. Emergency switch without signing in: the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_2FA_OFF\', true);</code> ' . esc_html__('in wp-config.php or an empty file', 'aguard-safe') . ' <code>AGUARD-2FA-OFF</code> ' . esc_html__('in the wp-content folder (it survives plugin updates).', 'aguard-safe') . '</p></details>';
                echo '<div class="ag-set-foot"><span></span><button class="button button-primary" name="aguard_2fa_save" value="1" form="ag-f-2fa">' . esc_html__('Save', 'aguard-safe') . '</button><button class="button" name="aguard_2fa_forget" value="1" form="ag-f-2fa" data-ag-confirm="' . esc_attr(__('Forget all remembered browsers? Next time every administrator will enter a code.', 'aguard-safe')) . '">' . esc_html__('Forget remembered browsers', 'aguard-safe') . '</button></div></div>';
                // file protection
                echo '<div class="ag-rows ag-sec2" id="ag-s-files"><div class="ag-rows-h">' . esc_html__('File protection', 'aguard-safe') . '<small>' . esc_html__('What the scanner checks and blocks.', 'aguard-safe') . '</small></div>';
                $row(__('Block PHP execution in the uploads folder', 'aguard-safe'), __('Closes the most common malware route', 'aguard-safe'), '<button class="button-link" name="aguard_uploads_verify" value="1" form="ag-f-main">' . esc_html__('Test the PHP block', 'aguard-safe') . '</button>' . $sw('block_php_uploads', !empty($o['block_php_uploads']), 'ag-f-main', $dis));
                $row(__('Check the content shown to Googlebot', 'aguard-safe'), __('Finds hidden spam shown only to search engines', 'aguard-safe'), $sw('cloak_check', $o['cloak_check'], 'ag-f-main', $dis));
                $row(__('Known extra files (allowlist, one per line):', 'aguard-safe'), __('Files the scanner should not report', 'aguard-safe'), '<textarea name="whitelist" form="ag-f-main" rows="3"' . esc_attr($dis) . '>' . esc_textarea(implode("\n", (array) ($o['whitelist'] ?? []))) . '</textarea>');
                echo '<div class="ag-set-foot"><span></span>' . $save . '<button class="button" name="aguard_rebaseline" value="1" form="ag-f-main"' . esc_attr($dis) . '>' . esc_html__('Update the baseline', 'aguard-safe') . '</button></div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $save is built from escaped parts.
                // tools
                echo '<div class="ag-rows ag-sec2" id="ag-s-tools"><div class="ag-rows-h">' . esc_html__('Tools', 'aguard-safe') . '<small>' . esc_html__('Read-only viewers and the notice on the site.', 'aguard-safe') . '</small></div>';
                $row(__('File viewer', 'aguard-safe'), __('Scan → Files. Read-only', 'aguard-safe'), $sw('tool_files', !empty($o['tool_files']), 'ag-f-main', $dis));
                $row(__('Log viewer', 'aguard-safe'), __('Activity → Logs. Read-only', 'aguard-safe'), $sw('tool_logs', !empty($o['tool_logs']), 'ag-f-main', $dis));
                $row(__('Notice on the site', 'aguard-safe'), __('One small line with a link to aguard.lt is added at the bottom of every public page. Off by default; nothing is shown until you tick the box.', 'aguard-safe') . ' “' . wp_strip_all_tags(self::credit_html()) . '”', $sw('credit', !empty($o['credit']), 'ag-f-main', $dis));
                echo '<div class="ag-set-foot"><span></span>' . $save . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $save is built from escaped parts.
                echo '<form method="post" class="ag-set">' . $nonce . '<div class="ag-set-t"><b>' . esc_html__('Remove events that contain the text:', 'aguard-safe') . '</b><span>' . esc_html__('(for example, your own file flagged by mistake; the action is logged and reported by e-mail)', 'aguard-safe') . '</span></div><div class="ag-set-c"><input type="text" name="aguard_prune_kw"' . esc_attr($dis) . '><button class="button" name="aguard_prune" value="1"' . esc_attr($dis) . '>' . esc_html__('Remove', 'aguard-safe') . '</button></div></form></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with wp_kses above.
                echo '</div></div>';
                break;
            case 'response':
                echo '<div style="background:#fff;padding:14px 18px;border:1px solid #ccd0d4;max-width:760px">';
                echo '<p>' . esc_html__('This tab is for an emergency, when you suspect that someone else controls the site. Normally there is nothing to do here.', 'aguard-safe') . '</p>';
                if (!empty($data['lockdown'])) echo '<p><strong style="color:#b32d2e">' . esc_html__('LOCKDOWN IS ON', 'aguard-safe') . '</strong> ' . esc_html__('since', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) ($data['lockdown']['t'] ?? 0))) . ' (' . esc_html((string) ($data['lockdown']['by'] ?? '')) . esc_html__('). Installing and changing plugins/themes and registration are disabled.', 'aguard-safe') . '</p><form method="post">' . wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button button-primary" name="aguard_lockdown_off" value="1">' . esc_html__('Turn LOCKDOWN off', 'aguard-safe') . '</button></form>';
                else echo '<p><strong>LOCKDOWN</strong> ' . esc_html__('in one click: signs out all other administrators, sends them password reset links, blocks installing and changing plugins and themes, turns registration off. The site keeps working for visitors. You can turn it off here at any time.', 'aguard-safe') . '</p><form method="post" data-ag-confirm="' . esc_attr(__('Turn LOCKDOWN on? All other administrators will be signed out.', 'aguard-safe')) . '">' . wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button" name="aguard_lockdown_on" value="1" style="border-color:#b32d2e;color:#b32d2e">' . esc_html__('Turn LOCKDOWN on', 'aguard-safe') . '</button></form>';
                echo '<hr><p>' . esc_html__('Quarantine:', 'aguard-safe') . ' ' . (int) $data['quarantine'] . ' ' . esc_html__('files ·', 'aguard-safe') . ' <a href="' . esc_url(self::url(['tab' => 'quarantine'])) . '">' . esc_html__('view', 'aguard-safe') . '</a>' . (self::tool_on('files') ? esc_html__('. A suspicious file can be moved to quarantine from Scan → Files, after opening the file.', 'aguard-safe') : esc_html__('. A suspicious file can be moved to quarantine from Scan → Files. The file viewer is turned off: turn it on in Settings → Tools.', 'aguard-safe')) . '</p>';
                echo '<p>' . esc_html__('Remote management / in-browser file editing tools:', 'aguard-safe') . ' ' . ($data['remote_admin']['found'] ? '<strong style="color:#b32d2e">' . esc_html(implode('; ', $data['remote_admin']['found'])) . '</strong>' : esc_html__('none found', 'aguard-safe')) . '</p></div>';
                break;
            case 'events':
                $all = self::req('all') !== ''; $list = (array) $data; $ftype = sanitize_key(self::req('type'));
                // what kind of event it is, in words, with its own sign and colour
                $kinds = [
                    'login' => [__('Logins', 'aguard-safe'), 'login', 'info'],
                    'scan' => [__('Checks', 'aguard-safe'), 'scan', 'info'],
                    'user' => [__('Users', 'aguard-safe'), 'user', 'warn'],
                    'plugin' => [__('Plugins', 'aguard-safe'), 'plugins', 'info'],
                    'theme' => [__('Themes', 'aguard-safe'), 'theme', 'risk'],
                    'settings' => [__('Settings', 'aguard-safe'), 'settings', 'info'],
                    'vuln' => [__('Vulnerabilities', 'aguard-safe'), 'alert', 'risk'],
                    'quarantine' => [__('Quarantine', 'aguard-safe'), 'emergency', 'risk'],
                    'tools' => [__('Viewers', 'aguard-safe'), 'activity', 'info'],
                    'test' => [__('Tests', 'aguard-safe'), 'settings', 'info'],
                    'error' => [__('Errors', 'aguard-safe'), 'alert', 'info'],
                ];
                $other = [__('Incidents', 'aguard-safe'), 'alert', 'info'];
                $counts = []; $day_ago = time() - DAY_IN_SECONDS; $recent = 0; $mailed = 0;
                foreach ($list as $e) { $k = isset($kinds[$e['type']]) ? $e['type'] : 'other'; $counts[$k] = ($counts[$k] ?? 0) + 1; if ((int) $e['t'] >= $day_ago) { $recent++; if (!empty($e['mailed'])) $mailed++; } }
                $total = count($list);
                /* translators: %d: number of events */
                echo '<div class="ag-top">' . wp_kses(self::dial((int) $recent), self::svg_kses() + ['span' => ['class' => true], 'b' => []]) . '<div class="ag-top-text"><b>' . esc_html(sprintf(_n('%d event in the last 24 hours', '%d events in the last 24 hours', $recent, 'aguard-safe'), $recent)) . '</b><span>' . esc_html__('E-mails sent about them:', 'aguard-safe') . ' ' . (int) $mailed . ' · ' . esc_html__('events in the log:', 'aguard-safe') . ' ' . (int) $total . '</span></div></div>';
                echo '<nav class="ag-filter"><a class="' . ($ftype === '' ? 'on' : '') . '" href="' . esc_url(self::url(['tab' => 'events'])) . '">' . esc_html__('All', 'aguard-safe') . '<i>' . (int) $total . '</i></a>';
                foreach ($kinds + ['other' => $other] as $k => $def) { if (empty($counts[$k])) continue; echo '<a class="' . ($ftype === $k ? 'on' : '') . '" href="' . esc_url(self::url(['tab' => 'events', 'type' => $k])) . '">' . esc_html($def[0]) . '<i>' . (int) $counts[$k] . '</i></a>'; }
                echo '</nav>';
                if ($ftype !== '') $list = array_values(array_filter($list, function ($e) use ($ftype, $kinds) { return (isset($kinds[$e['type']]) ? $e['type'] : 'other') === $ftype; }));
                $shown = count($list); if (!$all) $list = array_slice($list, 0, 100);
                if (!$list) echo '<p class="ag-note">' . esc_html__('No events yet.', 'aguard-safe') . '</p>';
                $day = ''; $today = wp_date('Y-m-d'); $yest = wp_date('Y-m-d', time() - DAY_IN_SECONDS);
                foreach ($list as $e) {
                    $d = wp_date('Y-m-d', $e['t']);
                    if ($d !== $day) {
                        if ($day !== '') echo '</div>';
                        $day = $d;
                        echo '<h3 class="ag-day-h">' . esc_html($d === $today ? __('Today', 'aguard-safe') : ($d === $yest ? __('Yesterday', 'aguard-safe') : wp_date('l, j F', $e['t']))) . '</h3><div class="ag-rows ag-feed">';
                    }
                    $def = $kinds[$e['type']] ?? $other; $lvl = $def[2]; if (self::is_critical($e['type'], $e['title'] ?? '', (array) ($e['data'] ?? []))) $lvl = in_array($e['type'], ['plugin', 'login', 'settings'], true) ? 'warn' : 'risk';
                    $who = (string) ($e['who'] ?? ''); $parts = array_map('trim', explode('|', $who)); $user = $parts[0] ?? ''; $ipraw = $parts[1] ?? '';
                    $ip = preg_match('~HTTP_CF_CONNECTING_IP: ([0-9a-f.:]+)~', $ipraw, $mm) ? $mm[1] : trim(str_replace('IP', '', preg_replace('~\(.*\)~', '', $ipraw)));
                    // who did it, in words
                    if ($user === 'cron') $by = __('automatic check', 'aguard-safe');
                    elseif ($user === 'wp-cli') $by = __('server command line', 'aguard-safe');
                    elseif ($user === 'anonymous' || $user === '') $by = ($e['type'] === 'login') ? '' : __('visitor who is not signed in', 'aguard-safe');
                    else $by = (string) preg_replace('~\s*\(#\d+\)$~', '', $user);
                    $meta = [esc_html(wp_date('H:i', $e['t']))];
                    if ($by !== '') $meta[] = esc_html($by);
                    if ($ip !== '' && $user !== 'cron' && $user !== 'wp-cli') $meta[] = 'IP ' . esc_html($ip);
                    $head = '<div class="ag-ev-ic ag-ev-' . esc_attr($lvl) . '">' . wp_kses(self::shield($def[1], 34), self::svg_kses()) . '</div><div class="ag-ev-t"><b>' . esc_html($e['title']) . '</b><span>' . implode(' · ', $meta) . '</span></div><div class="ag-ev-m">' . (!empty($e['mailed']) ? esc_html__('e-mail sent', 'aguard-safe') : '') . '</div>';
                    if (empty($e['data'])) { echo '<div class="ag-row ag-row-ev">' . wp_kses($head, self::svg_kses() + wp_kses_allowed_html('post')) . '<span></span></div>'; continue; }
                    echo '<details class="ag-row-d"><summary class="ag-row ag-row-ev">' . wp_kses($head, self::svg_kses() + wp_kses_allowed_html('post')) . '<span class="ag-row-more">' . esc_html__('Details', 'aguard-safe') . '</span></summary><div class="ag-row-open ag-row-kv">' . wp_kses(self::kv($e['data'], 1) . (is_array($e['data']) && array_filter($e['data'], 'is_array') ? self::json_details($e['data'], 'JSON') : ''), self::html_kses()) . '</div></details>';
                }
                if ($day !== '') echo '</div>';
                if (!$all && $shown > 100) echo '<p class="ag-one"><a href="' . esc_url(self::url(['tab' => 'events', 'all' => '1', 'type' => $ftype])) . '">' . esc_html__('show all', 'aguard-safe') . ' (' . (int) $shown . ')</a></p>';
                break;
            case 'scan':
                $what = sanitize_key(self::req('what'));
                echo wp_kses(self::scan_view($what, $data), self::svg_kses() + self::html_kses());
                // every single check as its own card: what it looks at and how long it takes
                $fast = __('a few seconds', 'aguard-safe'); $slow = __('up to a minute', 'aguard-safe');
                $runs = [
                    'sentinels' => [__('System files', 'aguard-safe'), __('wp-config.php, .htaccess, index.php, drop-ins and must-use plugins compared with the saved baseline.', 'aguard-safe'), $fast, 'settings'],
                    'core' => [__('WordPress core', 'aguard-safe'), __('Every core file compared with the official checksums from WordPress.org.', 'aguard-safe'), $slow, 'overview'],
                    'uploads' => [__('PHP in uploads and cache', 'aguard-safe'), __('Looks for PHP files in folders where only images and cache should be.', 'aguard-safe'), $fast, 'alert'],
                    'recent' => [__('Recently changed', 'aguard-safe'), __('Lists all files changed in the last 48 hours.', 'aguard-safe'), $fast, 'activity'],
                    'cloaking' => [__('Googlebot vs visitor', 'aguard-safe'), __('Loads the home page as a visitor and as Googlebot and compares the two.', 'aguard-safe'), $fast, 'user'],
                    'plugins' => [__('Plugins vs WordPress.org', 'aguard-safe'), __('Plugin files compared with their official checksums.', 'aguard-safe'), $slow, 'plugins'],
                    'suspicious' => [__('Suspicious code', 'aguard-safe'), __('Searches wp-content for backdoor and loader code patterns.', 'aguard-safe'), $slow, 'scan'],
                    'remote' => [__('Remote access tools', 'aguard-safe'), __('Looks for remote management and auto-login plugins that let someone in without a password.', 'aguard-safe'), $fast, 'login'],
                ];
                echo '<h3 class="ag-day-h">' . esc_html__('Run one check', 'aguard-safe') . '</h3><div class="ag-runs">';
                foreach ($runs as $k => $r) echo '<a class="ag-run' . ($what === $k ? ' on' : '') . '" data-ag-busy="1" href="' . esc_url(self::url(['tab' => 'scan', 'what' => $k])) . '"><span class="ag-ev-ic ag-ev-info">' . wp_kses(self::shield($r[3], 34), self::svg_kses()) . '</span><b>' . esc_html($r[0]) . '</b><span class="ag-run-d">' . esc_html($r[1]) . '</span><span class="ag-run-f"><i>' . esc_html($r[2]) . '</i><em>' . esc_html__('Run', 'aguard-safe') . ' →</em></span></a>';
                echo '</div>';
                echo wp_kses(self::json_details($data), self::html_kses());
                break;
            case 'files':
                if (isset($data['data'])) {
                    $own = self::file_owner($data['rel']);
                    $part = ['plugin' => $own['live'] ? __('active plugin', 'aguard-safe') : __('inactive plugin', 'aguard-safe'), 'theme' => $own['live'] ? __('active theme', 'aguard-safe') : __('inactive theme', 'aguard-safe'), 'core' => __('WordPress itself', 'aguard-safe'), 'mu' => __('must-use plugin (always loaded)', 'aguard-safe'), 'uploads' => __('uploads folder', 'aguard-safe'), 'other' => __('not part of WordPress, a plugin or a theme', 'aguard-safe')][$own['kind']];
                    $can = self::quarantinable($data['rel']); $orig = self::original_info($data['rel']);
                    $qn0 = wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]);
                    $ls0 = get_option(self::OPT . '_last_scan', []); $unk0 = false;
                    foreach ((array) ($ls0['core']['extra'] ?? []) as $x) { if (preg_replace('~ \(.*$~', '', (string) $x) === $data['rel']) { $unk0 = true; break; } }
                    echo '<div class="ag-rows ag-file"><div class="ag-file-p"><code>' . esc_html($data['rel']) . '</code></div><div class="ag-file-m"><span><i>' . esc_html__('Belongs to', 'aguard-safe') . '</i>' . esc_html($part . ($own['name'] !== '' && $own['kind'] !== 'core' ? ': ' . $own['name'] : '')) . '</span><span><i>' . esc_html__('Size', 'aguard-safe') . '</i>' . esc_html(size_format((int) $data['size'], 1)) . '</span><span><i>' . esc_html__('Changed', 'aguard-safe') . '</i>' . esc_html(wp_date('Y-m-d H:i', $data['mtime'])) . '</span></div>';
                    // what can be done with the file: first, in plain sight
                    echo '<div class="ag-file-do"><b>' . esc_html__('What to do', 'aguard-safe') . '</b>';
                    if ($orig && !$orig['same']) echo '<form method="post" data-ag-confirm="' . esc_attr__('Replace this file with the original from WordPress.org?', 'aguard-safe') . '">' . $qn0 . '<button class="button button-primary" name="aguard_replace" value="' . esc_attr($data['rel']) . '">' . esc_html__('Replace with the original', 'aguard-safe') . '</button></form><a class="button" href="' . esc_url(self::url(['tab' => 'files', 'file' => $data['rel'], 'diff' => '1']) . '#ag-diff') . '">' . esc_html__('Show what was changed', 'aguard-safe') . '</a>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $qn0 is escaped with wp_kses above.
                    elseif ($orig) echo '<span class="ag-file-ok">' . esc_html__('The file matches the original. Nothing to do.', 'aguard-safe') . '</span>';
                    elseif ($can === true) echo '<form method="post" data-ag-confirm="' . esc_attr($own['live'] ? __('This file belongs to something the site is running. Move it to quarantine anyway?', 'aguard-safe') : __('Move the file to quarantine? The site will no longer see it.', 'aguard-safe')) . '">' . $qn0 . '<button class="button ag-btn-danger" name="aguard_quarantine" value="' . esc_attr($data['rel']) . '">' . esc_html__('Move to quarantine', 'aguard-safe') . '</button></form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $qn0 is escaped with wp_kses above.
                    if ($unk0) echo '<form method="post">' . $qn0 . '<button class="button" name="aguard_allow" value="' . esc_attr($data['rel']) . '">' . esc_html__('I know this file: add to the allowlist', 'aguard-safe') . '</button></form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $qn0 is escaped with wp_kses above.
                    if (!self::is_unlocked() && (($orig && !$orig['same']) || $can === true || $unk0)) echo '<a class="ag-file-lock" href="' . esc_url(self::url(['tab' => 'settings'])) . '">' . esc_html__('Locked: unlock Settings first', 'aguard-safe') . ' →</a>';
                    echo '<span class="ag-file-more"><a href="' . esc_url(self::url(['aguard_download' => $data['rel']])) . '">' . esc_html__('Download', 'aguard-safe') . '</a><a href="' . esc_url(self::url(['tab' => 'files', 'path' => dirname($data['rel']) === '.' ? '' : dirname($data['rel'])])) . '">' . esc_html__('Open the folder', 'aguard-safe') . '</a></span></div></div>';
                    $lines = preg_split('~\r\n|\n|\r~', (string) wp_check_invalid_utf8((string) $data['data'], true)); $hl = self::req('hl') !== ''; $hits = [];
                    if ($hl) {
                        // matched on the whole text, exactly as the scan does, then mapped to line numbers
                        $text_all = implode("\n", $lines);
                        foreach (self::code_signs() as $name => $re) {
                            if (!preg_match_all($re, $text_all, $mm, PREG_OFFSET_CAPTURE)) continue;
                            foreach (array_slice($mm[0], 0, 40) as $hit) { $ln = substr_count($text_all, "\n", 0, (int) $hit[1]) + 1; $hits[$ln][] = $name; }
                        }
                        ksort($hits);
                    }
                    if ($hl) {
                        echo '<div class="ag-rows ag-hits"><div class="ag-rows-h">' . esc_html($hits ? __('Lines the scan pointed at', 'aguard-safe') : __('No marked lines in this part of the file', 'aguard-safe')) . '<small>' . esc_html__('A sign is not a verdict: plugins use these functions for ordinary work too. Look at what the line does with the data.', 'aguard-safe') . '</small></div>';
                        foreach (array_slice($hits, 0, 60, true) as $ln => $names) echo '<a class="ag-row ag-hit-row" href="#ag-l' . (int) $ln . '"><b>' . esc_html__('line', 'aguard-safe') . ' ' . (int) $ln . '</b><span>' . esc_html(implode(', ', array_unique($names))) . '</span><code>' . esc_html(wp_html_excerpt(trim($lines[$ln - 1]), 110, '…')) . '</code></a>';
                        echo '</div>';
                    }
                    echo '<pre class="ag-code">';
                    foreach ($lines as $ln => $text) echo '<span id="ag-l' . (int) ($ln + 1) . '" class="ag-ln' . (isset($hits[$ln + 1]) ? ' ag-ln-hit' : '') . '">' . esc_html($text) . "\n" . '</span>';
                    echo '</pre>';
                    if ($orig && !$orig['same'] && self::req('diff') !== '') {
                        $src = self::original_fetch($orig);
                        echo '<div class="ag-rows ag-diffbox" id="ag-diff"><div class="ag-rows-h">' . esc_html__('What was changed', 'aguard-safe') . '<small>' . esc_html(sprintf(/* translators: %s: what the original belongs to */ __('Left: the original of %s. Right: the file on this site. Only the changed places are shown.', 'aguard-safe'), $orig['of'])) . '</small></div>';
                        if (is_wp_error($src)) echo '<p class="ag-diff-n">' . esc_html($src->get_error_message()) . '</p>';
                        elseif (strlen($src) > MB_IN_BYTES || (int) $data['size'] > MB_IN_BYTES) echo '<p class="ag-diff-n">' . esc_html__('The file is too large to compare here. Download it and compare on your computer.', 'aguard-safe') . '</p>';
                        else { $d = self::diff_table($src, (string) wp_check_invalid_utf8((string) $data['data'], true)); echo $d ? wp_kses($d, ['table' => ['class' => true], 'colgroup' => [], 'col' => ['class' => true], 'tbody' => [], 'thead' => [], 'tr' => [], 'td' => ['class' => true, 'colspan' => true], 'th' => ['class' => true, 'colspan' => true], 'ins' => [], 'del' => [], 'span' => ['class' => true, 'aria-hidden' => true]]) : '<p class="ag-diff-n">' . esc_html__('The text is the same; the files differ only in line endings.', 'aguard-safe') . '</p>'; }
                        echo '</div>';
                    }
                    $qnonce = wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]);
                    $locked = self::is_unlocked() ? '' : '<span class="ag-qbox-l">' . esc_html__('Needs unlocked Settings (the code from the e-mail).', 'aguard-safe') . '</span>';
                    $what = $own['kind'] === 'core' ? __('WordPress itself', 'aguard-safe') : ($own['kind'] === 'mu' ? __('a must-use plugin', 'aguard-safe') : (($own['kind'] === 'theme' ? __('the active theme', 'aguard-safe') : __('the active plugin', 'aguard-safe')) . ' ' . $own['name']));
                    if ($orig && $can === true) {
                        // a file with an official original: the right fix is the original, not removal
                        echo '<div class="ag-rows ag-qbox' . ($orig['same'] ? '' : ' ag-qbox-live') . '"><div class="ag-rows-h">' . esc_html($orig['same'] ? __('This file matches the original', 'aguard-safe') : __('This file differs from the original', 'aguard-safe')) . '<small>' . esc_html(sprintf(/* translators: %s: what the original belongs to, e.g. "Elementor 3.5.0" */ __('Compared with the official checksum of %s on WordPress.org.', 'aguard-safe'), $orig['of'])) . '</small></div><div class="ag-qbox-b">';
                        if ($orig['same']) echo '<p>' . esc_html__('Nobody changed it: it is exactly the file its author published. A sign found in it is part of the normal code.', 'aguard-safe') . '</p>';
                        else {
                            echo '<p>' . esc_html__('The plugin downloads the original from WordPress.org, checks its checksum and puts it in place of this file. The current file is not deleted: it is kept in Scan → Quarantine. If the site answers with an error afterwards, the previous file is put back at once.', 'aguard-safe') . '</p>';
                            echo '<form method="post" data-ag-confirm="' . esc_attr__('Replace this file with the original from WordPress.org?', 'aguard-safe') . '">' . $qnonce . '<button class="button button-primary" name="aguard_replace" value="' . esc_attr($data['rel']) . '">' . esc_html__('Replace with the original', 'aguard-safe') . '</button><a class="button" href="' . esc_url(self::url(['tab' => 'files', 'file' => $data['rel'], 'diff' => '1']) . '#ag-diff') . '">' . esc_html__('Show what was changed', 'aguard-safe') . '</a>' . $locked . '</form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
                        }
                        /* translators: %s: what the file belongs to, e.g. "the active plugin Elementor" */
                        echo '<details class="ag-how ag-qbox-alt"><summary>' . esc_html__('Move to quarantine instead', 'aguard-safe') . '</summary><p class="ag-qbox-w"><b>' . esc_html(sprintf(__('This file is part of %s.', 'aguard-safe'), $own['live'] ? $what : $orig['of'])) . '</b> ' . esc_html__('Without it the site can stop working. Use this only when you are sure.', 'aguard-safe') . '</p>' . '<form method="post" data-ag-confirm="' . esc_attr($own['live'] ? __('This file belongs to something the site is running. Move it to quarantine anyway?', 'aguard-safe') : __('Move the file to quarantine? The site will no longer see it.', 'aguard-safe')) . '">' . $qnonce . '<button class="button ' . ($orig ? '' : 'ag-btn-danger') . '" name="aguard_quarantine" value="' . esc_attr($data['rel']) . '">' . esc_html__('Move to quarantine', 'aguard-safe') . '</button>' . $locked . '</form>' . '</details>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
                        echo '</div></div>';
                    } else {
                        $ls = get_option(self::OPT . '_last_scan', []); $unk = false;
                        foreach ((array) ($ls['core']['extra'] ?? []) as $x) { if (preg_replace('~ \(.*$~', '', (string) $x) === $data['rel']) { $unk = true; break; } }
                        if ($unk) echo '<div class="ag-rows ag-qbox"><div class="ag-rows-h">' . esc_html__('You know this file?', 'aguard-safe') . '<small>' . esc_html__('The check reports it because it is not part of WordPress. If you or your hosting put it here, add it to the allowlist and it will not be reported again. The list can be edited in Settings → File protection.', 'aguard-safe') . '</small></div><div class="ag-qbox-b"><form method="post">' . $qnonce . '<button class="button" name="aguard_allow" value="' . esc_attr($data['rel']) . '">' . esc_html__('Add to the allowlist', 'aguard-safe') . '</button>' . $locked . '</form></div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $qnonce and $locked are built from escaped parts.
                        echo '<div class="ag-rows ag-qbox' . ($own['live'] ? ' ag-qbox-live' : '') . '"><div class="ag-rows-h">' . esc_html__('Move this file to quarantine', 'aguard-safe') . '<small>' . esc_html__('The file leaves its place and can no longer run. Nothing is deleted: it can be put back in Scan → Quarantine.', 'aguard-safe') . '</small></div><div class="ag-qbox-b">';
                        if ($can !== true) echo '<p>' . esc_html($can) . '</p>';
                        else {
                            /* translators: %s: what the file belongs to, e.g. "the active plugin Elementor" */
                            if ($own['live']) echo '<p class="ag-qbox-w"><b>' . esc_html(sprintf(__('This file is part of %s.', 'aguard-safe'), $what)) . '</b> ' . esc_html__('Without it the site can stop working. If the file was changed by someone else, it is safer to replace it with a clean copy: reinstall the plugin, the theme or WordPress.', 'aguard-safe') . '</p>';
                            else echo '<p>' . esc_html__('This file is not part of anything the site is running now, so moving it should not affect the site.', 'aguard-safe') . '</p>';
                            echo '<p class="ag-qbox-n">' . esc_html__('Safety net: right after the move the plugin asks WordPress itself (not a cached page) whether it still loads, and opens the home page. If the site answers with an error, the file is put back at once.', 'aguard-safe') . '</p>';
                            echo '<form method="post" data-ag-confirm="' . esc_attr($own['live'] ? __('This file belongs to something the site is running. Move it to quarantine anyway?', 'aguard-safe') : __('Move the file to quarantine? The site will no longer see it.', 'aguard-safe')) . '">' . $qnonce . '<button class="button ' . ($orig ? '' : 'ag-btn-danger') . '" name="aguard_quarantine" value="' . esc_attr($data['rel']) . '">' . esc_html__('Move to quarantine', 'aguard-safe') . '</button>' . $locked . '</form>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
                        }
                        echo '</div></div>';
                    }
                } else {
                    $path = self::req('path');
                    echo '<p><a href="' . esc_url(self::url(['tab' => 'files', 'path' => ''])) . '">/</a> ' . esc_html($path) . ' · <a href="' . esc_url(self::url(['tab' => 'files', 'path' => $path, 'hash' => '1'])) . '">' . esc_html__('with SHA-256', 'aguard-safe') . '</a>' . ($path !== '' ? ' · <a href="' . esc_url(self::url(['tab' => 'files', 'path' => dirname($path) === '.' ? '' : dirname($path)])) . '">↑</a>' : '') . '</p>';
                    echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Name', 'aguard-safe') . '</th><th>' . esc_html__('Size', 'aguard-safe') . '</th><th>' . esc_html__('Changed', 'aguard-safe') . '</th><th>' . esc_html__('Created/ctime', 'aguard-safe') . '</th><th>' . esc_html__('Permissions', 'aguard-safe') . '</th><th>' . esc_html__('Owner', 'aguard-safe') . '</th><th>SHA-256</th></tr></thead><tbody>';
                    foreach ((array) $data as $r) {
                        $link = $r['dir'] ? self::url(['tab' => 'files', 'path' => $r['rel']]) : self::url(['tab' => 'files', 'file' => $r['rel']]);
                        echo '<tr><td>' . ($r['dir'] ? '📁 ' : '') . '<a href="' . esc_url($link) . '">' . esc_html($r['name']) . '</a>' . ($r['link'] ? ' → ' . esc_html($r['link']) : '') . '</td><td>' . ($r['dir'] ? '' : (int) $r['size']) . '</td><td>' . esc_html($r['mtime'] ? wp_date('Y-m-d H:i:s', $r['mtime']) : '') . '</td><td>' . esc_html($r['ctime'] ? wp_date('Y-m-d H:i:s', $r['ctime']) : '') . '</td><td>' . esc_html($r['perms']) . '</td><td>' . esc_html((string) ($r['owner'] ?? $r['uid'])) . '</td><td><code style="font-size:11px">' . esc_html($r['sha256'] ?? '') . '</code></td></tr>';
                    }
                    echo '</tbody></table>';
                }
                break;
            case 'sessions':
                $total = 0; foreach ($data as $u) $total += count($u['sessions']);
                echo '<div class="ag-top">' . wp_kses(self::dial((int) $total), self::svg_kses() + ['span' => ['class' => true], 'b' => []]) . '<div class="ag-top-text"><b>' . esc_html__('Accounts with admin permissions:', 'aguard-safe') . ' ' . count($data) . ' ' . esc_html__('· signed-in devices in total:', 'aguard-safe') . ' ' . (int) $total . '</b><span>' . esc_html__('Each row is one device or browser where the account is still signed in. If you see an unfamiliar device or IP, press “Sign out everywhere” and change that user\'s password.', 'aguard-safe') . '</span></div></div>';
                $dev_ic = ['pc' => 'M4 5.500h16v10.500H4zM2 19.500h20', 'phone' => 'M7.500 3h9v18h-9zM11 18h2', 'app' => 'M8 8l-4 4 4 4M16 8l4 4-4 4M13 6l-2 12'];
                foreach ($data as $u) {
                    $name = (string) ($u['display'] ?: $u['login']);
                    echo '<div class="ag-rows ag-user"><div class="ag-who"><div class="ag-av">' . esc_html((function_exists('mb_strtoupper') ? mb_strtoupper(mb_substr($name, 0, 1)) : strtoupper(substr($name, 0, 1)))) . '</div><div class="ag-who-text"><b>' . esc_html($name) . '</b><span>' . esc_html($u['role_h']) . ' · ' . esc_html($u['login']) . ' · ' . esc_html($u['email']) . '</span></div>';
                    if ($u['sessions']) echo '<form method="post" data-ag-confirm="' . esc_attr(sprintf(/* translators: %s: user login */ __('Sign %s out of all devices?', 'aguard-safe'), $u['login'])) . '">' . wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<input type="hidden" name="aguard_logout_user" value="' . (int) $u['id'] . '"><button class="button">' . esc_html__('Sign out everywhere', 'aguard-safe') . '</button></form>';
                    echo '</div>';
                    if (!$u['sessions']) { echo '<div class="ag-ses ag-ses-none">' . esc_html__('Not signed in anywhere right now.', 'aguard-safe') . '</div></div>'; continue; }
                    foreach ($u['sessions'] as $sx) {
                        $ua = strtolower((string) $sx['ua']);
                        $kind = preg_match('/iphone|android|mobile/', $ua) ? 'phone' : ((strpos($ua, 'mozilla') === false) ? 'app' : 'pc');
                        /* translators: %s: time span */
                        $ago = $sx['login_t'] ? sprintf(__('%s ago', 'aguard-safe'), human_time_diff($sx['login_t'])) : (string) $sx['login'];
                        echo '<div class="ag-ses"><div class="ag-dev' . ($kind === 'app' ? ' ag-dev-app' : '') . '">' . wp_kses('<svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="' . $dev_ic[$kind] . '"/></svg>', self::svg_kses()) . '</div>';
                        echo '<div title="' . esc_attr((string) $sx['ua']) . '"><b>' . esc_html($sx['device']) . '</b><span>' . esc_html__('IP address', 'aguard-safe') . ' ' . esc_html((string) $sx['ip']) . '</span></div>';
                        echo '<div><b>' . esc_html($ago) . '</b><span>' . esc_html__('Signed in', 'aguard-safe') . ' ' . esc_html((string) $sx['login']) . '</span></div>';
                        echo '<div><b>' . esc_html((string) $sx['expiration']) . '</b><span>' . esc_html__('Valid until', 'aguard-safe') . '</span></div>';
                        echo '<div class="ag-ses-mark">' . ($sx['current'] ? esc_html__('this device', 'aguard-safe') : '') . '</div></div>';
                    }
                    echo '</div>';
                }
                break;
            case 'plugins':
                $c = ['urgent' => 0, 'vulnerable' => 0, 'closed' => 0, 'updates' => 0];
                foreach ($data['rows'] as $r) { if ($r['urgent']) $c['urgent']++; if ($r['vulns']) $c['vulnerable']++; if ($r['closed']) $c['closed']++; if ($r['update']) $c['updates']++; }
                $st = $data['state'];
                if ($c['urgent']) { $ring = 'risk'; $n = $c['urgent']; $big = sprintf(/* translators: %d: number of plugins */ _n('%d plugin needs an urgent update', '%d plugins need an urgent update', $c['urgent'], 'aguard-safe'), $c['urgent']); }
                elseif ($c['vulnerable'] || $c['closed']) { $ring = 'warn'; $n = $c['vulnerable'] + $c['closed']; $big = __('Some plugins have known vulnerabilities', 'aguard-safe'); }
                elseif ($c['updates']) { $ring = 'warn'; $n = $c['updates']; $big = sprintf(/* translators: %d: number of plugins */ _n('%d update is waiting', '%d updates are waiting', $c['updates'], 'aguard-safe'), $c['updates']); }
                else { $ring = 'ok'; $n = count($data['rows']); $big = $data['on'] ? __('No known vulnerabilities in the installed plugins', 'aguard-safe') : __('All plugins are up to date', 'aguard-safe'); }
                $sub = esc_html__('Installed plugins:', 'aguard-safe') . ' ' . count($data['rows']) . ' · ' . esc_html__('updates available:', 'aguard-safe') . ' ' . (int) $c['updates'];
                if ($data['on']) $sub .= ' · ' . esc_html__('with known vulnerabilities:', 'aguard-safe') . ' ' . (int) $c['vulnerable'] . ' · ' . esc_html__('closed on WordPress.org:', 'aguard-safe') . ' ' . (int) $c['closed'];
                /* translators: %s: time span, e.g. 5 mins */
                if ($data['on'] && !empty($st['t'])) $sub .= ' · ' . esc_html(sprintf(__('Last check: %s ago.', 'aguard-safe'), human_time_diff((int) $st['t'])));
                echo '<form method="post" class="ag-top">'; wp_nonce_field('aguard_safe_settings');
                echo '' . wp_kses(self::dial((int) $n, $ring), self::svg_kses() + ['span' => ['class' => true], 'b' => []]) . '<div class="ag-top-text"><b>' . esc_html($big) . '</b><span>' . wp_kses($sub, []) . '</span></div>';
                if ($data['on']) echo '<button class="button button-primary" name="aguard_vuln_check" value="1">' . esc_html__('Check now', 'aguard-safe') . '</button>';
                echo '</form>';
                echo '<form method="post" class="ag-consent' . ($data['on'] ? '' : ' ag-consent-off') . '">'; wp_nonce_field('aguard_safe_settings');
                if (!$data['on']) {
                    echo '<p><b>' . esc_html__('The vulnerability check is off.', 'aguard-safe') . '</b> ' . esc_html__('When it is on, once a day the plugin asks data.aguard.lt whether the installed plugins have known vulnerabilities and whether they have been closed on WordPress.org. For that the folder names (slugs) of all installed plugins and their versions are sent to data.aguard.lt.', 'aguard-safe') . '</p>';
                    echo '<button class="button button-primary" name="aguard_vuln_on" value="1">' . esc_html__('Turn on the vulnerability check', 'aguard-safe') . '</button>';
                } else {
                    echo '<p>' . esc_html__('The vulnerability check is on: the folder names (slugs) of the installed plugins and their versions are sent to data.aguard.lt once a day and after the list of plugins changes.', 'aguard-safe');
                    if (!empty($st['error'])) echo ' <span class="ag-warn">' . esc_html__('The last request failed:', 'aguard-safe') . ' ' . esc_html((string) $st['error']) . '</span>';
                    echo '</p><button class="button-link" name="aguard_vuln_off" value="1">' . esc_html__('Turn off', 'aguard-safe') . '</button>';
                }
                echo '</form>';
                echo '<div class="ag-rows">';
                foreach ($data['rows'] as $r) {
                    $dot = $r['urgent'] ? 'risk' : (($r['vulns'] || $r['closed'] || $r['state'] === 'pending') ? 'warn' : (($r['state'] === 'off' || $r['state'] === 'wait') ? 'idle' : 'ok'));
                    if ($r['state'] === 'off') $res = __('check is off', 'aguard-safe');
                    elseif ($r['state'] === 'wait') $res = __('waiting for the next check', 'aguard-safe');
                    elseif ($r['state'] === 'pending') $res = __('has known vulnerabilities; the details are still being collected', 'aguard-safe');
                    elseif (!$r['vulns']) $res = __('none known for this version', 'aguard-safe');
                    /* translators: 1: number of urgent vulnerabilities, 2: number of other vulnerabilities */
                    elseif ($r['urgent']) $res = sprintf(__('urgent: %1$d, other: %2$d', 'aguard-safe'), $r['urgent'], count($r['vulns']) - $r['urgent']);
                    /* translators: %d: number of vulnerabilities */
                    else $res = sprintf(_n('%d known, not urgent', '%d known, none urgent', count($r['vulns']), 'aguard-safe'), count($r['vulns']));
                    $head = '<span class="ag-ev-ic ag-ev-' . esc_attr(in_array($dot, ['warn', 'risk'], true) ? $dot : 'info') . '">' . self::shield('plugins', 30) . '</span><div class="ag-row-name"><b>' . esc_html($r['name']) . '</b><span>' . esc_html($r['slug']) . ($r['active'] ? '' : ' · ' . esc_html__('inactive', 'aguard-safe')) . '</span></div>';
                    /* translators: %s: plugin version number */
                    $head .= '<div class="ag-row-ver"><b>' . esc_html($r['version']) . '</b>' . ($r['closed'] ? '<span class="ag-risk">' . esc_html__('Closed on WordPress.org: no more updates.', 'aguard-safe') . '</span>' : ($r['update'] ? '<span class="ag-warn">' . esc_html(sprintf(__('update to %s', 'aguard-safe'), $r['update'])) . '</span>' : '<span>' . esc_html__('up to date', 'aguard-safe') . '</span>')) . '</div>';
                    $head .= '<div class="ag-row-res ag-res-' . esc_attr($dot) . '">' . esc_html($res) . '</div>';
                    $hk = self::svg_kses() + wp_kses_allowed_html('post');
                    if (!$r['vulns']) { echo '<div class="ag-row ag-row-pl">' . wp_kses($head, $hk) . '<span></span></div>'; continue; }
                    echo '<details class="ag-row-d"' . ($r['urgent'] ? ' open' : '') . '><summary class="ag-row ag-row-pl">' . wp_kses($head, $hk) . '<span class="ag-row-more">' . esc_html__('Details', 'aguard-safe') . '</span></summary><div class="ag-row-open">';
                    foreach ($r['vulns'] as $x) {
                        $needs = self::vuln_needs($x['needs']); $meta = [];
                        if ($x['cve']) $meta[] = $x['url'] ? '<a href="' . esc_url($x['url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html($x['cve']) . '</a>' : esc_html($x['cve']);
                        elseif ($x['url']) $meta[] = '<a href="' . esc_url($x['url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('description', 'aguard-safe') . '</a>';
                        if ($x['cvss'] !== null) $meta[] = 'CVSS ' . esc_html(number_format((float) $x['cvss'], 1));
                        if ($x['kev']) $meta[] = esc_html__('on the CISA list of exploited vulnerabilities', 'aguard-safe');
                        if ($needs) $meta[] = esc_html($needs);
                        $title = ($x['title'] && $x['title'] !== $x['cve']) ? $x['title'] : ($x['cve'] ?: __('Vulnerability', 'aguard-safe'));
                        echo '<div class="ag-cve"><i class="' . ($x['urgent'] ? 'ag-risk' : 'ag-warn') . '">' . ($x['urgent'] ? esc_html__('Urgent', 'aguard-safe') : esc_html__('Not urgent', 'aguard-safe')) . '</i><div><b>' . esc_html($title) . '</b><small>' . wp_kses(implode(' · ', $meta), ['a' => ['href' => true, 'target' => true, 'rel' => true]]) . '</small></div><em>';
                        /* translators: %s: plugin version number */
                        if ($x['fixed_in']) echo esc_html(sprintf(__('fixed in %s', 'aguard-safe'), $x['fixed_in']));
                        /* translators: %s: plugin version number */
                        elseif ($x['fixed_after']) echo esc_html(sprintf(__('fixed after %s', 'aguard-safe'), $x['fixed_after']));
                        elseif ($x['unfixed']) echo esc_html__('no fixed version yet', 'aguard-safe');
                        echo '</em></div>';
                    }
                    echo '<div class="ag-row-acts">';
                    if ($r['update'] && current_user_can('update_plugins')) echo '<a class="button button-primary" href="' . esc_url(self_admin_url('plugins.php?plugin_status=upgrade')) . '">' . esc_html__('Go to updates', 'aguard-safe') . '</a>';
                    if ($r['urgent']) echo '<span>' . esc_html__('Need a hand with an update or a replacement?', 'aguard-safe') . ' <a href="https://aguard.lt/en" target="_blank" rel="noopener">aguard.lt</a></span>';
                    echo '</div></div></details>';
                }
                echo '</div>';
                if ($data['on']) echo '<p class="ag-foot-note">' . esc_html__('“Urgent” means: the vulnerability is on the CISA list of exploited vulnerabilities, or it is rated high, needs no login and no action by a user, and attacks on it are likely. Vulnerability data from WPVulnerability and CISA.', 'aguard-safe') . '</p>';
                break;
            case 'quarantine':
                echo '<p>' . esc_html__('Quarantine folder:', 'aguard-safe') . ' <code>' . esc_html((string) $data['dir']) . '</code> ' . esc_html__('(closed to direct access with .htaccess). Files are not deleted – they can be restored.', 'aguard-safe') . '</p>';
                echo '<table class="widefat striped"><colgroup><col style="width:135px"><col><col style="width:80px"><col style="width:170px"><col style="width:200px"><col style="width:110px"><col style="width:90px"></colgroup><thead><tr><th>' . esc_html__('Time', 'aguard-safe') . '</th><th>' . esc_html__('Original path', 'aguard-safe') . '</th><th>' . esc_html__('Size', 'aguard-safe') . '</th><th>SHA-256</th><th>' . esc_html__('Who', 'aguard-safe') . '</th><th>' . esc_html__('Status', 'aguard-safe') . '</th><th></th></tr></thead><tbody>';
                foreach (array_reverse((array) $data['items']) as $q) {
                    $exists = is_file($q['dest']);
                    echo '<tr><td>' . esc_html(wp_date('Y-m-d H:i:s', $q['t'])) . '</td><td><code>' . esc_html($q['rel']) . '</code></td><td>' . (int) $q['size'] . '</td><td style="font-size:10px">' . esc_html($q['sha256']) . '</td><td style="font-size:11px">' . esc_html($q['who']) . '</td><td>' . ($exists ? esc_html__('in quarantine', 'aguard-safe') : ($q['restored'] ?? false ? esc_html__('restored', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) $q['restored'])) : esc_html__('file is gone', 'aguard-safe'))) . '</td><td>';
                    if ($exists) echo '<form method="post" data-ag-confirm="' . esc_attr(__('Return the file to its original location?', 'aguard-safe')) . '">' . wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button button-small" name="aguard_restore" value="' . esc_attr($q['id']) . '">' . esc_html__('Restore', 'aguard-safe') . '</button></form>';
                    echo '</td></tr>';
                }
                echo '</tbody></table>';
                break;
            case 'logs':
                if (isset($data['lines'])) {
                    echo '<form method="get"><input type="hidden" name="page" value="aguard-safe"><input type="hidden" name="tab" value="logs"><input type="hidden" name="file" value="' . esc_attr($data['rel']) . '">' . wp_kses(wp_nonce_field('aguard_safe', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . ' <label>' . esc_html__('lines', 'aguard-safe') . ' <input type="number" name="lines" value="' . absint(self::req('lines', 200)) . '" style="width:90px"></label> <label>' . esc_html__('search (text or regexp)', 'aguard-safe') . ' <input type="text" name="q" value="' . esc_attr(self::req('q')) . '" class="regular-text"></label> <button class="button">' . esc_html__('Show', 'aguard-safe') . '</button> · <a href="' . esc_url(self::url(['aguard_download' => $data['rel']])) . '">' . esc_html__('download the whole file', 'aguard-safe') . '</a></form>';
                    echo '<pre style="background:#fff;padding:10px;border:1px solid #ccd0d4;white-space:pre-wrap;max-height:70vh;overflow:auto;font-size:11px">' . esc_html(implode("\n", $data['lines'])) . '</pre>';
                } else {
                    echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('File', 'aguard-safe') . '</th><th>' . esc_html__('Size', 'aguard-safe') . '</th><th>' . esc_html__('Changed', 'aguard-safe') . '</th></tr></thead><tbody>';
                    foreach ((array) $data as $r) echo '<tr><td><a href="' . esc_url(self::url(['tab' => 'logs', 'file' => $r['rel']])) . '">' . esc_html($r['rel']) . '</a></td><td>' . (int) $r['size'] . '</td><td>' . esc_html(wp_date('Y-m-d H:i:s', $r['mtime'])) . '</td></tr>';
                    echo '</tbody></table><p>' . esc_html__('Folder the tools can read:', 'aguard-safe') . ' <code>' . esc_html(self::base_dir()) . '</code></p>';
                }
                break;
        }
        echo '</div></div>';
    }
}

AGuard_Safe::init();
