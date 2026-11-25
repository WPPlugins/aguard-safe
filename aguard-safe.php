<?php
/**
 * Plugin Name: AGuard Safe
 * Description: Watches the site for signs of a break-in and reports them by e-mail: changed core files, new administrators, cloaking, PHP in uploads. Optional e-mail login confirmation, custom login address and file quarantine.
 * Version:     1.9.3
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

    const VERSION      = '1.9.3';
    const OPT          = 'aguard_safe';
    const OPT_EVENTS   = 'aguard_safe_events';
    const OPT_BASELINE = 'aguard_safe_baseline';
    const CRON         = 'aguard_safe_scan';
    const MAX_EVENTS   = 400;
    const OPT_Q        = 'aguard_safe_quarantine';
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
        add_action('wp_dashboard_setup', [__CLASS__, 'dashboard_widget_register']);
        // Fires only on this plugin's own admin page.
        add_action('load-toplevel_page_aguard-safe', [__CLASS__, 'handle_download']);
        add_action('load-toplevel_page_aguard-safe', [__CLASS__, 'handle_json']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) { array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=aguard-safe')) . '">' . __('Settings', 'aguard-safe') . '</a>'); return $links; });
        self::login_boot();
        if (!empty(self::opts()['lockdown'])) {
            add_filter('file_mod_allowed', '__return_false', 99);
            add_filter('pre_option_users_can_register', '__return_zero', 99);
            add_action('admin_notices', [__CLASS__, 'lockdown_notice']);
            add_action('network_admin_notices', [__CLASS__, 'lockdown_notice']);
        }
    }

    public static function activate() {
        if (!wp_next_scheduled(self::CRON)) wp_schedule_event(time() + 300, 'aguard_hourly', self::CRON);
        $o = self::opts();
        if (empty($o['installed'])) { $o['installed'] = time(); update_option(self::OPT, $o, true); }
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
            $d = ['email' => self::default_mail(), 'notify_cc' => '', 'notify' => 1, 'notify_admin_login' => 1, 'failed_threshold' => 20, 'cloak_check' => 1, 'whitelist' => ['service-worker.js'], 'block_php_uploads' => 0, 'lockdown' => 0, 'login_slug' => '', 'login_mode' => 'off', 'twofa' => 0, 'tool_files' => 0, 'tool_logs' => 0];
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
        if (in_array($type, ['lockdown', 'quarantine', 'attack', 'file', 'theme', 'option'], true)) return true;
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

    public static function on_login_failed($login) {
        $cip = (self::srv('HTTP_CF_CONNECTING_IP') ?: self::srv('REMOTE_ADDR'));
        $ipk = 'aguard_safe_fail_' . md5($cip);
        $n = (int) get_transient($ipk) + 1;
        set_transient($ipk, $n, 15 * MINUTE_IN_SECONDS);
        $day = 'aguard_safe_fail_day_' . wp_date('Ymd');
        $t = (int) get_transient($day) + 1; set_transient($day, $t, DAY_IN_SECONDS);
        $h = get_option(self::OPT . '_fail_hist', []); if (!is_array($h)) $h = []; $k = wp_date('Y-m-d'); $h[$k] = ($h[$k] ?? 0) + 1; if (count($h) > 14) $h = array_slice($h, -14, null, true); update_option(self::OPT . '_fail_hist', $h, false);
        $th = (int) self::opts()['failed_threshold'];
        if ($n === $th || ($n > $th && $n % 100 === 0)) {
            self::event('attack', __('Password guessing:', 'aguard-safe') . ' ' . $n . ' ' . __('failed attempts in 15 min from', 'aguard-safe') . ' ' . self::ip(), ['last_login_tried' => $login, 'today_total' => $t], true, 'bruteforce_' . $cip);
        }
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

    /** The scan itself. $base is an already validated absolute folder; paths in the result are shown relative to $root. */
    public static function scan_dir($base, $root, $dir, $limit = 400, $limit_seconds = 150) {
        if (function_exists('set_time_limit')) @set_time_limit(300); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a full file scan can take longer than the default limit.
        $sig = [
            'eval(' => '~\beval\s*\(~', 'base64_decode(' => '~\bbase64_decode\s*\(~', 'gzinflate/gzuncompress' => '~\bgz(inflate|uncompress|decode)\s*\(~', 'str_rot13' => '~\bstr_rot13\s*\(~', 'hex2bin' => '~\bhex2bin\s*\(~',
            'wp_set_auth_cookie(' => '~\bwp_set_auth_cookie\s*\(~', 'wp_signon(' => '~\bwp_signon\s*\(~', 'wp_set_current_user(' => '~\bwp_set_current_user\s*\(~', 'passwordless/one-time login' => '~one[_-]?time[_-]?login|auto[_-]?login|login[_-]?as[_-]?admin|passwordless~i', 'get_users(role=administrator)' => '~get_users\s*\([^;]{0,80}administrator~',
            'create_function' => '~\bcreate_function\s*\(~', 'assert(' => '~\bassert\s*\(~', 'preg_replace /e' => '~preg_replace\s*\(\s*[\'"][^\'"]*/[a-z]*e[a-z]*[\'"]~i', 'system/exec/shell' => '~\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(~',
            'variable function from request' => '~\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(~', 'dynamic call $x($y)' => '~\$[a-zA-Z_]\w*\s*\(\s*\$[a-zA-Z_]\w*\s*\(~', 'long hex string' => '~[\'"][0-9a-f]{120,}[\'"]~', 'chr() chain' => '~(chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}~', 'googlebot check' => '~googlebot~i', 'curl POST to http' => '~CURLOPT_URL~',
        ];
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
        $st['snippets'] = [__('Code Snippets code snippets', 'aguard-safe'), 'valymas'];
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
            case 'recent': return ['info', __('modified files:', 'aguard-safe') . ' ' . count($v) . ' ' . __('(the “Files” tab)', 'aguard-safe')];
            case 'cloaking': if (!empty($v['human']['error']) || !empty($v['googlebot']['error'])) return ['warn', __('could not compare:', 'aguard-safe') . ' ' . ($v['human']['error'] ?? $v['googlebot']['error'])]; return !empty($v['cloaked']) ? ['risk', __('the crawler is shown different content!', 'aguard-safe')] : ['ok', __('content matches', 'aguard-safe')];
            case 'snippets': if (empty($v['table'])) return ['info', __('the Code Snippets plugin is not installed', 'aguard-safe')]; return $v['changed'] ? ['warn', __('snippets changed:', 'aguard-safe') . ' ' . count($v['changed'])] : ['ok', (int) $v['count'] . ' ' . __('snippets, no changes', 'aguard-safe')];
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
            wp_send_json_success(['step' => 'finish', 'state' => $d['grade'], 'text' => __('Score', 'aguard-safe') . ' ' . (int) $d['score'] . ' / 100 · ' . ($n ? $n . ' ' . _n('note', 'notes', $n, 'aguard-safe') : __('no issues found', 'aguard-safe')), 'ms' => (int) round((microtime(true) - $t0) * 1000)]);
        }
        $fns = ['sentinels' => function () { return self::check_sentinels(); }, 'admins' => function () { return self::check_admins(); }, 'uploads' => function () { return self::scan_uploads(40, false); }, 'core' => function () { return self::check_core(); }, 'recent' => function () { return self::recent_files(48, 100, 30); }, 'cloaking' => function () { return self::check_cloaking(); }, 'snippets' => function () { return self::check_snippets(); }, 'remote_admin' => function () { return self::check_remote_admin(); }, 'uploads_guard' => function () { return self::uploads_guard_check(); }];
        if (!isset($fns[$step])) wp_send_json_error(['msg' => __('unknown step', 'aguard-safe')]);
        $r = self::step($r, $step, $fns[$step]); set_transient($key, $r, HOUR_IN_SECONDS);
        [$state, $text] = self::step_text($step, $r[$step]);
        wp_send_json_success(['step' => $step, 'state' => $state, 'text' => $text, 'ms' => (int) round((microtime(true) - $t0) * 1000)]);
    }

    public static function cron_scan($full = null) {
        global $wp_version;
        $bl = get_option(self::OPT_BASELINE, []);
        if (!empty($bl['files']) && (string) ($bl['wp'] ?? '') !== (string) $wp_version) { self::on_core_updated((string) $wp_version); } // atnaujinimas įvyko be mūsų kabliuko – nekelti aliarmo dėl branduolio failų
        $r = self::run_scan($full === null ? ((int) wp_date('G')) % 6 === 0 : (bool) $full); // pilna patikra (branduolys, nauji failai, cloaking) kas 6 val.; kitomis valandomis – lengva; rankinis mygtukas – visada pilna
        self::process_scan($r);
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
        if (is_array($r['snippets'] ?? null) && !empty($r['snippets']['table']) && $r['snippets']['changed']) { $alerts[__('Code Snippets snippets changed', 'aguard-safe')] = $r['snippets']['changed']; }
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

    /** Code Snippets (and similar) table: alert on any new/changed/activated snippet since the last run. */
    public static function check_snippets() {
        global $wpdb;
        $table = $wpdb->prefix . 'snippets';
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) return ['table' => null, 'changed' => []]; // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one-off maintenance query, nothing to cache.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT id, name, active, scope, modified, MD5(code) AS h, LENGTH(code) AS len FROM %i', $table), ARRAY_A) ?: []; // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one-off maintenance query, nothing to cache.
        $now = []; foreach ($rows as $r) $now[$r['id']] = $r;
        $prev = get_option(self::OPT . '_snippets', null);
        $changed = [];
        if (is_array($prev)) {
            foreach ($now as $id => $r) {
                if (!isset($prev[$id])) $changed[] = __('NEW', 'aguard-safe') . " #$id {$r['name']} (active={$r['active']}, {$r['len']} B)";
                elseif ($prev[$id]['h'] !== $r['h']) $changed[] = __('CHANGED', 'aguard-safe') . " #$id {$r['name']} ({$prev[$id]['len']}→{$r['len']} B, active={$r['active']})";
                elseif ($prev[$id]['active'] !== $r['active']) $changed[] = __('STATUS', 'aguard-safe') . " #$id {$r['name']}: active {$prev[$id]['active']}→{$r['active']}";
            }
            foreach ($prev as $id => $r) { if (!isset($now[$id])) $changed[] = __('DELETED', 'aguard-safe') . " #$id {$r['name']}"; }
        }
        update_option(self::OPT . '_snippets', $now, false);
        return ['table' => $table, 'count' => count($now), 'active' => count(array_filter($now, function ($r) { return (string) $r['active'] === '1'; })), 'changed' => $changed, 'first_run' => !is_array($prev)];
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
        wp_add_dashboard_widget('aguard_safe_widget', __('AGuard Safe · site protection', 'aguard-safe'), [__CLASS__, 'dashboard_widget'], null, null, 'normal', 'high');
    }
    public static function dashboard_widget() {
        try {
            $d = self::dashboard();
            $word = ['ok' => __('Protection is working', 'aguard-safe'), 'warn' => __('Needs attention', 'aguard-safe'), 'risk' => __('Action required', 'aguard-safe')];
            $g = $d['grade']; $last = (int) $d['last_scan']; $f = $d['files']; $a = $d['access'];
            $fv = $f['status'] === 'ok' ? __('matches the original', 'aguard-safe') : ($f['status'] === 'risk' ? $f['modified'] . ' ' . _n('modified', 'modified', $f['modified'], 'aguard-safe') : (!empty($f['checked']) ? $f['extra'] . ' ' . _n('unknown', 'unknown', $f['extra'], 'aguard-safe') : __('not checked yet', 'aguard-safe')));
            $rows = [
                ['skenavimas', __('Last check', 'aguard-safe'), $last ? sprintf(/* translators: %s: time span, e.g. 5 mins */ __('%s ago', 'aguard-safe'), human_time_diff($last)) : __('has not run yet', 'aguard-safe'), $last && time() - $last > 3 * HOUR_IN_SECONDS ? 'warn' : 'ok'],
                ['vientisumas', __('WordPress files', 'aguard-safe'), $fv, $f['status']],
                ['pavojaus_signalai', __('Failed logins today', 'aguard-safe'), (string) (int) $a['failed_today'], $a['status']],
                ['prisijungimai', __('Signed-in administrator devices', 'aguard-safe'), (int) $a['sessions'] . ' ' . __('(accounts:', 'aguard-safe') . ' ' . (int) $a['admins'] . ')', 'info'],
                ['ugniasiene', __('PHP block in the upload folders', 'aguard-safe'), $d['protection']['guard'] ? __('enabled', 'aguard-safe') : __('disabled', 'aguard-safe'), $d['protection']['guard'] ? 'ok' : 'warn'],
            ];
            // styles: assets/widget.css (enqueued in admin_assets)
            echo '<div class="agw-h">' . wp_kses(self::icon('mark', 34, 'ag-two'), self::svg_kses()) . '<div><b>' . esc_html($word[$g] ?? '') . '</b><small>' . esc_html($d['issues'] ? count($d['issues']) . ' ' . _n('note', 'notes', count($d['issues']), 'aguard-safe') . (' ' . esc_html__('– see AGuard Safe', 'aguard-safe')) : esc_html__('No issues found', 'aguard-safe')) . ' · ' . esc_html(wp_parse_url(home_url(), PHP_URL_HOST)) . '</small></div><div class="agw-score ag-' . esc_attr($g) . ' ag-bg-' . esc_attr($g) . '">' . (int) $d['score'] . '</div></div>';
            echo '<table>';
            foreach ($rows as $r) echo '<tr><td class="i">' . wp_kses(self::icon($r[0], 18), self::svg_kses()) . '</td><td class="l">' . esc_html($r[1]) . '</td><td class="v ag-' . esc_attr($r[3]) . '">' . esc_html($r[2]) . '</td></tr>';
            echo '</table>';
            $events = get_option(self::OPT_EVENTS, []); $events = is_array($events) ? array_values(array_filter($events, function ($e) { return is_array($e) && !empty($e['t']) && (($e['type'] ?? '') !== 'scan' || !empty($e['mailed']) || stripos((string) ($e['title'] ?? ''), __('no changes found', 'aguard-safe')) === false); })) : [];
            usort($events, function ($a, $b) { return (int) $b['t'] <=> (int) $a['t']; });
            if ($events) {
                echo '<p style="margin:12px 0 2px;font-weight:600;color:var(--ag-navy)">' . esc_html__('Recent events', 'aguard-safe') . '</p><ul class="agw-ev">';
                foreach (array_slice($events, 0, 3) as $e) echo '<li><time>' . esc_html(wp_date('m-d H:i', (int) $e['t'])) . '</time><span>' . esc_html(mb_substr((string) $e['title'], 0, 90)) . (!empty($e['mailed']) ? ' <span class="ag-risk">' . esc_html__('(notification sent)', 'aguard-safe') . '</span>' : '') . '</span></li>';
                echo '</ul>';
            }
            echo '<p style="margin:12px 0 0"><a class="button button-primary" href="' . esc_url(admin_url('admin.php?page=aguard-safe')) . '">' . esc_html__('Open AGuard Safe', 'aguard-safe') . '</a> <a class="button" href="' . esc_url(self::url(['tab' => 'events'])) . '">' . esc_html__('Event log', 'aguard-safe') . '</a></p>';
        } catch (\Throwable $e) { echo '<p>' . esc_html__('AGuard Safe: could not show the status (', 'aguard-safe') . esc_html($e->getMessage()) . ').</p>'; }
    }
    public static function dashboard() {
        $last = self::plain(get_option(self::OPT . '_last_scan', [])); $o = self::opts();
        $issues = []; $score = 100;
        $core = $last['core'] ?? null;
        if (is_array($core)) {
            if ($core['modified'] || $core['missing']) { $issues[] = ['risk', __('Modified or missing WordPress core files:', 'aguard-safe') . ' ' . count($core['modified']) . ' / ' . count($core['missing']) . __('. Check them and restore from the original.', 'aguard-safe'), 30]; $score -= 30; }
            if (!empty($core['extra'])) { $issues[] = ['warn', __('The core folders contain', 'aguard-safe') . ' ' . count($core['extra']) . ' ' . __('unknown files:', 'aguard-safe') . ' ' . implode(', ', array_slice($core['extra'], 0, 3)) . (count($core['extra']) > 3 ? '…' : '') . __('. If you know the file, add it to the allowlist.', 'aguard-safe'), 20]; $score -= 20; }
        }
        if (!empty($last['uploads']['found'])) { $issues[] = ['risk', __('Executable PHP files found in the upload/cache folders:', 'aguard-safe') . ' ' . count($last['uploads']['found']) . '.', 20]; $score -= 20; }
        if (!empty($last['cloaking']['cloaked'])) { $issues[] = ['risk', __('Google\'s crawler is shown different content than visitors (cloaking) – the site is infected.', 'aguard-safe'), 30]; $score -= 30; }
        if (!empty($last['sentinels']['changed']) || !empty($last['sentinels']['added'])) { $issues[] = ['warn', __('System files changed:', 'aguard-safe') . ' ' . implode(', ', array_slice(array_merge($last['sentinels']['changed'], $last['sentinels']['added']), 0, 3)) . '.', 10]; $score -= 10; }
        if (!empty($last['snippets']['changed'])) { $issues[] = ['warn', __('Code snippets changed (Code Snippets):', 'aguard-safe') . ' ' . implode('; ', array_slice($last['snippets']['changed'], 0, 3)) . '.', 10]; $score -= 10; }
        $remote = self::check_remote_admin()['found']; // live – reacts immediately when a plugin is removed
        if ($remote) { $issues[] = ['warn', __('Tools are active that allow managing the site without a password or changing files in the browser:', 'aguard-safe') . ' ' . implode('; ', $remote) . __('. If you do not use them, turn them off.', 'aguard-safe'), 10]; $score -= 10; }
        $guard = self::uploads_guard_check();
        if (empty($o['block_php_uploads'])) { $issues[] = ['info', __('PHP execution in the uploads folder is not blocked. Turn it on in Settings – it closes the most common malware route.', 'aguard-safe'), 10]; $score -= 10; }
        elseif ($guard['missing_real']) { $issues[] = ['warn', __('The PHP block rule is gone from:', 'aguard-safe') . ' ' . implode(', ', $guard['missing_real']) . ' ' . __('(it will be restored automatically).', 'aguard-safe'), 10]; $score -= 10; }
        $last_t = (int) ($last['t'] ?? 0);
        if (!$last_t || time() - $last_t > 3 * HOUR_IN_SECONDS) { $issues[] = ['warn', ($last_t ? sprintf(/* translators: %s: time span */ __('The automatic check has not run for %s', 'aguard-safe'), human_time_diff($last_t)) : __('The automatic check has never run', 'aguard-safe')) . __('. Press “Check now” or check WP-Cron.', 'aguard-safe'), 15]; $score -= 15; }
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
    public static function render_home($d) {
        $word = ['ok' => __('Protection is working', 'aguard-safe'), 'warn' => __('Needs attention', 'aguard-safe'), 'risk' => __('Action required', 'aguard-safe')];
        $g = $d['grade']; $last = (int) $d['last_scan']; $f = $d['files']; $a = $d['access']; $p = $d['protection']; $n = count($d['issues']);
        echo '<div class="ag-home">';
        // status headline
        $sub = ($last ? __('Last check', 'aguard-safe') . ' ' . wp_date('Y-m-d H:i', $last) . ' (' . sprintf(/* translators: %s: time span */ __('%s ago', 'aguard-safe'), human_time_diff($last)) . ')' : __('No automatic check has run yet', 'aguard-safe')) . ($d['next_scan'] ? ', ' . sprintf(/* translators: %s: time span */ __('next in %s', 'aguard-safe'), human_time_diff($d['next_scan'])) : '') . '. ' . ($n ? $n . ' ' . _n('note', 'notes', $n, 'aguard-safe') . (' ' . __('below.', 'aguard-safe')) : __('No issues found.', 'aguard-safe'));
        echo '<div class="ag-card ag-status"><div class="ag-badge ag-bg-' . esc_attr($g) . '"><b class="ag-' . esc_attr($g) . '">' . (int) $d['score'] . '</b></div><div><h2>' . esc_html($word[$g] ?? '') . '</h2><p>' . esc_html($sub) . '</p></div>';
        echo '<div class="ag-act"><button type="button" class="button button-primary" id="ag-scan-btn">' . esc_html__('Check now', 'aguard-safe') . '</button></div></div>';
        // scan dialog: what will be checked, progress per step, result
        $ls = self::plain(get_option(self::OPT . '_last_scan', [])); $fullt = (int) ($ls['full_t'] ?? 0);
        echo '<div class="ag-modal" id="ag-scan" hidden><div class="ag-dialog" role="dialog" aria-labelledby="ag-scan-h"><h3 id="ag-scan-h">' . esc_html__('Full check', 'aguard-safe') . '</h3>';
        echo '<p>' . esc_html__('The check goes through', 'aguard-safe') . ' ' . (!empty($f['checked']) ? esc_html(number_format_i18n((int) $f['checked'])) . ' ' . esc_html__('WordPress files,', 'aguard-safe') . ' ' : '') . esc_html__('the upload folders, settings and accounts. It takes from a dozen seconds to a few minutes and the server works harder meanwhile, so it only starts when you press “Start”. A light check runs automatically every hour, a full one every 6 hours.', 'aguard-safe') . ($fullt ? ' ' . esc_html__('Last full check:', 'aguard-safe') . ' ' . esc_html(wp_date('m-d H:i', $fullt)) . '.' : '') . '</p><ul class="ag-steps">';
        foreach (self::scan_steps() as $k => $st) echo '<li data-step="' . esc_attr($k) . '">' . wp_kses(self::icon($st[1], 18), self::svg_kses()) . '<span class="ag-sn">' . esc_html($st[0]) . '</span><span class="ag-sr">' . esc_html__('waiting', 'aguard-safe') . '</span></li>';
        echo '</ul><div class="ag-acts"><button type="button" class="button button-primary" id="ag-scan-go">' . esc_html__('Start the check', 'aguard-safe') . '</button><button type="button" class="button" id="ag-scan-close">' . esc_html__('Close', 'aguard-safe') . '</button><span class="ag-res" id="ag-scan-res"></span></div></div></div>';
        // script: assets/admin.js (enqueued in admin_assets)
        // KPI strip
        $fv = !empty($f['checked']) ? ($f['modified'] ? $f['modified'] . ' ' . _n('modified', 'modified', $f['modified'], 'aguard-safe') : ($f['extra'] ? $f['extra'] . ' ' . _n('unknown', 'unknown', $f['extra'], 'aguard-safe') : __('Matches the original', 'aguard-safe'))) : __('Not checked yet', 'aguard-safe');
        $kpi = [
            ['vientisumas', __('WordPress files', 'aguard-safe'), $fv, !empty($f['checked']) ? __('files checked:', 'aguard-safe') . ' ' . number_format_i18n((int) $f['checked']) : __('waiting for a full check', 'aguard-safe'), $f['status'], self::url(['tab' => 'files'])],
            ['pavojaus_signalai', __('Failed logins', 'aguard-safe'), (string) (int) $a['failed_today'], $a['failed_today'] ? __('today · alert from', 'aguard-safe') . ' ' . (int) self::opts()['failed_threshold'] : __('none today', 'aguard-safe'), $a['status'], self::url(['tab' => 'events'])],
            ['prisijungimai', __('Signed-in devices', 'aguard-safe'), (string) (int) $a['sessions'], __('administrator accounts:', 'aguard-safe') . ' ' . (int) $a['admins'], 'info', self::url(['tab' => 'sessions'])],
            ['valymas', __('Quarantine', 'aguard-safe'), (string) (int) $d['quarantine'], $d['quarantine'] ? _n('isolated file', 'isolated files', $d['quarantine'], 'aguard-safe') : __('no isolated files', 'aguard-safe'), $d['quarantine'] ? 'warn' : 'info', self::url(['tab' => 'quarantine'])],
        ];
        echo '<div class="ag-grid">';
        foreach ($kpi as $k) echo '<a class="ag-card ag-kpi" href="' . esc_url($k[5]) . '"><div class="ag-l">' . wp_kses(self::icon($k[0], 20), self::svg_kses()) . esc_html($k[1]) . '</div><div class="ag-v' . esc_attr($k[4] === 'info' ? '' : ' ag-' . $k[4]) . '">' . esc_html($k[2]) . '</div><div class="ag-s">' . esc_html($k[3]) . '</div></a>';
        echo '</div>';
        // modules
        $login = []; if (self::twofa_enabled()) $login[] = __('e-mail confirmation', 'aguard-safe'); if (self::login_mode() !== 'off') $login[] = __('custom login address', 'aguard-safe'); if ($p['lockdown']) $login[] = 'LOCKDOWN';
        $mods = [
            ['vientisumas', __('File integrity', 'aguard-safe'), __('The WordPress core is compared with the official checksums every 6 hours; between checks, new and changed files are tracked.', 'aguard-safe'), $f['status'], $fv],
            ['prisijungimai', __('Login protection', 'aguard-safe'), __('Administrator logins, failed attempts, e-mail confirmation, the login address of the site.', 'aguard-safe'), $login ? 'ok' : 'warn', $login ? __('Enabled:', 'aguard-safe') . ' ' . implode(', ', $login) : __('Standard wp-login without extra protection', 'aguard-safe')],
            ['ugniasiene', __('Upload and code protection', 'aguard-safe'), __('PHP block in the upload folders, remote management tools, comparison of the content with what Google sees.', 'aguard-safe'), $p['status'], ($p['guard'] ? __('PHP block enabled', 'aguard-safe') : __('PHP block disabled', 'aguard-safe')) . ($p['remote'] ? ' · ' . (int) $p['remote'] . ' ' . _n('risky tool', 'risky tools', $p['remote'], 'aguard-safe') : '') . ($p['cloak_clean'] ? '' : ' ' . __('· cloaking!', 'aguard-safe'))],
        ];
        echo '<div class="ag-grid3">';
        foreach ($mods as $m) echo '<div class="ag-card ag-mod">' . wp_kses(self::icon($m[0], 26), self::svg_kses()) . '<div><b>' . esc_html($m[1]) . '</b><span>' . esc_html($m[2]) . '</span><div class="ag-st ag-' . esc_attr($m[3]) . '">' . esc_html($m[4]) . '</div></div></div>';
        echo '</div>';
        // 7-day chart
        $max = 0; foreach ($d['days'] as $v) $max = max($max, $v['fails'], $v['events']); $max = max(1, $max);
        $step = $max <= 5 ? 1 : ($max <= 20 ? 5 : ($max <= 100 ? 20 : ($max <= 500 ? 100 : 500))); $top = (int) (ceil($max / $step) * $step);
        $W = 720; $H = 170; $L = 36; $Bt = 14; $Bb = 34; $plotH = $H - $Bt - $Bb; $colW = ($W - $L - 10) / 7;
        $cf = '#8A2D2D'; $ce = '#0A8E89';
        echo '<div class="ag-card" style="margin-bottom:14px"><div class="ag-card-h"><b>' . esc_html__('Last 7 days', 'aguard-safe') . '</b><div class="ag-legend"><i style="background:' . esc_attr($cf) . '"></i>' . esc_html__('failed logins', 'aguard-safe') . '<i style="background:' . esc_attr($ce) . '"></i>' . esc_html__('recorded events', 'aguard-safe') . '</div></div>';
        echo '<svg width="100%" viewBox="0 0 ' . esc_attr($W) . ' ' . esc_attr($H) . '" style="display:block;max-height:220px;font-family:inherit">';
        for ($g2 = 0; $g2 <= 4; $g2++) { $y = $Bt + $plotH - $plotH * $g2 / 4; $val = (int) esc_attr(round($top * $g2 / 4)); echo '<line x1="' . esc_attr($L) . '" y1="' . esc_attr($y) . '" x2="' . (int) ($W - 10) . '" y2="' . esc_attr($y) . '" stroke="' . esc_attr($g2 ? '#E8EDF2' : '#D6DDE5') . '"/><text x="' . (int) ($L - 6) . '" y="' . (int) ($y + 4) . '" text-anchor="end" font-size="10" fill="#64748B">' . esc_html($val) . '</text>'; }
        $i = 0; foreach ($d['days'] as $day => $v) {
            $x0 = $L + $i * $colW; $bw = min(26, ($colW - 18) / 2); $gap = 4; $xs = $x0 + ($colW - (2 * $bw + $gap)) / 2;
            foreach ([['fails', $cf, __('failed logins', 'aguard-safe')], ['events', $ce, __('events', 'aguard-safe')]] as $j => $ser) {
                $val = (int) $v[$ser[0]]; $h = $val ? max(2, $plotH * $val / $top) : 0; $x = $xs + $j * ($bw + $gap); $y = $Bt + $plotH - $h;
                if ($val) echo '<rect x="' . esc_attr(round($x, 1)) . '" y="' . esc_attr(round($y, 1)) . '" width="' . esc_attr(round($bw, 1)) . '" height="' . esc_attr(round($h, 1)) . '" rx="2" fill="' . esc_attr($ser[1]) . '" opacity=".85"><title>' . esc_attr($day . ': ' . $ser[2] . ' ' . $val) . '</title></rect><text x="' . esc_attr(round($x + $bw / 2, 1)) . '" y="' . esc_attr(round($y - 4, 1)) . '" text-anchor="middle" font-size="10" fill="#475569">' . esc_html($val) . '</text>';
            }
            $ts = strtotime($day . ' 12:00:00'); echo '<text x="' . esc_attr(round($x0 + $colW / 2, 1)) . '" y="' . (int) ($H - 18) . '" text-anchor="middle" font-size="11" font-weight="600" fill="#101827">' . esc_html(wp_date('D', $ts)) . '</text><text x="' . esc_attr(round($x0 + $colW / 2, 1)) . '" y="' . (int) ($H - 5) . '" text-anchor="middle" font-size="10" fill="#64748B">' . esc_html(gmdate('m-d', $ts)) . '</text>';
            $i++;
        }
        echo '</svg></div>';
        // what it means
        echo '<div class="ag-card"><div class="ag-card-h"><b>' . ($n ? esc_html__('Why not 100 out of 100', 'aguard-safe') : esc_html__('What is checked', 'aguard-safe')) . '</b></div>';
        if (!$n) echo '<p style="margin:4px 0;color:var(--ag-text2)">' . esc_html__('Files match the originals, no foreign code found, Google sees the same content as visitors, PHP does not run in the upload folders. Next automatic check', 'aguard-safe') . ' ' . ($d['next_scan'] ? esc_html(sprintf(/* translators: %s: time span */ __('in %s', 'aguard-safe'), human_time_diff($d['next_scan']))) : esc_html__('not scheduled', 'aguard-safe')) . '.</p>';
        else { echo '<ul class="ag-issues">'; foreach ($d['issues'] as $it) echo '<li><span class="ag-pt ag-' . esc_attr($it[0]) . '">−' . (int) ($it[2] ?? 0) . '</span><span>' . esc_html($it[1]) . '</span></li>'; echo '</ul>'; }
        echo '</div>';
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
    private static function twofa_send($user, $code) {
        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $body = __('Your login confirmation code:', 'aguard-safe') . ' ' . $code . "\n\n" . __('The code is valid for 10 minutes and for one login only.', 'aguard-safe') . "\n\n" . __('Site:', 'aguard-safe') . ' ' . home_url() . "\n" . __('Username:', 'aguard-safe') . ' ' . $user->user_login . "\n" . __('From: IP', 'aguard-safe') . ' ' . self::twofa_client_ip() . "\n\n" . __('If this was not you, do nothing, do not tell the code to anyone and inform the administrator: somebody knows your password.', 'aguard-safe') . "\n";
        return (bool) wp_mail($user->user_email, '[' . $site . __('] Login code:', 'aguard-safe') . ' ' . $code, $body, ['Content-Type: text/plain; charset=UTF-8']);
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
        $ok = wp_mail($to, '[AGuard Safe] ' . wp_parse_url(home_url(), PHP_URL_HOST) . __(': settings unlock code', 'aguard-safe'), $body, ['Content-Type: text/plain; charset=UTF-8']);
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
    /** Meniu ikona: AG ženklas, A balta, G akcentinė. Be fill="" ir be „;“ – WordPress svg-painter tada spalvų neperrašo. */
    public static function menu_icon() {
        return 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="-30 0 885 984">' . str_replace(['class="ag-a"', 'class="ag-g"'], ['fill="#fff"', 'fill="#0A8E89"'], self::icon_src('mark')) . '</svg>');
    }
    /** Bendras administravimo CSS (aguard.lt paletė: rašalas #0D1B2A, akcentas #0A8E89, būsenos žalia/gintaro/raudona be ryškių „hakerio“ atspalvių). */
    public static function admin_assets($hook) {
        $base = plugin_dir_url(__FILE__) . 'assets/';
        if ($hook === 'index.php' && current_user_can(self::cap())) wp_enqueue_style('aguard-safe-widget', $base . 'widget.css', [], self::VERSION);
        if ($hook !== 'toplevel_page_aguard-safe') return;
        wp_enqueue_style('aguard-safe-admin', $base . 'admin.css', [], self::VERSION);
        wp_enqueue_script('aguard-safe-admin', $base . 'admin.js', [], self::VERSION, true);
        wp_localize_script('aguard-safe-admin', 'aguardSafe', ['scanNonce' => wp_create_nonce('aguard_safe_scan'), 'checking' => __('checking…', 'aguard-safe'), 'refresh' => __('Refresh the overview', 'aguard-safe'), 'failed' => __('The check was interrupted, you can try again.', 'aguard-safe'), 'waiting' => __('waiting', 'aguard-safe'), 'serverError' => __('server error', 'aguard-safe'), 'stepFailed' => __('failed:', 'aguard-safe'), 'seconds' => __('s', 'aguard-safe'),
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
                else { $data = get_option(self::OPT . '_last_scan', null); if (is_array($data) && isset($data['t'])) $data = ['_note' => __('Result of the last automatic check (', 'aguard-safe') . wp_date('Y-m-d H:i', $data['t']) . __('). The buttons above run a check again – it takes up to a minute.', 'aguard-safe')] + $data; }
                break;
            case 'events':
                $title = __('Events', 'aguard-safe'); $data = get_option(self::OPT_EVENTS, []);
                break;
            case 'sessions':
                $title = __('Administrator sessions', 'aguard-safe'); $data = self::admin_sessions();
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
        if (!in_array($tab, ['home', 'status', 'events', 'scan', 'files', 'logs', 'sessions', 'quarantine', 'settings', 'response'], true)) $tab = 'status';
        if (!self::tool_on($tab)) { list($title, $data) = ['', new WP_Error('off', __('This tool is turned off. Turn it on in the Settings tab.', 'aguard-safe'))]; } else { list($title, $data) = self::collect($tab); }
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
            $o['failed_threshold'] = max(5, min(100000, absint(wp_unslash($_POST['failed_threshold'] ?? 20))));
            $o['whitelist'] = array_values(array_filter(array_map('trim', explode("\n", sanitize_textarea_field(wp_unslash($_POST['whitelist'] ?? ''))))));
            $want = empty($_POST['block_php_uploads']) ? 0 : 1;
            if ($want !== (int) ($o['block_php_uploads'] ?? 0)) { $res = self::uploads_guard_apply((bool) $want); $o['block_php_uploads'] = $want; echo '<div class="notice notice-info"><p>' . esc_html__('PHP block in uploads:', 'aguard-safe') . ' ' . esc_html(wp_json_encode($res, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</p></div>'; }
            update_option(self::OPT, $o, true); self::$opts = null;
            self::event('settings', __('Settings changed', 'aguard-safe'), ['email' => $o['email'], 'notify' => $o['notify'], 'whitelist' => $o['whitelist'], 'block_php_uploads' => $o['block_php_uploads']], true, 'settings_' . time());
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
        if (isset($_POST['aguard_quarantine']) && check_admin_referer('aguard_safe_q') && !self::is_unlocked()) { echo '<div class="notice notice-error"><p>' . esc_html__('Quarantine is locked: unlock Settings first with the code from the e-mail (the Settings tab).', 'aguard-safe') . '</p></div>'; unset($_POST['aguard_quarantine']); }
        if (isset($_POST['aguard_quarantine']) && check_admin_referer('aguard_safe_q')) {
            $r = self::quarantine_file(sanitize_text_field(wp_unslash($_POST['aguard_quarantine'])));
            echo '<div class="notice notice-' . (is_wp_error($r) ? 'error' : 'success') . '"><p>' . esc_html(is_wp_error($r) ? $r->get_error_message() : esc_html__('Moved to quarantine:', 'aguard-safe') . ' ' . $r['rel'] . ' → ' . $r['dest']) . '</p></div>';
            if (!is_wp_error($r)) $tab = 'quarantine';
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

        if (!in_array($tab, ['home', 'status', 'events', 'scan', 'files', 'logs', 'sessions', 'quarantine', 'settings', 'response'], true)) $tab = 'status';
        if (!self::tool_on($tab)) { $title = $tab === 'files' ? __('Files', 'aguard-safe') : __('Logs', 'aguard-safe'); $data = new WP_Error('off', __('This tool is turned off. Turn it on in the Settings tab.', 'aguard-safe')); }
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
    public static function rows_table($rows, $cols = [], $limit = 500) {
        $rows = array_values(array_filter((array) $rows, 'is_array')); if (!$rows) return '<span class="ag-muted">' . __('none', 'aguard-safe') . '</span>';
        if (!$cols) { foreach (array_slice($rows, 0, 20) as $r) foreach ($r as $k => $v) if (!isset($cols[$k])) $cols[$k] = self::key_h($k); }
        $h = '<table class="widefat striped ag-tbl"><thead><tr>'; foreach ($cols as $l) $h .= '<th>' . esc_html($l) . '</th>'; $h .= '</tr></thead><tbody>';
        foreach (array_slice($rows, 0, $limit) as $r) {
            $h .= '<tr>';
            foreach ($cols as $k => $l) { $v = $r[$k] ?? null; $cls = is_string($v) ? ($v === 'ok' ? ' class="ag-ok"' : (strtoupper($v) === 'MISMATCH' ? ' class="ag-risk"' : '')) : ''; $h .= '<td' . $cls . '>' . (is_array($v) ? self::kv($v, 1, (string) $k) : esc_html(self::scalar($v, (string) $k))) . '</td>'; }
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
        if (!is_array($data)) return '<p class="ag-note">' . __('No result yet – press one of the buttons above.', 'aguard-safe') . '</p>';
        $sum = function ($k, $v) { [$st, $tx] = self::step_text($k, $v); return '<p class="ag-sum ag-' . $st . '">' . esc_html($tx) . '</p>'; };
        $out = '';
        switch ($what) {
            case '': case 'all':
                if (!empty($data['_note'])) $out .= '<p class="ag-note">' . esc_html($data['_note']) . '</p>';
                $steps = self::scan_steps() + ['admins' => [__('List of administrator accounts', 'aguard-safe'), 'prisijungimai'], 'cloaking' => [__('Content for Google\'s crawler and for a visitor', 'aguard-safe'), 'srautas'], 'uploads_guard' => [__('PHP block rules', 'aguard-safe'), 'ugniasiene']];
                $out .= '<div class="ag-card ag-sec"><table class="widefat striped ag-tbl"><thead><tr><th style="width:40%">' . __('What was checked', 'aguard-safe') . '</th><th>' . __('Result', 'aguard-safe') . '</th><th style="width:120px">' . __('Details', 'aguard-safe') . '</th></tr></thead><tbody>';
                foreach ($steps as $k => $st) {
                    if (!array_key_exists($k, $data)) continue;
                    [$state, $tx] = self::step_text($k, $data[$k]);
                    $out .= '<tr><td>' . self::icon($st[1], 18) . ' ' . esc_html($st[0]) . '</td><td class="ag-' . $state . '">' . esc_html($tx) . '</td><td>' . (is_array($data[$k]) && $data[$k] ? '<details><summary>' . esc_html__('show', 'aguard-safe') . '</summary>' . self::kv($data[$k], 1, $k) . '</details>' : '<span class="ag-muted">—</span>') . '</td></tr>';
                }
                $out .= '</tbody></table>' . (!empty($data['t']) ? '<p class="ag-note" style="margin:10px 0 0">' . __('Check time:', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i:s', (int) $data['t'])) . (!empty($data['full_t']) ? ' ' . __('· last full check:', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) $data['full_t'])) : '') . '</p>' : '') . '</div>';
                break;
            case 'core': case 'uploads': case 'sentinels': case 'cloaking': case 'snippets':
                $out .= $sum($what, $data) . '<div class="ag-card ag-sec">' . self::kv($data) . '</div>'; break;
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
                $out .= '<p class="ag-sum ag-' . ($f ? 'warn' : 'ok') . '">' . __('Files checked:', 'aguard-safe') . ' ' . (int) ($data['files_scanned'] ?? 0) . ' (' . esc_html((string) ($data['dir'] ?? '')) . __(') · findings:', 'aguard-safe') . ' ' . count($f) . '</p><p class="ag-note">' . __('Findings are not a verdict but signs (encoded code, eval, remote requests). The higher the score, the more worthwhile it is to look at the file.', 'aguard-safe') . '</p><div class="ag-card ag-sec">' . self::rows_table($f, ['file' => __('File', 'aguard-safe'), 'score' => __('Score', 'aguard-safe'), 'hits' => __('Signs', 'aguard-safe'), 'size' => __('Size, B', 'aguard-safe'), 'mtime' => __('Changed', 'aguard-safe')]) . '</div>'; break;
            default:
                $out .= '<div class="ag-card ag-sec">' . self::kv($data) . '</div>';
        }
        return $out;
    }

    private static function render($tab, $title, $data) {
        $main = ['home' => __('Overview', 'aguard-safe'), 'events' => __('Events', 'aguard-safe'), 'quarantine' => __('Quarantine', 'aguard-safe'), 'settings' => __('Settings', 'aguard-safe')];
        $adv = ['status' => __('Status', 'aguard-safe'), 'scan' => __('Checks', 'aguard-safe'), 'files' => __('Files', 'aguard-safe'), 'logs' => __('Logs', 'aguard-safe'), 'sessions' => __('Logins', 'aguard-safe'), 'response' => __('Response', 'aguard-safe')];
        $ico = ['home' => 'apzvalga', 'events' => 'srautas', 'quarantine' => 'valymas', 'settings' => 'nustatymai', 'status' => 'ataskaitos', 'scan' => 'skenavimas', 'files' => 'vientisumas', 'logs' => 'ataskaitos', 'sessions' => 'prisijungimai', 'response' => 'pavojaus_signalai'];
        foreach (['files', 'logs'] as $t) { if (!self::tool_on($t)) unset($adv[$t]); }
        $tabs = array_merge($main, $adv);
        echo '<div class="wrap aguard"><h1 class="screen-reader-text">AGuard Safe</h1><div class="ag-head">' . wp_kses(self::icon('mark', 30, 'ag-two'), self::svg_kses()) . '<div class="ag-h1">AGuard Safe</div><span class="ag-meta">' . esc_html(wp_parse_url(home_url(), PHP_URL_HOST)) . ' · v' . esc_html(self::VERSION) . '</span></div><nav class="ag-nav">';
        foreach ($tabs as $k => $l) { if ($k === 'status') echo '<span class="ag-sep"></span>'; echo '<a class="' . ($tab === $k ? 'on' : '') . '" href="' . esc_url(self::url(['tab' => $k])) . '">' . wp_kses(self::icon($ico[$k] ?? 'apzvalga', 18), self::svg_kses()) . esc_html($l) . '</a>'; }
        echo '</nav>' . ($tab === 'home' ? '' : '<h2 class="ag-title">' . esc_html($title) . '</h2>');
        if (is_wp_error($data)) { echo '<div class="notice notice-error"><p>' . esc_html($data->get_error_message()) . '</p></div></div>'; return; }
        $esc = 'esc_html';
        switch ($tab) {
            case 'status':
                echo '<p>' . esc_html__('Settings have moved to the tab', 'aguard-safe') . ' <a href="' . esc_url(self::url(['tab' => 'settings'])) . '">' . esc_html__('Settings', 'aguard-safe') . '</a>.</p>';
                echo '<h3>' . esc_html__('Administrators (', 'aguard-safe') . (int) $data['admin_count'] . ')</h3><table class="widefat striped"><colgroup><col style="width:60px"><col style="width:140px"><col><col style="width:170px"><col></colgroup><thead><tr><th>ID</th><th>Login</th><th>' . esc_html__('E-mail', 'aguard-safe') . '</th><th>' . esc_html__('Registered', 'aguard-safe') . '</th><th>' . esc_html__('Name', 'aguard-safe') . '</th></tr></thead><tbody>';
                foreach ($data['admins'] as $a) echo '<tr><td>' . (int) $a['id'] . '</td><td>' . esc_html($a['login']) . '</td><td>' . esc_html($a['email']) . '</td><td>' . esc_html($a['registered']) . '</td><td>' . esc_html($a['display']) . '</td></tr>';
                echo '</tbody></table>';
                foreach (['mu_plugins' => __('Must-use plugins (mu-plugins)', 'aguard-safe'), 'dropins' => __('wp-content files (drop-ins)', 'aguard-safe')] as $k => $l) {
                    echo '<h3>' . esc_html($l) . '</h3><table class="widefat striped"><thead><tr><th>' . esc_html__('File', 'aguard-safe') . '</th><th>' . esc_html__('Size', 'aguard-safe') . '</th><th>' . esc_html__('Changed', 'aguard-safe') . '</th><th>' . esc_html__('Permissions', 'aguard-safe') . '</th><th>SHA-256</th></tr></thead><tbody>';
                    foreach ($data[$k] as $r) echo '<tr><td><a href="' . esc_url(self::url(['tab' => 'files', 'file' => $r['rel']])) . '">' . esc_html($r['rel']) . '</a></td><td>' . (int) $r['size'] . '</td><td>' . esc_html(wp_date('Y-m-d H:i:s', $r['mtime'])) . '</td><td>' . esc_html($r['perms']) . '</td><td><code style="font-size:11px">' . esc_html($r['sha256'] ?? '') . '</code></td></tr>';
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
                $o = $data['settings']; $un = $data['unlocked'];
                echo '<div style="background:#fff;padding:14px 18px;border:1px solid #ccd0d4;max-width:760px">';
                if ($un) echo '<p style="color:#1d6f27"><strong>' . esc_html__('Unlocked', 'aguard-safe') . '</strong> ' . esc_html__('15 min. Changes are reported by e-mail to the current address.', 'aguard-safe') . '</p>';
                else echo '<p><strong>' . esc_html__('Locked.', 'aguard-safe') . '</strong> ' . esc_html__('Security settings (notification address, allowlist, protection switches) can be changed only with a code that is sent to the current notification address', 'aguard-safe') . ' <code>' . esc_html(self::mask_email($o['email'])) . '</code>' . esc_html__('. This way an intruder, even with administrator access, cannot redirect the notifications.', 'aguard-safe') . '</p>';
                echo '<form method="post" style="margin-bottom:12px">'; wp_nonce_field('aguard_safe_settings');
                if (!$un) echo '<button class="button" name="aguard_unlock_request" value="1">' . esc_html__('Send the unlock code', 'aguard-safe') . '</button> &nbsp; <input type="text" name="aguard_unlock_code" placeholder="' . esc_attr__('code from the e-mail', 'aguard-safe') . '" style="width:140px" autocomplete="one-time-code"> <button class="button button-primary">' . esc_html__('Unlock', 'aguard-safe') . '</button>';
                else echo '<button class="button" name="aguard_lock" value="1">' . esc_html__('Lock now', 'aguard-safe') . '</button>';
                echo '</form>';
                $dis = $un ? '' : ' disabled';
                echo '<form method="post">'; wp_nonce_field('aguard_safe_settings');
                echo '<p><label>' . esc_html__('Notification e-mail', 'aguard-safe') . ' <input type="email" name="email" value="' . esc_attr($o['email']) . '" class="regular-text"' . esc_attr($dis) . '></label></p>';
                echo '<p><label>' . esc_html__('Client addresses (comma separated): they receive incidents only, no more than 5 e-mails a day; unlock codes are not sent to them', 'aguard-safe') . ' <input type="text" name="notify_cc" value="' . esc_attr($o['notify_cc'] ?? '') . '" class="regular-text"' . esc_attr($dis) . '></label></p>';
                echo '<p><label><input type="checkbox" name="notify" ' . checked($o['notify'], 1, false) . esc_attr($dis) . '> ' . esc_html__('Send notifications', 'aguard-safe') . '</label> &nbsp; <label><input type="checkbox" name="notify_admin_login" ' . checked($o['notify_admin_login'], 1, false) . esc_attr($dis) . '> ' . esc_html__('Report administrator logins', 'aguard-safe') . '</label> &nbsp; <label><input type="checkbox" name="cloak_check" ' . checked($o['cloak_check'], 1, false) . esc_attr($dis) . '> ' . esc_html__('Check the content shown to Googlebot', 'aguard-safe') . '</label></p>';
                echo '<p><label>' . esc_html__('Failed login threshold', 'aguard-safe') . ' <input type="number" name="failed_threshold" value="' . esc_attr($o['failed_threshold']) . '" min="5" style="width:80px"' . esc_attr($dis) . '></label></p>';
                echo '<p><label><input type="checkbox" name="block_php_uploads" ' . checked(!empty($o['block_php_uploads']), true, false) . esc_attr($dis) . '> ' . esc_html__('Block PHP execution in the uploads folder', 'aguard-safe') . '</label></p>';
                echo '<h3 style="margin:18px 0 4px">' . esc_html__('Optional tools', 'aguard-safe') . '</h3><p style="margin:0 0 6px;color:#646970">' . esc_html__('Read-only viewers for investigating an incident. They are off by default; when turned on, each one appears as a tab at the top.', 'aguard-safe') . '</p>';
                echo '<p><label><input type="checkbox" name="tool_files" ' . checked(!empty($o['tool_files']), true, false) . esc_attr($dis) . '> ' . esc_html__('Enable the “Files” tab (file viewer, read-only)', 'aguard-safe') . '</label> &nbsp; <label><input type="checkbox" name="tool_logs" ' . checked(!empty($o['tool_logs']), true, false) . esc_attr($dis) . '> ' . esc_html__('Enable the “Logs” tab (log viewer)', 'aguard-safe') . '</label></p>';
                echo '<p><label>' . esc_html__('Known extra files (allowlist, one per line):', 'aguard-safe') . '<br><textarea name="whitelist" rows="3" class="large-text" style="font-family:monospace"' . esc_attr($dis) . '>' . esc_textarea(implode("\n", (array) ($o['whitelist'] ?? []))) . '</textarea></label></p>';
                echo '<p><button class="button button-primary" name="aguard_save" value="1"' . esc_attr($dis) . '>' . esc_html__('Save', 'aguard-safe') . '</button> <button class="button" name="aguard_test_mail" value="1">' . esc_html__('Test e-mail', 'aguard-safe') . '</button> <button class="button" name="aguard_rebaseline" value="1"' . esc_attr($dis) . '>' . esc_html__('Update the baseline', 'aguard-safe') . '</button> <button class="button" name="aguard_uploads_verify" value="1">' . esc_html__('Test the PHP block', 'aguard-safe') . '</button></p>';
                echo '</form>';
                $li = $data['login']; $fails_today = (int) get_transient('aguard_safe_fail_day_' . wp_date('Ymd'));
                echo '<hr><h3 style="margin:10px 0 6px">' . esc_html__('Login address', 'aguard-safe') . '</h3>';
                echo '<p style="margin:0 0 6px">' . esc_html__('The standard address', 'aguard-safe') . ' <code>/wp-login.php</code> ' . esc_html__('is guessed by bots all the time (failed attempts today:', 'aguard-safe') . ' ' . (int) $fails_today . esc_html__('). When the address is changed,', 'aguard-safe') . ' <strong>' . esc_html__('nothing changes for customers', 'aguard-safe') . '</strong>' . esc_html__(': their login, registration at checkout and password reset happen on the shop pages (', 'aguard-safe') . '<code>/my-account/</code>' . esc_html__(', checkout), which do not use wp-login.php. The new address is needed only by administrators and staff – tell it to them. Every change is reported to the notification e-mail.', 'aguard-safe') . '</p>';
                echo '<p style="margin:0 0 8px">' . esc_html__('Now:', 'aguard-safe') . ' <strong>' . ($li['mode'] === 'off' ? esc_html__('standard address', 'aguard-safe') : ($li['mode'] === 'soft' ? esc_html__('trial mode – both addresses work', 'aguard-safe') : esc_html__('new address only', 'aguard-safe'))) . '</strong>' . ($li['mode'] !== 'off' ? ' · <a href="' . esc_url($li['url']) . '" target="_blank">' . esc_html($li['url']) . '</a>' : '') . ($li['killed'] ? ' · <span style="color:#b32d2e">' . esc_html__('turned off by the emergency switch (', 'aguard-safe') . esc_html($li['killed']) . ')</span>' : '') . '</p>';
                echo '<form method="post">'; wp_nonce_field('aguard_safe_settings');
                $m = $o['login_mode'] ?? 'off';
                echo '<p><label><input type="radio" name="login_mode" value="off" ' . checked($m, 'off', false) . '> ' . esc_html__('Off – only', 'aguard-safe') . ' <code>/wp-login.php</code></label><br>';
                echo '<label><input type="radio" name="login_mode" value="soft" ' . checked($m, 'soft', false) . '> ' . esc_html__('Trial –', 'aguard-safe') . ' <em>' . esc_html__('both', 'aguard-safe') . '</em> ' . esc_html__('addresses work, links on the site already point to the new one (safe to try, nobody gets locked out)', 'aguard-safe') . '</label><br>';
                echo '<label><input type="radio" name="login_mode" value="strict" ' . checked($m, 'strict', false) . '> ' . esc_html__('New address only –', 'aguard-safe') . ' <code>/wp-login.php</code> ' . esc_html__('and', 'aguard-safe') . ' <code>/wp-admin</code> ' . esc_html__('show “404” to visitors who are not signed in (bots no longer see the login form)', 'aguard-safe') . '</label></p>';
                echo '<p><label>' . esc_html__('New address:', 'aguard-safe') . ' <code>' . esc_html(home_url('/')) . '</code><input type="text" name="login_slug" value="' . esc_attr($o['login_slug'] ?? '') . '" placeholder="' . esc_attr__('e.g. team-entrance', 'aguard-safe') . '" pattern="[a-z0-9][a-z0-9-]{1,38}[a-z0-9]" style="width:220px"' . '></label> <span style="color:#666;font-size:12px">' . esc_html__('lowercase letters, digits, hyphen; not “login” or “admin”', 'aguard-safe') . '</span></p>';
                echo '<p><button class="button button-primary" name="aguard_login_save" value="1">' . esc_html__('Save and test', 'aguard-safe') . '</button> <button class="button" name="aguard_login_test" value="1">' . esc_html__('Check now', 'aguard-safe') . '</button></p>';
                echo '<p style="color:#666;font-size:12px;margin:0">' . esc_html__('After saving, the plugin opens the new address, the home page and the account page by itself; if any of them does not answer “200”, the setting is reverted automatically. The new address is sent to the notification e-mail. Emergency switch without signing in: the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_LOGIN_OFF\', true);</code> ' . esc_html__('in wp-config.php or an empty file', 'aguard-safe') . ' <code>AGUARD-LOGIN-OFF</code> ' . esc_html__('in the wp-content folder (it survives plugin updates).', 'aguard-safe') . '</p>';
                echo '</form>';
                $k2 = self::twofa_killed(); $tf = (int) ($o['twofa'] ?? 0);
                echo '<hr><h3 style="margin:10px 0 6px">' . esc_html__('E-mail confirmation (2FA)', 'aguard-safe') . '</h3>';
                echo '<p style="margin:0 0 6px">' . esc_html__('After the correct password, a 6-digit code is sent to the administrator\'s e-mail; signing in is not possible without it. The browser can be remembered for 30 days, so the code is not asked every day. Customers and non-administrators are not affected.', 'aguard-safe') . '</p>';
                echo '<p style="margin:0 0 8px">' . esc_html__('Now:', 'aguard-safe') . ' <strong>' . ($k2 !== '' ? esc_html__('turned off by the emergency switch (', 'aguard-safe') . esc_html($k2) . ')' : ($tf ? esc_html__('enabled', 'aguard-safe') : esc_html__('disabled', 'aguard-safe'))) . '</strong></p>';
                echo '<form method="post">'; wp_nonce_field('aguard_safe_settings');
                echo '<p><label><input type="radio" name="twofa" value="0" ' . checked($tf, 0, false) . '> ' . esc_html__('Disabled', 'aguard-safe') . '</label> &nbsp; <label><input type="radio" name="twofa" value="1" ' . checked($tf, 1, false) . '> ' . esc_html__('Enabled for administrators', 'aguard-safe') . '</label></p>';
                echo '<p><button class="button button-primary" name="aguard_2fa_save" value="1">' . esc_html__('Save', 'aguard-safe') . '</button> <button class="button" name="aguard_2fa_forget" value="1" data-ag-confirm="' . esc_attr(__('Forget all remembered browsers? Next time every administrator will enter a code.', 'aguard-safe')) . '">' . esc_html__('Forget remembered browsers', 'aguard-safe') . '</button></p>';
                echo '<p style="color:#666;font-size:12px;margin:0">' . esc_html__('If the e-mail cannot be sent (mail error), an administrator from a usual IP (used to sign in during the last 30 days) is let in without a code and this is reported; from an unknown IP – not. The confirmation can be turned off only when Settings are unlocked with a code. Emergency switch without signing in: the line', 'aguard-safe') . ' <code>define(\'AGUARD_SAFE_2FA_OFF\', true);</code> ' . esc_html__('in wp-config.php or an empty file', 'aguard-safe') . ' <code>AGUARD-2FA-OFF</code> ' . esc_html__('in the wp-content folder (it survives plugin updates).', 'aguard-safe') . '</p>';
                echo '</form>';
                echo '<hr><form method="post"><p style="margin:0"><label>' . esc_html__('Remove events that contain the text:', 'aguard-safe') . ' <input type="text" name="aguard_prune_kw" style="width:220px"' . esc_attr($dis) . '></label> <button class="button" name="aguard_prune" value="1"' . esc_attr($dis) . '>' . esc_html__('Remove', 'aguard-safe') . '</button> <span style="color:#666;font-size:12px">' . esc_html__('(for example, your own file flagged by mistake; the action is logged and reported by e-mail)', 'aguard-safe') . '</span></p>' . wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '</form></div>';
                break;
            case 'response':
                echo '<div style="background:#fff;padding:14px 18px;border:1px solid #ccd0d4;max-width:760px">';
                echo '<p>' . esc_html__('This tab is for an emergency, when you suspect that someone else controls the site. Normally there is nothing to do here.', 'aguard-safe') . '</p>';
                if (!empty($data['lockdown'])) echo '<p><strong style="color:#b32d2e">' . esc_html__('LOCKDOWN IS ON', 'aguard-safe') . '</strong> ' . esc_html__('since', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i', (int) ($data['lockdown']['t'] ?? 0))) . ' (' . esc_html((string) ($data['lockdown']['by'] ?? '')) . esc_html__('). Installing and changing plugins/themes and registration are disabled.', 'aguard-safe') . '</p><form method="post">' . wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button button-primary" name="aguard_lockdown_off" value="1">' . esc_html__('Turn LOCKDOWN off', 'aguard-safe') . '</button></form>';
                else echo '<p><strong>LOCKDOWN</strong> ' . esc_html__('in one click: signs out all other administrators, sends them password reset links, blocks installing and changing plugins and themes, turns registration off. The site keeps working for visitors. You can turn it off here at any time.', 'aguard-safe') . '</p><form method="post" data-ag-confirm="' . esc_attr(__('Turn LOCKDOWN on? All other administrators will be signed out.', 'aguard-safe')) . '">' . wp_kses(wp_nonce_field('aguard_safe_settings', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button" name="aguard_lockdown_on" value="1" style="border-color:#b32d2e;color:#b32d2e">' . esc_html__('Turn LOCKDOWN on', 'aguard-safe') . '</button></form>';
                echo '<hr><p>' . esc_html__('Quarantine:', 'aguard-safe') . ' ' . (int) $data['quarantine'] . ' ' . esc_html__('files ·', 'aguard-safe') . ' <a href="' . esc_url(self::url(['tab' => 'quarantine'])) . '">' . esc_html__('view', 'aguard-safe') . '</a>' . (self::tool_on('files') ? esc_html__('. A suspicious file can be moved to quarantine from the “Files” tab (after opening the file).', 'aguard-safe') : esc_html__('. A suspicious file can be moved to quarantine from the “Files” tab. The tab is off by default: turn it on in Settings, under “Optional tools”.', 'aguard-safe')) . '</p>';
                echo '<p>' . esc_html__('Remote management / in-browser file editing tools:', 'aguard-safe') . ' ' . ($data['remote_admin']['found'] ? '<strong style="color:#b32d2e">' . esc_html(implode('; ', $data['remote_admin']['found'])) . '</strong>' : esc_html__('none found', 'aguard-safe')) . '</p></div>';
                break;
            case 'events':
                $all = self::req('all') !== ''; $list = (array) $data; $total = count($list); if (!$all) $list = array_slice($list, 0, 100);
                echo '<p style="color:#666">' . esc_html__('Showing', 'aguard-safe') . ' ' . (int) count($list) . ' ' . esc_html__('of', 'aguard-safe') . ' ' . (int) $total . ' ' . esc_html__('events', 'aguard-safe') . (!$all && $total > 100 ? ' · <a href="' . esc_url(self::url(['tab' => 'events', 'all' => '1'])) . ('">' . esc_html__('show all', 'aguard-safe') . '</a>') : '') . esc_html__('. E-mail notifications are marked ✉.', 'aguard-safe') . '</p>';
                echo '<table class="widefat striped"><colgroup><col style="width:135px"><col style="width:90px"><col><col style="width:230px"><col style="width:300px"></colgroup><thead><tr><th>' . esc_html__('Time', 'aguard-safe') . '</th><th>' . esc_html__('Type', 'aguard-safe') . '</th><th>' . esc_html__('Event', 'aguard-safe') . '</th><th>' . esc_html__('Who', 'aguard-safe') . '</th><th>' . esc_html__('Data', 'aguard-safe') . '</th></tr></thead><tbody>';
                foreach ($list as $e) {
                    $who = (string) ($e['who'] ?? ''); $parts = array_map('trim', explode('|', $who)); $user = $parts[0] ?? ''; $ipraw = $parts[1] ?? ''; $path = $parts[2] ?? '';
                    $ip = preg_match('~HTTP_CF_CONNECTING_IP: ([0-9a-f.:]+)~', $ipraw, $m) ? $m[1] : trim(str_replace('IP', '', preg_replace('~\(.*\)~', '', $ipraw)));
                    $t = esc_html($e['type']);
                    echo '<tr><td class="nowrap">' . esc_html(wp_date('Y-m-d', $e['t'])) . '<br><span style="color:#666">' . esc_html(wp_date('H:i:s', $e['t'])) . '</span></td>';
                    echo '<td class="t-' . esc_attr($t) . '">' . esc_html($t . ($e['mailed'] ? ' ✉' : '')) . '</td>';
                    echo '<td>' . esc_html($e['title']) . '</td>';
                    echo '<td class="who" title="' . esc_attr($who) . '"><b>' . esc_html($user) . '</b><br>' . esc_html($ip) . ($path ? '<br><span style="color:#8c8f94">' . esc_html(wp_html_excerpt($path, 40, '…')) . '</span>' : '') . '</td>';
                    echo '<td>' . (!empty($e['data']) ? '<details><summary>' . esc_html__('show', 'aguard-safe') . '</summary>' . wp_kses(self::kv($e['data'], 1) . (is_array($e['data']) && array_filter($e['data'], 'is_array') ? self::json_details($e['data'], 'JSON') : ''), self::html_kses()) . '</details>' : '<span class="ag-muted">—</span>') . '</td></tr>';
                }
                echo '</tbody></table>';
                break;
            case 'scan':
                echo '<p>'; foreach (['all' => __('Full check', 'aguard-safe'), 'sentinels' => __('System files', 'aguard-safe'), 'core' => __('WordPress core', 'aguard-safe'), 'uploads' => __('PHP in uploads/cache', 'aguard-safe'), 'recent' => __('Recently changed (48 h)', 'aguard-safe'), 'cloaking' => __('Googlebot vs visitor', 'aguard-safe'), 'plugins' => __('Plugins vs wordpress.org', 'aguard-safe'), 'suspicious' => __('Suspicious code (wp-content)', 'aguard-safe')] as $k => $l) echo '<a class="button" href="' . esc_url(self::url(['tab' => 'scan', 'what' => $k])) . '">' . esc_html($l) . '</a> ';
                echo '</p><p class="ag-note">' . esc_html__('The buttons run the chosen check right away (core and suspicious code take up to a minute and the server works harder meanwhile). With nothing chosen, the result of the last automatic check is shown.', 'aguard-safe') . '</p>';
                echo wp_kses(self::scan_view(sanitize_key(self::req('what')), $data) . self::json_details($data), self::html_kses());
                break;
            case 'files':
                if (isset($data['data'])) {
                    echo '<p>' . (int) $data['size'] . ' ' . esc_html__('B · modified', 'aguard-safe') . ' ' . esc_html(wp_date('Y-m-d H:i:s', $data['mtime'])) . ' ' . esc_html__('· SHA-256', 'aguard-safe') . ' <code>' . esc_html((string) $data['sha256']) . '</code> · <a href="' . esc_url(self::url(['aguard_download' => $data['rel']])) . '">' . esc_html__('download', 'aguard-safe') . '</a> · <a href="' . esc_url(self::url(['tab' => 'files', 'path' => dirname($data['rel']) === '.' ? '' : dirname($data['rel'])])) . '">' . esc_html__('↑ folder', 'aguard-safe') . '</a></p>';
                    if (self::quarantinable($data['rel']) === true) echo '<form method="post" data-ag-confirm="' . esc_attr(__('Move the file to quarantine? The site will no longer see it.', 'aguard-safe')) . '">' . wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<button class="button" name="aguard_quarantine" value="' . esc_attr($data['rel']) . '" style="border-color:#b32d2e;color:#b32d2e">' . esc_html__('Move to quarantine', 'aguard-safe') . '</button></form>';
                    echo '<pre style="background:#fff;padding:10px;border:1px solid #ccd0d4;white-space:pre-wrap;max-height:70vh;overflow:auto">' . esc_html(wp_check_invalid_utf8((string) $data['data'], true)) . '</pre>';
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
                echo '<p>' . esc_html__('Who is currently signed in to the admin area. Each row is one device or browser where the account is still signed in (WordPress usually remembers a login for 2 days, with “remember me” – 14). If you see an unfamiliar device or IP, press “Sign out everywhere” and change that user\'s password.', 'aguard-safe') . '</p>';
                echo '<p style="color:#646970">' . esc_html__('Accounts with admin permissions:', 'aguard-safe') . ' <b>' . count($data) . '</b> ' . esc_html__('· signed-in devices in total:', 'aguard-safe') . ' <b>' . (int) $total . '</b></p>';
                foreach ($data as $u) {
                    $n = count($u['sessions']);
                    echo '<h3 style="margin:18px 0 6px">' . esc_html($u['display'] ?: $u['login']) . ' <span style="font-weight:400;color:#646970;font-size:13px">(' . esc_html($u['login']) . ' · ' . esc_html($u['role_h']) . ' · ' . esc_html($u['email']) . ')</span></h3>';
                    if (!$n) { echo '<p style="margin:0 0 6px;color:#646970">' . esc_html__('Not signed in anywhere right now.', 'aguard-safe') . '</p>'; continue; }
                    echo '<table class="widefat striped" style="max-width:980px"><colgroup><col style="width:160px"><col style="width:160px"><col style="width:150px"><col><col style="width:110px"></colgroup><thead><tr><th>' . esc_html__('Signed in', 'aguard-safe') . '</th><th>' . esc_html__('Valid until', 'aguard-safe') . '</th><th>' . esc_html__('IP address', 'aguard-safe') . '</th><th>' . esc_html__('Device', 'aguard-safe') . '</th><th></th></tr></thead><tbody>';
                    foreach ($u['sessions'] as $sx) {
                        $ago = $sx['login_t'] ? ' <span style="color:#646970">(' . esc_html(sprintf(/* translators: %s: time span */ __('%s ago', 'aguard-safe'), human_time_diff($sx['login_t']))) . ')</span>' : '';
                        echo '<tr><td>' . esc_html((string) $sx['login']) . wp_kses_post($ago) . '</td><td>' . esc_html((string) $sx['expiration']) . '</td><td><code>' . esc_html((string) $sx['ip']) . '</code></td><td title="' . esc_attr((string) $sx['ua']) . '">' . esc_html($sx['device']) . '</td><td>' . ($sx['current'] ? '<span style="color:#1e8e3e;font-weight:600">' . esc_html__('this device', 'aguard-safe') . '</span>' : '') . '</td></tr>';
                    }
                    echo '</tbody></table>';
                    echo '<form method="post" style="margin:6px 0 0" data-ag-confirm="' . esc_attr(sprintf(/* translators: %s: user login */ __('Sign %s out of all devices?', 'aguard-safe'), $u['login'])) . '">' . wp_kses(wp_nonce_field('aguard_safe_q', '_wpnonce', true, false), ['input' => ['type' => true, 'id' => true, 'name' => true, 'value' => true]]) . '<input type="hidden" name="aguard_logout_user" value="' . (int) $u['id'] . '"><button class="button">' . esc_html__('Sign out everywhere', 'aguard-safe') . '</button></form>';
                }
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
        echo '</div>';
    }
}

AGuard_Safe::init();
