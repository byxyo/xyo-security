<?php

namespace Xyo\WordpressSecurity\Actions;

use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Xyo\WordpressSecurity\Admin\Settings;

/**
 * File integrity monitoring (FIM). Once a day a WP-Cron job walks the whole
 * install — WordPress core, plugins, mu-plugins and the active theme — hashing
 * every executable file (PHP/JS/.htaccess) with SHA-256. The result is compared
 * against the baseline stored from the previous run; any added, modified or
 * removed file is reported three ways: an admin e-mail, a timestamped log file
 * and a dismissible wp-admin notice.
 *
 * Portability: the scan roots come from WordPress constants/APIs (ABSPATH,
 * WP_CONTENT_DIR, WPMU_PLUGIN_DIR, get_theme_root), never hard-coded paths, so
 * it behaves identically on a classic single-folder install and on Bedrock
 * (where core lives in web/wp and content in web/app). Nested roots are
 * de-duplicated, and the uploads directory plus our own data directory are
 * excluded from the hash baseline — uploads churns constantly with media.
 *
 * Uploads is instead covered by a separate, non-hashing check: the tree is
 * listed and any executable code (PHP or JS family) is flagged as a likely
 * web shell / stored-XSS vector. Media files (images, documents…) are never
 * hashed nor listed.
 */
class Integrity
{
    /** Daily WP-Cron hook. */
    const CRON_HOOK = 'xyo_security_integrity_scan';

    /** Option holding the pending alert shown in wp-admin (null when clear). */
    const ALERT_OPTION = 'xyo_security_integrity_alert';

    /** Option holding a signature of the last executable-in-uploads finding. */
    const UPLOADS_OPTION = 'xyo_security_integrity_uploads';

    /** Sub-directory of uploads/ holding the baseline manifest and the log. */
    const DATA_DIR = 'xyo-security';

    /** Query arg used to dismiss the admin notice. */
    const DISMISS_ARG = 'xyo_sec_fim_dismiss';

    /** admin-post action backing the "Scan file integrity" button. */
    const SCAN_ACTION = 'xyo_security_scan_now';

    /** admin-post action backing the "Scan uploads" button. */
    const SCAN_UPLOADS_ACTION = 'xyo_security_scan_uploads';

    /** Short-lived transient carrying the manual-scan result back to the page. */
    const SCAN_RESULT = 'xyo_security_scan_result';

    /** Hard cap on files listed in the e-mail / notice (the log keeps them all). */
    const REPORT_LIMIT = 200;

    /** Extensions treated as executable code and therefore hashed. */
    const WATCHED_EXTENSIONS = ['php', 'phtml', 'php5', 'php7', 'phps', 'inc', 'js', 'mjs', 'cjs'];

    /** Directory basenames pruned everywhere (noise, never shipped code to trust). */
    const SKIP_DIR_NAMES = ['node_modules', '.git', '.svn'];

    /**
     * Wire the feature: ensure the daily job is scheduled and attach the
     * admin-facing pieces. Only called when the toggle is on; the cron handler
     * itself is registered unconditionally by the bootstrap so a lingering event
     * can still self-unschedule after the feature is switched off.
     */
    public static function init(): void
    {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK);
        }

        if (is_admin()) {
            add_action('admin_notices', [self::class, 'renderNotice']);
            add_action('admin_init', [self::class, 'handleDismiss']);
            add_action('admin_post_' . self::SCAN_ACTION, [self::class, 'handleScanNow']);
            add_action('admin_post_' . self::SCAN_UPLOADS_ACTION, [self::class, 'handleScanUploads']);
            add_action('xyo_security_after_settings_form', [self::class, 'renderScanButton']);
        }
    }

    /** Drop the scheduled job (used on deactivation and self-cleanup). */
    public static function unschedule(): void
    {
        $timestamp = wp_next_scheduled(self::CRON_HOOK);
        if ($timestamp) {
            wp_unschedule_event($timestamp, self::CRON_HOOK);
        }
    }

    /**
     * The daily cron job. Delegates to the shared scan; the toggle may have been
     * turned off while an event was still queued, so clean up in that case.
     */
    public static function runScan(): void
    {
        if (!Settings::isEnabled('integrity')) {
            self::unschedule();
            return;
        }

        self::performScan();
    }

    /**
     * The daily cron run: both checks in a single, merged report. The two manual
     * buttons instead run each check on its own (performIntegrityScan /
     * performUploadsScan), since they answer different questions and have
     * different costs.
     *
     * @return array{status:string,summary:string} status is one of
     *         empty|baseline|clean|changed|threat
     */
    private static function performScan(): array
    {
        @set_time_limit(0);

        $integrity = self::computeIntegrity();
        if ($integrity['status'] === 'empty') {
            return ['status' => 'empty', 'summary' => __('Nothing to scan, or the data directory is not writable.', 'xyo-security')];
        }

        $threats = self::uploadsThreats();
        $threatsChanged = self::rememberThreats($threats);
        $emptyDiff = ['added' => [], 'modified' => [], 'removed' => []];

        if ($integrity['status'] === 'baseline') {
            // A web shell may already be sitting in uploads at first run — report
            // it now rather than silently leaving it unflagged.
            if ($threats !== []) {
                return ['status' => 'threat', 'summary' => self::notify($emptyDiff, $integrity['total'], $threats)];
            }

            return ['status' => 'baseline', 'summary' => self::baselineSummary($integrity['total'])];
        }

        $hasDiff = $integrity['status'] === 'changed';

        // Alert on any file-hash change, or on a new/changed executable in uploads.
        // A threat that merely persists unchanged does not re-alert (no daily spam).
        if (!$hasDiff && !($threats !== [] && $threatsChanged)) {
            return ['status' => 'clean', 'summary' => self::cleanSummary($integrity['total'])];
        }

        $summary = self::notify($integrity['diff'], $integrity['total'], $threats);

        return ['status' => $threats !== [] ? 'threat' : 'changed', 'summary' => $summary];
    }

    /**
     * Manual "Scan file integrity" button: the hash baseline/diff only. This is
     * the heavy scan and it re-writes the baseline; it does not look at uploads.
     *
     * @return array{status:string,summary:string}
     */
    private static function performIntegrityScan(): array
    {
        @set_time_limit(0);

        $integrity = self::computeIntegrity();

        switch ($integrity['status']) {
            case 'empty':
                return ['status' => 'empty', 'summary' => __('Nothing to scan, or the data directory is not writable.', 'xyo-security')];
            case 'baseline':
                return ['status' => 'baseline', 'summary' => self::baselineSummary($integrity['total'])];
            case 'changed':
                return ['status' => 'changed', 'summary' => self::notify($integrity['diff'], $integrity['total'])];
            default:
                return ['status' => 'clean', 'summary' => self::cleanSummary($integrity['total'])];
        }
    }

    /**
     * Manual "Scan uploads" button: the lightweight, read-only executable-code
     * check on the uploads tree only. It never touches the hash baseline.
     *
     * @return array{status:string,summary:string}
     */
    private static function performUploadsScan(): array
    {
        @set_time_limit(0);

        $threats = self::uploadsThreats();
        self::rememberThreats($threats);

        if ($threats === []) {
            return ['status' => 'clean', 'summary' => __('No executable files found in uploads.', 'xyo-security')];
        }

        $emptyDiff = ['added' => [], 'modified' => [], 'removed' => []];

        return ['status' => 'threat', 'summary' => self::notify($emptyDiff, 0, $threats)];
    }

    /**
     * Run the hash baseline/diff: build the manifest, persist the new baseline,
     * and compare against the previous one. Pure of any alerting.
     *
     * @return array{status:string,diff:array,total:int} status is one of
     *         empty|baseline|clean|changed
     */
    private static function computeIntegrity(): array
    {
        $empty = ['added' => [], 'modified' => [], 'removed' => []];

        $current = self::buildManifest();
        if ($current === null) {
            self::log('Scan aborted: nothing scannable or data directory unwritable.');

            return ['status' => 'empty', 'diff' => $empty, 'total' => 0];
        }

        $baseline = self::loadBaseline();
        self::saveBaseline($current);

        if ($baseline === null) {
            self::log('Baseline created: ' . count($current) . ' files hashed.');

            return ['status' => 'baseline', 'diff' => $empty, 'total' => count($current)];
        }

        $diff = self::diff($baseline, $current);
        $hasDiff = $diff['added'] !== [] || $diff['modified'] !== [] || $diff['removed'] !== [];

        return ['status' => $hasDiff ? 'changed' : 'clean', 'diff' => $diff, 'total' => count($current)];
    }

    /** One-line summary for a freshly recorded baseline. */
    private static function baselineSummary(int $total): string
    {
        return sprintf(
            /* translators: %s: number of files */
            __('Baseline created: %s files recorded.', 'xyo-security'),
            number_format_i18n($total)
        );
    }

    /** One-line summary for a scan that found no changes. */
    private static function cleanSummary(int $total): string
    {
        return sprintf(
            /* translators: %s: number of files */
            __('No changes. %s files verified.', 'xyo-security'),
            number_format_i18n($total)
        );
    }

    /**
     * Walk the uploads tree and return absolute paths of files that could be
     * executed server- or client-side (PHP or JS family). This is deliberately a
     * presence check, not a hash comparison: media files are never listed, and
     * any executable code under uploads is suspicious regardless of a baseline
     * (classic web-shell / stored-XSS vector). Our own data directory is skipped.
     *
     * @return string[] absolute paths, capped at REPORT_LIMIT
     */
    private static function uploadsThreats(): array
    {
        $uploads = wp_upload_dir();
        if (!empty($uploads['error']) || empty($uploads['basedir'])) {
            return [];
        }
        $base = realpath($uploads['basedir']);
        if ($base === false) {
            return [];
        }
        $data = realpath(self::dataDir());

        $directory = new RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS);
        $filter = new RecursiveCallbackFilterIterator($directory, static function ($current) use ($data) {
            if ($current->isDir()) {
                if ($data !== false) {
                    $real = $current->getRealPath();
                    if ($real === $data || strpos($real, $data . DIRECTORY_SEPARATOR) === 0) {
                        return false;
                    }
                }
                return true;
            }

            return self::isExecutableUpload($current->getFilename());
        });

        $found = [];
        foreach (new RecursiveIteratorIterator($filter) as $file) {
            $found[] = $file->getPathname();
            if (count($found) >= self::REPORT_LIMIT) {
                break;
            }
        }

        sort($found);

        return $found;
    }

    /**
     * Whether a filename under uploads is executable code. Catches the PHP family
     * including double-extension evasion (shell.php.jpg, x.phtml, y.phar) and the
     * JS family. Everything else (images, documents, archives…) is ignored.
     */
    private static function isExecutableUpload(string $filename): bool
    {
        if (preg_match('/\.ph(p[0-9]?|t|tml|ar|ps)(\.|$)/i', $filename)) {
            return true;
        }

        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        return in_array($ext, ['js', 'mjs', 'cjs'], true);
    }

    /**
     * Store a signature of the current uploads-threat list and report whether it
     * changed since the previous scan (so a persistent finding is not re-alerted).
     */
    private static function rememberThreats(array $threats): bool
    {
        $signature = $threats === [] ? '' : md5(implode("\n", $threats));
        $previous = (string) get_option(self::UPLOADS_OPTION, '');

        if ($signature !== $previous) {
            update_option(self::UPLOADS_OPTION, $signature, false);
            return true;
        }

        return false;
    }

    /**
     * Hash every watched file across the de-duplicated scan roots.
     *
     * @return array<string,string>|null path => sha256, or null if unscannable
     */
    private static function buildManifest(): ?array
    {
        $roots = self::scanRoots();
        if ($roots === []) {
            return null;
        }

        $excluded = self::excludedDirs();
        $manifest = [];

        foreach ($roots as $root) {
            $directory = new RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS);

            $filter = new RecursiveCallbackFilterIterator($directory, static function ($current) use ($excluded) {
                if ($current->isDir()) {
                    if (in_array($current->getFilename(), self::SKIP_DIR_NAMES, true)) {
                        return false;
                    }
                    $real = $current->getRealPath();
                    foreach ($excluded as $dir) {
                        if ($real === $dir || strpos($real, $dir . DIRECTORY_SEPARATOR) === 0) {
                            return false;
                        }
                    }
                    return true;
                }

                return self::isWatched($current->getFilename());
            });

            foreach (new RecursiveIteratorIterator($filter) as $file) {
                $path = $file->getPathname();
                $hash = @hash_file('sha256', $path);
                if ($hash !== false) {
                    $manifest[$path] = $hash;
                }
            }
        }

        if ($manifest === []) {
            return null;
        }

        ksort($manifest);

        return $manifest;
    }

    /**
     * Whether a filename is executable code we track (extension match, plus the
     * extension-less .htaccess which carries rewrite/exec directives).
     */
    private static function isWatched(string $filename): bool
    {
        if ($filename === '.htaccess') {
            return true;
        }

        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        return $ext !== '' && in_array($ext, self::WATCHED_EXTENSIONS, true);
    }

    /**
     * Root directories to walk, from WordPress itself, with any root nested
     * inside another removed so each file is hashed exactly once. On a classic
     * install this collapses to a single ABSPATH; on Bedrock it yields the
     * separate core (web/wp) and content (web/app) trees.
     *
     * @return string[] absolute, real paths
     */
    private static function scanRoots(): array
    {
        $candidates = array_filter([
            defined('ABSPATH') ? ABSPATH : null,
            defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : null,
            defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : null,
            function_exists('get_theme_root') ? get_theme_root() : null,
        ]);

        $real = [];
        foreach ($candidates as $candidate) {
            $resolved = realpath($candidate);
            if ($resolved !== false) {
                $real[$resolved] = true;
            }
        }
        $real = array_keys($real);

        $roots = [];
        foreach ($real as $path) {
            $nested = false;
            foreach ($real as $other) {
                if ($path !== $other && strpos($path, $other . DIRECTORY_SEPARATOR) === 0) {
                    $nested = true;
                    break;
                }
            }
            if (!$nested) {
                $roots[] = $path;
            }
        }

        return $roots;
    }

    /**
     * Directories pruned from the walk: the uploads tree (constant churn, no
     * executable code expected) and our own data directory.
     *
     * @return string[] absolute, real paths
     */
    private static function excludedDirs(): array
    {
        $dirs = [];

        $uploads = wp_upload_dir();
        if (empty($uploads['error']) && !empty($uploads['basedir'])) {
            $real = realpath($uploads['basedir']);
            if ($real !== false) {
                $dirs[] = $real;
            }
        }

        $data = realpath(self::dataDir());
        if ($data !== false) {
            $dirs[] = $data;
        }

        return $dirs;
    }

    /**
     * Compare two manifests.
     *
     * @param array<string,string> $old
     * @param array<string,string> $new
     * @return array{added:string[],modified:string[],removed:string[]}
     */
    private static function diff(array $old, array $new): array
    {
        $added = array_keys(array_diff_key($new, $old));
        $removed = array_keys(array_diff_key($old, $new));

        $modified = [];
        foreach (array_intersect_key($old, $new) as $path => $hash) {
            if ($new[$path] !== $hash) {
                $modified[] = $path;
            }
        }

        sort($added);
        sort($modified);
        sort($removed);

        return ['added' => $added, 'modified' => $modified, 'removed' => $removed];
    }

    /**
     * Fan the detected change out to the three channels: log file, e-mail and a
     * pending admin notice.
     *
     * @param array{added:string[],modified:string[],removed:string[]} $diff
     * @param string[] $threats executable files found in uploads
     * @return string the one-line summary of the change
     */
    private static function notify(array $diff, int $total, array $threats = []): string
    {
        $counts = [
            'added'    => count($diff['added']),
            'modified' => count($diff['modified']),
            'removed'  => count($diff['removed']),
        ];
        $hasDiff = $counts['added'] || $counts['modified'] || $counts['removed'];

        $parts = [];
        if ($threats !== []) {
            $parts[] = sprintf('%d executable file(s) found in uploads — possible web shell.', count($threats));
        }
        if ($hasDiff || $threats === []) {
            $parts[] = sprintf(
                '%d added, %d modified, %d removed (of %d watched files).',
                $counts['added'],
                $counts['modified'],
                $counts['removed'],
                $total
            );
        }
        $summary = implode(' ', $parts);

        // Log: every path, no truncation.
        $lines = [$summary];
        foreach ($threats as $path) {
            $lines[] = '! ' . self::relative($path);
        }
        foreach (['added' => '+', 'modified' => '~', 'removed' => '-'] as $kind => $marker) {
            foreach ($diff[$kind] as $path) {
                $lines[] = $marker . ' ' . self::relative($path);
            }
        }
        self::log(implode("\n", $lines));

        // Pending admin notice (persists until dismissed).
        update_option(self::ALERT_OPTION, [
            'time'     => time(),
            'counts'   => $counts,
            'threats'  => count($threats),
            'summary'  => $summary,
        ], false);

        // E-mail to the site admin, path list capped.
        self::sendEmail($diff, $threats, $summary);

        return $summary;
    }

    /**
     * @param array{added:string[],modified:string[],removed:string[]} $diff
     * @param string[] $threats executable files found in uploads
     */
    private static function sendEmail(array $diff, array $threats, string $summary): void
    {
        $to = get_option('admin_email');
        if (!is_email($to)) {
            return;
        }

        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $subject = $threats !== []
            ? sprintf('[%s] SECURITY: executable file in uploads', $site)
            : sprintf('[%s] File integrity alert', $site);

        $body = [$summary, '', home_url('/'), ''];
        $shown = 0;

        if ($threats !== []) {
            $body[] = 'Executable files in uploads (investigate — these are not normally present):';
            foreach ($threats as $path) {
                $body[] = '  ' . self::relative($path);
            }
            $body[] = '';
        }

        foreach (['added' => 'Added', 'modified' => 'Modified', 'removed' => 'Removed'] as $kind => $heading) {
            if ($diff[$kind] === []) {
                continue;
            }
            $body[] = $heading . ':';
            foreach ($diff[$kind] as $path) {
                if ($shown >= self::REPORT_LIMIT) {
                    $body[] = sprintf('  … and more (see %s).', self::logPath());
                    break 2;
                }
                $body[] = '  ' . self::relative($path);
                $shown++;
            }
            $body[] = '';
        }

        wp_mail($to, $subject, implode("\n", $body));
    }

    /**
     * Render the pending-alert banner in wp-admin, with a dismiss link.
     */
    public static function renderNotice(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $alert = get_option(self::ALERT_OPTION);
        if (!is_array($alert) || empty($alert['summary'])) {
            return;
        }

        $dismiss = wp_nonce_url(
            add_query_arg(self::DISMISS_ARG, '1'),
            self::DISMISS_ARG
        );

        $title = !empty($alert['threats'])
            ? __('Xyo Security — executable file found in uploads', 'xyo-security')
            : __('Xyo Security — file change detected', 'xyo-security');

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p><p>%s %s</p></div>',
            esc_html($title),
            esc_html($alert['summary']),
            sprintf(
                /* translators: %s: path to the integrity log file */
                esc_html__('Full report logged to %s.', 'xyo-security'),
                '<code>' . esc_html(self::logPath()) . '</code>'
            ),
            '<a href="' . esc_url($dismiss) . '">' . esc_html__('Dismiss', 'xyo-security') . '</a>'
        );
    }

    /**
     * Clear the pending alert when the admin clicks "Dismiss".
     */
    public static function handleDismiss(): void
    {
        if (!isset($_GET[self::DISMISS_ARG]) || !current_user_can('manage_options')) {
            return;
        }
        check_admin_referer(self::DISMISS_ARG);

        delete_option(self::ALERT_OPTION);

        wp_safe_redirect(remove_query_arg([self::DISMISS_ARG, '_wpnonce']));
        exit;
    }

    /**
     * "Scan file integrity" button: run the hash baseline/diff on demand, then
     * redirect back to the settings page carrying the result for display.
     */
    public static function handleScanNow(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do that.', 'xyo-security'));
        }
        check_admin_referer(self::SCAN_ACTION);

        set_transient(self::SCAN_RESULT, self::performIntegrityScan(), MINUTE_IN_SECONDS);

        wp_safe_redirect(self::settingsUrl());
        exit;
    }

    /**
     * "Scan uploads" button: run the lightweight executable-code check on the
     * uploads tree only, then redirect back with the result.
     */
    public static function handleScanUploads(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do that.', 'xyo-security'));
        }
        check_admin_referer(self::SCAN_UPLOADS_ACTION);

        set_transient(self::SCAN_RESULT, self::performUploadsScan(), MINUTE_IN_SECONDS);

        wp_safe_redirect(self::settingsUrl());
        exit;
    }

    /**
     * Render the two scan tools on the settings page, preceded by the result of a
     * just-completed manual scan (if any). The checks are split deliberately: the
     * integrity scan is heavy and re-baselines; the uploads scan is a quick,
     * read-only web-shell check — different costs, different alerts.
     */
    public static function renderScanButton(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $result = get_transient(self::SCAN_RESULT);
        if (is_array($result) && !empty($result['summary'])) {
            delete_transient(self::SCAN_RESULT);
            $class = in_array($result['status'], ['changed', 'threat'], true) ? 'notice-error' : 'notice-success';
            printf(
                '<div class="notice %1$s inline"><p>%2$s</p></div>',
                esc_attr($class),
                esc_html($result['summary'])
            );
        }

        echo '<h2>' . esc_html__('File integrity', 'xyo-security') . '</h2>';

        // WP-Cron off → the queued event won't fire from page loads; warn so the
        // admin wires a real system cron or relies on the buttons below.
        if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
            printf(
                '<div class="notice notice-warning inline"><p>%s</p></div>',
                esc_html__('WP-Cron is disabled (DISABLE_WP_CRON). The daily scan will only run if a system cron triggers wp-cron.php — otherwise use the buttons below.', 'xyo-security')
            );
        }

        self::renderScanForm(
            self::SCAN_ACTION,
            __('Scan file integrity', 'xyo-security'),
            __('Hash core, plugins, mu-plugins and the theme and compare to the baseline. Heavier scan; also records the baseline on first run.', 'xyo-security')
        );

        self::renderScanForm(
            self::SCAN_UPLOADS_ACTION,
            __('Scan uploads', 'xyo-security'),
            __('List the uploads folder and flag any executable code (PHP/JS) — a likely web shell. Quick, read-only check.', 'xyo-security')
        );
    }

    /** Render a single scan tool: description + nonce-protected submit button. */
    private static function renderScanForm(string $action, string $label, string $description): void
    {
        echo '<p class="description">' . esc_html($description) . '</p>';
        echo '<form action="' . esc_url(admin_url('admin-post.php')) . '" method="post" style="margin-bottom:1.5em">';
        echo '<input type="hidden" name="action" value="' . esc_attr($action) . '">';
        wp_nonce_field($action);
        submit_button($label, 'secondary', 'submit', false);
        echo '</form>';
    }

    /** URL of the settings page this feature lives on. */
    private static function settingsUrl(): string
    {
        return admin_url('options-general.php?page=' . Settings::PAGE);
    }

    /**
     * Load the stored baseline manifest.
     *
     * @return array<string,string>|null null when no baseline exists yet
     */
    private static function loadBaseline(): ?array
    {
        $path = self::manifestPath();
        if (!is_file($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }

        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }

    /**
     * Persist the manifest as JSON in the protected data directory.
     *
     * @param array<string,string> $manifest
     */
    private static function saveBaseline(array $manifest): void
    {
        $path = self::manifestPath();
        $json = wp_json_encode($manifest);
        if ($json !== false) {
            @file_put_contents($path, $json, LOCK_EX);
        }
    }

    /** Append a timestamped entry to the log file. */
    private static function log(string $message): void
    {
        $line = '[' . gmdate('Y-m-d H:i:s') . " UTC]\n" . $message . "\n\n";
        @file_put_contents(self::logPath(), $line, FILE_APPEND | LOCK_EX);
    }

    /** Absolute path to the baseline manifest. */
    private static function manifestPath(): string
    {
        return self::dataDir() . '/manifest.json';
    }

    /** Absolute path to the log file. */
    private static function logPath(): string
    {
        return self::dataDir() . '/integrity.log';
    }

    /**
     * Ensure the data directory exists under uploads and is not web-readable
     * (Apache .htaccess + IIS web.config + a silent index.php), then return it.
     */
    private static function dataDir(): string
    {
        $uploads = wp_upload_dir();
        $base = !empty($uploads['basedir']) ? $uploads['basedir'] : WP_CONTENT_DIR . '/uploads';
        $dir = $base . '/' . self::DATA_DIR;

        if (!is_dir($dir)) {
            wp_mkdir_p($dir);

            @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            @file_put_contents($dir . '/web.config', "<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n");
            @file_put_contents($dir . '/index.php', "<?php\n// Silence is golden.\n");
        }

        return $dir;
    }

    /** Shorten an absolute path for display, relative to the install root. */
    private static function relative(string $path): string
    {
        foreach (self::scanRoots() as $root) {
            if (strpos($path, $root . DIRECTORY_SEPARATOR) === 0) {
                return ltrim(substr($path, strlen($root)), DIRECTORY_SEPARATOR);
            }
        }

        return $path;
    }
}
