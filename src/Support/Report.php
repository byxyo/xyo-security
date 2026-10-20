<?php

namespace Xyo\WordpressSecurity\Support;

/**
 * Shared alert fan-out for every scanner. A finding is reported three ways: a
 * timestamped line in the log file, a wp-admin notice that persists until the
 * admin dismisses it, and an e-mail to the site admin. Scanners build their own
 * domain-specific wording and call the generic channels here, so the reporting
 * plumbing (log file, dismissible notice, mailer) lives in one place.
 *
 * The log file name and the alert option key are kept from the original
 * integrity feature for continuity on sites already running it.
 */
class Report
{
    /** Option holding the pending alert shown in wp-admin (absent when clear). */
    const ALERT_OPTION = 'xyo_security_integrity_alert';

    /** Query arg used to dismiss the admin notice. */
    const DISMISS_ARG = 'xyo_sec_fim_dismiss';

    /** Log file basename inside the protected data directory. */
    const LOG_FILE = 'integrity.log';

    /** Append a timestamped entry to the shared log file. */
    public static function log(string $message): void
    {
        $line = '[' . gmdate('Y-m-d H:i:s') . " UTC]\n" . $message . "\n\n";
        @file_put_contents(self::logPath(), $line, FILE_APPEND | LOCK_EX);
    }

    /** Absolute path to the shared log file. */
    public static function logPath(): string
    {
        return Paths::dataDir() . '/' . self::LOG_FILE;
    }

    /**
     * Store the pending alert shown in wp-admin until dismissed. The title and
     * summary are rendered verbatim by renderNotice().
     */
    public static function alert(string $title, string $summary): void
    {
        update_option(self::ALERT_OPTION, [
            'time'    => time(),
            'title'   => $title,
            'summary' => $summary,
        ], false);
    }

    /** E-mail a report to the site admin (no-op when no valid admin e-mail). */
    public static function email(string $subject, string $body): void
    {
        $to = get_option('admin_email');
        if (!is_email($to)) {
            return;
        }

        wp_mail($to, $subject, $body);
    }

    /** Render the pending-alert banner in wp-admin, with a dismiss link. */
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

        $title = !empty($alert['title'])
            ? $alert['title']
            : __('Security by Xyo — alert', 'xyo-security');

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p><p>%s %s</p></div>',
            esc_html($title),
            esc_html($alert['summary']),
            sprintf(
                /* translators: %s: path to the log file */
                esc_html__('Full report logged to %s.', 'xyo-security'),
                '<code>' . esc_html(self::logPath()) . '</code>'
            ),
            '<a href="' . esc_url($dismiss) . '">' . esc_html__('Dismiss', 'xyo-security') . '</a>'
        );
    }

    /** Clear the pending alert when the admin clicks "Dismiss". */
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
}
