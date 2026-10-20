<?php

namespace Xyo\WordpressSecurity\Admin;

/**
 * Settings screen (Settings → Xyo Security) that turns each hardening feature
 * on/off. State lives in a single array option, read through isEnabled() which
 * the bootstrap uses to decide whether to wire each Action. Built on the native
 * WordPress Settings API (nonce + sanitisation handled by core).
 *
 * Every feature defaults to ON, so a freshly activated plugin behaves exactly
 * like the hard-wired version until an admin changes something.
 */
class Settings
{
    const OPTION = 'xyo_security_settings';
    const GROUP  = 'xyo_security';
    const PAGE   = 'xyo-security';

    /** Option sub-key holding the admin-editable public REST route prefixes. */
    const REST_PREFIXES_KEY = 'rest_public_prefixes';

    /** Initial, editable public REST prefixes (shown until an admin changes them). */
    const DEFAULT_REST_PREFIXES = ['/xyo/', '/bee/', '/contact-form-7/'];

    /** @var array<string,mixed>|null in-request cache of the whole option */
    private static $options = null;

    /**
     * Feature keys and their default state — no translations, so this is safe to
     * call at plugin-load time (the bootstrap reads it via isEnabled()). The
     * translated labels live in features(), which must only run at/after `init`.
     *
     * @return array<string,bool>
     */
    public static function defaults(): array
    {
        return [
            'cleanup'      => true,
            'rest_lock'    => true,
            'integrity'    => true,
            'headers'      => true,
            'yoast'        => true,
            'login_errors' => true,
            'admin_footer' => true,
        ];
    }

    /**
     * Feature registry with translated UI strings: key => [label, description,
     * default]. Calls __(), so it MUST NOT run before `init` (WordPress 6.7 warns
     * about just-in-time textdomain loading); only the admin screen uses it.
     *
     * @return array<string, array{0:string,1:string,2:bool}>
     */
    public static function features(): array
    {
        $defaults = self::defaults();

        return [
            'cleanup' => [
                __('Clean <head> & disable XML-RPC', 'xyo-security'),
                __('Remove generator, RSD, WLW manifest, feeds, shortlink and asset version strings; disable XML-RPC.', 'xyo-security'),
                $defaults['cleanup'],
            ],
            'rest_lock' => [
                __('Lock the REST API', 'xyo-security'),
                __('Restrict the REST API to authenticated users. Public routes (favorites slider, Contact Form 7, oEmbed) stay open.', 'xyo-security'),
                $defaults['rest_lock'],
            ],
            'integrity' => [
                __('File integrity monitoring', 'xyo-security'),
                __('Hash core, plugins, mu-plugins and the active theme once a day and alert (e-mail, log, admin notice) on any added, changed or removed executable file.', 'xyo-security'),
                $defaults['integrity'],
            ],
            'headers' => [
                __('Security headers', 'xyo-security'),
                __('Send hardened HTTP headers (X-Frame-Options, Referrer-Policy, Permissions-Policy…) and mask X-Powered-By.', 'xyo-security'),
                $defaults['headers'],
            ],
            'yoast' => [
                __('Tame Yoast', 'xyo-security'),
                __('Strip Yoast HTML comments, force robots index/follow and exclude authors from the sitemap.', 'xyo-security'),
                $defaults['yoast'],
            ],
            'login_errors' => [
                __('Generic login errors', 'xyo-security'),
                __('Hide whether the username or the password was wrong on failed logins.', 'xyo-security'),
                $defaults['login_errors'],
            ],
            'admin_footer' => [
                __('Admin footer credit', 'xyo-security'),
                __('Show the "Cleaned by xyo" note in the wp-admin footer.', 'xyo-security'),
                $defaults['admin_footer'],
            ],
        ];
    }

    /**
     * The stored option, read once per request.
     *
     * @return array<string,mixed>
     */
    private static function options(): array
    {
        if (self::$options === null) {
            $stored = get_option(self::OPTION, []);
            self::$options = is_array($stored) ? $stored : [];
        }

        return self::$options;
    }

    /**
     * Whether a feature is enabled (default when never saved).
     */
    public static function isEnabled(string $key): bool
    {
        $options = self::options();
        if (array_key_exists($key, $options)) {
            return (bool) $options[$key];
        }

        $defaults = self::defaults();

        return isset($defaults[$key]) ? $defaults[$key] : false;
    }

    /**
     * Admin-configured public REST route prefixes (falls back to the defaults).
     * The forced `/oembed/` baseline is added by WpJson, not stored here.
     *
     * @return string[]
     */
    public static function restPublicPrefixes(): array
    {
        $options = self::options();
        if (isset($options[self::REST_PREFIXES_KEY]) && is_array($options[self::REST_PREFIXES_KEY])) {
            return $options[self::REST_PREFIXES_KEY];
        }

        return self::DEFAULT_REST_PREFIXES;
    }

    /**
     * Normalise a textarea / list of route prefixes to clean `/prefix/` strings.
     *
     * @param mixed $raw
     * @return string[]
     */
    private static function normalizePrefixes($raw): array
    {
        $lines = is_array($raw) ? $raw : preg_split('/[\r\n,]+/', (string) $raw);

        $out = [];
        foreach ((array) $lines as $line) {
            $line = trim((string) $line);
            if ($line === '') {
                continue;
            }
            $line = '/' . trim($line, "/ \t") . '/';
            if ($line !== '//') {
                $out[] = $line;
            }
        }

        return array_values(array_unique($out));
    }

    public static function registerMenu(): void
    {
        add_options_page(
            __('Xyo Security', 'xyo-security'),
            __('Xyo Security', 'xyo-security'),
            'manage_options',
            self::PAGE,
            [self::class, 'renderPage']
        );
    }

    public static function registerSettings(): void
    {
        register_setting(self::GROUP, self::OPTION, [
            'type'              => 'array',
            'sanitize_callback' => [self::class, 'sanitize'],
            'default'           => [],
        ]);

        add_settings_section(
            'xyo_security_main',
            __('Features', 'xyo-security'),
            [self::class, 'renderSectionIntro'],
            self::PAGE
        );

        foreach (self::features() as $key => $feature) {
            add_settings_field(
                $key,
                $feature[0],
                [self::class, 'renderField'],
                self::PAGE,
                'xyo_security_main',
                ['key' => $key, 'desc' => $feature[1], 'label_for' => self::OPTION . '_' . $key]
            );
        }

        add_settings_field(
            self::REST_PREFIXES_KEY,
            __('Public REST routes', 'xyo-security'),
            [self::class, 'renderPrefixesField'],
            self::PAGE,
            'xyo_security_main',
            ['label_for' => self::OPTION . '_' . self::REST_PREFIXES_KEY]
        );
    }

    /**
     * Coerce every known feature to a strict boolean; ignore anything unknown.
     *
     * @param mixed $input
     * @return array<string,bool>
     */
    public static function sanitize($input): array
    {
        $clean = [];
        foreach (array_keys(self::defaults()) as $key) {
            $clean[$key] = !empty($input[$key]);
        }

        $clean[self::REST_PREFIXES_KEY] = self::normalizePrefixes($input[self::REST_PREFIXES_KEY] ?? '');

        return $clean;
    }

    public static function renderSectionIntro(): void
    {
        echo '<p>' . esc_html__('Toggle each hardening feature. All are on by default.', 'xyo-security') . '</p>';
    }

    /**
     * @param array{key:string,desc:string,label_for:string} $args
     */
    public static function renderField($args): void
    {
        printf(
            '<label><input type="checkbox" id="%1$s" name="%2$s[%3$s]" value="1" %4$s> %5$s</label>',
            esc_attr($args['label_for']),
            esc_attr(self::OPTION),
            esc_attr($args['key']),
            checked(self::isEnabled($args['key']), true, false),
            esc_html($args['desc'])
        );
    }

    /**
     * @param array{label_for:string} $args
     */
    public static function renderPrefixesField($args): void
    {
        printf(
            '<textarea id="%1$s" name="%2$s[%3$s]" rows="4" cols="40" class="regular-text code">%4$s</textarea>',
            esc_attr($args['label_for']),
            esc_attr(self::OPTION),
            esc_attr(self::REST_PREFIXES_KEY),
            esc_textarea(implode("\n", self::restPublicPrefixes()))
        );
        echo '<p class="description">' .
            esc_html__('One route prefix per line (e.g. /xyo/). Used only when "Lock the REST API" is on. /oembed/ is always allowed.', 'xyo-security') .
            '</p>';
    }

    public static function renderPage(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Xyo Security', 'xyo-security'); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields(self::GROUP);
                do_settings_sections(self::PAGE);
                submit_button();
                ?>
            </form>
            <?php
            /**
             * Fires after the settings form on the Xyo Security page. Features
             * (e.g. file integrity monitoring) hook here to add their own tools,
             * keeping this screen agnostic of individual features.
             */
            do_action('xyo_security_after_settings_form');
            ?>
        </div>
        <?php
    }

    /**
     * "Settings" shortcut on the Plugins screen.
     *
     * @param array $links
     * @return array
     */
    public static function actionLinks($links): array
    {
        $url = admin_url('options-general.php?page=' . self::PAGE);
        array_unshift($links, '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'xyo-security') . '</a>');

        return $links;
    }
}
