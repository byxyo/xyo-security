<?php

namespace Xyo\WordpressSecurity\Actions;

use WP_Error;
use Xyo\WordpressSecurity\Admin\Settings;

class WpJson
{
    /**
     * Route prefixes always kept public, regardless of admin settings — oEmbed
     * must stay reachable for WordPress embeds to work. The rest of the public
     * whitelist is admin-configurable (Settings → Xyo Security) and merged on
     * top; extend programmatically via the 'xyo_security_public_rest_prefixes'
     * filter.
     */
    const FORCED_PREFIXES = ['/oembed/'];

    /**
     * Gate the REST API: authenticated users keep full access, anonymous
     * requests are allowed only on the whitelisted public routes.
     *
     * @param mixed $access current authentication result
     * @return mixed|WP_Error
     */
    public static function disable($access)
    {
        // Preserve any pre-existing error from an earlier filter.
        if (is_wp_error($access)) {
            return $access;
        }

        if (is_user_logged_in() || self::isPublicRoute()) {
            return $access;
        }

        $message = apply_filters(
            'xyo_security_rest_api_error',
            __('REST API restricted to authenticated users.', 'xyo-security')
        );

        return new WP_Error('rest_login_required', $message, ['status' => rest_authorization_required_code()]);
    }

    /**
     * @return bool whether the current REST route is on the public whitelist
     */
    private static function isPublicRoute(): bool
    {
        $route = self::currentRoute();
        if ($route === '') {
            return false;
        }

        foreach (self::publicPrefixes() as $prefix) {
            if (strpos($route, $prefix) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Effective public whitelist: forced baseline + admin-configured prefixes,
     * then the filter, de-duplicated.
     *
     * @return string[]
     */
    private static function publicPrefixes(): array
    {
        $prefixes = array_merge(self::FORCED_PREFIXES, Settings::restPublicPrefixes());
        $prefixes = apply_filters('xyo_security_public_rest_prefixes', $prefixes);

        return array_values(array_unique(array_filter((array) $prefixes)));
    }

    /**
     * Resolve the REST route being requested, normalised with a leading slash.
     * Works for both pretty (/wp-json/ns/route) and plain (?rest_route=) forms.
     *
     * @return string
     */
    private static function currentRoute(): string
    {
        $route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';

        if ($route === '' && isset($_SERVER['REQUEST_URI'])) {
            $prefix = '/' . rest_get_url_prefix() . '/';
            $path   = (string) wp_parse_url(wp_unslash($_SERVER['REQUEST_URI']), PHP_URL_PATH);
            $pos    = strpos($path, $prefix);
            if ($pos !== false) {
                $route = substr($path, $pos + strlen($prefix) - 1); // keep the leading slash
            }
        }

        return $route === '' ? '' : '/' . ltrim((string) $route, '/');
    }
}
