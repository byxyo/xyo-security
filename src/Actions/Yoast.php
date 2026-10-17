<?php

namespace Xyo\WordpressSecurity\Actions;

class Yoast
{
    public static function init()
    {
        add_filter('wp_robots', function ($robots) {
            if (is_home() || is_single() || is_category() || is_singular() || is_page()) {
                $robots['index'] = true;
                $robots['noindex'] = false;
                $robots['noarchive'] = false;
                $robots['follow'] = true;
                $robots['nofollow'] = false;
            }
            return $robots;
        }, (PHP_INT_MAX - 9));

        add_filter('wpseo_debug_markers', '__return_false');
        add_action(
            'wp_head',
            function () {
                ob_start(
                    function ($o) {
                        return preg_replace('/\n?<.*?Yoast SEO plugin.*?>/mi', '', $o);
                    }
                );
            },
            (PHP_INT_MAX - 9)
        );

        add_filter('wpseo_sitemap_exclude_author', [self::class, 'removeAuthorFromYoast'], 10, 1);
    }

    public static function removeAuthorFromYoast($users)
    {
        return false;
    }
}
