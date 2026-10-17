<?php

namespace Xyo\WordpressSecurity\Actions;

class Cleanup
{
    /**
     * Removes any informations regarding your WordPress installation
     */
    public static function clean()
    {
        // category feeds
        remove_action('wp_head', 'feed_links_extra', 3);
        // post and comment feeds
        remove_action('wp_head', 'feed_links', 2);
        // EditURI link
        remove_action('wp_head', 'rsd_link');
        // previous link
        remove_action('wp_head', 'parent_post_rel_link');
        // start link
        remove_action('wp_head', 'start_post_rel_link');
        // links for adjacent posts
        remove_action('wp_head', 'adjacent_posts_rel_link_wp_head');
        // Display the links to the extra feeds such as category feeds
        remove_action('wp_head', 'feed_links_extra', 3);
        // Display the links to the general feeds: Post and Comment Feed
        remove_action('wp_head', 'feed_links', 2);

        // Get outta my Wordpress codez dangit!
        remove_filter('the_content', 'capital_P_dangit');
        remove_filter('the_title', 'capital_P_dangit');
        remove_filter('comment_text', 'capital_P_dangit');

        add_filter('xmlrpc_enabled', '__return_false');

        add_filter('the_generator', function () {
            return '';
        });
        add_filter('style_loader_src', [self::class, 'removeCssJsVersion'], 9999);
        add_filter('script_loader_src', [self::class, 'removeCssJsVersion'], 9999);
        remove_action('wp_head', 'wp_generator');
        remove_action('wp_head', 'index_rel_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
    }

    public static function removeCssJsVersion($src)
    {
        if (strpos($src, 'ver=')) {
            $queryParameters = wp_parse_url($src, PHP_URL_QUERY);
            $parameters = \explode('&', $queryParameters);
            $params = [];

            foreach ($parameters as $parameter) {
                list($key, $value) = explode('=', $parameter, 2);
                $params[$key] = $value;
            }

            $currentVersion = $params['ver'] ?? get_bloginfo('version');
            $newVersion = substr(md5(wp_hash($currentVersion)), 0, 8);
            $src = str_replace('ver='.$currentVersion, 'ver='.$newVersion, $src);
        }

        return $src;
    }
}
