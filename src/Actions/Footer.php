<?php

namespace Xyo\WordpressSecurity\Actions;

class Footer
{
    public static function init(): void
    {
        add_filter('admin_footer_text', [self::class, 'adminFooterTextOutput'], 11);
    }

    public static function adminFooterTextOutput(string $text): string
    {
        global $wp_version;

        return ' WordPress ' . $wp_version . ' <br> ' .
            'Cleaned by <a href="https://xyo.dev/" title="Patrick Petit for xyo">xyo</a>';
    }
}
