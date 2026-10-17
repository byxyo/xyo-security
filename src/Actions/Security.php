<?php

namespace Xyo\WordpressSecurity\Actions;

class Security
{
    public static function init()
    {
        // Generic login error → no username/password enumeration.
        add_filter('login_errors', function () {
            return __('Authentication failed.', 'xyo-security');
        });
    }
}
