<?php

namespace Xyo\WordpressSecurity\Actions;

class Header
{
    public static function setHeader()
    {
        if (headers_sent()) {
            return;
        }

        // Overwrite the real "X-Powered-By" with a harmless decoy. header()
        // replaces the existing value, so this masks PHP/WordPress even when the
        // server never disabled expose_php — no stack fingerprint leaks out.
        \header('X-Powered-By: beers and caffeine');

        \header('X-Content-Type-Options: nosniff');
        \header('X-Frame-Options: SAMEORIGIN');
        \header('Referrer-Policy: strict-origin-when-cross-origin');
        // Lock down powerful features we never use. Kept conservative so YouTube
        // embeds (fullscreen) and the like keep working.
        \header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    }
}
