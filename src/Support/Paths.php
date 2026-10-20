<?php

namespace Xyo\WordpressSecurity\Support;

/**
 * Filesystem helpers shared by every scanner (file-integrity baseline, upstream
 * checksum verification, uploads/content checks…). Every path comes from
 * WordPress constants/APIs, never hard-coded, so it behaves identically on a
 * classic single-folder install and on Bedrock (core in web/wp, content in
 * web/app). Pure of any state: no options, no I/O beyond ensuring the protected
 * data directory exists.
 */
class Paths
{
    /** Sub-directory of uploads/ holding each scanner's manifests and the log. */
    const DATA_DIR = 'xyo-security';

    /**
     * Root directories to walk, from WordPress itself, with any root nested
     * inside another removed so each file is visited exactly once. On a classic
     * install this collapses to a single ABSPATH; on Bedrock it yields the
     * separate core (web/wp) and content (web/app) trees.
     *
     * @return string[] absolute, real paths
     */
    public static function scanRoots(): array
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
     * Directories pruned from a walk: the uploads tree (constant churn, no
     * executable code expected) and our own data directory.
     *
     * @return string[] absolute, real paths
     */
    public static function excludedDirs(): array
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

    /** Shorten an absolute path for display, relative to the install root. */
    public static function relative(string $path): string
    {
        foreach (self::scanRoots() as $root) {
            if (strpos($path, $root . DIRECTORY_SEPARATOR) === 0) {
                return ltrim(substr($path, strlen($root)), DIRECTORY_SEPARATOR);
            }
        }

        return $path;
    }

    /**
     * Ensure the data directory exists under uploads and is not web-readable
     * (Apache .htaccess + IIS web.config + a silent index.php), then return it.
     */
    public static function dataDir(): string
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
}
