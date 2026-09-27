<?php

namespace GlpiPlugin\Mlabvuln;

/**
 * Pure matching logic, no GLPI dependency (tested by tests/check.php).
 */
final class Matcher
{
    /**
     * Inventoried OS full name (glpi_operatingsystems.name) → OSV ecosystem, or null.
     * e.g. "Debian GNU/Linux 12 (bookworm)" → "Debian:12"
     */
    public static function ecosystem(string $os): ?string
    {
        $patterns = [
            '/debian\D*(\d+)/i'                => fn($m) => "Debian:{$m[1]}",
            '/ubuntu\D*(\d+\.\d+)/i'           => fn($m) => "Ubuntu:{$m[1]}",
            '/alpine\D*(\d+\.\d+)/i'           => fn($m) => "Alpine:v{$m[1]}",
            '/rocky\D*(\d+)/i'                 => fn($m) => "Rocky Linux:{$m[1]}",
            '/alma\D*(\d+)/i'                  => fn($m) => "AlmaLinux:{$m[1]}",
        ];
        foreach ($patterns as $re => $fn) {
            if (preg_match($re, $os, $m)) {
                return $fn($m);
            }
        }
        return null;
    }

    /** First dotted numeric run: "118.0.5993.70 (x64)" → "118.0.5993.70". */
    public static function normalizeVersion(string $v): ?string
    {
        return preg_match('/\d+(?:\.\d+)*/', $v, $m) ? $m[0] : null;
    }

    /** Split a CPE 2.3 string on unescaped ':' and unescape. */
    public static function cpeParts(string $cpe): array
    {
        return array_map(
            fn($p) => preg_replace('/\\\\(.)/', '$1', $p),
            preg_split('/(?<!\\\\):/', $cpe)
        );
    }

    /**
     * Does one NVD cpe_match entry (vuln.mlab.sh format) cover vendor:product at $version?
     */
    public static function cpeMatches(array $match, string $vendor, string $product, string $version): bool
    {
        if (empty($match['vulnerable'])) {
            return false;
        }
        $p = self::cpeParts($match['criteria'] ?? '');
        if (($p[3] ?? null) !== $vendor || ($p[4] ?? null) !== $product) {
            return false;
        }
        $v = self::normalizeVersion($version);
        if ($v === null) {
            return false;
        }
        $cpe_version = $p[5] ?? '*';
        if ($cpe_version === '-') {
            return false;
        }
        if ($cpe_version !== '*') {
            return self::normalizeVersion($cpe_version) === $v;
        }
        $bounds = [
            'version_start_including' => '>=',
            'version_start_excluding' => '>',
            'version_end_including'   => '<=',
            'version_end_excluding'   => '<',
        ];
        foreach ($bounds as $key => $op) {
            if (!empty($match[$key])) {
                $b = self::normalizeVersion($match[$key]);
                if ($b !== null && !version_compare($v, $b, $op)) {
                    return false;
                }
            }
        }
        // '*' with no bound at all = every version is vulnerable (NVD semantics)
        return true;
    }

    /** Sort key: KEV first, then EPSS, then CVSS. */
    public static function priority(bool $kev, float $epss, float $cvss): string
    {
        return match (true) {
            $kev                        => 'critical',
            $epss >= 0.1 || $cvss >= 9  => 'high',
            $cvss >= 7                  => 'medium',
            default                     => 'low',
        };
    }
}
