<?php

// php plugin/mlabvuln/tests/check.php
require __DIR__ . '/../src/Matcher.php';

use GlpiPlugin\Mlabvuln\Matcher as M;


$eq = function ($a, $b) {
    if ($a !== $b) {
        throw new Exception('expected ' . var_export($b, true) . ' got ' . var_export($a, true));
    }
};

$eq(M::ecosystem('Debian GNU/Linux 12 (bookworm)'), 'Debian:12');
$eq(M::ecosystem('Ubuntu 22.04.3 LTS'), 'Ubuntu:22.04');
$eq(M::ecosystem('Alpine Linux v3.18'), 'Alpine:v3.18');
$eq(M::ecosystem('Rocky Linux 9.3 (Blue Onyx)'), 'Rocky Linux:9');
$eq(M::ecosystem('AlmaLinux 9.4 (Seafoam Ocelot)'), 'AlmaLinux:9');
$eq(M::ecosystem('Microsoft Windows 11 Professionnel'), null);

$eq(M::normalizeVersion('118.0.5993.70 (x64)'), '118.0.5993.70');
$eq(M::cpeParts('cpe:2.3:a:notepad-plus-plus:notepad\+\+:*:*')[4], 'notepad++');

$range = ['criteria' => 'cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*', 'vulnerable' => true, 'version_end_excluding' => '24.09'];
$eq(M::cpeMatches($range, '7-zip', '7-zip', '23.01'), true);
$eq(M::cpeMatches($range, '7-zip', '7-zip', '24.09'), false);
$eq(M::cpeMatches($range, 'google', 'chrome', '23.01'), false);
$eq(M::cpeMatches(['vulnerable' => false] + $range, '7-zip', '7-zip', '23.01'), false);
$exact = ['criteria' => 'cpe:2.3:a:putty:putty:0.80:*:*:*:*:*:*:*', 'vulnerable' => true];
$eq(M::cpeMatches($exact, 'putty', 'putty', '0.80.0.0'), false);
$eq(M::cpeMatches($exact, 'putty', 'putty', '0.80'), true);
$both = ['criteria' => 'cpe:2.3:a:google:chrome:*:*', 'vulnerable' => true,
    'version_start_including' => '100.0', 'version_end_including' => '118.0.5993.70'];
$eq(M::cpeMatches($both, 'google', 'chrome', '118.0.5993.70'), true);
$eq(M::cpeMatches($both, 'google', 'chrome', '99.0'), false);

$eq(M::priority(true, 0.0, 0.0), 'critical');
$eq(M::priority(false, 0.5, 5.0), 'high');
$eq(M::priority(false, 0.0, 7.5), 'medium');

echo "ok\n";
