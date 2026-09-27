<?php

use GlpiPlugin\Mlabvuln\CpeRule;
use GlpiPlugin\Mlabvuln\Cve;
use GlpiPlugin\Mlabvuln\Scanner;

const PLUGIN_MLABVULN_TABLES = [
    'glpi_plugin_mlabvuln_cves',
    'glpi_plugin_mlabvuln_findings',
    'glpi_plugin_mlabvuln_scans',
    'glpi_plugin_mlabvuln_cperules',
    'glpi_plugin_mlabvuln_products',
    'glpi_plugin_mlabvuln_tickets',
];

function plugin_mlabvuln_install(): bool
{
    global $DB;

    $opts = sprintf(
        'ENGINE=InnoDB DEFAULT CHARSET=%s COLLATE=%s ROW_FORMAT=DYNAMIC',
        DBConnection::getDefaultCharset(),
        DBConnection::getDefaultCollation()
    );
    $pk = 'int ' . DBConnection::getDefaultPrimaryKeySignOption() . ' NOT NULL AUTO_INCREMENT';
    $fk = 'int ' . DBConnection::getDefaultPrimaryKeySignOption() . ' NOT NULL DEFAULT 0';

    $schema = [
        // CVE metadata cache (CVSS / EPSS / KEV), one row per CVE
        'glpi_plugin_mlabvuln_cves' => "
            id $pk,
            name varchar(64) NOT NULL,
            description text,
            cvss_score decimal(3,1) NOT NULL DEFAULT 0,
            severity varchar(16) NOT NULL DEFAULT '',
            epss decimal(6,5) NOT NULL DEFAULT 0,
            is_kev tinyint NOT NULL DEFAULT 0,
            kev_due_date date DEFAULT NULL,
            score decimal(6,3) NOT NULL DEFAULT 0,
            date_sync timestamp NULL DEFAULT NULL,
            PRIMARY KEY (id), UNIQUE KEY name (name), KEY is_kev (is_kev), KEY score (score)",
        // CVE affecting a software version (dedup: 1 version = 1 lookup, whatever the number of installs)
        'glpi_plugin_mlabvuln_findings' => "
            id $pk,
            softwareversions_id $fk,
            plugin_mlabvuln_cves_id $fk,
            source varchar(64) NOT NULL DEFAULT '',
            fixed_version varchar(255) NOT NULL DEFAULT '',
            date_creation timestamp NULL DEFAULT NULL,
            PRIMARY KEY (id), UNIQUE KEY unicity (softwareversions_id, plugin_mlabvuln_cves_id),
            KEY plugin_mlabvuln_cves_id (plugin_mlabvuln_cves_id)",
        // Last scan state per software version
        'glpi_plugin_mlabvuln_scans' => "
            id $pk,
            softwareversions_id $fk,
            method varchar(64) NOT NULL DEFAULT '',
            status varchar(16) NOT NULL DEFAULT '',
            message varchar(255) NOT NULL DEFAULT '',
            date_scan timestamp NULL DEFAULT NULL,
            PRIMARY KEY (id), UNIQUE KEY softwareversions_id (softwareversions_id), KEY date_scan (date_scan)",
        // Windows/macOS software name → CPE vendor:product
        'glpi_plugin_mlabvuln_cperules' => "
            id $pk,
            name varchar(255) NOT NULL DEFAULT '',
            name_pattern varchar(255) NOT NULL DEFAULT '',
            publisher_pattern varchar(255) NOT NULL DEFAULT '',
            vendor varchar(255) NOT NULL DEFAULT '',
            product varchar(255) NOT NULL DEFAULT '',
            search_term varchar(255) NOT NULL DEFAULT '',
            is_active tinyint NOT NULL DEFAULT 1,
            comment text,
            date_mod timestamp NULL DEFAULT NULL,
            date_creation timestamp NULL DEFAULT NULL,
            PRIMARY KEY (id), KEY is_active (is_active)",
        // Per CPE product: every CVE with its cpe_matches, refreshed every N days
        'glpi_plugin_mlabvuln_products' => "
            id $pk,
            vendor varchar(255) NOT NULL DEFAULT '',
            product varchar(255) NOT NULL DEFAULT '',
            data longtext,
            date_sync timestamp NULL DEFAULT NULL,
            PRIMARY KEY (id), UNIQUE KEY unicity (vendor, product)",
        // One auto-created ticket per CVE
        'glpi_plugin_mlabvuln_tickets' => "
            id $pk,
            plugin_mlabvuln_cves_id $fk,
            tickets_id $fk,
            PRIMARY KEY (id), UNIQUE KEY plugin_mlabvuln_cves_id (plugin_mlabvuln_cves_id)",
    ];
    foreach ($schema as $table => $cols) {
        if (!$DB->tableExists($table)) {
            $DB->doQuery("CREATE TABLE `$table` ($cols) $opts");
        }
    }

    if (countElementsInTable('glpi_plugin_mlabvuln_cperules') === 0) {
        foreach (CpeRule::DEFAULTS as [$name, $pattern, $vendor, $product, $search]) {
            $DB->insert('glpi_plugin_mlabvuln_cperules', [
                'name' => $name, 'name_pattern' => $pattern, 'vendor' => $vendor,
                'product' => $product, 'search_term' => $search, 'is_active' => 1,
                'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
            ]);
        }
    }

    // default list columns (users_id 0 = everyone)
    $prefs = [Cve::class => [12, 3, 5, 6, 7, 11, 10], CpeRule::class => [100, 101, 102, 103, 104, 105]];
    foreach ($prefs as $itemtype => $nums) {
        if (!countElementsInTable('glpi_displaypreferences', ['itemtype' => $itemtype])) {
            foreach ($nums as $rank => $num) {
                $DB->insert('glpi_displaypreferences', ['itemtype' => $itemtype, 'num' => $num, 'rank' => $rank + 1, 'users_id' => 0]);
            }
        }
    }

    $cfg = Scanner::config();
    unset($cfg['api_token']); // already stored encrypted, do not re-encrypt
    Config::setConfigurationValues('plugin:mlabvuln', $cfg);

    CronTask::register(Scanner::class, 'scan', HOUR_TIMESTAMP, [
        'comment' => 'Scan des versions logicielles inventoriées sur vuln.mlab.sh',
        'mode'    => CronTask::MODE_EXTERNAL,
        'param'   => 2000,
    ]);
    return true;
}

function plugin_mlabvuln_uninstall(): bool
{
    global $DB;
    foreach (PLUGIN_MLABVULN_TABLES as $table) {
        $DB->dropTable($table, true);
    }
    $DB->delete('glpi_displaypreferences', ['itemtype' => [Cve::class, CpeRule::class]]);
    Config::deleteConfigurationValues('plugin:mlabvuln', array_keys(Scanner::DEFAULT_CONFIG));
    return true;
}
