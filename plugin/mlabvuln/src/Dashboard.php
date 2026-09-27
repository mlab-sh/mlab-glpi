<?php

namespace GlpiPlugin\Mlabvuln;

final class Dashboard
{
    private const CARDS = [
        'kev'       => ['CVE activement exploitées (KEV)', '#d63939', 'c.is_kev = 1'],
        'critical'  => ['CVE critiques (CVSS ≥ 9)', '#f76707', 'c.cvss_score >= 9'],
        'all'       => ['CVE présentes dans le parc', '#4263eb', '1 = 1'],
        'computers' => ['Machines exposées à une KEV', '#ae3ec9', null],
    ];

    public static function cards(?array $cards): array
    {
        foreach (self::CARDS as $key => [$label]) {
            $cards["mlabvuln_$key"] = [
                'widgettype' => ['bigNumber'],
                'label'      => $label,
                'group'      => 'mlab vuln',
                'provider'   => self::class . '::' . $key,
            ];
        }
        return $cards ?? [];
    }

    public static function __callStatic(string $key, array $args): array
    {
        global $DB;
        [$label, $color, $where] = self::CARDS[$key];
        $sql = $where !== null
            ? "SELECT COUNT(DISTINCT c.id) FROM glpi_plugin_mlabvuln_cves c
               JOIN glpi_plugin_mlabvuln_findings f ON f.plugin_mlabvuln_cves_id = c.id WHERE $where"
            : "SELECT COUNT(DISTINCT isv.items_id) FROM glpi_plugin_mlabvuln_cves c
               JOIN glpi_plugin_mlabvuln_findings f ON f.plugin_mlabvuln_cves_id = c.id
               JOIN glpi_items_softwareversions isv ON isv.softwareversions_id = f.softwareversions_id
                 AND isv.itemtype = 'Computer' AND isv.is_deleted = 0
               WHERE c.is_kev = 1";
        return [
            'number' => (int) $DB->doQuery($sql)->fetch_row()[0],
            'url'    => Cve::getSearchURL(),
            'label'  => $label,
            'icon'   => Cve::getIcon(),
            'color'  => $color,
        ];
    }
}
