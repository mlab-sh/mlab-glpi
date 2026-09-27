<?php

namespace GlpiPlugin\Mlabvuln;

use CommonDBTM;
use CommonGLPI;
use Computer;
use Software;
use SoftwareVersion;

/**
 * A CVE affecting a software version. Displayed as "Vulnérabilités" tabs on Computer and Software.
 */
final class Finding extends CommonDBTM
{
    public static $rightname = 'software';

    public const BADGES = [
        'critical' => ['bg-danger', 'Critique (KEV)'],
        'high'     => ['bg-orange', 'Haute'],
        'medium'   => ['bg-warning', 'Moyenne'],
        'low'      => ['bg-secondary', 'Basse'],
    ];

    public static function getTypeName($nb = 0)
    {
        return _n('Vulnérabilité', 'Vulnérabilités', $nb);
    }

    public static function getIcon()
    {
        return 'ti ti-shield-exclamation';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!self::canView()) {
            return '';
        }
        $nb = $_SESSION['glpishow_count_on_tabs'] ? self::countRows($item) : 0;
        return self::createTabEntry(self::getTypeName(2), $nb, $item::class, self::getIcon());
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        self::showTable(self::rows($item), $item instanceof Computer);
        if ($item instanceof Computer) {
            self::showCoverage($item->getID());
        }
        return true;
    }

    /** Tab badge: a COUNT, not the full list (runs on every Computer/Software page load). */
    private static function countRows(CommonGLPI $item): int
    {
        global $DB;
        $criteria = self::criteria($item);
        unset($criteria['DISTINCT'], $criteria['ORDER']);
        $criteria['SELECT'] = ['COUNT DISTINCT' => 'f.id AS cpt'];
        return (int) $DB->request($criteria)->current()['cpt'];
    }

    /** Findings for a computer (via installs) or a software (via its versions), most urgent first. */
    public static function rows(CommonGLPI $item): array
    {
        global $DB;
        return iterator_to_array($DB->request(self::criteria($item)), false);
    }

    private static function criteria(CommonGLPI $item): array
    {
        $where = match (true) {
            $item instanceof Computer => [
                'isv.itemtype' => 'Computer', 'isv.items_id' => $item->getID(), 'isv.is_deleted' => 0,
            ],
            $item instanceof Software => ['sv.softwares_id' => $item->getID()],
            default => ['f.id' => -1],
        };
        $joins = [
            'glpi_plugin_mlabvuln_cves AS c' => ['ON' => ['c' => 'id', 'f' => 'plugin_mlabvuln_cves_id']],
            'glpi_softwareversions AS sv'    => ['ON' => ['sv' => 'id', 'f' => 'softwareversions_id']],
            'glpi_softwares AS s'            => ['ON' => ['s' => 'id', 'sv' => 'softwares_id']],
        ];
        if ($item instanceof Computer) {
            $joins = ['glpi_items_softwareversions AS isv' => ['ON' => ['isv' => 'softwareversions_id', 'f' => 'softwareversions_id']]] + $joins;
        }
        return [
            'SELECT'     => ['c.*', 's.name AS software', 's.id AS softwares_id', 'sv.name AS version', 'f.fixed_version', 'f.source'],
            'DISTINCT'   => true,
            'FROM'       => 'glpi_plugin_mlabvuln_findings AS f',
            'INNER JOIN' => $joins,
            'WHERE'      => $where,
            'ORDER'      => ['c.score DESC', 'c.name DESC'],
        ];
    }

    public static function badge(array $c): string
    {
        [$class, $label] = self::BADGES[Matcher::priority((bool) $c['is_kev'], (float) $c['epss'], (float) $c['cvss_score'])];
        return sprintf('<span class="badge %s text-white">%s</span>', $class, htmlescape($label));
    }

    public static function showTable(array $rows, bool $with_software = true): void
    {
        if (!$rows) {
            echo '<div class="alert alert-success m-3">Aucune vulnérabilité connue.</div>';
            return;
        }
        $counts = array_count_values(array_map(
            fn($c) => Matcher::priority((bool) $c['is_kev'], (float) $c['epss'], (float) $c['cvss_score']),
            $rows
        ));
        echo '<div class="m-2">';
        foreach (self::BADGES as $k => [$class, $label]) {
            printf('<span class="badge %s text-white me-2 fs-5">%s : %d</span>', $class, htmlescape($label), $counts[$k] ?? 0);
        }
        echo '</div>';
        self::showSummary($rows);

        $max = 200;
        printf(
            '<h3 class="m-2">Détail%s</h3>',
            count($rows) > $max ? htmlescape(" : les $max plus urgentes sur " . count($rows)) : ''
        );
        echo '<table class="table table-hover table-sm"><thead><tr>
            <th>Priorité</th><th>CVE</th><th>Logiciel</th><th>Version</th><th>Corrigé en</th>
            <th>CVSS</th><th>EPSS</th><th>KEV</th><th>Source</th></tr></thead><tbody>';
        foreach (array_slice($rows, 0, $max) as $c) {
            printf(
                '<tr><td>%s</td><td><a href="%s" title="%s">%s</a></td><td><a href="%s">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="text-muted">%s</td></tr>',
                self::badge($c),
                htmlescape(Cve::getFormURLWithID($c['id'])),
                htmlescape(mb_substr($c['description'] ?? '', 0, 300)),
                htmlescape($c['name']),
                htmlescape(Software::getFormURLWithID($c['softwares_id'])),
                htmlescape($c['software']),
                htmlescape($c['version']),
                htmlescape($c['fixed_version']),
                $c['date_sync'] ? htmlescape($c['cvss_score']) : '…',
                $c['date_sync'] ? sprintf('%.1f%%', $c['epss'] * 100) : '…',
                $c['is_kev'] ? '<span class="badge bg-danger text-white">KEV</span> ' . htmlescape($c['kev_due_date'] ?? '') : '',
                htmlescape($c['source'])
            );
        }
        echo '</tbody></table>';
    }

    /** One line per installed version: what to upgrade to, and what it fixes. Rows are already sorted by urgency. */
    private static function showSummary(array $rows): void
    {
        $by = [];
        foreach ($rows as $c) {
            $k = $c['software'] . ' ' . $c['version'];
            $by[$k] ??= ['first' => $c, 'nb' => 0, 'kev' => 0, 'fix' => '', 'nofix' => 0];
            $by[$k]['nb']++;
            $by[$k]['kev'] += (int) $c['is_kev'];
            $by[$k]['nofix'] += (int) ($c['fixed_version'] === '');
            // ponytail: version_compare approximates dpkg/rpm ordering (~, epochs); use a real dpkg comparator if it misleads
            if ($c['fixed_version'] !== '' && version_compare($c['fixed_version'], $by[$k]['fix'], '>')) {
                $by[$k]['fix'] = $c['fixed_version'];
            }
        }
        echo '<h3 class="m-2">À mettre à jour</h3><table class="table table-sm"><thead><tr>
            <th>Priorité</th><th>Logiciel</th><th>Version installée</th><th>CVE</th><th>dont KEV</th><th>Mettre à jour vers</th></tr></thead><tbody>';
        foreach ($by as $x) {
            $c = $x['first'];
            printf(
                '<tr><td>%s</td><td><a href="%s">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td><b>%s</b></td></tr>',
                self::badge($c),
                htmlescape(Software::getFormURLWithID($c['softwares_id'])),
                htmlescape($c['software']),
                htmlescape($c['version']),
                $x['nb'],
                $x['kev'] ? '<span class="badge bg-danger text-white">' . $x['kev'] . '</span>' : '0',
                htmlescape(
                    ($x['fix'] ?: 'pas de correctif connu')
                    . ($x['fix'] && $x['nofix'] ? " ({$x['nofix']} CVE sans correctif)" : '')
                )
            );
        }
        echo '</tbody></table>';
    }

    /** Which installed software could be checked, so "0 CVE" is never mistaken for "safe". */
    private static function showCoverage(int $computers_id): void
    {
        global $DB;
        $res = $DB->request([
            'SELECT'    => ['sc.status', 'COUNT DISTINCT' => 'isv.softwareversions_id AS nb'],
            'FROM'      => 'glpi_items_softwareversions AS isv',
            'LEFT JOIN' => ['glpi_plugin_mlabvuln_scans AS sc' => ['ON' => ['sc' => 'softwareversions_id', 'isv' => 'softwareversions_id']]],
            'WHERE'     => ['isv.itemtype' => 'Computer', 'isv.items_id' => $computers_id, 'isv.is_deleted' => 0],
            'GROUPBY'   => 'sc.status',
        ]);
        $labels = ['ok' => 'vérifiés', 'nomatch' => 'non couverts (aucune règle CPE)', 'error' => 'en erreur', '' => 'pas encore scannés'];
        $parts = [];
        foreach ($res as $r) {
            $parts[] = $r['nb'] . ' ' . $labels[$r['status'] ?? ''];
        }
        echo '<p class="text-muted m-2">Logiciels : ' . htmlescape(implode(' · ', $parts)) . '</p>';
    }
}
