<?php

namespace GlpiPlugin\Mlabvuln;

use CommonDBTM;
use Computer;
use Glpi\Search\DefaultSearchRequestInterface;
use Html;
use Ticket;

/**
 * A CVE present somewhere in the fleet. Tools > Vulnérabilités lists them (generic search engine).
 */
final class Cve extends CommonDBTM implements DefaultSearchRequestInterface
{
    public static $rightname = 'software';

    public static function getTypeName($nb = 0)
    {
        return _n('Vulnérabilité', 'Vulnérabilités', $nb);
    }

    public static function getIcon()
    {
        return 'ti ti-shield-exclamation';
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function canUpdate(): bool
    {
        return false;
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    public function rawSearchOptions()
    {
        $t = self::getTable();
        return [
            ['id' => 'common', 'name' => self::getTypeName(1)],
            ['id' => 1, 'table' => $t, 'field' => 'name', 'name' => 'CVE', 'datatype' => 'itemlink'],
            ['id' => 2, 'table' => $t, 'field' => 'id', 'name' => 'ID', 'datatype' => 'number', 'massiveaction' => false],
            ['id' => 3, 'table' => $t, 'field' => 'cvss_score', 'name' => 'CVSS', 'datatype' => 'decimal'],
            ['id' => 4, 'table' => $t, 'field' => 'severity', 'name' => 'Sévérité', 'datatype' => 'string'],
            ['id' => 5, 'table' => $t, 'field' => 'epss', 'name' => 'EPSS', 'datatype' => 'decimal', 'decimal' => 3],
            ['id' => 6, 'table' => $t, 'field' => 'is_kev', 'name' => 'CISA KEV', 'datatype' => 'bool'],
            ['id' => 7, 'table' => $t, 'field' => 'kev_due_date', 'name' => 'Échéance KEV', 'datatype' => 'date'],
            ['id' => 8, 'table' => $t, 'field' => 'description', 'name' => __('Description'), 'datatype' => 'text'],
            ['id' => 9, 'table' => $t, 'field' => 'date_sync', 'name' => 'Synchronisé le', 'datatype' => 'datetime'],
            ['id' => 12, 'table' => $t, 'field' => 'score', 'name' => 'Score de priorité', 'datatype' => 'decimal', 'massiveaction' => false],
            [
                'id' => 10, 'table' => 'glpi_plugin_mlabvuln_findings', 'field' => 'id', 'name' => 'Versions touchées',
                'datatype' => 'count', 'forcegroupby' => true, 'usehaving' => true, 'massiveaction' => false,
                'joinparams' => ['jointype' => 'child'],
            ],
            [
                'id' => 11, 'table' => 'glpi_softwares', 'field' => 'name', 'name' => __('Software'),
                'datatype' => 'itemlink', 'forcegroupby' => true, 'massiveaction' => false,
                'joinparams' => ['beforejoin' => [
                    'table' => 'glpi_softwareversions',
                    'joinparams' => ['beforejoin' => [
                        'table' => 'glpi_plugin_mlabvuln_findings', 'joinparams' => ['jointype' => 'child'],
                    ]],
                ]],
            ],
        ];
    }

    public static function getDefaultSearchRequest(): array
    {
        return ['sort' => 12, 'order' => 'DESC'];
    }

    public function showForm($ID, array $options = [])
    {
        global $DB;
        if (!$this->getFromDB($ID)) {
            return false;
        }
        $c = $this->fields;
        printf(
            '<div class="card m-2"><div class="card-body">
               <h2>%s %s</h2><p>%s</p>
               <p>CVSS <b>%s</b> %s · EPSS <b>%.1f%%</b> %s</p>
               <p><a target="_blank" href="https://vuln.mlab.sh/cve/%s">Voir sur vuln.mlab.sh</a></p>',
            htmlescape($c['name']),
            Finding::badge($c),
            htmlescape($c['description'] ?? ''),
            htmlescape($c['cvss_score']),
            htmlescape($c['severity']),
            $c['epss'] * 100,
            $c['is_kev'] ? '· <span class="badge bg-danger text-white">CISA KEV</span> échéance ' . htmlescape($c['kev_due_date'] ?? '?') : '',
            rawurlencode($c['name'])
        );
        $t = $DB->request(['FROM' => 'glpi_plugin_mlabvuln_tickets', 'WHERE' => ['plugin_mlabvuln_cves_id' => $ID]])->current();
        if ($t) {
            printf('<p>Ticket : <a href="%s">#%d</a></p>', htmlescape(Ticket::getFormURLWithID($t['tickets_id'])), $t['tickets_id']);
        }

        $rows = $DB->request([
            'SELECT'     => ['comp.id', 'comp.name', 's.name AS software', 'sv.name AS version', 'f.fixed_version'],
            'DISTINCT'   => true,
            'FROM'       => 'glpi_plugin_mlabvuln_findings AS f',
            'INNER JOIN' => [
                'glpi_items_softwareversions AS isv' => ['ON' => ['isv' => 'softwareversions_id', 'f' => 'softwareversions_id'], ['AND' => ['isv.itemtype' => 'Computer', 'isv.is_deleted' => 0]]],
                'glpi_computers AS comp' => ['ON' => ['comp' => 'id', 'isv' => 'items_id']],
                'glpi_softwareversions AS sv' => ['ON' => ['sv' => 'id', 'f' => 'softwareversions_id']],
                'glpi_softwares AS s' => ['ON' => ['s' => 'id', 'sv' => 'softwares_id']],
            ],
            'WHERE' => ['f.plugin_mlabvuln_cves_id' => $ID, 'comp.is_deleted' => 0] + getEntitiesRestrictCriteria('comp'),
            'ORDER' => 'comp.name',
        ]);
        echo '<h3>Machines exposées (' . count($rows) . ')</h3><table class="table table-sm"><thead><tr><th>Ordinateur</th><th>Logiciel</th><th>Version</th><th>Corrigé en</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            printf(
                '<tr><td><a href="%s">%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>',
                htmlescape(Computer::getFormURLWithID($r['id'])),
                htmlescape($r['name']),
                htmlescape($r['software']),
                htmlescape($r['version']),
                htmlescape($r['fixed_version'])
            );
        }
        echo '</tbody></table></div></div>';
        return true;
    }
}
