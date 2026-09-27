<?php

namespace GlpiPlugin\Mlabvuln;

use CommonGLPI;
use Config;
use CronTask;
use GLPIKey;
use Item_Ticket;
use Ticket;
use Throwable;

final class Scanner extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return 'mlab vuln';
    }

    public const DEFAULT_CONFIG = [
        'api_url'            => 'https://vuln.mlab.sh',
        'api_token'          => '',      // personal token from vuln.mlab.sh/me/tokens, raises quotas
        'rescan_hours'       => 24,
        'product_cache_days' => 7,
        'cve_refresh_days'   => 3,
        'ticket_mode'        => 'kev',   // off | kev | kev_epss
        'epss_threshold'     => 0.5,
    ];

    private Api $api;
    private array $cfg;
    private array $products = [];
    private array $cveIds = [];   // per-run cache: CVE name => row id
    private array $stats = ['scanned' => 0, 'osv' => 0, 'cpe' => 0, 'nomatch' => 0, 'errors' => 0, 'enriched' => 0, 'tickets' => 0];

    public static function config(): array
    {
        $cfg = Config::getConfigurationValues('plugin:mlabvuln') + self::DEFAULT_CONFIG;
        // encrypted on write by GLPI (secured_configs hook), not decrypted on read
        $cfg['api_token'] = $cfg['api_token'] !== '' ? (string) (new GLPIKey())->decrypt($cfg['api_token']) : '';
        return $cfg;
    }

    public static function cronInfo($name): array
    {
        return ['description' => 'Scan des vulnérabilités (vuln.mlab.sh)', 'parameter' => 'Versions logicielles par exécution'];
    }

    public static function cronScan(CronTask $task): int
    {
        $stats = (new self())->run((int) ($task->fields['param'] ?: 2000));
        $task->addVolume($stats['scanned']);
        $task->log(json_encode($stats));
        return $stats['scanned'] > 0 ? 1 : 0;
    }

    public function __construct()
    {
        $this->cfg = self::config();
        $this->api = new Api($this->cfg['api_url'], (string) $this->cfg['api_token']);
    }

    public function run(int $limit): array
    {
        $rules = CpeRule::activeRules();
        $due = $this->dueVersions($limit);
        // OSV lookups (~1 s each) are fetched concurrently up front
        $queries = [];
        foreach ($due as $sv) {
            if ($eco = Matcher::ecosystem($sv['os'])) {
                $queries[$sv['id']] = [$eco, $sv['software'], $sv['version']];
            }
        }
        $osv = $queries ? $this->api->osvMany($queries) : [];
        foreach ($due as $sv) {
            $this->scanVersion($sv, $rules, $osv[$sv['id']] ?? null);
        }
        $this->enrich();
        $this->purgeOrphans();
        $this->tickets();
        return $this->stats;
    }

    /** Installed versions never scanned or scanned more than rescan_hours ago, oldest first. */
    private function dueVersions(int $limit): array
    {
        global $DB;
        $hours = (int) $this->cfg['rescan_hours'];
        $res = $DB->doQuery("
            SELECT sv.id, sv.name AS version, s.name AS software, COALESCE(m.name, '') AS publisher, COALESCE(os.name, '') AS os
            FROM glpi_softwareversions sv
            JOIN glpi_softwares s ON s.id = sv.softwares_id AND s.is_deleted = 0
            JOIN (SELECT DISTINCT softwareversions_id FROM glpi_items_softwareversions WHERE is_deleted = 0) i
                ON i.softwareversions_id = sv.id
            LEFT JOIN glpi_manufacturers m ON m.id = s.manufacturers_id
            LEFT JOIN glpi_operatingsystems os ON os.id = sv.operatingsystems_id
            LEFT JOIN glpi_plugin_mlabvuln_scans sc ON sc.softwareversions_id = sv.id
            WHERE sc.date_scan IS NULL OR sc.date_scan < NOW() - INTERVAL $hours HOUR
            ORDER BY sc.date_scan IS NOT NULL, sc.date_scan
            LIMIT " . max(1, $limit));
        return $res->fetch_all(MYSQLI_ASSOC);
    }

    private function scanVersion(array $sv, array $rules, array|Throwable|null $osv): void
    {
        global $DB;
        $this->stats['scanned']++;
        $method = '';
        try {
            if ($eco = Matcher::ecosystem($sv['os'])) {
                $method = "osv:$eco";
                if ($osv instanceof Throwable) {
                    throw $osv;
                }
                $found = $this->osvFindings($eco, $sv['software'], $osv ?? []);
                $this->stats['osv']++;
            } elseif ($rule = CpeRule::match($rules, $sv['software'], $sv['publisher'])) {
                $method = "cpe:{$rule['vendor']}:{$rule['product']}";
                $found = $this->cpeFindings($rule, $sv['version']);
                $this->stats['cpe']++;
            } else {
                $found = [];
                $this->stats['nomatch']++;
            }
            $this->saveFindings((int) $sv['id'], $found, $method);
            $status = $method === '' ? 'nomatch' : 'ok';
            $message = count($found) . ' CVE';
        } catch (Throwable $e) {
            // keep previous findings: an outage is not a clean result
            $this->stats['errors']++;
            $status = 'error';
            $message = mb_substr($e->getMessage(), 0, 255);
        }
        $DB->updateOrInsert('glpi_plugin_mlabvuln_scans', [
            'method' => $method, 'status' => $status, 'message' => $message, 'date_scan' => date('Y-m-d H:i:s'),
        ], ['softwareversions_id' => (int) $sv['id']]);
    }

    /** @return array<string, array{fixed: string, meta: ?array}> keyed by CVE id */
    private function osvFindings(string $eco, string $name, array $vulns): array
    {
        $out = [];
        foreach ($vulns as $vuln) {
            // "CVE-x", "UBUNTU-CVE-x", "DEBIAN-CVE-x"… → "CVE-x"
            $cves = fn(array $ids) => array_values(array_filter(array_map(
                fn($id) => preg_match('/CVE-\d{4}-\d+/', $id, $m) ? $m[0] : null,
                $ids
            )));
            // distro advisories (USN, some ALSA…) only list their CVEs under "related"
            $ids = $cves(array_merge([$vuln['id']], $vuln['aliases'] ?? [], $vuln['upstream'] ?? []))
                ?: $cves($vuln['related'] ?? [])
                ?: [$vuln['id']];
            $fixed = '';
            foreach ($vuln['affected'] ?? [] as $aff) {
                // one advisory can cover dozens of packages (e.g. HTTP/2 Rapid Reset): keep ours only
                $aff_eco = $aff['package']['ecosystem'] ?? '';
                // answers may be more specific than the query: "Ubuntu:22.04" → "Ubuntu:22.04:LTS"
                if (($aff_eco !== $eco && !str_starts_with($aff_eco, "$eco:")) || ($aff['package']['name'] ?? '') !== $name) {
                    continue;
                }
                foreach ($aff['ranges'] ?? [] as $range) {
                    foreach ($range['events'] as $ev) {
                        $fixed = $ev['fixed'] ?? $fixed;
                    }
                }
            }
            foreach (array_unique($ids) as $id) {
                $out[$id] = ['fixed' => $fixed ?: ($out[$id]['fixed'] ?? ''), 'meta' => null];
            }
        }
        return $out;
    }

    private function cpeFindings(array $rule, string $version): array
    {
        $out = [];
        foreach ($this->product($rule) as $cve) {
            foreach ($cve['m'] as $match) {
                if (Matcher::cpeMatches($match, $rule['vendor'], $rule['product'], $version)) {
                    $out[$cve['id']] = ['fixed' => $match['version_end_excluding'] ?? '', 'meta' => $cve];
                    break;
                }
            }
        }
        return $out;
    }

    /** Every CVE of a CPE product with its relevant cpe_matches, cached product_cache_days in DB. */
    private function product(array $rule): array
    {
        global $DB;
        $key = ['vendor' => $rule['vendor'], 'product' => $rule['product']];
        $k = implode(':', $key);
        if (isset($this->products[$k])) {
            return $this->products[$k];
        }
        $days = (int) $this->cfg['product_cache_days'];
        $row = $DB->request(['FROM' => 'glpi_plugin_mlabvuln_products', 'WHERE' => $key])->current();
        if ($row && strtotime($row['date_sync']) > time() - $days * DAY_TIMESTAMP) {
            return $this->products[$k] = json_decode($row['data'], true);
        }

        $cves = [];
        // ponytail: 200 pages (20k CVEs) cap, enough for Chrome (~7k); raise if a product outgrows it
        $this->api->searchAll($rule['search_term'] ?: str_replace('_', ' ', $rule['product']), 200, function (array $c) use ($rule, &$cves) {
            $m = array_values(array_filter(
                $c['cpe_matches'] ?? [],
                fn($m) => array_slice(Matcher::cpeParts($m['criteria'] ?? ''), 3, 2) === [$rule['vendor'], $rule['product']]
            ));
            if ($m) {
                $cves[$c['id']] = [
                    'id' => $c['id'], 'm' => $m,
                    'description' => mb_substr($c['description'] ?? '', 0, 1000),
                    'cvss_score' => $c['cvss_score'] ?? 0, 'cvss_severity' => $c['cvss_severity'] ?? '',
                    'epss_score' => $c['epss_score'] ?? 0, 'in_kev' => $c['in_kev'] ?? false,
                    'kev_due_date' => $c['kev_due_date'] ?? null,
                ];
            }
        });
        $cves = array_values($cves);
        $DB->updateOrInsert('glpi_plugin_mlabvuln_products', ['data' => json_encode($cves), 'date_sync' => date('Y-m-d H:i:s')], $key);
        return $this->products[$k] = $cves;
    }

    private function saveFindings(int $svid, array $found, string $source): void
    {
        global $DB;
        $ids = $this->cveIds($found);

        $existing = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_mlabvuln_findings', 'WHERE' => ['softwareversions_id' => $svid]]) as $row) {
            $existing[$row['plugin_mlabvuln_cves_id']] = $row;
        }
        $insert = [];
        foreach ($found as $cve => $f) {
            $cid = $ids[$cve];
            $fixed = mb_substr((string) $f['fixed'], 0, 255);
            if (!isset($existing[$cid])) {
                $insert[] = [$svid, $cid, $source, $fixed, date('Y-m-d H:i:s')];
            } elseif ($existing[$cid]['fixed_version'] !== $fixed || $existing[$cid]['source'] !== $source) {
                $DB->update('glpi_plugin_mlabvuln_findings', ['fixed_version' => $fixed, 'source' => $source], ['id' => $existing[$cid]['id']]);
            }
            unset($existing[$cid]);
        }
        self::bulkInsert('glpi_plugin_mlabvuln_findings', ['softwareversions_id', 'plugin_mlabvuln_cves_id', 'source', 'fixed_version', 'date_creation'], $insert);
        if ($existing) {
            $DB->delete('glpi_plugin_mlabvuln_findings', ['id' => array_column($existing, 'id')]);
        }
    }

    /**
     * CVE name => row id, creating missing rows. Search metadata (CPE path) is written once per run per CVE.
     * @return array<string, int>
     */
    private function cveIds(array $found): array
    {
        global $DB;
        $cols = ['name', 'score', 'description', 'cvss_score', 'severity', 'epss', 'is_kev', 'kev_due_date', 'date_sync'];
        $with_meta = $bare = [];
        foreach ($found as $name => $f) {
            if (isset($this->cveIds[$name])) {
                continue;
            }
            if ($f['meta']) {
                $with_meta[] = array_merge([$name], array_values(self::cveFields($f['meta'])));
            } elseif (!str_starts_with($name, 'CVE-')) {
                // distro advisory with no CVE (USN-xxxx…): nothing to enrich from, mark synced
                $bare[] = [$name, date('Y-m-d H:i:s')];
            } else {
                $bare[] = [$name, null];
            }
        }
        $update = implode(', ', array_map(fn($c) => "`$c` = VALUES(`$c`)", array_slice($cols, 1)));
        self::bulkInsert('glpi_plugin_mlabvuln_cves', $cols, $with_meta, "ON DUPLICATE KEY UPDATE $update");
        self::bulkInsert('glpi_plugin_mlabvuln_cves', ['name', 'date_sync'], $bare, 'ON DUPLICATE KEY UPDATE `date_sync` = COALESCE(`date_sync`, VALUES(`date_sync`))');

        $missing = array_keys(array_diff_key($found, $this->cveIds));
        foreach (array_chunk($missing, 1000) as $chunk) {
            foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_plugin_mlabvuln_cves', 'WHERE' => ['name' => $chunk]]) as $row) {
                $this->cveIds[$row['name']] = (int) $row['id'];
            }
        }
        return $this->cveIds;
    }

    /** Multi-row INSERT, 500 rows per statement. */
    private static function bulkInsert(string $table, array $cols, array $rows, string $suffix = ''): void
    {
        global $DB;
        $names = implode(', ', array_map([$DB, 'quoteName'], $cols));
        foreach (array_chunk($rows, 500) as $chunk) {
            $values = implode(', ', array_map(
                fn($r) => '(' . implode(', ', array_map([$DB, 'quoteValue'], $r)) . ')',
                $chunk
            ));
            $DB->doQuery("INSERT INTO `$table` ($names) VALUES $values $suffix");
        }
    }

    private static function cveFields(array $c): array
    {
        $kev = empty($c['in_kev']) ? 0 : 1;
        return [
            // single sortable key for list views: KEV, then EPSS, then CVSS
            'score'        => $kev * 100 + (float) ($c['epss_score'] ?? 0) * 10 + (float) ($c['cvss_score'] ?? 0) / 10,
            'description'  => mb_substr($c['description'] ?? '', 0, 1000),
            'cvss_score'   => (float) ($c['cvss_score'] ?? 0),
            'severity'     => (string) ($c['cvss_severity'] ?? ''),
            'epss'         => (float) ($c['epss_score'] ?? 0),
            'is_kev'       => $kev,
            'kev_due_date' => $c['kev_due_date'] ? substr($c['kev_due_date'], 0, 10) : null,
            'date_sync'    => date('Y-m-d H:i:s'),
        ];
    }

    /** CVSS / EPSS / KEV for CVEs found via OSV (or stale). */
    private function enrich(): void
    {
        global $DB;
        $days = (int) $this->cfg['cve_refresh_days'];
        $res = $DB->doQuery("
            SELECT c.id, c.name FROM glpi_plugin_mlabvuln_cves c
            WHERE (c.date_sync IS NULL OR c.date_sync < NOW() - INTERVAL $days DAY)
              AND c.name LIKE 'CVE-%'
              AND EXISTS (SELECT 1 FROM glpi_plugin_mlabvuln_findings f WHERE f.plugin_mlabvuln_cves_id = c.id)
            LIMIT 1000");
        $rows = array_column($res->fetch_all(MYSQLI_ASSOC), 'id', 'name');
        foreach ($rows ? $this->api->cveMany(array_keys($rows)) : [] as $name => $c) {
            if ($c instanceof Throwable) {
                $this->stats['errors']++;
                continue;
            }
            $row = ['id' => $rows[$name]];
            // unknown upstream: mark synced so we do not hammer it every run
            $DB->update('glpi_plugin_mlabvuln_cves', $c ? self::cveFields($c) : ['date_sync' => date('Y-m-d H:i:s')], ['id' => $row['id']]);
            $this->stats['enriched']++;
        }
    }

    private function purgeOrphans(): void
    {
        global $DB;
        $DB->doQuery("
            DELETE c FROM glpi_plugin_mlabvuln_cves c
            LEFT JOIN glpi_plugin_mlabvuln_findings f ON f.plugin_mlabvuln_cves_id = c.id
            LEFT JOIN glpi_plugin_mlabvuln_tickets t ON t.plugin_mlabvuln_cves_id = c.id
            WHERE f.id IS NULL AND t.id IS NULL");
    }

    /** One ticket per KEV (or high-EPSS) CVE, linked to every exposed computer. */
    private function tickets(): void
    {
        global $DB;
        $mode = $this->cfg['ticket_mode'];
        if ($mode === 'off') {
            return;
        }
        $cond = $mode === 'kev_epss' ? '(c.is_kev = 1 OR c.epss >= ' . (float) $this->cfg['epss_threshold'] . ')' : 'c.is_kev = 1';
        $installs = "JOIN glpi_plugin_mlabvuln_findings f ON f.plugin_mlabvuln_cves_id = c.id
            JOIN glpi_items_softwareversions isv ON isv.softwareversions_id = f.softwareversions_id
                AND isv.itemtype = 'Computer' AND isv.is_deleted = 0
            JOIN glpi_computers comp ON comp.id = isv.items_id AND comp.is_deleted = 0 AND comp.is_template = 0";
        // three narrow queries: one wide row per (CVE x computer) would carry the description thousands of times
        $by_cve = [];
        foreach ($DB->doQuery("SELECT DISTINCT c.* FROM glpi_plugin_mlabvuln_cves c $installs WHERE $cond") as $r) {
            $by_cve[$r['id']] = ['cve' => $r, 'computers' => [], 'soft' => []];
        }
        if (!$by_cve) {
            return;
        }
        foreach ($DB->doQuery("SELECT DISTINCT c.id, isv.items_id, comp.entities_id FROM glpi_plugin_mlabvuln_cves c $installs WHERE $cond") as $r) {
            $by_cve[$r['id']]['computers'][$r['items_id']] = (int) $r['entities_id'];
        }
        foreach ($DB->doQuery("
            SELECT DISTINCT c.id, s.name AS software, sv.name AS version, f.fixed_version
            FROM glpi_plugin_mlabvuln_cves c $installs
            JOIN glpi_softwareversions sv ON sv.id = f.softwareversions_id
            JOIN glpi_softwares s ON s.id = sv.softwares_id
            WHERE $cond") as $r) {
            $by_cve[$r['id']]['soft']["{$r['software']} {$r['version']}"] = $r['fixed_version'];
        }

        foreach ($by_cve as $cid => $x) {
            $ticket = new Ticket();
            $link = $DB->request(['FROM' => 'glpi_plugin_mlabvuln_tickets', 'WHERE' => ['plugin_mlabvuln_cves_id' => $cid]])->current();
            if (!$link || !$ticket->getFromDB($link['tickets_id']) || $ticket->fields['status'] == Ticket::CLOSED) {
                $tid = $this->createTicket($x['cve'], $x['soft'], min($x['computers']));
                if (!$tid) {
                    continue;
                }
                $DB->updateOrInsert('glpi_plugin_mlabvuln_tickets', ['tickets_id' => $tid], ['plugin_mlabvuln_cves_id' => $cid]);
                $ticket->getFromDB($tid);
                $this->stats['tickets']++;
            }
            // ponytail: raw bulk insert (no per-link history / hooks): Item_Ticket::add costs ~3.4 ms per link,
            // i.e. minutes for a KEV on thousands of machines. Switch back to add() if link history matters.
            $linked = array_column(iterator_to_array($DB->request([
                'SELECT' => 'items_id', 'FROM' => Item_Ticket::getTable(),
                'WHERE'  => ['tickets_id' => $ticket->getID(), 'itemtype' => 'Computer'],
            ])), 'items_id', 'items_id');
            $missing = array_diff_key($x['computers'], $linked);
            self::bulkInsert(
                Item_Ticket::getTable(),
                ['tickets_id', 'itemtype', 'items_id'],
                array_map(fn($id) => [$ticket->getID(), 'Computer', $id], array_keys($missing))
            );
        }
    }

    private function createTicket(array $c, array $softs, int $entity): int|false
    {
        $kev = $c['is_kev'] ? 'KEV' : sprintf('EPSS %.0f%%', $c['epss'] * 100);
        $lines = '';
        foreach ($softs as $soft => $fixed) {
            $lines .= '<li>' . htmlescape($soft) . ($fixed ? ' → corrigé en <b>' . htmlescape($fixed) . '</b>' : '') . '</li>';
        }
        $content = sprintf(
            '<p><b>%s</b> : CVSS %s, EPSS %.1f%%%s</p><p>%s</p><p>Logiciels concernés :</p><ul>%s</ul><p><a href="https://vuln.mlab.sh/cve/%s">Détail sur vuln.mlab.sh</a></p>',
            htmlescape($c['name']),
            htmlescape($c['cvss_score']),
            $c['epss'] * 100,
            $c['is_kev'] ? ', <b>exploitée activement (CISA KEV)</b>, échéance ' . htmlescape($c['kev_due_date'] ?? '?') : '',
            htmlescape($c['description'] ?? ''),
            $lines,
            rawurlencode($c['name'])
        );
        $input = [
            'name'        => sprintf('[Vuln] %s (%s) : %s', $c['name'], $kev, implode(', ', array_keys($softs))),
            'content'     => $content,
            'entities_id' => $entity,
            'type'        => Ticket::INCIDENT_TYPE,
            'urgency'     => $c['is_kev'] ? 5 : 4,
            'impact'      => $c['is_kev'] ? 5 : 4,
        ];
        if (!empty($c['kev_due_date']) && strtotime($c['kev_due_date']) > time()) {
            $input['time_to_resolve'] = $c['kev_due_date'] . ' 23:59:59';
        }
        $input['name'] = mb_substr($input['name'], 0, 250);
        return (new Ticket())->add($input);
    }
}
