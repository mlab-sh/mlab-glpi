<?php

namespace GlpiPlugin\Mlabvuln;

use CommonDropdown;
use Session;

/**
 * Inventoried software name (+ publisher) → NVD CPE vendor:product.
 * CommonDropdown gives list / form / search for free (GLPI 11 generic controllers).
 */
final class CpeRule extends CommonDropdown
{
    public static $rightname = 'config';

    /** [label, name regex, vendor, product, search term], CPE ids checked against vuln.mlab.sh */
    public const DEFAULTS = [
        ['Google Chrome', '^Google Chrome', 'google', 'chrome', 'google chrome'],
        ['Mozilla Firefox', '^Mozilla Firefox', 'mozilla', 'firefox', 'firefox'],
        ['Mozilla Thunderbird', '^Mozilla Thunderbird', 'mozilla', 'thunderbird', 'thunderbird'],
        ['Microsoft Edge', '^Microsoft Edge$', 'microsoft', 'edge_chromium', 'microsoft edge'],
        ['7-Zip', '^7-Zip', '7-zip', '7-zip', '7-zip'],
        ['Notepad++', '^Notepad\+\+', 'notepad-plus-plus', 'notepad++', 'notepad++'],
        ['VLC', '^VLC media player', 'videolan', 'vlc_media_player', 'vlc'],
        ['Adobe Acrobat Reader', '^Adobe Acrobat (Reader|DC)', 'adobe', 'acrobat_reader_dc', 'acrobat reader'],
        ['WinRAR', '^WinRAR', 'rarlab', 'winrar', 'winrar'],
        ['PuTTY', '^PuTTY', 'putty', 'putty', 'putty'],
        ['WinSCP', '^WinSCP', 'winscp', 'winscp', 'winscp'],
        ['FileZilla', '^FileZilla', 'filezilla-project', 'filezilla_client', 'filezilla'],
        ['KeePass', '^KeePass', 'keepass', 'keepass', 'keepass'],
        ['Wireshark', '^Wireshark', 'wireshark', 'wireshark', 'wireshark'],
        ['OpenVPN', '^OpenVPN', 'openvpn', 'openvpn', 'openvpn'],
        ['TeamViewer', '^TeamViewer', 'teamviewer', 'teamviewer', 'teamviewer'],
        ['AnyDesk', '^AnyDesk', 'anydesk', 'anydesk', 'anydesk'],
        ['LibreOffice', '^LibreOffice', 'libreoffice', 'libreoffice', 'libreoffice'],
    ];

    // "config" right only knows READ / UPDATE: map create/delete/purge on UPDATE
    public static function canCreate(): bool
    {
        return Session::haveRight(self::$rightname, UPDATE);
    }

    public static function canDelete(): bool
    {
        return self::canCreate();
    }

    public static function canPurge(): bool
    {
        return self::canCreate();
    }

    public static function getTypeName($nb = 0)
    {
        return _n('Règle CPE', 'Règles CPE', $nb);
    }

    public function getAdditionalFields()
    {
        return [
            ['name' => 'name_pattern', 'label' => 'Regex nom du logiciel', 'type' => 'text', 'list' => true],
            ['name' => 'publisher_pattern', 'label' => 'Regex éditeur (optionnel)', 'type' => 'text', 'list' => true],
            ['name' => 'vendor', 'label' => 'CPE vendor', 'type' => 'text', 'list' => true],
            ['name' => 'product', 'label' => 'CPE product', 'type' => 'text', 'list' => true],
            ['name' => 'search_term', 'label' => 'Terme de recherche vuln.mlab.sh', 'type' => 'text', 'list' => true],
            ['name' => 'is_active', 'label' => __('Active'), 'type' => 'bool', 'list' => true],
        ];
    }

    public function rawSearchOptions()
    {
        $opts = parent::rawSearchOptions();
        $id = 100;
        foreach ($this->getAdditionalFields() as $f) {
            $opts[] = [
                'id' => $id++, 'table' => self::getTable(), 'field' => $f['name'], 'name' => $f['label'],
                'datatype' => $f['type'] === 'bool' ? 'bool' : 'string',
            ];
        }
        return $opts;
    }

    /** A new or changed rule must apply at the next cron run, not after rescan_hours. */
    public function post_addItem()
    {
        $this->queueRescan();
    }

    public function post_updateItem($history = true)
    {
        $this->queueRescan();
    }

    public function post_purgeItem()
    {
        $this->queueRescan();
    }

    private function queueRescan(): void
    {
        global $DB;
        $methods = ["cpe:{$this->fields['vendor']}:{$this->fields['product']}"];
        if (isset($this->oldvalues['vendor']) || isset($this->oldvalues['product'])) {
            $methods[] = 'cpe:' . ($this->oldvalues['vendor'] ?? $this->fields['vendor']) . ':' . ($this->oldvalues['product'] ?? $this->fields['product']);
        }
        $DB->update('glpi_plugin_mlabvuln_scans', ['date_scan' => null], ['OR' => ['status' => 'nomatch', 'method' => $methods]]);
    }

    public function post_getEmpty()
    {
        $this->fields['is_active'] = 1;
    }

    public function prepareInputForAdd($input)
    {
        return $this->validate($input);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->validate($input);
    }

    private function validate(array $input): array|false
    {
        foreach (['name_pattern', 'publisher_pattern'] as $f) {
            if (($input[$f] ?? '') !== '' && @preg_match(self::regex($input[$f]), '') === false) {
                Session::addMessageAfterRedirect(htmlescape("Regex invalide : {$input[$f]}"), false, ERROR);
                return false;
            }
        }
        return $input;
    }

    private static function regex(string $pattern): string
    {
        return '~' . str_replace('~', '\~', $pattern) . '~i';
    }

    public static function activeRules(): array
    {
        global $DB;
        return iterator_to_array($DB->request(['FROM' => self::getTable(), 'WHERE' => ['is_active' => 1], 'ORDER' => 'id']), false);
    }

    public static function match(array $rules, string $name, string $publisher): ?array
    {
        foreach ($rules as $r) {
            if (
                $r['name_pattern'] !== '' && preg_match(self::regex($r['name_pattern']), $name)
                && ($r['publisher_pattern'] === '' || preg_match(self::regex($r['publisher_pattern']), $publisher))
            ) {
                return $r;
            }
        }
        return null;
    }
}
