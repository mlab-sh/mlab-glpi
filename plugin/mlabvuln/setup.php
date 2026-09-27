<?php

use Glpi\Plugin\Hooks;
use GlpiPlugin\Mlabvuln\Cve;
use GlpiPlugin\Mlabvuln\Dashboard;
use GlpiPlugin\Mlabvuln\Finding;

define('PLUGIN_MLABVULN_VERSION', '0.1.0');

function plugin_version_mlabvuln(): array
{
    return [
        'name'         => 'mlab vuln',
        'version'      => PLUGIN_MLABVULN_VERSION,
        'author'       => 'mlab',
        'license'      => 'MIT',
        'homepage'     => 'https://vuln.mlab.sh',
        'requirements' => ['glpi' => ['min' => '11.0', 'max' => '11.99']],
    ];
}

function plugin_init_mlabvuln(): void
{
    global $PLUGIN_HOOKS;

    Plugin::registerClass(Finding::class, ['addtabon' => ['Computer', 'Software']]);
    Plugin::registerClass(Cve::class);

    $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['mlabvuln']     = 'front/config.php';
    $PLUGIN_HOOKS[Hooks::MENU_TOADD]['mlabvuln']      = ['tools' => Cve::class];
    $PLUGIN_HOOKS[Hooks::DASHBOARD_CARDS]['mlabvuln'] = [Dashboard::class, 'cards'];
    // stored encrypted with the GLPI key
    $PLUGIN_HOOKS[Hooks::SECURED_CONFIGS]['mlabvuln'] = ['api_token'];
}
