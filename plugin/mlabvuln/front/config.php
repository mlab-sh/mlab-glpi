<?php

use GlpiPlugin\Mlabvuln\CpeRule;
use GlpiPlugin\Mlabvuln\Scanner;

Session::checkRight('config', UPDATE);

if (isset($_POST['save'])) {
    $url = trim($_POST['api_url'] ?? '');
    if (!preg_match('~^https?://~', $url)) {
        Session::addMessageAfterRedirect(__s('URL invalide'), false, ERROR);
        Html::back();
    }
    $values = [
        'api_url'            => $url,
        'rescan_hours'       => max(1, (int) $_POST['rescan_hours']),
        'product_cache_days' => max(1, (int) $_POST['product_cache_days']),
        'cve_refresh_days'   => max(1, (int) $_POST['cve_refresh_days']),
        'ticket_mode'        => in_array($_POST['ticket_mode'], ['off', 'kev', 'kev_epss'], true) ? $_POST['ticket_mode'] : 'kev',
        'epss_threshold'     => min(1, max(0, (float) $_POST['epss_threshold'])),
    ];
    // blank field = keep the current token
    if (!empty($_POST['clear_token'])) {
        $values['api_token'] = '';
    } elseif (trim($_POST['api_token'] ?? '') !== '') {
        $values['api_token'] = trim($_POST['api_token']);
    }
    Config::setConfigurationValues('plugin:mlabvuln', $values);
    Session::addMessageAfterRedirect(__s('Configuration enregistrée'));
    Html::back();
}
if (isset($_POST['rescan'])) {
    global $DB;
    $DB->update('glpi_plugin_mlabvuln_scans', ['date_scan' => null], [new \Glpi\DBAL\QueryExpression('1 = 1')]);
    $DB->update('glpi_plugin_mlabvuln_products', ['date_sync' => null], [new \Glpi\DBAL\QueryExpression('1 = 1')]);
    Session::addMessageAfterRedirect(__s('Tout sera rescanné au prochain passage de la tâche.'));
    Html::back();
}
if (isset($_POST['run'])) {
    set_time_limit(600);
    $stats = (new Scanner())->run(100);
    Session::addMessageAfterRedirect(htmlescape('Scan : ' . json_encode($stats)));
    Html::back();
}

Html::header('mlab vuln', '', 'config', 'plugin');
$cfg = Scanner::config();
$field = fn($name, $label, $type = 'number', $extra = '') => sprintf(
    '<div class="mb-3 col-md-4"><label class="form-label">%s</label><input class="form-control" type="%s" name="%s" value="%s" %s></div>',
    htmlescape($label), $type, $name, htmlescape($cfg[$name]), $extra
);
$modes = ['off' => 'Désactivé', 'kev' => 'CVE KEV uniquement', 'kev_epss' => 'KEV + EPSS ≥ seuil'];
$options = '';
foreach ($modes as $k => $v) {
    $options .= sprintf('<option value="%s" %s>%s</option>', $k, $cfg['ticket_mode'] === $k ? 'selected' : '', htmlescape($v));
}
$token_state = $cfg['api_token'] !== ''
    ? '<span class="badge bg-success text-white">configuré</span> <label class="ms-2"><input type="checkbox" name="clear_token" value="1"> supprimer</label>'
    : '<span class="badge bg-secondary text-white">aucun, quotas anonymes</span>';
$token = Session::getNewCSRFToken();
echo <<<HTML
<div class="container-fluid"><div class="card"><div class="card-body">
<h2>mlab vuln (vuln.mlab.sh)</h2>
<form method="post"><input type="hidden" name="_glpi_csrf_token" value="$token"><div class="row">
{$field('api_url', 'URL de l\'API', 'url', 'class="col-12"')}
<div class="mb-3 col-md-8"><label class="form-label">Token API vuln.mlab.sh (Bearer, généré sur <a target="_blank" href="https://vuln.mlab.sh/me/tokens">/me/tokens</a>) $token_state</label>
<input class="form-control" type="password" name="api_token" autocomplete="new-password" placeholder="laisser vide pour conserver le token actuel"></div>
{$field('rescan_hours', 'Rescanner une version toutes les (heures)')}
{$field('product_cache_days', 'Cache CVE par produit CPE (jours)')}
{$field('cve_refresh_days', 'Rafraîchir EPSS/KEV (jours)')}
<div class="mb-3 col-md-4"><label class="form-label">Tickets automatiques</label><select class="form-select" name="ticket_mode">$options</select></div>
{$field('epss_threshold', 'Seuil EPSS (0 à 1)', 'number', 'step="0.01" min="0" max="1"')}
</div><button class="btn btn-primary" name="save" value="1">Enregistrer</button></form>
<hr>
HTML;
printf(
    '<p><a class="btn btn-outline-secondary" href="%s">Gérer les règles CPE (Windows / macOS)</a>
     <a class="btn btn-outline-secondary" href="%s">Voir les vulnérabilités</a></p>',
    htmlescape(CpeRule::getSearchURL()),
    htmlescape(GlpiPlugin\Mlabvuln\Cve::getSearchURL())
);
$token = Session::getNewCSRFToken();
echo <<<HTML
<form method="post" class="d-inline"><input type="hidden" name="_glpi_csrf_token" value="$token">
<button class="btn btn-warning" name="run" value="1">Scanner maintenant (100 versions)</button></form>
HTML;
$token = Session::getNewCSRFToken();
echo <<<HTML
<form method="post" class="d-inline"><input type="hidden" name="_glpi_csrf_token" value="$token">
<button class="btn btn-outline-danger" name="rescan" value="1">Tout rescanner au prochain passage</button></form>
<p class="text-muted mt-3">La tâche planifiée <code>scan</code> (Configuration › Actions automatiques) traite les versions par lots.
En ligne de commande : <code>php front/cron.php --force scan</code>.</p>
</div></div></div>
HTML;
Html::footer();
