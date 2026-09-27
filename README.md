# mlab-glpi

Plugin GLPI 11 `mlabvuln` : croise les versions logicielles inventoriées (glpi-agent) avec
[vuln.mlab.sh](https://vuln.mlab.sh) pour afficher les CVE du parc, prioriser (KEV > EPSS > CVSS)
et ouvrir des tickets pour les failles activement exploitées.

## Comment ça matche

| Logiciel inventorié | Méthode | Endpoint |
|---|---|---|
| Paquets Linux (Debian, Ubuntu, Alpine, Rocky, AlmaLinux) | OS de la machine vers écosystème OSV, recherche exacte paquet + version | `POST /api/v2/query` |
| Applications Windows / macOS | Règle CPE (regex nom / éditeur vers `vendor:product`), CVE du produit filtrées localement sur les plages de versions NVD | `GET /api/v1/cve?q=` |
| Enrichissement CVSS / EPSS / KEV | par CVE, rafraîchi tous les N jours | `GET /api/v1/cve/{id}` |

Un scan par **version** logicielle, pas par machine : 1000 postes avec le même Chrome = 1 appel.
Une erreur API (5xx, 429 épuisé) garde les résultats précédents : une panne n'est jamais « sain ».

## Lancer l'environnement de test

```bash
docker compose up -d
```

GLPI : http://localhost:8080 (compte `glpi` / `glpi`, les identifiants par défaut de l'image).
Premier démarrage : environ 1 min (installation de la base).

```bash
docker compose exec glpi bin/console plugin:install -u glpi mlabvuln
docker compose exec glpi bin/console plugin:activate mlabvuln
docker compose exec glpi bin/console config:set --context=inventory enabled_inventory 1
python3 seed/seed.py
docker compose exec -u www-data glpi php front/cron.php --force scan
```

`seed/seed.py` pousse 7 inventaires glpi-agent (3 postes Windows, serveurs Debian 12, Ubuntu 22.04,
Rocky 9, Alpine 3.18) par l'inventaire natif, comme un vrai agent.

## Où regarder

- **Parc > Ordinateurs > une machine > onglet Vulnérabilités** : « À mettre à jour » (version cible par logiciel), puis le détail des CVE.
- **Parc > Logiciels > un logiciel > onglet Vulnérabilités**.
- **Outils > Vulnérabilités** : toutes les CVE du parc, triées par priorité, filtrables et exportables ; fiche CVE avec les machines exposées.
- **Assistance > Tickets** : un ticket par CVE KEV, machines liées, échéance CISA en date de résolution.
- **Tableau de bord** : mode édition, ajouter une carte du groupe « mlab vuln ».
- **Configuration > Plugins > mlab vuln** : token API, fréquences, mode tickets, règles CPE, scan immédiat.

## Token API

Optionnel. Token personnel généré sur https://vuln.mlab.sh/me/tokens, envoyé en `Authorization: Bearer`.
Stocké chiffré avec la clé GLPI. Sans token : quotas anonymes.

## Tâche planifiée

`scan` (Configuration > Actions automatiques), toutes les heures, 2000 versions par passage.
Appels API parallélisés (8 simultanés).

## Tests

```bash
docker compose exec glpi php plugins/mlabvuln/tests/check.php
```

## Mesures (parc de charge : 5000 postes, 3000 logiciels, 272k installations)

| Opération | Temps |
|---|---|
| Onglet Vulnérabilités d'un poste (4196 CVE) | 60 à 80 ms |
| Badge de l'onglet | 5 ms |
| Fiche CVE avec 2503 machines exposées | 71 ms |
| Tableau de bord (4 cartes) | < 50 ms |
| Scan à froid des 20 produits CPE (dont 6600 CVE Chrome) | 6 s |
| Scan OSV | environ 23 versions/s |
| Enrichissement | environ 50 CVE/s |
| Tickets : 68 821 liens machine, premier passage / passages suivants | 0,7 s / 0,35 s |

## Limites connues

- Debian / Ubuntu : OSV indexe les paquets **source**, l'agent remonte les paquets **binaires**
  (`openssh-server`, `libssl3`…) : ceux dont le nom diffère ne sont pas trouvés.
- Windows / macOS : couverture = règles CPE (18 fournies, extensibles dans l'UI). L'OS Windows lui-même n'est pas encore couvert.
- La version « à mettre à jour » compare les versions avec `version_compare`, approximatif pour les epochs / `~` dpkg.
- Les liens ticket / machine sont insérés en masse, sans entrée d'historique par lien.
- L'onglet « Éléments » natif d'un ticket lié à 2500 machines met environ 2,4 s (rendu GLPI core).
