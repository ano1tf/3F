# Outils de développement

## Tests de fumée de l'interface (jsdom)

Deux scripts chargent `app/static/index.html` + `app/static/app.js` dans jsdom et simulent
l'application, sans navigateur ni serveur :

| Script | Ce qu'il vérifie |
|---|---|
| `ui-smoke.mjs` | Un scan complet (flux NDJSON) : synthèse, radar, ruban de sévérités, constats, chips de confiance, plan, diff, pages, dépendances tierces, et le comportement des onglets. |
| `ui-trend-smoke.mjs` | Le tableau de bord : KPI, liste de surveillance et courbe de tendance alimentée par le bon hôte. |

```bash
npm install            # une seule fois (dev)
npm run ui:check       # les deux tests
```

Sortie attendue : `OK — parcours complet rendu sans erreur` puis
`OK — tendance alimentée par le bon hôte` (code de sortie 0). Toute erreur JavaScript fait échouer
le script, ce qui en fait un garde-fou de régression front dans la CI.
