# HayabusaRunner

Automatise l'exécution de [Hayabusa](https://github.com/Yamato-Security/hayabusa) sur une preuve Requiem et convertit le CSV généré en JSONL indexable.

## Fonctionnement

1. Recherche tous les fichiers `*.evtx` sous `EVIDENCE_PATH`
2. Les copie vers `OUTPUT_DIR/evtx/`
3. Lance `hayabusa evtx hunt` sur ce répertoire (CSV en sortie)
4. Convertit la sortie JSON/CSV en JSONL (`hayabusa_findings_*.jsonl`) enrichi de `case_id`, `evidence_uid`, `source`

## Dépendances

- Binaire Hayabusa (>= 2.19 recommandé) accessible dans le `PATH` ou via `HAYABUSA_BIN`
- Aucun package Python supplémentaire (voir `requirements.txt`)

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `CASE_ID` | Identifiant du cas (optionnel mais conseillé) |
| `EVIDENCE_UID` | Identifiant de la preuve (optionnel) |
| `EVIDENCE_PATH` | Répertoire racine de la preuve montée |
| `OUTPUT_DIR` | Répertoire de sortie (JSONL + artefacts temporaires) |
| `HAYABUSA_BIN` | (Optionnel) Chemin du binaire Hayabusa (`hayabusa` par défaut) |
| `HAYABUSA_RULESET` | (Optionnel) Répertoire de règles personnalisé passé à `-r` |
| `HAYABUSA_ARGS` | (Optionnel) Arguments supplémentaires passés tels quels à Hayabusa |
| `HAYABUSA_OUTPUT` | `json` (défaut, utilise `--json-timeline`) ou `csv` |
| `MAX_LINES_PER_FILE` | (Optionnel) Lignes max par JSONL avant rotation (défaut `100000`) |
| `LOG_LEVEL` | (Optionnel) Niveau de logs Python (`INFO`, `DEBUG`, ...) |

## Utilisation

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/lake/case_001/evd_123/evidence"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/HayabusaRunner"
# facultatif : préciser le binaire et les règles
export HAYABUSA_BIN="/opt/hayabusa/hayabusa"
export HAYABUSA_RULESET="/opt/hayabusa/rules"
python3 script.py
```

Le script crée `hayabusa_findings_00000.jsonl`, prêt à être ingéré par OpenSearch. Les fichiers temporaires (`evtx/`, `hayabusa_raw.jsonl|csv`) sont supprimés en fin d'exécution.

## Notes

- Assurez-vous que Hayabusa dispose des droits de lecture sur les fichiers EVTX copiés
- Par défaut, le script demande la timeline JSON (`--json-timeline`) et enrichit chaque événement avec les métadonnées Requiem
- Pour revenir au CSV natif de Hayabusa, définissez `HAYABUSA_OUTPUT=csv` (le script effectuera la conversion vers JSONL)
- Pour ajouter des arguments (ex: `--timezone UTC`), utilisez `HAYABUSA_ARGS` :
  `export HAYABUSA_ARGS="--timezone UTC --min-level medium"`
- Les fichiers EVTX sont copiés pour éviter toute modification de la preuve montée et accélérer le traitement
