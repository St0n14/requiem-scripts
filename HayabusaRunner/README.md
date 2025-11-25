# HayabusaRunner

Automatise l'exécution de [Hayabusa](https://github.com/Yamato-Security/hayabusa) sur une preuve Requiem et convertit le CSV généré en JSONL indexable.

## Fonctionnement

1. Recherche tous les fichiers `*.evtx` sous `EVIDENCE_PATH`
2. Les copie vers `OUTPUT_DIR/evtx/`
3. Lance `hayabusa evtx hunt` sur ce répertoire (CSV en sortie)
4. Convertit la sortie JSON/CSV en JSONL (`hayabusa_findings_*.jsonl`) enrichi de `case_id`, `evidence_uid`, `source`

## Dépendances

- **Hayabusa** : Le script télécharge automatiquement la dernière release depuis GitHub si le binaire n'est pas déjà installé
  - Vous pouvez aussi installer manuellement Hayabusa (>= 2.19 recommandé) dans le `PATH` ou via `HAYABUSA_BIN`
  - Le binaire téléchargé est mis en cache dans `~/.cache/requiem/hayabusa/` pour éviter les téléchargements répétés
- Aucun package Python supplémentaire (voir `requirements.txt`)

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `CASE_ID` | Identifiant du cas (optionnel mais conseillé) |
| `EVIDENCE_UID` | Identifiant de la preuve (optionnel) |
| `EVIDENCE_PATH` | Répertoire racine de la preuve montée |
| `OUTPUT_DIR` | Répertoire de sortie (JSONL + artefacts temporaires) |
| `HAYABUSA_BIN` | (Optionnel) Chemin du binaire Hayabusa. Si absent, télécharge automatiquement depuis GitHub |
| `HAYABUSA_VERSION` | (Optionnel) Version de Hayabusa à télécharger (`latest` par défaut, ex: `v2.19.0`) |
| `HAYABUSA_RULESET` | (Optionnel) Répertoire de règles personnalisé passé à `-r` |
| `HAYABUSA_ARGS` | (Optionnel) Arguments supplémentaires passés tels quels à Hayabusa |
| `HAYABUSA_OUTPUT` | `json` (défaut, utilise `--json-timeline`) ou `csv` |
| `MAX_LINES_PER_FILE` | (Optionnel) Lignes max par JSONL avant rotation (défaut `100000`) |
| `LOG_LEVEL` | (Optionnel) Niveau de logs Python (`INFO`, `DEBUG`, ...) |

## Utilisation

### Utilisation basique (téléchargement automatique)

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/lake/case_001/evd_123/evidence"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/HayabusaRunner"
python3 script.py
```

Le script téléchargera automatiquement Hayabusa si nécessaire.

### Utilisation avancée

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/lake/case_001/evd_123/evidence"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/HayabusaRunner"

# Spécifier une version particulière de Hayabusa
export HAYABUSA_VERSION="v2.19.0"

# Ou utiliser un binaire local
export HAYABUSA_BIN="/opt/hayabusa/hayabusa"

# Utiliser un ruleset personnalisé
export HAYABUSA_RULESET="/opt/hayabusa/rules"

# Arguments additionnels
export HAYABUSA_ARGS="--timezone UTC --min-level medium"

python3 script.py
```

Le script crée `hayabusa_findings_00000.jsonl`, prêt à être ingéré par OpenSearch. Les fichiers temporaires (`evtx/`, `hayabusa_raw.jsonl|csv`) sont supprimés en fin d'exécution.

## Téléchargement automatique de Hayabusa

Le script détecte automatiquement votre système d'exploitation et votre architecture, puis télécharge la version appropriée de Hayabusa depuis GitHub si nécessaire :

1. **Priorité** :
   - Si `HAYABUSA_BIN` est défini, utilise ce chemin
   - Sinon, cherche `hayabusa` dans le `PATH`
   - En dernier recours, télécharge automatiquement depuis GitHub

2. **Systèmes supportés** :
   - Linux (x64, aarch64) - Idéal pour Docker
   - macOS (x64, aarch64/Apple Silicon)
   - Windows (x64, x86, aarch64)

3. **Cache** :
   - Le binaire téléchargé est stocké dans `~/.cache/requiem/hayabusa/`
   - Les téléchargements suivants réutilisent le binaire en cache
   - Pour forcer un nouveau téléchargement, supprimez ce répertoire

4. **Version** :
   - Par défaut, télécharge la dernière release stable (actuellement v3.7.0)
   - Pour spécifier une version : définissez `HAYABUSA_VERSION` (ex: `v2.19.0`)

5. **Test du téléchargement** :
   ```bash
   # Mode interactif (demande confirmation)
   python3 test_download.py

   # Tests rapides uniquement (sans téléchargement)
   python3 test_download.py --quick

   # Tous les tests (pour CI/CD, non-interactif)
   python3 test_download.py --ci

   # Ou avec --full
   python3 test_download.py --full
   ```
   Ce script teste la détection de plateforme, la récupération de l'URL, le téléchargement et l'exécution du binaire.
   Le mode `--ci` est automatiquement activé si les variables d'environnement `CI` ou `GITHUB_ACTIONS` sont définies.

## Notes

- Assurez-vous que Hayabusa dispose des droits de lecture sur les fichiers EVTX copiés
- Par défaut, le script demande la timeline JSON (`--json-timeline`) et enrichit chaque événement avec les métadonnées Requiem
- Pour revenir au CSV natif de Hayabusa, définissez `HAYABUSA_OUTPUT=csv` (le script effectuera la conversion vers JSONL)
- Pour ajouter des arguments (ex: `--timezone UTC`), utilisez `HAYABUSA_ARGS` :
  `export HAYABUSA_ARGS="--timezone UTC --min-level medium"`
- Les fichiers EVTX sont copiés pour éviter toute modification de la preuve montée et accélérer le traitement

## Docker

Le script fonctionne parfaitement dans Docker :
- Le téléchargement automatique détectera l'environnement Linux du conteneur
- Les binaires Linux précompilés seront utilisés (pas de compilation nécessaire)
- Le cache sera stocké dans `~/.cache/requiem/hayabusa/` du conteneur
- Pour persister le cache entre les exécutions, montez ce répertoire comme volume

Exemple de Dockerfile :
```dockerfile
FROM python:3.11-slim
RUN mkdir -p /root/.cache/requiem/hayabusa
VOLUME /root/.cache/requiem/hayabusa
WORKDIR /app
COPY script.py .
CMD ["python3", "script.py"]
```
