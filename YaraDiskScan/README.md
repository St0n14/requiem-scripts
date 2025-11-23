# YaraDiskScan

Scanne récursivement une image disque (VHDX/E01/RAW…) à l'aide de `dissect.target` et `yara-python`, puis produit des alertes JSONL. Les fichiers sont lus directement depuis la cible sans montage préalable, ce qui évite les copies massives tout en respectant les limites de taille configurables.

## Dépendances

```
pip install -r requirements.txt
```

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `CASE_ID`, `EVIDENCE_UID` | Métadonnées (optionnelles) |
| `EVIDENCE_PATH` | Image disque brute à analyser |
| `OUTPUT_DIR` | Répertoire de sortie |
| `YARA_RULES_PATH` | Fichier `.yar` ou dossier contenant les règles |
| `YARA_INCLUDE_EXT` | (Optionnel) extensions ciblées (`.exe,.dll` par défaut). `*` pour tout scanner |
| `YARA_EXCLUDE_DIRS` | (Optionnel) dossiers exclus (défaut : `System Volume Information,$Recycle.Bin,Windows.old,WinSxS`) |
| `YARA_MAX_FILESIZE_MB` | Taille max lue par fichier (défaut `50`) |
| `YARA_MAX_MATCHES_PER_FILE` | Nombre d'alertes par fichier (défaut `5`) |
| `YARA_MAX_STRINGS` / `YARA_STRING_SAMPLE_BYTES` | Limite sur les chaînes renvoyées |
| `YARA_MIN_SEVERITY` | Seuil minimal si la règle expose `severity`/`score` |
| `YARA_REQUIRE_SEVERITY` | Ignorer les règles sans métadonnée de sévérité (`1/true`) |
| `YARA_TIMEOUT_SECONDS` | Timeout YARA par fichier (défaut `30`) |
| `MAX_LINES_PER_FILE`, `LOG_LEVEL` | Paramètres généraux |

## Utilisation

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/evidence/exchange01-triage.vhdx"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/YaraDiskScan"
export YARA_RULES_PATH="/opt/yara/rules"
export YARA_INCLUDE_EXT=".exe,.dll"
python3 script.py
```

Chaque match YARA est écrit dans `yara_disk_matches_*.jsonl` avec : chemin du fichier dans l'image, taille, tags de la règle, sévérité éventuelle, snippets encodés en base64, etc.

## Réduction des faux positifs

- Chargez des règles avec métadonnées (`severity`, `reference`, …) et exploitez `YARA_MIN_SEVERITY`
- Utilisez les filtres d'extensions/dossiers pour éviter les zones connues (Backup, WinSxS, …)
- Limitez la taille (`YARA_MAX_FILESIZE_MB`) pour cibler les binaires et scripts pertinents
