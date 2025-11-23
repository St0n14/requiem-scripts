# RegistryRunKeys

Extraction des valeurs des clés `Run` / `RunOnce` directement depuis une image disque (VHDX, E01, RAW, …) à l'aide de `dissect.target`. Le script s'appuie sur le plugin `runkeys()` de Dissect pour limiter les faux positifs et rester robuste face aux hives multiples.

## Dépendances

```
pip install -r requirements.txt
```

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `EVIDENCE_PATH` | Fichier image à analyser (VHDX/E01/RAW) |
| `OUTPUT_DIR` | Répertoire où écrire les JSONL |
| `CASE_ID`, `EVIDENCE_UID` | Métadonnées Requiem optionnelles |
| `MAX_LINES_PER_FILE`, `LOG_LEVEL` | (Optionnel) paramètres de rotation/logging |

## Utilisation

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/evidence/exchange01-triage.vhdx"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/RegistryRunKeys"
python3 script.py
```

Chaque match produit une ligne JSON enrichie (`case_id`, `evidence_uid`, `source=dissect.runkeys`, timestamp, chemin de registre, nom/commande). Aucun montage préalable de la preuve n'est nécessaire : Dissect lit l'image brute.
