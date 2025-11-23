# ChromeHistoryExtract

Parse l'historique de navigation Chrome/Chromium/Brave directement depuis une image disque brute grâce à `dissect.target`. Aucun montage préalable n'est requis : les fichiers `History` sont copiés temporairement et convertis en JSONL.

## Dépendances

```
pip install -r requirements.txt
```

## Variables d'environnement

| Variable | Description |
|----------|-------------|
| `EVIDENCE_PATH` | Fichier image (VHDX/E01/RAW) |
| `OUTPUT_DIR` | Répertoire de sortie |
| `CASE_ID`, `EVIDENCE_UID` | Métadonnées Requiem optionnelles |
| `MAX_LINES_PER_FILE`, `LOG_LEVEL` | Options de rotation/logging |

## Utilisation

```bash
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/evidence/exchange01-triage.vhdx"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/ChromeHistoryExtract"
python3 script.py
```

Les fichiers générés `chrome_history_*.jsonl` contiennent les visites (URL, titre, transition, compteurs...) enrichies avec `case_id`/`evidence_uid`. Les profils pris en charge incluent Google Chrome, Chromium et Brave (`Users/<user>/AppData/Local/.../User Data/*/History`).

## Notes

- Le script limite les copies aux fichiers `History` détectés via Dissect (pas besoin de monter l'image manuellement)
- Les bases SQLite sont copiées dans `OUTPUT_DIR/tmp` le temps de l'analyse puis supprimées
- Ajustez `MAX_LINES_PER_FILE` ou `LOG_LEVEL` selon vos besoins
