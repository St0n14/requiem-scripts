# EvtxExtract

Extraction rapide des journaux Windows `.evtx` vers des fichiers JSONL compatibles Requiem.

## Fonctionnalités

- Découverte automatique de tous les fichiers EVTX dans `EVIDENCE_PATH`
- Parsing via `python-evtx` et sérialisation des champs `System`, `EventData` et `UserData`
- Écriture en JSONL avec rotation automatique (`MAX_LINES_PER_FILE`)
- Ajout des métadonnées Requiem (`case_id`, `evidence_uid`, chemin de l'artefact)

## Dépendances

```
pip install -r requirements.txt
```

## Utilisation

```
export CASE_ID="case_001"
export EVIDENCE_UID="evd_123"
export EVIDENCE_PATH="/lake/case_001/evd_123/evidence"
export OUTPUT_DIR="/lake/case_001/evd_123/scripts/EvtxExtract"
python3 script.py
```

## Sortie

Les fichiers sont écrits dans `OUTPUT_DIR/evtx_events_*.jsonl`. Chaque ligne suit la structure :

```json
{
  "@timestamp": "2024-01-15T10:30:00.000000Z",
  "event_id": "4624",
  "computer": "DC01",
  "event_data": {
    "TargetUserName": "Administrator"
  }
}
```

## Personnalisation

- `MAX_LINES_PER_FILE` (env) : limite les lignes par fichier
- `LOG_LEVEL` (env) : `DEBUG`, `INFO`, `WARNING`, etc.
