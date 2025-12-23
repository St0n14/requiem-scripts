#!/usr/bin/env python3
import json
import os
from pathlib import Path

from dissect.target import Target

MAX_LINES_PER_FILE = 100_000
FLUSH_INTERVAL = 10_000


class ChunkedJSONLWriter:
    """Rotate JSONL files when the line threshold is reached."""

    def __init__(self, output_dir: Path, base_name: str, max_lines: int = MAX_LINES_PER_FILE):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.base_name = base_name
        self.max_lines = max_lines
        self._file_index = 0
        self._line_count = 0
        self._handle = None
        self.files: list[Path] = []

    def _rotate(self):
        if self._handle:
            self._handle.close()
        self._file_index += 1
        self._line_count = 0
        file_path = self.output_dir / f"{self.base_name}_{self._file_index:04d}.jsonl"
        self._handle = open(file_path, "w", encoding="utf-8")
        self.files.append(file_path)
        print(f"[writer] Nouveau fichier créé: {file_path}")

    def write(self, record: dict):
        if self._handle is None or self._line_count >= self.max_lines:
            self._rotate()
        self._handle.write(json.dumps(record, default=str) + "\n")
        self._line_count += 1

    def flush(self):
        if self._handle:
            self._handle.flush()

    def close(self):
        if self._handle:
            self._handle.close()
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def normalize_value(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [normalize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}
    return str(value)


def safe_getattr(obj, *attrs, default=None):
    for attr in attrs:
        if hasattr(obj, attr):
            value = getattr(obj, attr)
            if value is not None:
                return value
    return default


def main():
    evidence_path = os.getenv("EVIDENCE_PATH")
    output_dir = os.getenv("OUTPUT_DIR")
    case_id = os.getenv("CASE_ID") or "unknown_case"
    evidence_uid = os.getenv("EVIDENCE_UID") or "unknown_evidence"

    if not evidence_path:
        raise ValueError("EVIDENCE_PATH environment variable not set")

    if not output_dir:
        raise ValueError("OUTPUT_DIR environment variable not set")

    output_dir_path = Path(output_dir)
    print(f"Ouverture de l'evidence: {evidence_path}")
    print(f"Répertoire de sortie: {output_dir_path}")

    target = Target.open(evidence_path)
    print("Target ouvert avec succès")

    total_records = 0
    try:
        mft_plugin = target.mft()
        with ChunkedJSONLWriter(output_dir_path, base_name="mft_extract") as writer:
            for entry in mft_plugin:
                total_records += 1
                doc = {
                    "case_id": case_id,
                    "evidence_uid": evidence_uid,
                    "source": "dissect.mft",
                    "@timestamp": normalize_value(
                        safe_getattr(entry, "ts", "timestamp", "created", "modified")
                    ),
                    "hostname": normalize_value(safe_getattr(entry, "hostname")),
                    "domain": normalize_value(safe_getattr(entry, "domain")),
                    "ts": normalize_value(safe_getattr(entry, "ts")),
                    "ts_type": normalize_value(safe_getattr(entry, "ts_type")),
                    "filename": normalize_value(safe_getattr(entry, "filename", "name")),
                    "filename_index": normalize_value(safe_getattr(entry, "filename_index")),
                    "path": normalize_value(safe_getattr(entry, "path", "full_path")),
                    "segment": normalize_value(safe_getattr(entry, "segment", "mft_entry", "entry")),
                    "filesize": normalize_value(safe_getattr(entry, "filesize", "size")),
                    "resident": normalize_value(safe_getattr(entry, "resident")),
                    "inuse": normalize_value(safe_getattr(entry, "inuse", "is_allocated", default=True)),
                    "ads": normalize_value(safe_getattr(entry, "ads", default=False)),
                    "owner": normalize_value(safe_getattr(entry, "owner")),
                    "volume_uuid": normalize_value(safe_getattr(entry, "volume_uuid")),
                }

                for numeric_key in ("filename_index", "segment", "filesize"):
                    if doc.get(numeric_key) is not None:
                        try:
                            doc[numeric_key] = int(doc[numeric_key])
                        except (TypeError, ValueError):
                            pass

                writer.write(doc)

                if total_records % FLUSH_INTERVAL == 0:
                    writer.flush()
                    print(f"Traité {total_records} enregistrements MFT...")

            writer.flush()
            created_files = list(writer.files)

        print(f"Total d'enregistrements MFT extraits: {total_records}")
        print(f"Fichiers générés ({len(created_files)}):")
        for path in created_files:
            print(f" - {path}")
    except Exception:
        print("Erreur lors de l'extraction MFT")
        raise
    finally:
        print("Target fermé")


if __name__ == "__main__":
    try:
        main()
        print("Extraction MFT terminée avec succès!")
    except Exception as err:
        print(f"Erreur: {err}")
        raise
