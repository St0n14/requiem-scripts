#!/usr/bin/env python3
"""Orchestre l'exécution de Hayabusa sur des fichiers EVTX."""
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional

import csv

MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "100000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("hayabusa_runner")


def env_or_exit(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} doit être défini")
    return value


@dataclass
class ScriptContext:
    case_id: Optional[str]
    evidence_uid: Optional[str]
    evidence_path: Path
    output_dir: Path


class ChunkedJSONLWriter:
    def __init__(self, output_dir: Path, base_name: str, max_lines: int = MAX_LINES_PER_FILE) -> None:
        self.output_dir = output_dir
        self.base_name = base_name
        self.max_lines = max_lines
        self._file_index = 0
        self._line_count = 0
        self._fh = None
        self._current_path: Optional[Path] = None
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _open_next_file(self) -> None:
        if self._fh:
            self._fh.close()
        filename = f"{self.base_name}_{self._file_index:05d}.jsonl"
        self._current_path = self.output_dir / filename
        self._fh = self._current_path.open("w", encoding="utf-8")
        self._line_count = 0
        self._file_index += 1
        logger.debug("Création du fichier %s", filename)

    def write(self, obj: Dict) -> None:
        if not self._fh or self._line_count >= self.max_lines:
            self._open_next_file()
        self._fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._line_count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def load_context() -> ScriptContext:
    evidence_path = env_or_exit("EVIDENCE_PATH")
    output_dir = env_or_exit("OUTPUT_DIR")
    ctx = ScriptContext(
        case_id=os.getenv("CASE_ID"),
        evidence_uid=os.getenv("EVIDENCE_UID"),
        evidence_path=Path(evidence_path),
        output_dir=Path(output_dir),
    )
    if not ctx.evidence_path.exists():
        raise SystemExit(f"EVIDENCE_PATH inexistant: {ctx.evidence_path}")
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    return ctx


def discover_evtx(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.evtx"):
        if path.is_file():
            yield path


def hayabusa_output_format() -> str:
    fmt = os.getenv("HAYABUSA_OUTPUT", "json").lower()
    if fmt not in {"json", "jsonl", "json-timeline", "csv"}:
        logger.warning("Format %s inconnu, utilisation de json", fmt)
        fmt = "json"
    return fmt


def clean_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def stage_evtx_files(ctx: ScriptContext, staging_dir: Path) -> int:
    clean_directory(staging_dir)
    count = 0
    for src in discover_evtx(ctx.evidence_path):
        try:
            rel_path = src.relative_to(ctx.evidence_path)
        except ValueError:
            rel_path = Path(src.name)
        dst = staging_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
        except Exception as exc:
            logger.warning("Impossible de copier %s: %s", src, exc)
            continue
        count += 1
    return count


def resolve_hayabusa_binary() -> str:
    binary = os.getenv("HAYABUSA_BIN", "hayabusa")
    if shutil.which(binary) is None:
        raise SystemExit(
            f"Binaire Hayabusa introuvable ({binary}). Définissez HAYABUSA_BIN ou ajoutez-le au PATH."
        )
    return binary


def run_hayabusa(staging_dir: Path, ctx: ScriptContext, output_format: str) -> Path:
    binary = resolve_hayabusa_binary()
    if output_format == "csv":
        result_path = ctx.output_dir / "hayabusa_raw.csv"
    else:
        result_path = ctx.output_dir / "hayabusa_raw.jsonl"
    cmd = [
        binary,
        "evtx",
        "hunt",
        "-d",
        str(staging_dir),
        "-o",
        str(result_path),
    ]
    if output_format == "csv":
        cmd.append("--csv")
    else:
        cmd.append("--json-timeline")
    ruleset = os.getenv("HAYABUSA_RULESET")
    if ruleset:
        cmd.extend(["-r", ruleset])
    extra = os.getenv("HAYABUSA_ARGS")
    if extra:
        cmd.extend(shlex.split(extra))
    logger.info("Commande Hayabusa: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        raise SystemExit("Hayabusa n'est pas installé ou inaccessible")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Hayabusa a échoué (code {exc.returncode})") from exc
    return result_path


def normalize_row(row: Dict[str, str]) -> Dict[str, Optional[str]]:
    normalized: Dict[str, Optional[str]] = {}
    for key, value in row.items():
        if isinstance(value, str):
            normalized[key] = value if value.strip() else None
        else:
            normalized[key] = value
    return normalized


def iter_json_timeline(json_path: Path) -> Iterator[Dict]:
    try:
        with json_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                yield json.loads(stripped)
        return
    except json.JSONDecodeError:
        logger.debug("JSON Hayabusa non NDJSON, parsing complet requis")

    raw = json_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
    elif isinstance(data, dict):
        yield data
    else:
        logger.warning("Format JSON inattendu (%s), ignoré", type(data).__name__)


def csv_to_jsonl(csv_path: Path, ctx: ScriptContext) -> None:
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="hayabusa_findings")
    total = 0
    candidates = ("@timestamp", "timestamp", "Timestamp", "event_time", "EventTime")
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            logger.warning("CSV Hayabusa vide: %s", csv_path)
            writer.close()
            return
        for row in reader:
            normalized = normalize_row(row)
            event: Dict[str, Optional[str]] = {
                "case_id": ctx.case_id,
                "evidence_uid": ctx.evidence_uid,
                "source": "hayabusa",
            }
            for candidate in candidates:
                if candidate in normalized and normalized[candidate]:
                    event["@timestamp"] = normalized.get(candidate)
                    break
            event.update({k: v for k, v in normalized.items() if v is not None})
            writer.write(event)
            total += 1
    writer.close()
    logger.info("Entrées Hayabusa converties: %d", total)


def json_timeline_to_jsonl(json_path: Path, ctx: ScriptContext) -> None:
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="hayabusa_findings")
    total = 0
    candidates = ("@timestamp", "timestamp", "Timestamp", "event_time", "EventTime")
    for record in iter_json_timeline(json_path):
        if not isinstance(record, dict):
            continue
        event = dict(record)
        event["case_id"] = ctx.case_id
        event["evidence_uid"] = ctx.evidence_uid
        event["source"] = "hayabusa"
        if "@timestamp" not in event:
            for candidate in candidates:
                if candidate in event and event[candidate]:
                    event["@timestamp"] = event[candidate]
                    break
        writer.write(event)
        total += 1
    writer.close()
    logger.info("Entrées JSON Hayabusa converties: %d", total)


def main() -> None:
    ctx = load_context()
    staging_dir = ctx.output_dir / "evtx"
    file_count = stage_evtx_files(ctx, staging_dir)
    if file_count == 0:
        raise SystemExit("Aucun fichier EVTX trouvé dans la preuve")
    logger.info("Fichiers EVTX copiés: %d", file_count)
    output_format = hayabusa_output_format()
    raw_path = run_hayabusa(staging_dir, ctx, output_format)
    logger.info("Sortie Hayabusa générée: %s", raw_path)
    if output_format == "csv":
        csv_to_jsonl(raw_path, ctx)
    else:
        json_timeline_to_jsonl(raw_path, ctx)
    try:
        raw_path.unlink()
    except OSError:
        pass
    shutil.rmtree(staging_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
