#!/usr/bin/env python3
"""Extraction basique d'événements Windows EVTX vers JSONL."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional
import xml.etree.ElementTree as ET

try:
    from Evtx.Evtx import Evtx  # type: ignore
except Exception:  # pragma: no cover - import résolu dynamiquement
    Evtx = None  # type: ignore

EVTX_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "100000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("evtx_extract")


@dataclass
class ScriptContext:
    case_id: Optional[str]
    evidence_uid: Optional[str]
    evidence_path: Path
    output_dir: Path


class ChunkedJSONLWriter:
    """Écrit des objets JSON dans plusieurs fichiers si nécessaire."""

    def __init__(self, output_dir: Path, base_name: str, max_lines: int = MAX_LINES_PER_FILE) -> None:
        self.output_dir = output_dir
        self.base_name = base_name
        self.max_lines = max_lines
        self._file_index = 0
        self._line_count = 0
        self._fh = None
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _open_next_file(self) -> None:
        if self._fh:
            self._fh.close()
        filename = f"{self.base_name}_{self._file_index:05d}.jsonl"
        self._fh = (self.output_dir / filename).open("w", encoding="utf-8")
        self._line_count = 0
        self._file_index += 1
        logger.debug("Nouveau fichier JSONL: %s", filename)

    def write(self, obj: Dict) -> None:
        if not self._fh or self._line_count >= self.max_lines:
            self._open_next_file()
        self._fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._line_count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def ensure_dependencies() -> None:
    if Evtx is None:
        raise SystemExit("python-evtx n'est pas installé (pip install -r requirements.txt)")


def load_context() -> ScriptContext:
    evidence_path = os.getenv("EVIDENCE_PATH")
    output_dir = os.getenv("OUTPUT_DIR")
    if not evidence_path:
        raise SystemExit("EVIDENCE_PATH doit être défini")
    if not output_dir:
        raise SystemExit("OUTPUT_DIR doit être défini")
    ctx = ScriptContext(
        case_id=os.getenv("CASE_ID"),
        evidence_uid=os.getenv("EVIDENCE_UID"),
        evidence_path=Path(evidence_path),
        output_dir=Path(output_dir),
    )
    if not ctx.evidence_path.exists():
        raise SystemExit(f"EVIDENCE_PATH inexistant: {ctx.evidence_path}")
    return ctx


def discover_evtx_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.evtx"):
        if path.is_file():
            yield path


def parse_evtx_file(path: Path, ctx: ScriptContext) -> Iterator[Dict]:
    logger.info("Parsing %s", path)
    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                event = build_event(record.xml(), path, ctx)
                if event:
                    yield event
    except Exception as exc:
        logger.exception("Erreur lors du parsing de %s: %s", path, exc)


def build_event(xml_data: str, evtx_path: Path, ctx: ScriptContext) -> Optional[Dict]:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        logger.debug("XML invalide dans %s: %s", evtx_path, exc)
        return None

    system = root.find(f"{EVTX_NS}System")
    if system is None:
        return None

    def text(tag: str) -> Optional[str]:
        elem = system.find(f"{EVTX_NS}{tag}")
        return elem.text if elem is not None else None

    provider = system.find(f"{EVTX_NS}Provider")
    provider_name = provider.attrib.get("Name") if provider is not None else None
    provider_guid = provider.attrib.get("Guid") if provider is not None else None
    security = system.find(f"{EVTX_NS}Security")
    user_sid = security.attrib.get("UserID") if security is not None else None

    timestamp = None
    time_created = system.find(f"{EVTX_NS}TimeCreated")
    if time_created is not None:
        timestamp = time_created.attrib.get("SystemTime")

    def parse_data_block(block_name: str) -> Optional[Dict[str, Optional[str]]]:
        block = root.find(f"{EVTX_NS}{block_name}")
        if block is None:
            return None
        entries: Dict[str, Optional[str]] = {}
        for data in block.findall(f"{EVTX_NS}Data"):
            key = data.attrib.get("Name") or "Value"
            entries[key] = data.text
        return entries or None

    execution = system.find(f"{EVTX_NS}Execution")
    process_id = execution.attrib.get("ProcessID") if execution is not None else None
    thread_id = execution.attrib.get("ThreadID") if execution is not None else None
    correlation = system.find(f"{EVTX_NS}Correlation")

    event = {
        "@timestamp": timestamp,
        "case_id": ctx.case_id,
        "evidence_uid": ctx.evidence_uid,
        "source": "evtx_extract",
        "evtx_path": str(evtx_path),
        "channel": text("Channel"),
        "computer": text("Computer"),
        "event_id": text("EventID"),
        "event_record_id": text("EventRecordID"),
        "event_level": text("Level"),
        "keywords": text("Keywords"),
        "opcode": text("Opcode"),
        "provider_name": provider_name,
        "provider_guid": provider_guid,
        "task": text("Task"),
        "user_sid": user_sid,
        "process_id": process_id,
        "thread_id": thread_id,
        "activity_id": correlation.attrib.get("ActivityID") if correlation is not None else None,
        "related_activity_id": correlation.attrib.get("RelatedActivityID") if correlation is not None else None,
        "event_data": parse_data_block("EventData"),
        "user_data": parse_data_block("UserData"),
    }
    return event


def main() -> None:
    ensure_dependencies()
    ctx = load_context()
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="evtx_events")
    total_records = 0
    files = 0
    for evtx_path in discover_evtx_files(ctx.evidence_path):
        files += 1
        for event in parse_evtx_file(evtx_path, ctx):
            writer.write(event)
            total_records += 1
    writer.close()
    logger.info("Fichiers EVTX traités: %d", files)
    logger.info("Événements exportés: %d", total_records)


if __name__ == "__main__":
    main()
