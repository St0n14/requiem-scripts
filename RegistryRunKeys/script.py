#!/usr/bin/env python3
"""Extraction des clés Run/RunOnce via dissect.target directement sur une image disque."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional

from dissect.target import Target
from dissect.target.exceptions import TargetError

MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "100000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("registry_run_keys")


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
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _open_next_file(self) -> None:
        if self._fh:
            self._fh.close()
        filename = f"{self.base_name}_{self._file_index:05d}.jsonl"
        self._fh = (self.output_dir / filename).open("w", encoding="utf-8")
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


def normalize(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    return str(value)


def safe_getattr(entry, *names, default=None):
    for name in names:
        if hasattr(entry, name):
            value = getattr(entry, name)
            if value is not None:
                return value
    return default


def load_context() -> ScriptContext:
    evidence_path = Path(env_or_exit("EVIDENCE_PATH"))
    output_dir = Path(env_or_exit("OUTPUT_DIR"))
    output_dir.mkdir(parents=True, exist_ok=True)
    if not evidence_path.exists():
        raise SystemExit(f"Evidence introuvable: {evidence_path}")
    return ScriptContext(
        case_id=os.getenv("CASE_ID"),
        evidence_uid=os.getenv("EVIDENCE_UID"),
        evidence_path=evidence_path,
        output_dir=output_dir,
    )


def iter_runkeys(target: Target) -> Iterator[object]:
    try:
        plugin = target.runkeys()
    except AttributeError as exc:
        raise SystemExit("Le plugin runkeys de dissect.target est indisponible") from exc
    return iter(plugin)


def record_from_entry(entry, ctx: ScriptContext) -> Dict:
    executable, args = None, None
    command = safe_getattr(entry, "command")
    if isinstance(command, (tuple, list)) and command:
        executable = command[0]
        if len(command) > 1:
            args = command[1]
    elif isinstance(command, str):
        executable = command

    return {
        "case_id": ctx.case_id,
        "evidence_uid": ctx.evidence_uid,
        "source": "dissect.runkeys",
        "@timestamp": normalize(safe_getattr(entry, "ts", "timestamp")),
        "hostname": normalize(safe_getattr(entry, "hostname")),
        "domain": normalize(safe_getattr(entry, "domain")),
        "username": normalize(safe_getattr(entry, "username")),
        "user_sid": normalize(safe_getattr(entry, "user_id", "sid")),
        "hive_path": normalize(safe_getattr(entry, "regf_hive_path", "hive_path")),
        "registry_path": normalize(safe_getattr(entry, "regf_key_path", "key")),
        "value_name": normalize(safe_getattr(entry, "name")),
        "value_data": normalize(safe_getattr(entry, "command")),
        "command_executable": normalize(executable),
        "command_args": normalize(args),
    }


def main() -> None:
    ctx = load_context()
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="registry_run_keys")
    total = 0
    try:
        with Target.open(str(ctx.evidence_path)) as target:
            for entry in iter_runkeys(target):
                record = record_from_entry(entry, ctx)
                writer.write(record)
                total += 1
    except TargetError as exc:
        raise SystemExit(f"Impossible d'ouvrir l'image avec dissect.target: {exc}") from exc
    finally:
        writer.close()
    logger.info("Clés Run extraites: %d", total)


if __name__ == "__main__":
    main()
