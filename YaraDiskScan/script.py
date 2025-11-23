#!/usr/bin/env python3
"""Scanne une image disque avec des règles YARA (dissect.target + yara-python)."""
from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, Optional, Sequence, Set, Tuple

import yara
from dissect.target import Target
from dissect.target.exceptions import FilesystemError, TargetError
from dissect.target.helpers.fsutil import TargetPath

MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "100000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("yara_disk_scan")

DEFAULT_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".ocx",
    ".drv",
    ".com",
    ".cpl",
    ".bin",
    ".dat",
}
DEFAULT_EXCLUDES = {"system volume information", "$recycle.bin", "windows.old", "winsxs"}
SEVERITY_KEYS = ("severity", "confidence", "score", "level", "weight")
ROOT_CANDIDATES = ("/", "\\", "C:", "C:/", "C\\", "\\Device\\HarddiskVolume1")


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


@dataclass
class ScanConfig:
    rules_path: Path
    include_extensions: Optional[Set[str]]
    exclude_dirs: Set[str]
    max_file_size: int
    max_matches_per_file: int
    max_strings: int
    string_sample_bytes: int
    min_severity: Optional[float]
    require_severity: bool
    yara_timeout: int


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


def parse_extensions(value: Optional[str]) -> Optional[Set[str]]:
    if not value:
        return set(DEFAULT_EXTENSIONS)
    normalized = {ext.strip().lower() for ext in value.split(",") if ext.strip()}
    if not normalized or "*" in normalized:
        return None
    return {ext if ext.startswith(".") else f".{ext}" for ext in normalized}


def parse_excludes(value: Optional[str]) -> Set[str]:
    if not value:
        return set(DEFAULT_EXCLUDES)
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def load_context() -> ScriptContext:
    evidence_path = Path(env_or_exit("EVIDENCE_PATH"))
    output_dir = Path(env_or_exit("OUTPUT_DIR"))
    if not evidence_path.exists():
        raise SystemExit(f"Evidence introuvable: {evidence_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    return ScriptContext(
        case_id=os.getenv("CASE_ID"),
        evidence_uid=os.getenv("EVIDENCE_UID"),
        evidence_path=evidence_path,
        output_dir=output_dir,
    )


def load_scan_config() -> ScanConfig:
    rules_path = Path(env_or_exit("YARA_RULES_PATH"))
    include_extensions = parse_extensions(os.getenv("YARA_INCLUDE_EXT"))
    exclude_dirs = parse_excludes(os.getenv("YARA_EXCLUDE_DIRS"))
    max_file_size_mb = float(os.getenv("YARA_MAX_FILESIZE_MB", "50"))
    max_file_size = int(max_file_size_mb * 1024 * 1024)
    max_matches = int(os.getenv("YARA_MAX_MATCHES_PER_FILE", "5"))
    max_strings = int(os.getenv("YARA_MAX_STRINGS", "3"))
    string_sample_bytes = int(os.getenv("YARA_STRING_SAMPLE_BYTES", "96"))
    min_severity_env = os.getenv("YARA_MIN_SEVERITY")
    min_severity = float(min_severity_env) if min_severity_env else None
    require_severity = os.getenv("YARA_REQUIRE_SEVERITY", "0") in {"1", "true", "TRUE", "yes"}
    yara_timeout = int(os.getenv("YARA_TIMEOUT_SECONDS", "30"))
    return ScanConfig(
        rules_path=rules_path,
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        max_file_size=max_file_size,
        max_matches_per_file=max_matches,
        max_strings=max_strings,
        string_sample_bytes=string_sample_bytes,
        min_severity=min_severity,
        require_severity=require_severity,
        yara_timeout=yara_timeout,
    )


def gather_rule_files(path: Path) -> Sequence[Path]:
    candidates = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule"}]
    return sorted(candidates)


def compile_rules(config: ScanConfig) -> "yara.Rules":
    path = config.rules_path
    if not path.exists():
        raise SystemExit(f"Chemin de règles introuvable: {path}")
    if path.is_file():
        logger.info("Compilation de %s", path)
        return yara.compile(filepath=str(path))
    rule_files = gather_rule_files(path)
    if not rule_files:
        raise SystemExit(f"Aucune règle .yar trouvée sous {path}")
    file_map = {f"rule_{idx}": str(rule) for idx, rule in enumerate(rule_files)}
    logger.info("Compilation de %d fichiers YARA", len(rule_files))
    return yara.compile(filepaths=file_map)


def safe_stat(path: TargetPath):
    try:
        return path.stat()
    except FilesystemError:
        return None


def should_scan_file(path: TargetPath, config: ScanConfig):
    stat = safe_stat(path)
    if stat is None:
        return None
    if stat.st_size == 0 or stat.st_size > config.max_file_size:
        return None
    if config.include_extensions is not None and path.suffix.lower() not in config.include_extensions:
        return None
    parts_lower = {part.lower() for part in path.parts}
    if parts_lower & config.exclude_dirs:
        return None
    return stat


def extract_severity(meta: Dict[str, object]) -> Optional[float]:
    for key, value in meta.items():
        if not isinstance(key, str):
            continue
        if key.lower() in SEVERITY_KEYS:
            try:
                return float(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
    return None


def format_strings(match, config: ScanConfig) -> Sequence[Dict[str, object]]:
    entries = []
    for idx, (offset, identifier, data) in enumerate(match.strings):
        if idx >= config.max_strings:
            break
        if isinstance(data, bytes):
            snippet = base64.b64encode(data[: config.string_sample_bytes]).decode("ascii")
        else:
            snippet = str(data)[: config.string_sample_bytes]
        entries.append({"identifier": identifier, "offset": offset, "snippet_b64": snippet})
    return entries


def file_timestamp(stat) -> Optional[str]:
    mtime = getattr(stat, "st_mtime", None)
    if mtime is None:
        return None
    return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def read_file_bytes(path: TargetPath, limit: int) -> Optional[bytes]:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except (FilesystemError, OSError) as exc:
        logger.debug("Lecture impossible de %s: %s", path, exc)
        return None


def scan_file(
    path: TargetPath,
    stat,
    rules,
    ctx: ScriptContext,
    config: ScanConfig,
    writer: ChunkedJSONLWriter,
) -> int:
    data = read_file_bytes(path, config.max_file_size)
    if not data:
        return 0
    try:
        matches = rules.match(data=data, timeout=config.yara_timeout)
    except yara.TimeoutError:
        logger.warning("Timeout YARA sur %s", path)
        return 0
    except yara.Error as exc:
        logger.warning("Erreur YARA sur %s: %s", path, exc)
        return 0

    ts = file_timestamp(stat)
    matches_written = 0
    for match in matches:
        severity = extract_severity(match.meta)
        if config.require_severity and severity is None:
            continue
        if severity is not None and config.min_severity is not None and severity < config.min_severity:
            continue
        record = {
            "@timestamp": ts,
            "case_id": ctx.case_id,
            "evidence_uid": ctx.evidence_uid,
            "source": "yara_disk_scan",
            "file_path": str(path),
            "file_size": getattr(stat, "st_size", None),
            "rule_name": match.rule,
            "rule_namespace": match.namespace,
            "tags": match.tags,
            "severity": severity,
            "meta": match.meta,
            "strings": format_strings(match, config),
        }
        writer.write(record)
        matches_written += 1
        if matches_written >= config.max_matches_per_file:
            break
    return matches_written


def determine_roots(fs) -> list[TargetPath]:
    roots = []
    seen = set()
    for candidate in ROOT_CANDIDATES:
        try:
            path = fs.path(candidate)
        except FilesystemError:
            continue
        try:
            exists = path.exists()
        except FilesystemError:
            continue
        if not exists:
            continue
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        roots.append(path)
    if not roots:
        try:
            roots.append(fs.path("/"))
        except FilesystemError:
            pass
    return roots


def walk_files(target: Target, config: ScanConfig) -> Iterator[Tuple[TargetPath, object]]:
    fs = target.fs
    stack = determine_roots(fs)
    visited = set()
    while stack:
        current = stack.pop()
        key = str(current).lower()
        if key in visited:
            continue
        visited.add(key)
        try:
            entries = list(current.iterdir())
        except FilesystemError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name.lower() in config.exclude_dirs:
                        continue
                    stack.append(entry)
                elif entry.is_file():
                    stat = should_scan_file(entry, config)
                    if stat:
                        yield entry, stat
            except FilesystemError:
                continue


def main() -> None:
    ctx = load_context()
    config = load_scan_config()
    rules = compile_rules(config)
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="yara_disk_matches")
    scanned = 0
    matches = 0
    try:
        with Target.open(str(ctx.evidence_path)) as target:
            for file_path, stat in walk_files(target, config):
                scanned += 1
                matches += scan_file(file_path, stat, rules, ctx, config, writer)
    except TargetError as exc:
        raise SystemExit(f"Impossible d'ouvrir l'image avec dissect.target: {exc}") from exc
    finally:
        writer.close()
    logger.info("Fichiers scannés: %d", scanned)
    logger.info("Matches YARA écrits: %d", matches)


if __name__ == "__main__":
    main()
