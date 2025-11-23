#!/usr/bin/env python3
"""Extraction de l'historique Chrome/Chromium directement depuis une image disque (dissect.target)."""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, Optional

from dissect.target import Target
from dissect.target.exceptions import FilesystemError, TargetError
from dissect.target.helpers.fsutil import TargetPath

MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "100000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("chrome_history")

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
USER_DIR_CANDIDATES = (
    "C:/Users",
    "C:/Documents and Settings",
    "Users",
    "Documents and Settings",
    "/Users",
)
BROWSER_ROOTS = (
    ("Google", "Chrome", "User Data"),
    ("Chromium", "User Data"),
    ("BraveSoftware", "Brave-Browser", "User Data"),
)
TRANSITION_CORE = {
    0: "LINK",
    1: "TYPED",
    2: "AUTO_BOOKMARK",
    3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME",
    5: "GENERATED",
    6: "START_PAGE",
    7: "FORM_SUBMIT",
    8: "RELOAD",
    9: "KEYWORD",
    10: "KEYWORD_GENERATED",
}
TRANSITION_QUALIFIERS = {
    0x01000000: "BLOCKED",
    0x02000000: "FORWARD_BACK",
    0x04000000: "FROM_ADDRESS_BAR",
    0x08000000: "HOME_PAGE",
    0x10000000: "FROM_API",
    0x20000000: "CHAIN_START",
    0x40000000: "CHAIN_END",
    0x80000000: "CLIENT_REDIRECT",
    0x00800000: "SERVER_REDIRECT",
}


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
        logger.debug("Nouveau fichier %s", filename)

    def write(self, obj: Dict) -> None:
        if not self._fh or self._line_count >= self.max_lines:
            self._open_next_file()
        self._fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._line_count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def env_or_exit(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} doit être défini")
    return value


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


def safe_path(fs, raw_path: str) -> Optional[TargetPath]:
    try:
        path = fs.path(raw_path)
    except FilesystemError:
        return None
    try:
        if path.exists():
            return path
    except FilesystemError:
        return None
    return None


def iter_user_dirs(target: Target) -> Iterator[TargetPath]:
    fs = target.fs
    seen = set()
    for candidate in USER_DIR_CANDIDATES:
        base = safe_path(fs, candidate)
        if not base:
            continue
        try:
            for entry in base.iterdir():
                try:
                    if not entry.is_dir():
                        continue
                except FilesystemError:
                    continue
                lower_name = entry.name.lower()
                if lower_name in {"default", "default user", "public", "all users"}:
                    continue
                key = str(entry).lower()
                if key in seen:
                    continue
                seen.add(key)
                yield entry
        except FilesystemError:
            continue


def iter_history_files(target: Target) -> Iterator[TargetPath]:
    for user_dir in iter_user_dirs(target):
        local_app = user_dir / "AppData" / "Local"
        try:
            if not local_app.exists():
                continue
        except FilesystemError:
            continue
        for segments in BROWSER_ROOTS:
            base = local_app
            valid = True
            for segment in segments:
                base = base / segment
                try:
                    exists = base.exists()
                except FilesystemError:
                    valid = False
                    break
                if not exists:
                    valid = False
                    break
            if not valid:
                continue
            try:
                for profile in base.iterdir():
                    try:
                        if not profile.is_dir():
                            continue
                    except FilesystemError:
                        continue
                    history = profile / "History"
                    try:
                        if history.exists() and history.is_file():
                            yield history
                    except FilesystemError:
                        continue
            except FilesystemError:
                continue


def chrome_time_to_iso(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    try:
        dt = CHROME_EPOCH + timedelta(microseconds=int(value))
    except (OverflowError, ValueError):
        return None
    return dt.isoformat().replace("+00:00", "Z")


def decode_transition(value: Optional[int]) -> Dict[str, Optional[str]]:
    if value is None:
        return {"raw": None, "core": None, "qualifiers": []}
    core = value & 0xFF
    qualifiers = [name for mask, name in TRANSITION_QUALIFIERS.items() if value & mask]
    return {
        "raw": value,
        "core": TRANSITION_CORE.get(core, str(core)),
        "qualifiers": qualifiers,
    }


def copy_remote_file(remote: TargetPath, workspace: Path) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    safe_suffix = abs(hash(str(remote))) & 0xFFFF
    target = workspace / f"history_{safe_suffix:04x}.db"
    with remote.open("rb") as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    return target


def export_history(remote: TargetPath, ctx: ScriptContext, writer: ChunkedJSONLWriter) -> None:
    logger.info("Extraction Chrome: %s", remote)
    tmp_workspace = ctx.output_dir / "tmp"
    local_copy = copy_remote_file(remote, tmp_workspace)
    try:
        conn = sqlite3.connect(f"file:{local_copy}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        logger.error("Connexion SQLite impossible (%s): %s", remote, exc)
        try:
            local_copy.unlink()
        except OSError:
            pass
        return
    conn.row_factory = sqlite3.Row
    query = """
        SELECT
            visits.id AS visit_id,
            visits.visit_time,
            visits.from_visit,
            visits.transition,
            urls.id AS url_id,
            urls.url,
            urls.title,
            urls.visit_count,
            urls.typed_count,
            urls.last_visit_time
        FROM visits
        JOIN urls ON visits.url = urls.id
        ORDER BY visits.visit_time ASC
    """
    total_rows = 0
    try:
        for row in conn.execute(query):
            transition = decode_transition(row["transition"])
            event = {
                "@timestamp": chrome_time_to_iso(row["visit_time"]),
                "case_id": ctx.case_id,
                "evidence_uid": ctx.evidence_uid,
                "source": "chrome_history",
                "history_path": str(remote),
                "visit_id": row["visit_id"],
                "from_visit": row["from_visit"],
                "url_id": row["url_id"],
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "last_visit_time": chrome_time_to_iso(row["last_visit_time"]),
                "transition": transition,
            }
            writer.write(event)
            total_rows += 1
    except sqlite3.Error as exc:
        logger.exception("Erreur pendant l'export %s: %s", remote, exc)
    finally:
        conn.close()
        try:
            local_copy.unlink()
        except OSError:
            pass
    logger.info("Entrées exportées depuis %s: %d", remote, total_rows)


def main() -> None:
    ctx = load_context()
    writer = ChunkedJSONLWriter(ctx.output_dir, base_name="chrome_history")
    files = 0
    try:
        with Target.open(str(ctx.evidence_path)) as target:
            for remote_history in iter_history_files(target):
                files += 1
                export_history(remote_history, ctx, writer)
    except TargetError as exc:
        raise SystemExit(f"Impossible d'ouvrir la preuve avec dissect.target: {exc}") from exc
    finally:
        writer.close()
    if files == 0:
        logger.warning("Aucun profil Chrome/Chromium détecté dans l'image")
    else:
        logger.info("Fichiers Chrome traités: %d", files)


if __name__ == "__main__":
    main()
