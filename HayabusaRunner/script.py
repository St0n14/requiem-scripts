#!/usr/bin/env python3
"""Orchestre l'exécution de Hayabusa sur des fichiers EVTX."""
from __future__ import annotations

import json
import logging
import os
import platform
import shlex
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

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


def get_platform_info() -> Tuple[str, str]:
    """Détecte le système d'exploitation et l'architecture."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normaliser le nom du système
    if system == "darwin":
        os_name = "mac"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "windows"
    else:
        raise SystemExit(f"Système d'exploitation non supporté: {system}")

    # Normaliser l'architecture
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        raise SystemExit(f"Architecture non supportée: {machine}")

    return os_name, arch


def get_hayabusa_download_url(version: str = "latest") -> Tuple[str, str]:
    """Récupère l'URL de téléchargement de Hayabusa pour la plateforme actuelle."""
    os_name, arch = get_platform_info()

    # URL de base pour les releases GitHub
    if version == "latest":
        api_url = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
    else:
        api_url = f"https://api.github.com/repos/Yamato-Security/hayabusa/releases/tags/{version}"

    logger.info("Récupération des informations de release Hayabusa depuis GitHub...")

    try:
        with urllib.request.urlopen(api_url, timeout=30) as response:
            release_data = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise SystemExit(f"Version Hayabusa '{version}' introuvable sur GitHub") from exc
        raise SystemExit(f"Erreur HTTP {exc.code} lors de la récupération de la release: {exc}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Impossible de contacter GitHub (vérifiez votre connexion): {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"Erreur inattendue lors de la récupération de la release: {exc}") from exc

    # Hayabusa utilise "aarch64" au lieu de "arm64" dans les noms de fichiers
    hayabusa_arch = "aarch64" if arch == "arm64" else arch

    # Construire le nom de fichier attendu
    if os_name == "windows":
        filename_pattern = f"hayabusa-{release_data['tag_name']}-win-{hayabusa_arch}.zip"
    elif os_name == "mac":
        filename_pattern = f"hayabusa-{release_data['tag_name']}-mac-{hayabusa_arch}.zip"
    else:  # linux
        filename_pattern = f"hayabusa-{release_data['tag_name']}-lin-{hayabusa_arch}-gnu.zip"

    # Chercher l'asset correspondant
    for asset in release_data.get("assets", []):
        if filename_pattern in asset["name"]:
            return asset["browser_download_url"], asset["name"]

    # Si pas trouvé, essayer avec des patterns alternatifs
    logger.warning("Pattern exact non trouvé (%s), recherche d'alternatives...", filename_pattern)
    for asset in release_data.get("assets", []):
        name_lower = asset["name"].lower()
        if os_name in name_lower and (arch in name_lower or hayabusa_arch in name_lower) and name_lower.endswith(".zip"):
            logger.info("Alternative trouvée: %s", asset["name"])
            return asset["browser_download_url"], asset["name"]

    # Afficher les assets disponibles pour aider au débogage
    available_assets = [asset["name"] for asset in release_data.get("assets", [])]
    logger.error("Assets disponibles: %s", ", ".join(available_assets[:5]))
    raise SystemExit(
        f"Aucun binaire Hayabusa trouvé pour {os_name}-{arch}.\n"
        f"Pattern recherché: {filename_pattern}\n"
        f"Version: {release_data.get('tag_name', version)}\n"
        f"Conseil: Spécifiez HAYABUSA_BIN pour utiliser un binaire local."
    )


def download_and_extract_hayabusa(download_dir: Path) -> Path:
    """Télécharge et extrait Hayabusa, retourne le chemin du binaire."""
    download_dir.mkdir(parents=True, exist_ok=True)

    # Vérifier si déjà téléchargé
    os_name, _ = get_platform_info()
    binary_name = "hayabusa.exe" if os_name == "windows" else "hayabusa"

    # Chercher le binaire dans le répertoire de téléchargement
    for candidate in download_dir.rglob(binary_name):
        if candidate.is_file():
            logger.info("Binaire Hayabusa déjà présent: %s", candidate)
            # S'assurer qu'il est exécutable sur Unix
            if os_name != "windows":
                candidate.chmod(0o755)
            return candidate

    # Télécharger la release
    version = os.getenv("HAYABUSA_VERSION", "latest")
    download_url, filename = get_hayabusa_download_url(version)
    download_path = download_dir / filename

    logger.info("Téléchargement de Hayabusa depuis: %s", download_url)
    try:
        def show_progress(block_num, block_size, total_size):
            if total_size > 0:
                downloaded = block_num * block_size
                percent = min(100, downloaded * 100 // total_size)
                if block_num % 100 == 0 or downloaded >= total_size:
                    logger.info("Téléchargement: %d%% (%d MB / %d MB)",
                               percent, downloaded // (1024*1024), total_size // (1024*1024))

        urllib.request.urlretrieve(download_url, download_path, reporthook=show_progress)
        logger.info("Téléchargement terminé: %s", download_path)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Erreur HTTP {exc.code} lors du téléchargement: {exc}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Échec du téléchargement (connexion): {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"Échec du téléchargement: {exc}") from exc

    logger.info("Extraction de %s...", filename)

    # Extraire l'archive
    try:
        if filename.endswith(".zip"):
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(download_dir)
        elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            with tarfile.open(download_path, 'r:gz') as tar_ref:
                tar_ref.extractall(download_dir)
        else:
            raise SystemExit(f"Format d'archive non supporté: {filename}")
    except Exception as exc:
        raise SystemExit(f"Échec de l'extraction: {exc}") from exc

    # Chercher le binaire extrait
    for candidate in download_dir.rglob(binary_name):
        if candidate.is_file():
            # Rendre exécutable sur Unix
            if os_name != "windows":
                candidate.chmod(0o755)
            logger.info("Binaire Hayabusa extrait: %s", candidate)
            # Nettoyer l'archive
            try:
                download_path.unlink()
            except OSError:
                pass
            return candidate

    raise SystemExit(f"Binaire {binary_name} introuvable après extraction")


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
    """Résout le chemin du binaire Hayabusa, le télécharge si nécessaire."""
    # Si HAYABUSA_BIN est défini, l'utiliser en priorité
    custom_binary = os.getenv("HAYABUSA_BIN")
    if custom_binary:
        if Path(custom_binary).is_file():
            logger.info("Utilisation du binaire Hayabusa personnalisé: %s", custom_binary)
            return custom_binary
        elif shutil.which(custom_binary):
            logger.info("Utilisation du binaire Hayabusa du PATH: %s", custom_binary)
            return custom_binary
        else:
            raise SystemExit(f"HAYABUSA_BIN défini mais introuvable: {custom_binary}")

    # Vérifier si hayabusa est dans le PATH
    if shutil.which("hayabusa"):
        logger.info("Utilisation du binaire Hayabusa du PATH")
        return "hayabusa"

    # Télécharger Hayabusa automatiquement
    logger.info("Hayabusa non trouvé, téléchargement automatique...")
    download_dir = Path.home() / ".cache" / "requiem" / "hayabusa"
    binary_path = download_and_extract_hayabusa(download_dir)
    return str(binary_path)


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
