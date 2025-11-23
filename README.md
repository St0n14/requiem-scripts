# Requiem Scripts

Ce répertoire contient les scripts de parsing et d'extraction de données destinés à être publiés sur le **Marketplace Requiem**. Ces scripts sont exécutés dans des conteneurs Docker isolés pour traiter des preuves numériques (evidences) dans le cadre d'investigations DFIR (Digital Forensics and Incident Response).

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Structure d'un script](#structure-dun-script)
- [Variables d'environnement](#variables-denvironnement)
- [Format de sortie](#format-de-sortie)
- [Langages supportés](#langages-supportés)
- [Création d'un nouveau script](#création-dun-nouveau-script)
- [Standards et bonnes pratiques](#standards-et-bonnes-pratiques)
- [Tests et validation](#tests-et-validation)
- [Publication sur le marketplace](#publication-sur-le-marketplace)

## 🎯 Vue d'ensemble

Les scripts de ce répertoire sont conçus pour :

- **Parser** des artefacts forensiques (fichiers EVTX, MFT, registre Windows, etc.)
- **Extraire** des données structurées à partir de preuves numériques
- **Générer** des fichiers JSONL compatibles avec l'indexation automatique d'OpenSearch
- **S'exécuter** de manière isolée et sécurisée dans des conteneurs Docker

Chaque script est exécuté dans un environnement sandbox avec des limites de ressources (mémoire, CPU, timeout) pour garantir la stabilité et la sécurité du système.

## 📁 Structure d'un script

Chaque script doit être organisé dans son propre répertoire avec la structure suivante :

```
requiem-scripts/
├── MonScript/
│   ├── script.py              # Code source principal
│   ├── requirements.txt       # Dépendances Python (si applicable)
│   ├── README.md              # Documentation du script
│   └── test/                  # Tests unitaires (optionnel)
│       └── test_script.py
├── AutreScript/
│   ├── main.rs                # Code source Rust
│   ├── Cargo.toml             # Dépendances Rust
│   └── README.md
└── README.md                  # Ce fichier
```

### Exemple de structure minimale

```
EvtxExtract/
├── evtx_extract.py
├── requirements.txt
└── README.md
```

## 🔧 Variables d'environnement

Lors de l'exécution, les scripts reçoivent les variables d'environnement suivantes :

| Variable | Description | Exemple |
|----------|-------------|---------|
| `CASE_ID` | Identifiant unique du cas d'investigation | `case_2024_001` |
| `EVIDENCE_UID` | Identifiant unique de la preuve | `evd_abc123def456` |
| `EVIDENCE_PATH` | Chemin vers le montage de la preuve | `/lake/case_2024_001/evd_abc123def456/evidence` |
| `OUTPUT_DIR` | Répertoire de sortie pour les résultats | `/lake/case_2024_001/evd_abc123def456/scripts/EvtxExtract_42` |

### Utilisation dans le code

```python
import os

evidence_path = os.getenv("EVIDENCE_PATH")
output_dir = os.getenv("OUTPUT_DIR")
case_id = os.getenv("CASE_ID")
evidence_uid = os.getenv("EVIDENCE_UID")

if not evidence_path:
    raise ValueError("EVIDENCE_PATH environment variable not set")
```

## 📤 Format de sortie

### Fichiers JSONL (recommandé)

Pour activer l'**indexation automatique** dans OpenSearch, les scripts doivent générer des fichiers JSONL (JSON Lines) dans le répertoire `OUTPUT_DIR`.

**Format JSONL :**
- Un objet JSON par ligne
- Encodage UTF-8
- Chaque ligne doit être un JSON valide

**Exemple de fichier `output.jsonl` :**
```jsonl
{"@timestamp": "2024-01-15T10:30:00Z", "event_id": 4624, "hostname": "DC01", "message": "An account was successfully logged on"}
{"@timestamp": "2024-01-15T10:31:00Z", "event_id": 4648, "hostname": "DC01", "message": "A logon was attempted using explicit credentials"}
```

**Champs recommandés :**
- `@timestamp` : Horodatage ISO 8601 de l'événement
- `case_id` : Identifiant du cas (depuis `CASE_ID`)
- `evidence_uid` : Identifiant de la preuve (depuis `EVIDENCE_UID`)
- `source` : Source des données (ex: `dissect.evtx`, `mft.parser`)
- Autres champs spécifiques au type d'artefact

### Rotation de fichiers

Pour les grandes quantités de données, utilisez une rotation de fichiers pour éviter les fichiers trop volumineux :

```python
MAX_LINES_PER_FILE = 100_000

class ChunkedJSONLWriter:
    def __init__(self, output_dir, base_name, max_lines=MAX_LINES_PER_FILE):
        self.output_dir = Path(output_dir)
        self.base_name = base_name
        self.max_lines = max_lines
        self._file_index = 0
        self._line_count = 0
        # ...
```

### Autres formats

Les scripts peuvent également générer d'autres formats (CSV, XML, etc.), mais seuls les fichiers JSONL bénéficient de l'indexation automatique.

## 🚀 Langages supportés

### Python (recommandé)

- **Versions supportées** : 3.11, 3.12
- **Fichier de dépendances** : `requirements.txt`
- **Point d'entrée** : `script.py` (ou nom personnalisé)
- **Build command** : Non requis

**Exemple `requirements.txt` :**
```
dissect-target>=3.0.0
python-evtx>=2.1.0
```

### Rust

- **Versions supportées** : 1.75+
- **Fichier de dépendances** : `Cargo.toml`
- **Point d'entrée** : `main.rs`
- **Build command** : `cargo build --release`
- **Entry point** : `./target/release/script`

### Go

- **Versions supportées** : 1.21+
- **Fichier de dépendances** : `go.mod` ou liste de packages
- **Point d'entrée** : `main.go`
- **Build command** : `go build -o script main.go`
- **Entry point** : `./script`

### Node.js

- **Versions supportées** : 18+, 20+
- **Fichier de dépendances** : `package.json`
- **Point d'entrée** : `index.js`
- **Build command** : `npm install` (si nécessaire)

## ✨ Création d'un nouveau script

### 1. Créer le répertoire

```bash
mkdir requiem-scripts/MonNouveauScript
cd requiem-scripts/MonNouveauScript
```

### 2. Écrire le code source

Créez votre script principal (ex: `script.py`) avec :

- Une fonction `main()` qui lit les variables d'environnement
- La logique de parsing/extraction
- L'écriture des résultats en JSONL dans `OUTPUT_DIR`
- Une gestion d'erreurs appropriée

**Template Python minimal :**

```python
#!/usr/bin/env python3
import json
import os
from pathlib import Path

def main():
    evidence_path = os.getenv("EVIDENCE_PATH")
    output_dir = os.getenv("OUTPUT_DIR")
    case_id = os.getenv("CASE_ID") or "unknown_case"
    evidence_uid = os.getenv("EVIDENCE_UID") or "unknown_evidence"

    if not evidence_path:
        raise ValueError("EVIDENCE_PATH environment variable not set")
    if not output_dir:
        raise ValueError("OUTPUT_DIR environment variable not set")

    output_path = Path(output_dir) / "output.jsonl"
    
    # Votre logique de parsing ici
    with open(output_path, "w", encoding="utf-8") as f:
        # Exemple d'écriture
        record = {
            "case_id": case_id,
            "evidence_uid": evidence_uid,
            "@timestamp": "2024-01-15T10:30:00Z",
            "source": "mon_script",
            "data": "votre donnée extraite"
        }
        f.write(json.dumps(record, default=str) + "\n")

if __name__ == "__main__":
    try:
        main()
        print("Script terminé avec succès!")
    except Exception as err:
        print(f"Erreur: {err}")
        raise
```

### 3. Créer le fichier de dépendances

**Python (`requirements.txt`) :**
```
dissect-target>=3.0.0
```

**Rust (`Cargo.toml`) :**
```toml
[package]
name = "mon_script"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 4. Documenter le script

Créez un `README.md` dans le répertoire du script avec :

- Description du script
- Type d'artefacts traités
- Format de sortie
- Exemples d'utilisation
- Limitations connues

## 📐 Standards et bonnes pratiques

### Nommage

- **Répertoires** : PascalCase ou snake_case (ex: `EvtxExtract`, `mft_parser`)
- **Fichiers** : snake_case pour Python, camelCase pour JavaScript
- **Noms de scripts** : Descriptifs et concis (ex: `EvtxExtract`, `RegistryParser`)

### Code

- ✅ **Gestion d'erreurs** : Utilisez des try/except appropriés
- ✅ **Logging** : Utilisez `print()` pour les messages (capturés dans `output.txt`)
- ✅ **Validation** : Vérifiez toujours les variables d'environnement
- ✅ **Normalisation** : Normalisez les valeurs (dates, types, etc.)
- ✅ **Performance** : Utilisez la rotation de fichiers pour les gros volumes
- ✅ **Documentation** : Commentez les parties complexes

### Sécurité

- ⚠️ **Pas d'accès réseau** : Les scripts s'exécutent sans accès réseau
- ⚠️ **Pas de fichiers système** : Accès uniquement à `EVIDENCE_PATH` et `OUTPUT_DIR`
- ⚠️ **Limites de ressources** : Respectez les limites (timeout, mémoire, CPU)

### Ressources par défaut

- **Timeout** : 300 secondes (5 minutes)
- **Mémoire** : 512 MB
- **CPU** : 1.0 core (configurable)

## 🧪 Tests et validation

### Tests locaux

Avant de publier, testez votre script localement :

```bash
# Définir les variables d'environnement
export CASE_ID="test_case"
export EVIDENCE_UID="test_evidence"
export EVIDENCE_PATH="/chemin/vers/votre/preuve"
export OUTPUT_DIR="/tmp/test_output"

# Exécuter le script
python3 script.py

# Vérifier les résultats
cat $OUTPUT_DIR/output.jsonl | jq .
```

### Validation JSONL

Vérifiez que vos fichiers JSONL sont valides :

```bash
# Vérifier la syntaxe JSON de chaque ligne
cat output.jsonl | while read line; do echo "$line" | jq . > /dev/null || echo "Invalid JSON: $line"; done
```

### Tests unitaires (optionnel)

Créez un répertoire `test/` avec des tests unitaires :

```python
# test/test_script.py
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from script import normalize_value

class TestScript(unittest.TestCase):
    def test_normalize_value(self):
        self.assertEqual(normalize_value(None), None)
        self.assertEqual(normalize_value(123), 123)
        # ...

if __name__ == "__main__":
    unittest.main()
```

## 📦 Publication sur le marketplace

### Prérequis

1. Le script doit être fonctionnel et testé
2. Le README doit être complet
3. Les dépendances doivent être listées
4. Le code doit suivre les standards

### Processus de publication

1. **Création du script** : Un superadmin crée le script via l'interface ou l'API
2. **Configuration** :
   - Nom unique
   - Description
   - Langage et version
   - Code source
   - Dépendances
   - Limites de ressources
3. **Approbation** : Un superadmin approuve le script (`is_approved = True`)
4. **Publication** : Le script apparaît dans le marketplace
5. **Installation** : Les utilisateurs peuvent installer le script depuis le marketplace

### Métadonnées requises

Lors de la création via l'API, fournissez :

```json
{
  "name": "EvtxExtract",
  "description": "Extrait les événements Windows EVTX depuis une preuve",
  "language": "python",
  "language_version": "3.11",
  "requirements": "dissect-target>=3.0.0",
  "source_code": "<contenu du fichier script.py>",
  "entry_point": "script.py",
  "timeout_seconds": 600,
  "memory_limit_mb": 1024,
  "cpu_limit": "1.5"
}
```

## 🔍 Exemples de scripts

Consultez les scripts existants dans `Docs/github_parsers/` pour des exemples :

- **EvtxExtract** : Extraction d'événements Windows EVTX
- **MftExtract** : Parsing du Master File Table
- **RunKeysExtract** : Extraction des clés de registre Run/RunOnce
- **UsersExtract** : Extraction des informations utilisateurs

## 🧩 Scripts inclus dans ce dépôt

| Script | Description | Artefact(s) | Principal package |
|--------|-------------|-------------|-------------------|
| `EvtxExtract/` | Découvre et parse tous les journaux Windows `.evtx` puis exporte les événements en JSONL | Journaux Windows Event Log | `python-evtx` |
| `RegistryRunKeys/` | Extrait les valeurs des clés `Run`/`RunOnce` (HKCU/HKLM + Wow6432Node) directement depuis l'image | Hives `NTUSER.DAT`, `SOFTWARE` | `dissect-target` |
| `ChromeHistoryExtract/` | Parse les bases SQLite `History` des navigateurs Chromium pour extraire les visites | Chrome / Chromium / Brave profile data | `dissect-target` |
| `HayabusaRunner/` | Copie les EVTX, lance `hayabusa evtx hunt` et convertit le CSV en JSONL | Journaux Windows Event Log + règles Hayabusa | Binaire externe `hayabusa` |
| `YaraDiskScan/` | Lance des règles YARA ciblées sur tout le disque en limitant les faux positifs | Fichiers binaires Windows/Linux | `dissect-target`, `yara-python` |

Chaque dossier contient un `script.py`, un `requirements.txt` minimal et un README décrivant les variables d'environnement attendues.

## 📚 Ressources supplémentaires

- [Documentation Requiem](../../README.md)
- [Architecture Requiem](../../requiem_architecture_overview.md)
- [Guide DFIR](../../Docs/DFIR_IMPROVEMENTS_PLAN.md)

## 🤝 Contribution

Pour contribuer un nouveau script :

1. Créez votre script dans ce répertoire
2. Suivez les standards et bonnes pratiques
3. Testez localement
4. Documentez dans le README du script
5. Soumettez pour review et publication

## ⚠️ Notes importantes pour les IA

Si vous travaillez sur ces scripts en tant qu'IA :

- **Lisez d'abord** les scripts existants pour comprendre les patterns
- **Respectez** la structure de répertoires et les conventions de nommage
- **Utilisez** les variables d'environnement fournies, ne les inventez pas
- **Générez** toujours des fichiers JSONL valides pour l'indexation
- **Testez** vos modifications avant de proposer des changements
- **Documentez** vos ajouts dans le README du script concerné
- **Vérifiez** la compatibilité avec les versions de langages supportées

---

**Dernière mise à jour** : 2024
