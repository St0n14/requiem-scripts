#!/usr/bin/env python3
"""Script de test pour vérifier le téléchargement automatique de Hayabusa."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ajouter le répertoire parent au PATH pour importer le script
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

# Importer les fonctions de téléchargement
from script import get_platform_info, get_hayabusa_download_url, download_and_extract_hayabusa

def test_platform_detection():
    """Test la détection de la plateforme."""
    print("=== Test de détection de plateforme ===")
    try:
        os_name, arch = get_platform_info()
        print(f"✓ Système détecté: {os_name}")
        print(f"✓ Architecture détectée: {arch}")
        return True
    except Exception as e:
        print(f"✗ Erreur: {e}")
        return False

def test_download_url():
    """Test la récupération de l'URL de téléchargement."""
    print("\n=== Test de récupération de l'URL ===")
    try:
        url, filename = get_hayabusa_download_url()
        print(f"✓ URL trouvée: {url}")
        print(f"✓ Nom de fichier: {filename}")
        return True
    except Exception as e:
        print(f"✗ Erreur: {e}")
        return False

def test_download_binary():
    """Test le téléchargement et l'extraction du binaire."""
    print("\n=== Test de téléchargement ===")
    temp_dir = Path(tempfile.mkdtemp(prefix="hayabusa_test_"))
    try:
        print(f"Répertoire temporaire: {temp_dir}")
        binary_path = download_and_extract_hayabusa(temp_dir)
        print(f"✓ Binaire téléchargé: {binary_path}")
        print(f"✓ Taille: {binary_path.stat().st_size / (1024*1024):.2f} MB")

        # Vérifier que le binaire est exécutable
        if not binary_path.is_file():
            print(f"✗ Le binaire n'est pas un fichier valide")
            return False

        print(f"✓ Le binaire existe et est un fichier")

        # Vérifier les permissions d'exécution (Unix uniquement)
        os_name, _ = get_platform_info()
        if os_name != "windows":
            if not binary_path.stat().st_mode & 0o111:
                print("✗ Le binaire n'est pas exécutable")
                return False
            print("✓ Le binaire a les permissions d'exécution")

        return True
    except Exception as e:
        print(f"✗ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Nettoyer le répertoire temporaire
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"Nettoyage: {temp_dir}")


def test_binary_execution():
    """Test l'exécution du binaire Hayabusa."""
    print("\n=== Test d'exécution du binaire ===")
    temp_dir = Path(tempfile.mkdtemp(prefix="hayabusa_test_"))
    try:
        binary_path = download_and_extract_hayabusa(temp_dir)

        # Tester avec --help
        print(f"Exécution de: {binary_path} --help")
        result = subprocess.run(
            [str(binary_path), "--help"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"✗ Le binaire a retourné le code {result.returncode}")
            print(f"stderr: {result.stderr[:500]}")
            return False

        # Vérifier que la sortie contient "Hayabusa"
        if "hayabusa" not in result.stdout.lower():
            print("✗ La sortie ne contient pas 'Hayabusa'")
            print(f"stdout: {result.stdout[:200]}")
            return False

        # Extraire la version si possible
        first_line = result.stdout.split('\n')[0] if result.stdout else ''
        print(f"✓ Le binaire s'exécute correctement")
        print(f"✓ Première ligne: {first_line[:80]}")
        return True
    except subprocess.TimeoutExpired:
        print("✗ Timeout lors de l'exécution du binaire (>30s)")
        return False
    except Exception as e:
        print(f"✗ Erreur lors de l'exécution: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser(
        description="Test du système de téléchargement automatique de Hayabusa"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Exécuter tous les tests incluant le téléchargement (~44 MB)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Exécuter uniquement les tests rapides (détection + API)"
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Mode CI/CD : tous les tests en mode non-interactif"
    )
    args = parser.parse_args()

    # Déterminer le mode
    if args.ci or os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
        # Mode CI : tous les tests sans interaction
        run_download_tests = True
        print("Mode CI/CD détecté - exécution de tous les tests\n")
    elif args.full:
        run_download_tests = True
    elif args.quick:
        run_download_tests = False
    else:
        # Mode interactif par défaut
        print("Test du système de téléchargement automatique de Hayabusa\n")
        print("Options disponibles:")
        print("  --full : Tous les tests (téléchargement inclus)")
        print("  --quick : Tests rapides uniquement")
        print("  --ci : Mode automatique pour CI/CD\n")

    print("Test du système de téléchargement automatique de Hayabusa\n")

    # Exécuter les tests rapides
    results = []
    results.append(("Détection de plateforme", test_platform_detection()))
    results.append(("Récupération de l'URL", test_download_url()))

    # Décider si on exécute les tests de téléchargement
    if 'run_download_tests' not in locals():
        # Mode interactif
        print("\n" + "="*60)
        print("Les tests suivants vont télécharger ~44 MB depuis GitHub")
        try:
            response = input("Voulez-vous continuer avec les tests de téléchargement ? (o/N) : ")
            run_download_tests = response.lower() in ['o', 'oui', 'y', 'yes']
        except (EOFError, KeyboardInterrupt):
            print("\nTests interrompus")
            return 130

    if run_download_tests:
        results.append(("Téléchargement du binaire", test_download_binary()))
        results.append(("Exécution du binaire", test_binary_execution()))
    else:
        print("Tests de téléchargement ignorés")

    # Résumé
    print("\n" + "="*60)
    print("RÉSUMÉ DES TESTS")
    print("="*60)
    for test_name, success in results:
        status = "✓ RÉUSSI" if success else "✗ ÉCHOUÉ"
        print(f"{test_name}: {status}")

    all_success = all(success for _, success in results)
    total = len(results)
    passed = sum(1 for _, success in results if success)

    print("="*60)
    print(f"Résultat: {passed}/{total} tests réussis")
    if all_success:
        print("✓ Tous les tests ont réussi !")
        return 0
    else:
        print("✗ Certains tests ont échoué")
        return 1

if __name__ == "__main__":
    sys.exit(main())
