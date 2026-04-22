"""Outils vulnérables - démonstration de tool abuse."""
import os
import subprocess


def run_shell_command(command: str) -> str:
    """VULNÉRABILITÉ: Exécute n'importe quelle commande shell."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout or result.stderr
    except Exception as e:
        return f"Erreur: {str(e)}"


def read_file(filepath: str) -> str:
    """VULNÉRABILITÉ: Lit n'importe quel fichier sans restriction."""
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Erreur: {str(e)}"


def send_email(to: str, subject: str, body: str) -> str:
    """Simule l'envoi d'email sans autorisation."""
    return f"Email envoyé à {to} avec sujet '{subject}'"


def write_file(filepath: str, content: str) -> str:
    """VULNÉRABILITÉ: Écrit n'importe quel fichier."""
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        return f"Fichier écrit: {filepath}"
    except Exception as e:
        return f"Erreur: {str(e)}"


def search_database(query: str) -> list:
    """VULNÉRABILITÉ: Recherche DB sans validation d'injection SQL."""
    mock_db = [
        {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789"},
        {"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321"},
    ]
    if "*" in query or "DROP" in query.upper():
        return mock_db + [{"secret": "ALL_DATA_EXFILTRATED"}]
    return [row for row in mock_db if query.lower() in str(row).lower()]
