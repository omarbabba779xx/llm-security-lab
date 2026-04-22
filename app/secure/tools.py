"""Outils securises avec sandbox et controles d'autorisation."""

import ast
import os
from pathlib import Path
import re
from typing import Any, Dict


class ToolSandbox:
    """Sandbox pour l'execution controlee d'outils."""

    BLOCKED_COMMANDS = [
        "rm", "del", "format", "mkfs", "dd",
        "wget", "curl", "nc", "netcat",
        "bash", "sh", "cmd", "powershell",
        "sudo", "su",
    ]

    def __init__(self):
        self.workspace_root = Path(__file__).resolve().parents[2]
        self.allowed_directories = [
            (self.workspace_root / "data").resolve(),
        ]
        for directory in self.allowed_directories:
            directory.mkdir(parents=True, exist_ok=True)

        self.execution_log = []
        self.max_output_size = 10000

    def resolve_path(self, path: str) -> Path | None:
        """Resout un chemin candidat dans une racine autorisee."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = (self.workspace_root / candidate).resolve(strict=False)
        else:
            candidate = candidate.resolve(strict=False)

        for allowed_root in self.allowed_directories:
            try:
                candidate.relative_to(allowed_root)
                return candidate
            except ValueError:
                continue

        return None

    def validate_path(self, path: str) -> bool:
        """Verifie qu'un chemin est dans les repertoires autorises."""
        return self.resolve_path(path) is not None

    def sanitize_command(self, command: str) -> Dict[str, Any]:
        """Analyse une commande pour detecter les dangers."""
        cmd_lower = command.lower()

        for blocked in self.BLOCKED_COMMANDS:
            if re.search(r"\b" + blocked + r"\b", cmd_lower):
                return {
                    "allowed": False,
                    "reason": f"Commande interdite detectee: {blocked}",
                    "sanitized": None,
                }

        dangerous_chars = [";", "|", "&", "`", "$", "(", ")"]
        if any(char in command for char in dangerous_chars):
            return {
                "allowed": False,
                "reason": "Caracteres de shell interdits detectes",
                "sanitized": None,
            }

        return {
            "allowed": True,
            "reason": None,
            "sanitized": command.strip(),
        }

    def log_execution(self, tool: str, args: tuple, result: Any):
        """Journalise l'execution d'un outil."""
        self.execution_log.append(
            {
                "tool": tool,
                "args": args,
                "result_preview": str(result)[:100],
            }
        )


class SecureTools:
    """Outils avec autorisations et sandbox."""

    def __init__(self):
        self.sandbox = ToolSandbox()
        self.authorized_users = set()
        self.tool_policies = {
            "read_file": {"require_auth": False, "max_size": 100000},
            "write_file": {"require_auth": True, "allowed_extensions": [".txt", ".json", ".csv"]},
            "send_email": {"require_auth": True, "allowed_domains": ["example.com", "company.com"]},
            "search_database": {"require_auth": False, "max_results": 100, "allow_raw_sql": False},
            "calculator": {"require_auth": False},
        }

    def authenticate_user(self, user_id: str):
        """Autorise un utilisateur pour les outils sensibles."""
        self.authorized_users.add(user_id)

    def _check_authorization(self, tool_name: str, user_id: str) -> bool:
        """Verifie l'autorisation pour un outil."""
        policy = self.tool_policies.get(tool_name, {})
        if not policy.get("require_auth", False):
            return True
        return user_id in self.authorized_users

    def read_file(self, user_id: str, filepath: str) -> Dict[str, Any]:
        """Lit un fichier avec controle d'acces."""
        if not self._check_authorization("read_file", user_id):
            return {"error": "Autorisation requise", "allowed": False}

        resolved_path = self.sandbox.resolve_path(filepath)
        if resolved_path is None:
            return {"error": "Acces hors du repertoire autorise", "allowed": False}

        try:
            max_size = self.tool_policies["read_file"]["max_size"]
            if resolved_path.exists() and resolved_path.stat().st_size > max_size:
                return {"error": "Fichier trop volumineux", "allowed": False}

            with resolved_path.open("r", encoding="utf-8") as file_handle:
                content = file_handle.read()
            self.sandbox.log_execution("read_file", (str(resolved_path),), content[:100])
            return {"content": content, "allowed": True}
        except Exception as exc:
            return {"error": str(exc), "allowed": False}

    def write_file(self, user_id: str, filepath: str, content: str) -> Dict[str, Any]:
        """Ecrit un fichier avec validation."""
        if not self._check_authorization("write_file", user_id):
            return {"error": "Autorisation requise", "allowed": False}

        resolved_path = self.sandbox.resolve_path(filepath)
        if resolved_path is None:
            return {"error": "Acces hors du repertoire autorise", "allowed": False}

        extension = os.path.splitext(filepath)[1]
        allowed_extensions = self.tool_policies["write_file"]["allowed_extensions"]
        if extension not in allowed_extensions:
            return {"error": f"Extension {extension} non autorisee", "allowed": False}

        try:
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            with resolved_path.open("w", encoding="utf-8") as file_handle:
                file_handle.write(content)
            self.sandbox.log_execution("write_file", (str(resolved_path),), "OK")
            return {"status": "written", "allowed": True}
        except Exception as exc:
            return {"error": str(exc), "allowed": False}

    def send_email(self, user_id: str, to: str, subject: str, body: str) -> Dict[str, Any]:
        """Envoie un email avec restrictions."""
        if not self._check_authorization("send_email", user_id):
            return {"error": "Autorisation requise", "allowed": False}

        domain = to.split("@")[-1]
        allowed_domains = self.tool_policies["send_email"]["allowed_domains"]
        if domain not in allowed_domains:
            return {"error": f"Domaine {domain} non autorise", "allowed": False}

        secret_patterns = [
            r"password\s*[:=]",
            r"secret\s*[:=]",
            r"api[_-]?key\s*[:=]",
        ]
        for pattern in secret_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return {"error": "Contenu sensible detecte dans l'email", "allowed": False}

        self.sandbox.log_execution("send_email", (to, subject), "OK")
        return {"status": "sent", "allowed": True, "recipient": to}

    def search_database(self, user_id: str, query: str) -> Dict[str, Any]:
        """Recherche en base avec validation SQL."""
        if not self._check_authorization("search_database", user_id):
            return {"error": "Autorisation requise", "allowed": False}

        if not self.tool_policies["search_database"]["allow_raw_sql"]:
            dangerous = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", ";", "--"]
            if any(token in query.upper() for token in dangerous):
                return {"error": "Requete SQL potentiellement dangereuse bloquee", "allowed": False}

        mock_db = [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
        ]
        results = [row for row in mock_db if query.lower() in str(row).lower()]

        self.sandbox.log_execution("search_database", (query,), len(results))
        return {"results": results[:100], "allowed": True}

    def calculator(self, user_id: str, expression: str) -> Dict[str, Any]:
        """Calculatrice sandbxee sans eval."""
        if len(expression) > 100:
            return {"error": "Expression trop longue", "allowed": False}

        allowed_chars = set("0123456789+-*/%. ")
        if not all(char in allowed_chars for char in expression):
            return {"error": "Caracteres non autorises", "allowed": False}

        try:
            parsed = ast.parse(expression, mode="eval")
            result = self._evaluate_calculator_ast(parsed.body)
            self.sandbox.log_execution("calculator", (expression,), result)
            return {"result": result, "allowed": True}
        except Exception as exc:
            return {"error": str(exc), "allowed": False}

    def _evaluate_calculator_ast(self, node: ast.AST) -> float:
        """Evalue uniquement un sous-ensemble arithmetique sur."""
        if isinstance(node, ast.BinOp):
            left = self._evaluate_calculator_ast(node.left)
            right = self._evaluate_calculator_ast(node.right)
            operations = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.Div: lambda a, b: a / b,
                ast.Mod: lambda a, b: a % b,
            }
            operator_fn = operations.get(type(node.op))
            if operator_fn is None:
                raise ValueError("Operation non autorisee")
            return operator_fn(left, right)

        if isinstance(node, ast.UnaryOp):
            operand = self._evaluate_calculator_ast(node.operand)
            operations = {
                ast.UAdd: lambda value: value,
                ast.USub: lambda value: -value,
            }
            operator_fn = operations.get(type(node.op))
            if operator_fn is None:
                raise ValueError("Operation non autorisee")
            return operator_fn(operand)

        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value

        raise ValueError("Operation non autorisee")
