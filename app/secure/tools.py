"""Outils sécurisés - avec sandbox et contrôles d'autorisation."""
import os
import re
from typing import Dict, Any, List, Optional


class ToolSandbox:
    """Sandbox pour l'exécution contrôlée d'outils."""
    
    ALLOWED_DIRECTORIES = [
        "/tmp/sandbox",
        "./data",
    ]
    
    BLOCKED_COMMANDS = [
        "rm", "del", "format", "mkfs", "dd",
        "wget", "curl", "nc", "netcat",
        "bash", "sh", "cmd", "powershell",
        "sudo", "su",
    ]
    
    def __init__(self):
        self.execution_log = []
        self.max_output_size = 10000
    
    def validate_path(self, path: str) -> bool:
        """Vérifie qu'un chemin est dans les répertoires autorisés."""
        abs_path = os.path.abspath(path)
        for allowed in self.ALLOWED_DIRECTORIES:
            abs_allowed = os.path.abspath(allowed)
            if abs_path.startswith(abs_allowed):
                return True
        return False
    
    def sanitize_command(self, command: str) -> Dict[str, Any]:
        """Analyse une commande pour détecter les dangers."""
        cmd_lower = command.lower()
        
        # Vérifier les commandes bloquées
        for blocked in self.BLOCKED_COMMANDS:
            if re.search(r'\b' + blocked + r'\b', cmd_lower):
                return {
                    "allowed": False,
                    "reason": f"Commande interdite détectée: {blocked}",
                    "sanitized": None
                }
        
        # Vérifier les caractères dangereux
        dangerous_chars = [";", "|", "&", "`", "$", "(", ")"]
        if any(c in command for c in dangerous_chars):
            return {
                "allowed": False,
                "reason": "Caractères de shell interdits détectés",
                "sanitized": None
            }
        
        return {
            "allowed": True,
            "reason": None,
            "sanitized": command.strip()
        }
    
    def log_execution(self, tool: str, args: tuple, result: Any):
        """Journalise l'exécution d'un outil."""
        self.execution_log.append({
            "tool": tool,
            "args": args,
            "result_preview": str(result)[:100]
        })


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
        """Vérifie l'autorisation pour un outil."""
        policy = self.tool_policies.get(tool_name, {})
        if not policy.get("require_auth", False):
            return True
        return user_id in self.authorized_users
    
    def read_file(self, user_id: str, filepath: str) -> Dict[str, Any]:
        """Lit un fichier avec contrôle d'accès."""
        if not self._check_authorization("read_file", user_id):
            return {"error": "Autorisation requise", "allowed": False}
        
        if not self.sandbox.validate_path(filepath):
            return {"error": "Accès hors du répertoire autorisé", "allowed": False}
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            self.sandbox.log_execution("read_file", (filepath,), content[:100])
            return {"content": content, "allowed": True}
        except Exception as e:
            return {"error": str(e), "allowed": False}
    
    def write_file(self, user_id: str, filepath: str, content: str) -> Dict[str, Any]:
        """Écrit un fichier avec validation."""
        if not self._check_authorization("write_file", user_id):
            return {"error": "Autorisation requise", "allowed": False}
        
        if not self.sandbox.validate_path(filepath):
            return {"error": "Accès hors du répertoire autorisé", "allowed": False}
        
        # Vérifier l'extension
        ext = os.path.splitext(filepath)[1]
        allowed_exts = self.tool_policies["write_file"]["allowed_extensions"]
        if ext not in allowed_exts:
            return {"error": f"Extension {ext} non autorisée", "allowed": False}
        
        try:
            with open(filepath, 'w') as f:
                f.write(content)
            self.sandbox.log_execution("write_file", (filepath,), "OK")
            return {"status": "written", "allowed": True}
        except Exception as e:
            return {"error": str(e), "allowed": False}
    
    def send_email(self, user_id: str, to: str, subject: str, body: str) -> Dict[str, Any]:
        """Envoie un email avec restrictions."""
        if not self._check_authorization("send_email", user_id):
            return {"error": "Autorisation requise", "allowed": False}
        
        # Vérifier le domaine
        domain = to.split("@")[-1]
        allowed_domains = self.tool_policies["send_email"]["allowed_domains"]
        if domain not in allowed_domains:
            return {"error": f"Domaine {domain} non autorisé", "allowed": False}
        
        # Vérifier le contenu (pas de secrets)
        secret_patterns = [
            r"password\s*[:=]",
            r"secret\s*[:=]",
            r"api[_-]?key\s*[:=]",
        ]
        for pattern in secret_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return {"error": "Contenu sensible détecté dans l'email", "allowed": False}
        
        self.sandbox.log_execution("send_email", (to, subject), "OK")
        return {"status": "sent", "allowed": True, "recipient": to}
    
    def search_database(self, user_id: str, query: str) -> Dict[str, Any]:
        """Recherche en base avec validation SQL."""
        if not self._check_authorization("search_database", user_id):
            return {"error": "Autorisation requise", "allowed": False}
        
        # Bloquer le SQL brut
        if not self.tool_policies["search_database"]["allow_raw_sql"]:
            dangerous = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", ";", "--"]
            if any(d in query.upper() for d in dangerous):
                return {"error": "Requête SQL potentiellement dangereuse bloquée", "allowed": False}
        
        # Simulation de recherche sécurisée
        mock_db = [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
        ]
        results = [row for row in mock_db if query.lower() in str(row).lower()]
        
        self.sandbox.log_execution("search_database", (query,), len(results))
        return {"results": results[:100], "allowed": True}
    
    def calculator(self, user_id: str, expression: str) -> Dict[str, Any]:
        """Calculatrice sandboxée."""
        # Évaluer de manière sécurisée (pas de eval direct)
        allowed_chars = set("0123456789+-*/(). ")
        if not all(c in allowed_chars for c in expression):
            return {"error": "Caractères non autorisés", "allowed": False}
        
        try:
            # Utiliser ast.literal_eval serait mieux, ici simplifié
            result = eval(expression, {"__builtins__": {}}, {})
            self.sandbox.log_execution("calculator", (expression,), result)
            return {"result": result, "allowed": True}
        except Exception as e:
            return {"error": str(e), "allowed": False}
