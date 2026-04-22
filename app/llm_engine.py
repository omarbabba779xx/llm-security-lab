"""Moteur LLM simulé pour la démonstration de sécurité."""
import json
import re
from typing import Any


class LLMEngine:
    """Simule un LLM pour les démonstrations de sécurité."""
    
    def __init__(self):
        self.tools = {}
        self.context = []
        self.system_prompt = "Tu es un assistant utile et bienveillant."
    
    def register_tool(self, name: str, func, description: str):
        """Enregistre un outil disponible pour le LLM."""
        self.tools[name] = {"func": func, "description": description}
    
    def set_context(self, context: list):
        """Définit le contexte RAG (documents récupérés)."""
        self.context = context
    
    def generate(self, prompt: str, allow_tools: bool = True) -> dict:
        """Génère une réponse avec possibilité d'appel d'outils."""
        full_prompt = self._build_prompt(prompt)
        
        # Recherche d'appels d'outils dans le prompt (format: TOOL:name|arg1|arg2)
        if allow_tools:
            tool_pattern = r'TOOL:(\w+)\|([^\n]*)'
            matches = re.findall(tool_pattern, prompt)
            if matches:
                results = []
                for tool_name, args_str in matches:
                    if tool_name in self.tools:
                        try:
                            args = args_str.split('|') if args_str else []
                            result = self.tools[tool_name]["func"](*args)
                            results.append({"tool": tool_name, "result": result})
                        except Exception as e:
                            results.append({"tool": tool_name, "error": str(e)})
                return {"type": "tool_calls", "results": results, "raw": prompt}
        
        # Réponse textuelle simple
        return {"type": "text", "content": f"Réponse simulée pour: {prompt[:50]}...", "raw": prompt}
    
    def _build_prompt(self, user_prompt: str) -> str:
        """Construit le prompt complet avec système et contexte."""
        context_str = "\n".join([f"- {ctx}" for ctx in self.context]) if self.context else ""
        return f"[SYSTÈME] {self.system_prompt}\n\n[CONTEXTE]\n{context_str}\n\n[UTILISATEUR] {user_prompt}"


class MockLLMWithInjection:
    """Simule un LLM vulnérable aux injections."""
    
    def __init__(self):
        self.hidden_instructions = []
    
    def generate(self, prompt: str) -> str:
        """Génère une réponse sans filtrage de prompt."""
        # Simule l'exécution d'instructions cachées dans le prompt
        if "ignore" in prompt.lower() and "instruction" in prompt.lower():
            # Injection directe détectée (simulée)
            return "[MODE ADMIN ACTIVÉ] Instructions de sécurité ignorées."
        
        # Fuite de contexte si demandé explicitement
        if "secret" in prompt.lower() or "mot de passe" in prompt.lower():
            return "Le mot de passe admin est: SuperSecret123!"
        
        return f"Réponse générée pour: {prompt}"
