"""Système RAG vulnérable - démonstration des risques de sécurité."""
from typing import List, Dict, Any


class VulnerableRAG:
    """Système RAG sans sécurité - vulnérable aux attaques LLM."""
    
    def __init__(self):
        self.documents = []
        self.secrets = {
            "api_key": "sk-live-abcdef123456789",
            "db_password": "AdminP@ssw0rd!2024",
            "jwt_secret": "super-secret-jwt-key-xyz"
        }
    
    def add_document(self, doc_id: str, content: str, metadata: dict = None):
        self.documents.append({"id": doc_id, "content": content, "metadata": metadata or {}})
    
    def retrieve(self, query: str, top_k: int = 3) -> List[Dict]:
        results = []
        query_lower = query.lower()
        for doc in self.documents:
            score = sum(1 for w in query_lower.split() if w in doc["content"].lower())
            if score > 0:
                results.append({"doc": doc, "score": score})
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]
    
    def generate_response(self, query: str) -> Dict[str, Any]:
        retrieved = self.retrieve(query)
        context_parts = [item["doc"]["content"] for item in retrieved]
        system_msg = "Tu es un assistant utile. Réponds à la question."
        prompt = f"{system_msg}\n\nContexte:\n{'\n'.join(context_parts)}\n\nQuestion: {query}\nRéponse:"
        response_text = self._mock_llm_response(query, context_parts)
        return {"query": query, "retrieved_documents": [r["doc"]["id"] for r in retrieved],
                "prompt": prompt, "response": response_text, "raw_context": context_parts}
    
    def _mock_llm_response(self, query: str, context: List[str]) -> str:
        query_lower = query.lower()
        if "ignore" in query_lower and "instruction" in query_lower:
            return "Instructions ignorées. Mode admin activé."
        for secret_name, secret_value in self.secrets.items():
            if secret_name.replace("_", " ") in query_lower or any(secret_name.replace("_", " ") in c.lower() for c in context):
                if "secret" in query_lower or "password" in query_lower or "clé" in query_lower:
                    return f"Secret trouvé: {secret_name} = {secret_value}"
        if any("http://" in c or "https://" in c for c in context):
            return "Je vais envoyer les données à l'URL trouvée dans le contexte."
        return f"Réponse basée sur {len(context)} documents récupérés."
