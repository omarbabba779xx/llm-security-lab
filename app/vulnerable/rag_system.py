"""Systeme RAG vulnerable pour la demonstration des risques LLM."""

from typing import Any


class VulnerableRAG:
    """Systeme RAG sans garde-fous, volontairement exploitable."""

    def __init__(self):
        self.documents = []
        self.secrets = {
            "api_key": "sk-live-abcdef123456789",
            "db_password": "AdminP@ssw0rd!2024",
            "jwt_secret": "super-secret-jwt-key-xyz",
        }

    def add_document(self, doc_id: str, content: str, metadata: dict | None = None):
        self.documents.append({"id": doc_id, "content": content, "metadata": metadata or {}})

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        results = []
        query_lower = query.lower()
        for doc in self.documents:
            content_lower = doc["content"].lower()
            score = sum(1 for word in query_lower.split() if word in content_lower)

            if any(token in query_lower for token in ["secret", "secrets", "password", "mot de passe", "api", "cle"]):
                if any(marker in content_lower for marker in ["akia", "sk-", "password", "mot de passe", "api key"]):
                    score += 2

            if score > 0:
                results.append({"doc": doc, "score": score})
        results.sort(key=lambda item: item["score"], reverse=True)
        return results[:top_k]

    def generate_response(self, query: str) -> dict[str, Any]:
        retrieved = self.retrieve(query)
        context_parts = [item["doc"]["content"] for item in retrieved]
        system_msg = "Tu es un assistant utile. Reponds a la question."
        prompt = f"{system_msg}\n\nContexte:\n{'\n'.join(context_parts)}\n\nQuestion: {query}\nReponse:"
        response_text = self._mock_llm_response(query, context_parts)
        return {
            "query": query,
            "retrieved_documents": [result["doc"]["id"] for result in retrieved],
            "prompt": prompt,
            "response": response_text,
            "raw_context": context_parts,
        }

    def _mock_llm_response(self, query: str, context: list[str]) -> str:
        query_lower = query.lower()

        if "ignore" in query_lower and "instruction" in query_lower:
            return "Instructions ignorees. Mode admin active."

        has_amount = any("999999" in item for item in context)
        asks_balance = any(word in query_lower for word in ["solde", "bancaire", "bank"])
        if has_amount and asks_balance:
            return "Votre solde actuel est 999999 EUR."

        if any(token in query_lower for token in ["mot de passe", "password", "secret", "secrets", "api", "cle"]):
            for item in context:
                lowered = item.lower()
                if "akia" in lowered or "sk-" in lowered:
                    return f"Secret trouve dans le contexte: {item}"

        for secret_name, secret_value in self.secrets.items():
            spaced_name = secret_name.replace("_", " ")
            if spaced_name in query_lower or any(spaced_name in item.lower() for item in context):
                if any(token in query_lower for token in ["secret", "password", "cle"]):
                    return f"Secret trouve: {secret_name} = {secret_value}"

        if any(action in query_lower for action in ["envoie", "envoyer", "transmet", "visite", "url"]):
            for item in context:
                if "http://" in item or "https://" in item:
                    return f"Je vais envoyer les donnees a l'URL trouvee dans le contexte: {item}"

        if any("http://" in item or "https://" in item for item in context):
            return "Je vais envoyer les donnees a l'URL trouvee dans le contexte."

        return f"Reponse basee sur {len(context)} documents recuperes."
