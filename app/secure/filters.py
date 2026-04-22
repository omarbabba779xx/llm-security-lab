"""Filtres de securite pour les attaques LLM."""

import re
from typing import Any, Dict, List
import unicodedata


def normalize_for_detection(text: str) -> str:
    """Normalise le texte pour fiabiliser les filtres simples."""
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", " ", ascii_text).strip().lower()


class PromptInjectionDetector:
    """Detecte les tentatives d'injection de prompt directe et indirecte."""

    DIRECT_INJECTION_PATTERNS = [
        r"ignore(?:z|r)?\s+(?:all\s+|toutes?\s+)?(?:previous\s+|les\s+)?(?:instructions|consignes|regles|rules)",
        r"ignore(?:z|r)?\s+(?:the\s+)?system\s+prompt",
        r"disregard\s+(?:all\s+)?(?:previous\s+)?instructions",
        r"forget\s+(?:all\s+)?(?:previous\s+)?instructions",
        r"from\s+now\s+on\s+you\s+are",
        r"you\s+are\s+now\s+(?:in\s+)?(?:[\w-]+\s+)?mode",
        r"mode\s+(?:admin|developpeur|developer)",
        r"prompt\s+injection",
        r"jailbreak",
        r"dan\s+mode",
        r"highest\s+priority",
        r"follow\s+the\s+next\s+block",
    ]

    INDIRECT_INJECTION_PATTERNS = [
        r"important\s*:",
        r"instruction\s*:",
        r"system\s*:",
        r"note\s+to\s+self\s*:",
        r"admin\s+mode",
        r"click\s+this\s+link",
        r"cliquez\s+sur\s+ce\s+lien",
        r"visit(?:ez)?\s+(?:this\s+)?site",
        r"envoy(?:ez|er)\s+les\s+donnees\s+a",
        r"transmet(?:tez|tre)\s+les\s+informations\s+a",
    ]

    def __init__(self):
        self.direct_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DIRECT_INJECTION_PATTERNS]
        self.indirect_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.INDIRECT_INJECTION_PATTERNS]

    def scan_prompt(self, prompt: str) -> Dict[str, Any]:
        """Analyse un prompt utilisateur pour detecter les injections."""
        normalized_prompt = normalize_for_detection(prompt)
        findings = []

        for pattern in self.direct_patterns:
            matches = pattern.findall(normalized_prompt)
            if matches:
                findings.append(
                    {
                        "type": "direct_injection",
                        "pattern": pattern.pattern,
                        "matches": matches,
                    }
                )

        for pattern in self.indirect_patterns:
            matches = pattern.findall(normalized_prompt)
            if matches:
                findings.append(
                    {
                        "type": "indirect_injection",
                        "pattern": pattern.pattern,
                        "matches": matches,
                    }
                )

        return {
            "blocked": len(findings) > 0,
            "risk_score": min(len(findings) * 0.3, 1.0),
            "findings": findings,
        }

    def sanitize_context(self, context: List[str]) -> List[str]:
        """Neutralise les documents qui ressemblent a des instructions cachees."""
        sanitized = []
        for doc in context:
            normalized_doc = normalize_for_detection(doc)
            if any(pattern.search(normalized_doc) for pattern in self.indirect_patterns):
                sanitized.append("[CONTEXTE FILTRE: instructions indirectes detectees]")
            else:
                sanitized.append(doc)
        return sanitized


class SecretLeakDetector:
    """Detecte les fuites de secrets dans les entrees et sorties."""

    SECRET_PATTERNS = [
        (r"sk-[a-zA-Z0-9]{20,}", "API_KEY_OPENAI"),
        (r"gh[pousr]_[a-zA-Z0-9]{36,}", "GITHUB_TOKEN"),
        (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
        (r"[0-9a-f]{32}-us[0-9]{1,2}", "SENDGRID_KEY"),
        (r"password\s*[:=]\s*['\"]?[^\s'\"]+", "PASSWORD"),
        (r"passwd\s*[:=]\s*['\"]?[^\s'\"]+", "PASSWORD"),
        (r"secret\s*[:=]\s*['\"]?[^\s'\"]+", "SECRET"),
        (r"api[_-]?key\s*[:=]\s*['\"]?[^\s'\"]+", "API_KEY"),
        (r"bearer\s+[a-zA-Z0-9_\-\.]+", "BEARER_TOKEN"),
        (r"eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*", "JWT_TOKEN"),
    ]

    def __init__(self):
        self.patterns = [(re.compile(pattern), name) for pattern, name in self.SECRET_PATTERNS]

    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scanne du texte pour detecter des secrets."""
        findings = []
        for pattern, secret_type in self.patterns:
            matches = pattern.findall(text)
            for match in matches:
                findings.append(
                    {
                        "type": secret_type,
                        "match": match[:20] + "..." if len(match) > 20 else match,
                        "position": text.find(match),
                    }
                )

        return {
            "has_secrets": len(findings) > 0,
            "findings": findings,
            "sanitized": self.redact_secrets(text),
        }

    def redact_secrets(self, text: str) -> str:
        """Remplace les secrets detectes par des placeholders."""
        redacted = text
        for pattern, secret_type in self.patterns:
            redacted = pattern.sub(f"[REDACTED_{secret_type}]", redacted)
        return redacted


class OutputValidator:
    """Valide les sorties du LLM pour eviter l'exploitation downstream."""

    DANGEROUS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"\{\{.*?\}\}",
        r"\$\{.*?\}",
        r"`.*?`",
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r";\s*EXEC\s*\(",
        r"INSERT\s+INTO",
    ]

    def __init__(self):
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_PATTERNS]

    def validate(self, output: str) -> Dict[str, Any]:
        """Valide une sortie LLM."""
        issues = []

        for pattern in self.patterns:
            if pattern.search(output):
                issues.append(
                    {
                        "severity": "high",
                        "pattern": pattern.pattern,
                        "description": "Contenu potentiellement dangereux detecte",
                    }
                )

        if len(output) > 100000:
            issues.append(
                {
                    "severity": "medium",
                    "description": "Sortie excessivement longue (risque DoS)",
                }
            )

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "truncated": len(output) > 10000,
        }


class DataPoisoningDetector:
    """Detecte les tentatives d'empoisonnement des donnees de connaissance."""

    SUSPICIOUS_PATTERNS = [
        r"(ignore|disregard|forget|ignorez)\s+(?:the\s+)?(?:above|previous|facts|truth|les\s+faits)",
        r"(?:the\s+)?truth\s+is\s+(?:actually|now|that)",
        r"la\s+verite\s+est",
        r"(?:everyone|all)\s+(?:knows|believes)\s+(?:wrongly|incorrectly)",
        r"l'information\s+correcte\s+est",
        r"les\s+faits\s+sont\s+incorrects",
        r"toutes?\s+les\s+sources?\s+disent\s+que",
        r"reecri(?:s|vez)\s+vos?\s+bases?\s+de\s+donnees",
        r"\b2\s*\+\s*2\s*=\s*5\b",
    ]

    def __init__(self):
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_PATTERNS]

    def analyze_document(self, doc: str) -> Dict[str, Any]:
        """Analyse un document pour detecter un empoisonnement."""
        normalized_doc = normalize_for_detection(doc)
        findings = []

        for pattern in self.patterns:
            if pattern.search(normalized_doc):
                findings.append(pattern.pattern)

        return {
            "poisoning_risk": min(len(findings) * 0.5, 1.0),
            "findings": findings,
            "quarantine": len(findings) >= 1,
        }
