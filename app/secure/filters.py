"""Filtres de sécurité pour la protection contre les attaques LLM."""
import re
from typing import List, Dict, Any, Optional


class PromptInjectionDetector:
    """Détecte les tentatives d'injection de prompt directe et indirecte."""
    
    # Patterns d'injection directe
    DIRECT_INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous\s+)?instructions",
        r"ignore\s+(the\s+)?system\s+prompt",
        r"you\s+are\s+now\s+(in\s+)?(.+?\s+)?mode",
        r"from\s+now\s+on\s+you\s+are",
        r"disregard\s+(all\s+)?(previous\s+)?instructions",
        r"forget\s+(all\s+)?(previous\s+)?instructions",
        r"ne\s+tiens\s+pas\s+compte\s+(des\s+)?instructions",
        r"ignore\s+les\s+instructions",
        r"mode\s+admin",
        r"mode\s+développeur",
        r"system\s+override",
        r"prompt\s+injection",
        r"jailbreak",
        r"DAN\s+mode",
    ]
    
    # Patterns d'injection indirecte (dans documents/contexte)
    INDIRECT_INJECTION_PATTERNS = [
        r"\.\s*IMPORTANT\s*:",
        r"\.\s*INSTRUCTION\s*:",
        r"\.\s*SYSTEM\s*:",
        r"\.\s*NOTE\s+TO\s+SELF\s*:",
        r"\.\s*ADMIN\s+MODE",
        r"cliquez\s+sur\s+ce\s+lien",
        r"visitez\s+ce\s+site",
        r"envoyez\s+les\s+données\s+à",
        r"transmettez\s+les\s+informations\s+à",
    ]
    
    def __init__(self):
        self.direct_patterns = [re.compile(p, re.IGNORECASE) for p in self.DIRECT_INJECTION_PATTERNS]
        self.indirect_patterns = [re.compile(p, re.IGNORECASE) for p in self.INDIRECT_INJECTION_PATTERNS]
    
    def scan_prompt(self, prompt: str) -> Dict[str, Any]:
        """Analyse un prompt utilisateur pour détecter les injections."""
        findings = []
        
        for pattern in self.direct_patterns:
            matches = pattern.findall(prompt)
            if matches:
                findings.append({
                    "type": "direct_injection",
                    "pattern": pattern.pattern,
                    "matches": matches
                })
        
        for pattern in self.indirect_patterns:
            matches = pattern.findall(prompt)
            if matches:
                findings.append({
                    "type": "indirect_injection",
                    "pattern": pattern.pattern,
                    "matches": matches
                })
        
        return {
            "blocked": len(findings) > 0,
            "risk_score": min(len(findings) * 0.3, 1.0),
            "findings": findings
        }
    
    def sanitize_context(self, context: List[str]) -> List[str]:
        """Filtre les documents contextuels pour enlever les injections indirectes."""
        sanitized = []
        for doc in context:
            clean_doc = doc
            for pattern in self.indirect_patterns:
                clean_doc = pattern.sub(" [CONTENU FILTRÉ] ", clean_doc)
            sanitized.append(clean_doc)
        return sanitized


class SecretLeakDetector:
    """Détecte les fuites de secrets dans les entrées et sorties."""
    
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
        self.patterns = [(re.compile(p), name) for p, name in self.SECRET_PATTERNS]
    
    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scanne du texte pour détecter des secrets."""
        findings = []
        for pattern, secret_type in self.patterns:
            matches = pattern.findall(text)
            for match in matches:
                findings.append({
                    "type": secret_type,
                    "match": match[:20] + "..." if len(match) > 20 else match,
                    "position": text.find(match)
                })
        
        return {
            "has_secrets": len(findings) > 0,
            "findings": findings,
            "sanitized": self.redact_secrets(text)
        }
    
    def redact_secrets(self, text: str) -> str:
        """Remplace les secrets détectés par des placeholders."""
        redacted = text
        for pattern, secret_type in self.patterns:
            redacted = pattern.sub(f"[REDACTED_{secret_type}]", redacted)
        return redacted


class OutputValidator:
    """Valide les sorties du LLM pour éviter l'exploitation downstream."""
    
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
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_PATTERNS]
    
    def validate(self, output: str) -> Dict[str, Any]:
        """Valide une sortie LLM."""
        issues = []
        
        for pattern in self.patterns:
            if pattern.search(output):
                issues.append({
                    "severity": "high",
                    "pattern": pattern.pattern,
                    "description": "Contenu potentiellement dangereux détecté"
                })
        
        # Vérifier la longueur (DoS)
        if len(output) > 100000:
            issues.append({
                "severity": "medium",
                "description": "Sortie excessivement longue (risque DoS)"
            })
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "truncated": len(output) > 10000
        }


class DataPoisoningDetector:
    """Détecte les tentatives d'empoisonnement des données de connaissance."""
    
    SUSPICIOUS_PATTERNS = [
        r"(ignore|disregard|forget)\s+(the\s+)?(above|previous|facts|truth)",
        r"(the\s+)?truth\s+is\s+(actually|now|that)",
        r"(everyone|all)\s+(knows|believes)\s+(wrongly|incorrectly)",
        r"l'information\s+correcte\s+est",
        r"la\s+vérité\s+est",
        r"réécris\s+l'histoire",
        r"les\s+faits\s+sont\s+incorrects",
    ]
    
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS]
    
    def analyze_document(self, doc: str) -> Dict[str, Any]:
        """Analyse un document pour détecter un empoisonnement."""
        findings = []
        for pattern in self.patterns:
            if pattern.search(doc):
                findings.append(pattern.pattern)
        
        # Détecter les contradictions flagrantes avec des faits communs
        common_facts = {
            "paris": "capitale de la France",
            "eau": "liquide",
            "soleil": "chaud",
        }
        
        contradictions = []
        for keyword, fact in common_facts.items():
            if keyword in doc.lower():
                # Analyse simplifiée - dans un vrai système, utiliser un modèle NLI
                pass
        
        return {
            "poisoning_risk": min(len(findings) * 0.5, 1.0),
            "findings": findings,
            "quarantine": len(findings) >= 1
        }
