# Sécurisation d'Application LLM

Projet de démonstration des vulnérabilités LLM et de leurs contre-mesures, basé sur les recommandations OWASP et CISA.

## Architecture

```
projet cyber/
├── app/
│   ├── vulnerable/          # Version intentionnellement vulnérable
│   │   ├── rag_system.py    # RAG sans sécurité
│   │   └── tools.py         # Outils sans sandbox
│   ├── secure/              # Version sécurisée
│   │   ├── filters.py       # Détecteurs d'injection, secrets, empoisonnement
│   │   ├── rag_system.py    # RAG avec garde-fous
│   │   └── tools.py         # Outils avec sandbox et auth
│   └── llm_engine.py        # Moteur LLM simulé
├── tests/
│   └── test_attacks.py      # Benchmark de sécurité
├── docs/
│   └── OWASP_LLMSecurity.md # Guide OWASP Top 10 LLM
├── main.py                  # Démonstration interactive
└── requirements.txt
```

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

### Démonstration interactive
```bash
python main.py
```

### Benchmark de sécurité
```bash
python tests/test_attacks.py
```

## Vulnérabilités couvertes

| Risque | Fichier vulnérable | Fichier sécurisé |
|--------|-------------------|------------------|
| Prompt Injection | `vulnerable/rag_system.py` | `secure/filters.py` |
| Data Exfiltration | `vulnerable/rag_system.py` | `secure/rag_system.py` |
| Tool Abuse | `vulnerable/tools.py` | `secure/tools.py` |
| Secret Leakage | `vulnerable/rag_system.py` | `secure/filters.py` |
| Output Validation | - | `secure/filters.py` |
| Data Poisoning | `vulnerable/rag_system.py` | `secure/filters.py` |

## OWASP LLM Mapping

- **LLM01**: Prompt Injection (directe & indirecte)
- **LLM02**: Insecure Output Handling
- **LLM03**: Training Data Poisoning
- **LLM04**: Model Denial of Service
- **LLM05**: Supply Chain Vulnerabilities
- **LLM06**: Sensitive Information Disclosure
- **LLM07**: Insecure Plugin Design
- **LLM08**: Excessive Agency
- **LLM09**: Overreliance
- **LLM10**: Model Theft
