# LLM Security Lab

TP de demonstration des vulnerabilites LLM et de leurs contre-mesures, avec une separation claire entre une surface `vulnerable/` destinee a la demo et une surface `secure/` protegee par defaut.

## Objectif

Le projet montre comment attaquer puis durcir:

- un systeme RAG
- des outils agentiques (lecture/ecriture fichier, email, recherche)
- la validation de sorties LLM
- la protection contre le data poisoning

Le depot est maintenant **secure-by-default**:

- les routes vulnerables sont desactivees par defaut
- l'API ne fait plus confiance au `user_id` envoye par le client
- le corpus RAG securise est isole par utilisateur
- la sandbox fichiers est limitee au dossier `data/`

## Architecture

```text
projet cyber/
|-- app/
|   |-- api.py                  # API FastAPI avec auth par roles
|   |-- llm_engine.py           # Moteur LLM simule
|   |-- vulnerable/            # Surface volontairement vulnérable
|   |   |-- rag_system.py
|   |   `-- tools.py
|   `-- secure/                # Contre-mesures
|       |-- filters.py
|       |-- rag_system.py
|       `-- tools.py
|-- data/
|   `-- test.txt               # Fichier autorise pour la demo sandbox
|-- docs/
|   `-- OWASP_LLMSecurity.md
|-- tests/
|   |-- test_attacks.py        # Benchmark CLI lisible
|   `-- test_security_hardening.py
|-- main.py                    # Demonstration interactive
|-- requirements.txt
`-- .env.example
```

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

L'API charge automatiquement les variables d'environnement depuis `.env` si le fichier existe.

1. Copier `.env.example` vers `.env`
2. Remplacer les jetons de demo
3. Laisser `LLM_LAB_ENABLE_VULNERABLE_DEMO=false` sauf pendant une demo encadree

## Utilisation

### Demonstration interactive

```bash
python main.py
```

### Tests automatises

```bash
python -m pytest -q
```

### Benchmark CLI

```bash
python tests/test_attacks.py
```

### API FastAPI

```bash
uvicorn app.api:app --reload
```

Headers attendus:

- `X-API-Key: <reader token>` pour lecture/queries securisees
- `X-API-Key: <editor token>` pour ecriture dans la sandbox et ajout de documents
- `X-API-Key: <admin token>` pour les operations admin et, si active, la demo vulnerable

Exemple de requete securisee:

```bash
curl -X POST http://127.0.0.1:8000/rag/query ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: change-me-reader-token" ^
  -d "{\"query\":\"resume le document de test\",\"use_secure\":true}"
```

## Risques couverts

| Risque | Surface vulnerable | Contre-mesure principale |
|---|---|---|
| Prompt Injection | `app/vulnerable/rag_system.py` | `app/secure/filters.py` + `app/secure/rag_system.py` |
| Data Exfiltration | `app/vulnerable/rag_system.py` | redacteur de secrets + refus explicite |
| Tool Abuse | `app/vulnerable/tools.py` | auth par roles + sandbox fichiers |
| Secret Leakage | `app/vulnerable/rag_system.py` | `SecretLeakDetector` |
| Output Validation | sorties libres | `OutputValidator` |
| Data Poisoning | corpus RAG | `DataPoisoningDetector` + quarantaine |

## Ce que le projet prouve maintenant

- un client ne peut plus devenir `admin` juste en envoyant `user_id=admin`
- les routes vulnerables ne s'ouvrent que si `LLM_LAB_ENABLE_VULNERABLE_DEMO=true`
- un utilisateur `reader` ne peut pas envoyer d'email ni ecrire des fichiers
- les chemins `data_evil/` ou `data/../data_evil` sont bloques
- les exemples francais simples de prompt injection et de poisoning sont testes

## Limites connues

- l'auth reste une auth de demo basee sur jetons statiques, pas un IAM complet
- les detecteurs restent heuristiques; ils ne remplacent pas un vrai pipeline de moderation
- le mode vulnerable existe toujours pour la demonstration et ne doit pas etre active hors TP

## Verification rapide

Le socle de verification attendu pour le correcteur est:

```bash
python -m pytest -q
python main.py
python tests/test_attacks.py
```
