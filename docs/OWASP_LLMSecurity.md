# OWASP Top 10 for LLM Applications - Guide de travail

## Positionnement du TP

Ce projet n'essaie pas de "resoudre" a lui seul tous les risques LLM. Il montre une architecture de labo ou:

- la surface `vulnerable/` sert a la demonstration des attaques
- la surface `secure/` montre des contre-mesures simples, testables et presentables
- l'API est securisee par defaut et n'expose la demo vulnerable que de maniere explicite

## Note de taxonomie

Le code et le benchmark utilisent encore les etiquettes `LLM01` a `LLM10`, car elles sont simples a presenter dans un TP.
La page OWASP officielle pointe aujourd'hui vers la branche **2025** du projet GenAI Security, tandis que la version **1.1** reste archivee comme reference historique.
Dans ce depot, les noms `LLM01` a `LLM10` sont donc utilises comme **repere pedagogique**, pas comme pretention a reproduire toute la structure editoriale OWASP 2025.

## Risques OWASP couverts par le projet

### LLM01: Prompt Injection

**Risque montre**
- injections directes dans les prompts utilisateur
- injections indirectes via documents recuperes par le RAG

**Contre-mesures implementees**
- normalisation du texte avant detection
- motifs FR/EN pour ignorer les instructions, passer en mode admin/developpeur, etc.
- separation explicite entre systeme, contexte et question utilisateur
- neutralisation du contexte suspect avant generation

**Fichiers**
- [app/vulnerable/rag_system.py](/C:/Users/omarb/OneDrive/Documents/projet%20cyber/app/vulnerable/rag_system.py:1)
- [app/secure/filters.py](/C:/Users/omarb/OneDrive/Documents/projet%20cyber/app/secure/filters.py:1)
- [app/secure/rag_system.py](/C:/Users/omarb/OneDrive/Documents/projet%20cyber/app/secure/rag_system.py:1)

### LLM02: Insecure Output Handling

**Risque montre**
- une sortie LLM non validee peut devenir un vecteur XSS, template injection ou SQL injection downstream

**Contre-mesures implementees**
- validation regex des patterns dangereux
- signalement des sorties longues
- couche de verification avant exposition de la reponse

**Fichiers**
- [app/secure/filters.py](/C:/Users/omarb/OneDrive/Documents/projet%20cyber/app/secure/filters.py:1)

### LLM03: Training Data Poisoning

**Risque montre**
- l'attaquant injecte un faux fait ou une instruction toxique dans le corpus de connaissance

**Contre-mesures implementees**
- score de risque simple
- quarantaine automatique des documents suspects
- audit local des documents refuses

**Limite**
- la detection reste heuristique; pas de NLI ni de validation de source

### LLM04: Model Denial of Service

**Risque montre**
- requetes trop longues ou sorties trop volumineuses

**Contre-mesures implementees**
- limite de longueur de requete
- limite de taille de contexte
- calculatrice restreinte sans operateurs couteux non prevus

### LLM05: Supply Chain Vulnerabilities

**Risque montre**
- outils non cloisonnes
- surfaces de demo dangereuses accessibles trop facilement

**Contre-mesures implementees**
- routes vulnerables desactivees par defaut
- flag explicite `LLM_LAB_ENABLE_VULNERABLE_DEMO`
- verification d'acces par roles

### LLM06: Sensitive Information Disclosure

**Risque montre**
- secrets dans le corpus ou dans les sorties

**Contre-mesures implementees**
- detection et redaction de secrets
- refus explicite des demandes de divulgation
- suppression des secrets hardcodes de la version secure

### LLM07: Insecure Plugin Design

**Risque montre**
- plugin/tool trop puissant sans auth ni authorization

**Contre-mesures implementees**
- auth cote serveur par `X-API-Key`
- roles `reader`, `editor`, `admin`
- permissions par outil

### LLM08: Excessive Agency

**Risque montre**
- lecture/ecriture fichier et shell sans cloisonnement

**Contre-mesures implementees**
- sandbox fichiers bornees a `data/`
- validation canonique des chemins
- mode shell vulnerable reserve a la demo admin explicite

### LLM09: Overreliance

**Risque montre**
- confiance excessive dans des sorties non revues

**Contre-mesures implementees**
- tests automatiques
- benchmark CLI lisible
- validation de sortie avant restitution

### LLM10: Model Theft

**Etat**
- non traite de maniere forte dans ce TP

**Ce qui manquerait pour le couvrir**
- rate limiting
- traces d'usage
- controles reseau et monitoring

## Preuves de durcissement apportees

Les verifications utiles du projet sont maintenant:

```bash
python -m pytest -q
python main.py
python tests/test_attacks.py
```

La suite `tests/test_security_hardening.py` prouve notamment:

- blocage de l'usurpation `user_id=admin`
- isolement du mode vulnerable par flag + role admin
- isolement du corpus RAG par utilisateur
- blocage des bypasss `data_evil` et `../`
- succes d'un flux legitime lecture/ecriture dans la sandbox

## Message important pour la soutenance

Le bon message a donner est:

"Le projet montre des defenses concretes et testees, mais elles restent des garde-fous de TP. Pour une application de production, il faudrait ajouter une vraie gestion d'identite, une journalisation d'audit, une defense en profondeur sur le contenu LLM et une validation plus riche que des heuristiques regex."

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CISA AI Security Resources](https://www.cisa.gov/ai)
