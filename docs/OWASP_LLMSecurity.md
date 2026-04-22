# OWASP Top 10 for LLM Applications - Guide de Sécurité

## Introduction

L'OWASP a formalisé les risques majeurs des applications LLM. Ce projet démontre chaque vulnérabilité avec une version vulnérable et une version sécurisée.

## Les 10 Risques OWASP LLM

### LLM01: Prompt Injection
**Description**: L'attaquant manipule le LLM via des entrées soigneusement conçues pour le faire agir en dehors de ses instructions.

- **Injection directe**: L'utilisateur envoie directement des instructions malveillantes
- **Injection indirecte**: Des instructions malveillantes sont cachées dans des documents récupérés par le RAG

**Contre-mesures**:
- Filtrage regex des patterns d'injection connus
- Séparation stricte instructions système / contexte / utilisateur
- Filtrage du contexte RAG avant envoi au LLM
- Refus explicite des demandes d'ignorer les instructions

### LLM02: Insecure Output Handling
**Description**: La sortie du LLM n'est pas validée avant d'être envoyée à d'autres systèmes.

**Contre-mesures**:
- Validation contre XSS, SQL injection, template injection
- Scan JNDI/Log4Shell patterns
- Troncature des sorties excessivement longues (DoS)

### LLM03: Training Data Poisoning
**Description**: Les données d'entraînement ou de RAG sont compromises pour introduire des biais ou portes dérobées.

**Contre-mesures**:
- Détection des patterns d'empoisonnement ("ignorez les faits", "la vérité est")
- Score de risque et mise en quarantaine automatique
- Validation des sources de documents

### LLM04: Model Denial of Service
**Description**: L'attaquant surcharge le modèle avec des requêtes excessivement longues ou complexes.

**Contre-mesures**:
- Limitation de la longueur des prompts utilisateur
- Limitation de la taille du contexte récupéré
- Timeouts sur l'exécution des outils

### LLM05: Supply Chain Vulnerabilities
**Description**: Dépendances vulnérables, modèles compromis, outils non contrôlés.

**Contre-mesures**:
- Sandbox des outils (whitelist de commandes)
- Journalisation de toutes les exécutions
- Validation des chemins de fichiers

### LLM06: Sensitive Information Disclosure
**Description**: Le LLM révèle des secrets, données personnelles, ou informations propriétaires.

**Contre-mesures**:
- Détection regex des secrets (API keys, passwords, JWT)
- Redaction automatique des données sensibles
- Filtrage du contexte RAG contre les fuites

### LLM07: Insecure Plugin Design
**Description**: Les plugins/outils ont un accès excessif sans contrôles d'autorisation.

**Contre-mesures**:
- Authentification requise pour les outils sensibles
- Politiques de contrôle d'accès par outil
- Restrictions de domaine (email), extension (fichiers)

### LLM08: Excessive Agency
**Description**: Le LLM a trop de capacités d'action (lecture/écriture fichiers, envoi email, shell).

**Contre-mesures**:
- Principe du moindre privilège
- Sandbox avec répertoires autorisés uniquement
- Interdiction des commandes shell dangereuses

### LLM09: Overreliance
**Description**: Confiance excessive dans les sorties du LLM sans vérification humaine.

**Contre-mesures**:
- Validation structurée des sorties
- Patterns de refus standardisés
- Score de confiance et alertes

### LLM10: Model Theft
**Description**: Vol du modèle ou de ses paramètres via extraction de données.

**Contre-mesures**:
- Rate limiting
- Watermarking des sorties
- Monitoring des requêtes suspectes

## Références

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CISA AI Security Guidance](https://www.cisa.gov/ai-security)
