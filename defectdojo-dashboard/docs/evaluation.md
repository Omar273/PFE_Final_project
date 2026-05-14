# Évaluation du Modèle IA de Priorisation des Vulnérabilités

## 1. Objectif du Projet

Ce projet vise à développer un modèle d'intelligence artificielle capable de prédire si une vulnérabilité a de fortes chances d'être exploitée, afin d'aider les équipes de cybersécurité à prioriser leurs efforts de remédiation.

L'approche proposée est comparée à une méthode traditionnelle basée uniquement sur le score CVSS.

## 2. Sources de Données et Méthodologie de Jointure

### Sources utilisées

**Base CVE / NVD**

Les vulnérabilités ont été récupérées depuis la base du National Vulnerability Database (NVD), contenant :

- CVE ID
- CVSS Score
- CVSS Severity
- CWE
- Description
- Vendor
- Produit
- Date de publication
- Données techniques associées

**Base KEV**

La liste des vulnérabilités réellement exploitées provient du catalogue Cybersecurity and Infrastructure Security Agency KEV (Known Exploited Vulnerabilities).

Cette source fournit les CVE confirmées comme exploitées dans des attaques réelles.

### Méthodologie de Jointure

Les deux jeux de données ont été fusionnés via la clé :

**CVE_ID**

Processus :

1. Extraction des vulnérabilités depuis la NVD
2. Extraction des CVE présentes dans KEV
3. Jointure sur CVE_ID
4. Création de la variable cible :
   - `Exploited = 1` si CVE présente dans KEV
   - `Exploited = 0` sinon

## 3. Prétraitement des Données

### Nettoyage

- Suppression des valeurs manquantes critiques
- Encodage des variables catégorielles
- Normalisation des variables numériques

### Gestion du déséquilibre des classes

Le dataset présente un fort déséquilibre :

- Très peu de vulnérabilités sont réellement exploitées
- La majorité ne le sont pas

Pour corriger ce problème :

- Utilisation de la technique **SMOTE** (Synthetic Minority Oversampling Technique)

**Résultats :**

| Étape | Nombre d'échantillons |
|-------|----------------------|
| Avant SMOTE | 266,321 |
| Après SMOTE | 530,098 |

## 4. Distribution des Classes

### Dataset initial

| Classe | Nombre |
|--------|--------|
| Not Exploited | 266,003 |
| Exploited | 318 |

Le dataset est extrêmement déséquilibré.

**Taux de vulnérabilités exploitées :**


Cela justifie l'utilisation de techniques d'équilibrage comme SMOTE.

## 5. Modèles Entraînés

Deux modèles ont été évalués :

- **Random Forest**
- **XGBoost**

Validation utilisée :

- Cross-validation 5-fold

## 6. Résultats de Cross-Validation

| Modèle | F1-score moyen | Écart-type |
|--------|---------------|------------|
| Random Forest | 0.9496 | ± 0.0009 |
| **XGBoost** | **0.9747** | **± 0.0004** |

Le modèle XGBoost présente les meilleures performances globales.

## 7. Évaluation sur le Jeu de Test

### Random Forest

| Classe | Precision | Recall | F1-score |
|--------|-----------|--------|----------|
| Not Exploited | 1.00 | 0.93 | 0.96 |
| Exploited | 0.04 | 0.72 | 0.08 |

**Matrice de confusion**

| | Prédit Non Exploité | Prédit Exploité |
|---|--------------------|-----------------|
| **Réel Non Exploité** | 61,307 | 4,956 |
| **Réel Exploité** | 89 | 229 |

### XGBoost (Modèle Final)

| Classe | Precision | Recall | F1-score |
|--------|-----------|--------|----------|
| Not Exploited | 1.00 | 0.97 | 0.98 |
| Exploited | 0.08 | 0.55 | 0.14 |

**Matrice de confusion**

| | Prédit Non Exploité | Prédit Exploité |
|---|--------------------|-----------------|
| **Réel Non Exploité** | 64,184 | 2,079 |
| **Réel Exploité** | 143 | 175 |

## 8. Comparaison IA vs Approche CVSS

### Résultats de Seuillage

| Méthode | Precision | Recall | F1-score |
|---------|-----------|--------|----------|
| IA | 0.149 | 0.567 | 0.236 |
| CVSS | 0.005 | 1.000 | 0.010 |

## 9. Analyse ROC-AUC

### Scores AUC-ROC

| Méthode | AUC |
|---------|-----|
| **IA** | **0.951** |
| CVSS | 0.500 |

**Interprétation :**

- Une AUC de **0.951** indique une excellente capacité de discrimination du modèle IA.
- Une AUC de **0.500** pour CVSS correspond quasiment à un comportement aléatoire.

## 10. Gain Opérationnel

L'objectif principal est de réduire la charge de travail des analystes sécurité tout en conservant un niveau élevé de détection.

### Résultats à 80 % de Recall

| Méthode | Findings à Traiter |
|---------|-------------------|
| IA | 23,600 |
| CVSS | 283,529 |

### Réduction de Charge

### Résultat Final

Le modèle IA permet une réduction de :

**91.7 % de la charge opérationnelle**

tout en conservant un niveau élevé de détection des vulnérabilités exploitées.

> C'est le principal bénéfice métier du projet.

## 11. Temps d'Entraînement

| Modèle | Temps |
|--------|-------|
| Random Forest | 47.8 s |
| **XGBoost** | **8.8 s** |

XGBoost est à la fois :

- plus performant
- plus rapide

## 12. Modèle Final Sélectionné

**Modèle retenu : XGBoost**

Critères de sélection :

- Meilleur F1-score global
- Excellente AUC-ROC
- Temps d'entraînement réduit
- Meilleur compromis précision/rappel

Le modèle final a été sauvegardé dans :

## 13. Conclusion

Ce projet démontre qu'une approche basée sur l'intelligence artificielle permet de largement améliorer la priorisation des vulnérabilités par rapport à une approche classique basée uniquement sur CVSS.

Le modèle XGBoost atteint :

- une excellente capacité de discrimination (AUC = 0.951)
- une réduction de **91.7 %** de la charge opérationnelle
- une meilleure priorisation des vulnérabilités réellement dangereuses

Cette approche peut être intégrée dans des plateformes SOC, SIEM ou outils de gestion des vulnérabilités afin d'aider les analystes sécurité à traiter les risques les plus critiques en priorité.