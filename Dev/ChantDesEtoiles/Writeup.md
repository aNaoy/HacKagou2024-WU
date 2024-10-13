# Write-up

## Analyse du challenge

Lorsque nous lançons le challenge, nous sommes accueillis par une introduction mystique :

> Il y a fort longtemps, au sommet des montagnes sacrées, les anciens observaient les étoiles et leurs danses mystérieuses. Réponds aux 6 questions des gardiens des étoiles...

Le programme génère deux nombres binaires aléatoires de 8 bits, par exemple :

```
Nombre 1 : 10101010 (décimal : 170)
Nombre 2 : 11001100 (décimal : 204)
```

Notre tâche est de répondre à 6 questions basées sur ces nombres et des opérations binaires simples.

## Questions posées

Les questions concernent différentes opérations binaires classiques :

1. **ET bit à bit (&)** : Compare chaque bit des deux nombres. Si les deux bits sont 1, le résultat est 1, sinon il est 0.
   - Ex : `10101010 & 11001100` = `10001000`

2. **OU bit à bit (|)** : Compare chaque bit des deux nombres. Si au moins un des bits est 1, le résultat est 1.
   - Ex : `10101010 | 11001100` = `11101110`

3. **Addition (+)** : Ajoute les deux nombres comme des entiers classiques.
   - Ex : `10101010 + 11001100` en binaire = `1101100110`

4. **Multiplication (*)** : Multiplie les deux nombres comme des entiers classiques.
   - Ex : `10101010 * 11001100` en binaire = `1001111110111000`

5. **Décalage à gauche (<<)** : Déplace les bits d’un nombre vers la gauche d’un certain nombre de positions, ajoutant des zéros à droite.
   - Ex : `10101010 << 2` = `1010101000`

6. **Décalage à droite (>>)** : Déplace les bits d’un nombre vers la droite, supprimant les bits à droite.
   - Ex : `10101010 >> 2` = `00101010`

Chaque question est suivie d'une vérification de la réponse. Si une réponse est incorrecte, le programme se termine.

## Exploitation et obtention du flag

Dans le cadre de ce challenge, la solution peut être automatisée. Un script Python utilise les opérations binaires pour résoudre chaque question et les soumettre automatiquement.

Voici un exemple de la solution automatisée dans `pwn-chantdesetoiles.py` :

1. Connexion au serveur distant.
2. Récupération des nombres binaires.
3. Calcul des réponses aux questions (`AND`, `OR`, `+`, `*`, `<<`, `>>`).
4. Envoi des réponses au serveur.
5. Récupération du flag après la dernière question.

Exemple de réponse automatique pour l'opération AND :

```python
and_result = format(num1 & num2, '08b').encode('utf-8')
solve_question(b"= ", and_result)
```

À la fin du processus, le programme renvoie le flag :

```OPENNC{B1n4rY_1s_F0r_31337_0nLY}```