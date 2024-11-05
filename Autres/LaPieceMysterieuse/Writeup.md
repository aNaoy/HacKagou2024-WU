# Write-up

## Analyse du challenge
L'énoncé propose de retrouver le métal dans lequel est fabriqué la plus grosse pièce HK exposée à la Station N.
Les dimensions et la masse de la pièce sont indiquées, on nous invite manifestement à retrouverle métal à l'aide de sa masse volumique.

## Résolution
On trouve facilement des listes de métaux avec leur masse volumique (par exemple : https://fr.wikipedia.org/wiki/Masse_volumique).
Ces masses volumiques sont exprimées en kg/m3.
Une pièce est un cylindre et la formule pour calculer le volume d'un cylindre est :
```
PI x rayon au carré x hauteur (ou ici épaisseur)
```
On veut la masse volumique en kg/m3, on a donc ici :
```
volume  = PI x (0,04445/2)² x 0,003 = 0,000004655 m3
masse volumique = 0,09 / 0,000004655 = 19332 kg/m3
```
D'après le tableau, 2 métaux correspondent : l'or et le tungstène.
Compte tenu du cours de l'or, une telle pièce vaudrait environ 800 000 F, la réponse la plus probable est donc que la pièce est faite en tungstène.
Le tungstène se distingue pas sa forte densité et sa dureté. Le nom tungstène provient du suédois tung ("lourd") et sten ("pierre") et signifie donc "pierre lourde".