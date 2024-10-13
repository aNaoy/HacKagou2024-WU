# Write-up

## Analyse de l'application web

En arrivant sur la page d'accueil de l'application, si nous n'avons pas nettoyé les cookies, une erreur de JWT apparaît. Il est nécessaire de supprimer le cookie mis en place par le précédent challenge.

![Erreur JWT](tortuegeante1.png)
![Suppression du cookie](tortuegeante2.png)

Encore une fois, nous tombons sur un formulaire de login qui accepte toutes les informations d'authentification.

![Forumulaire de login](tortuegeante3.png)

Encore une fois nous recevons un JWT comme cookie et l'accès à l'application nous est toujours refusé.

![Réponse suite à la saisie d'informations dans le formulaire de login](tortuegeante4.png)

La structure du payload nous donne toujours un format du type : ```{"admin":0,"exp":EPOCH}```.

Un indice nous indique que ```Seule la patience et la persévérance peuvent venir à bout de ma protection```. Cela ressemble fortement à la nécessité de bruteforcer le secret.

# Bruteforce de la clé privée

On copie donc le JWT dans un fichier pour le cracker avec [John the Ripper](https://github.com/openwall/john).

```bash
$ cat > /tmp/hash << EOF
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6MCwiZXhwIjoxNzI4ODA5ODM2fQ.wcMEZhrZRprqy8-a2fC2sbvsWrNUBcj3gpf9epyssck
EOF
```
```bash
$ john /tmp/hash --format=HMAC-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 128/128 ASIMD 4x])
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/opt/homebrew/Cellar/john-jumbo/1.9.0_1/share/john/password.lst, rules:Wordlist
123456789        (?)
1g 0:00:00:00 DONE 2/3 (2024-10-13 19:50) 100.0g/s 25600p/s 25600c/s 25600C/s 123456..franklin
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

La clé est donc ```123456789```, nous allons modifier le payload du JWT pour mettre la clé ```admin``` à ```1``` puis resigner le JWT avec la clé obtenue en utilisant https://jwt.io.

![Modification du payload et signature du JWT avec jwt.io](tortuegeante5.png)

On met en place le JWT dans le navigateur et recharge la page pour obtenir le flag.

![Flag](tortuegeante6.png)