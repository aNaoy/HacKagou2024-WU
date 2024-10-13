# Write-up

## Analyse de l'application web

En arrivant sur la page d'accueil de l'application, un formulaire de login apparaît.

![Page de login](kagu1.png)

Quelque soit les informations entrées, l'authentification semble bien se passer puisque la réponse à notre POST est un 302 avec un "Set-Cookie".

![Réponse suite à la saisie d'informations dans le formulaire de login](kagu2.png)

Par contre il semblerait que l'accès à l'application soit toujours verrouillé.

![Accès refusé](kagu3.png)

En regardant de plus près le cookie transmis, il semblerait que la clé ```auth``` soit encodée en base64 : ```YWRtaW49MA==```

Nous pouvons le décoder facilement via ```echo "YWRtaW49MA==" | base64 -d``` qui nous donne la valeur ```admin=0```.

Nous essayons de créer une nouvelle valeur pour ce cookie en encodant ```admin=1``` en base64 via ```echo -n "admin=1" | base64``` pour obtenir ```YWRtaW49MQ==```.

Nous insérons cette valeur dans le cookie et rechargeons la page.

![Modification du cookie](kagu4.png)

Nous obtenons bien le flag.

![Flag](kagu5.png)