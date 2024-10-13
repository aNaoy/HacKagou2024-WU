# Write-up

## Analyse de l'application web

En arrivant sur la page d'accueil de l'application, si nous n'avons pas nettoyé les cookies, une erreur de JWT apparaît. Il est nécessaire de supprimer le cookie mis en place par le précédent challenge.

![Erreur JWT](anguille1.png)
![alt text](anguille2.png)

Encore une fois, nous tombons sur un formulaire de login qui accepte toutes les informations d'authentification.

![Forumulaire de login](anguille3.png)

Cette fois, le Set-Cookie semble nous donner un nouveau format de cookie.

![Réponse suite à la saisie d'informations dans le formulaire de login](anguille4.png)

L'accès à l'application nous est toujours refusé en l'état.

![Accès refusé](anguille5.png)

En regardant de plus près la structure du cookie fourni par l'application, on remarque encore du base64, semblant séparé en plusieurs blocs par des points :
```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6MCwiZXhwIjoxNzI3ODc5NDE3fQ.pj8ncEtv_goFw3_Cxq0KhBQYQXAAZwElcPN31xjfQGw```

En décodant le premier bloc nous obtenons :
```{"alg":"HS256","typ":"JWT"}```

Une recherche sur Google nous informe que cela ressemble à l'entête d'un JWT (JSON Web Token) qui est un moyen d'échanger des informations de manière sécurisée entre deux parties (comme un client et un serveur) sous la forme d'une chaîne de caractères, souvent utilisé dans les applications web.

Un JWT est composé de trois parties séparées par des points (.) :

* Header (Entête) : Contient des informations sur le type de token et l'algorithme de signature utilisé.
* Payload (Corps) : Contient les informations (ou claims) que l'on veut transmettre, comme l'ID de l'utilisateur, son nom, etc.
* Signature : Vérifie que le token n'a pas été modifié.

En décodant la partie payload de notre JWT, nous observons ```{"admin":0,"exp":1727879417}```.

La signature d'un JWT permet normalement à un serveur de valider l'intégrité de celui-ci. Nous essayons de modifier le payload afin de voir si la signature est bien vérifiée en encodant le nouveau le payload ```{"admin":1,"exp":1727879417}``` en base64 et l'insérant dans la partie centrale de notre JWT.

![Modification du JWT sans vérification de signature](anguille6.png)

En rechargeant la page nous obtenons le flag.

![Flag](anguille7.png)