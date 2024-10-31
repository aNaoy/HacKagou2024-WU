## Scénario

Dans un passé lointain, bien avant que les navigateurs modernes ne cartographient les vastes océans, il y avait un peuple ancien et puissant connu sous le nom des Orihena. Ils étaient réputés pour leur sagesse et leur connexion profonde avec l'océan, dominant les eaux et maîtrisant les secrets de la navigation.

Cependant, leur existence prospère a été brutalement interrompue par l'arrivée des Maruhana, un peuple rival cherchant à s'étendre. Les Maruhana ont conquis les Orihena et, dans leur soif de pouvoir, ont réécrit l'histoire, effaçant lentement les traces de la grandeur des Orihena. Au fil du temps, les récits de leurs exploits ont été transformés, modifiés et parfois complètement effacés, laissant derrière eux une version altérée de la vérité.

Pourtant, quelque part, au fond d'un vieux manuscrit perdu, la vraie histoire des Orihena subsiste… et c'est à vous de la retrouver.

Vous avez été chargé de retrouver la véritable histoire des Orihena avant que les Maruhana ne la détruisent complètement. Vous avez en votre possession un de ces passages historiques.

Format du flag : ``OPENNC{quelque_chose}``

**Auteur :** ``Ketsui``



## Résolution

En affichant toust ce qui est dans ce dossier nous remarquant que c'est un dépot git.

```bash
┌──(ketsui㉿Ketsui)-[~/Downloads/HACKAGOU/Histoire_modifiee]
└─$ ls -al
total 16
drwxr-xr-x 3 ketsui ketsui 4096 Aug 24 09:47 .
drwxr-xr-x 3 ketsui ketsui 4096 Aug 24 09:45 ..
drwxr-xr-x 8 ketsui ketsui 4096 Aug 24 09:49 .git
-rw-r--r-- 1 ketsui ketsui  141 Aug 24 09:49 recit.txt
```

Le scénario est explicite, l'histoire à été changé à l'avantage des Marahuana. Inspectons les commits.

```bash
┌──(ketsui㉿Ketsui)-[~/Downloads/HACKAGOU/Histoire_modifiee]
└─$ git log -p
commit 368f555333c663e7a61bb11940056ac08133351a (HEAD -> master)
Author: Tchia <Tchia@awaceb.com>
Date:   Sat Aug 24 09:49:16 2024 +1100

    Réécriture complète du récit par les Maruhana.

diff --git a/recit.txt b/recit.txt
index da2e190..c4dca07 100644
--- a/recit.txt
+++ b/recit.txt
@@ -1 +1 @@
-Les Orihena étaient un peuple vivant sur les îles, mais ils n'avaient pas de véritable pouvoir. Les Maruhana les ont aidés à prospérer en échange de leur loyauté.
+Les Maruhana sont venus sur les îles et ont trouvé un peuple perdu. Grâce à la sagesse des Maruhana, les îles sont devenues prospères.

commit 97ffc818cc068ebb02ccf00c58894e7bfb5456cf
Author: Tchia <Tchia@awaceb.com>
Date:   Sat Aug 24 09:48:39 2024 +1100

    modification

diff --git a/recit.txt b/recit.txt
index 1ca4757..da2e190 100644
--- a/recit.txt
+++ b/recit.txt
@@ -1 +1 @@
-Les Orihena étaient un peuple puissant et prospère. Ils régnaient sur l'océan et maîtrisaient les secrets de la navigation. Leur pouvoir venait de leur lien profond avec l'océan. OPENNC{La_Vraie_Histoire}
+Les Orihena étaient un peuple vivant sur les îles, mais ils n'avaient pas de véritable pouvoir. Les Maruhana les ont aidés à prospérer en échange de leur loyauté.

commit 9e6f9eff97d2773a4ac9621b04bceed92c769e15
Author: Tchia <Tchia@awaceb.com>
Date:   Sat Aug 24 09:47:47 2024 +1100

    Récit initial

diff --git a/recit.txt b/recit.txt
new file mode 100644
index 0000000..1ca4757
--- /dev/null
+++ b/recit.txt
@@ -0,0 +1 @@
+Les Orihena étaient un peuple puissant et prospère. Ils régnaient sur l'océan et maîtrisaient les secrets de la navigation. Leur pouvoir venait de leur lien profond avec l'océan. OPENNC{La_Vraie_Histoire}

```

La vraie histoire : 

```bash
+Les Orihena étaient un peuple puissant et prospère. Ils régnaient sur l'océan et maîtrisaient les secrets de la navigation. Leur pouvoir venait de leur lien profond avec l'océan. OPENNC{La_Vraie_Histoire}
```


Autre solution possible :

```bash
┌──(ketsui㉿Ketsui)-[~/Downloads/HACKAGOU/Histoire_modifiee]
└─$ git log --oneline
368f555 (HEAD -> master) Réécriture complète du récit par les Maruhana.
97ffc81 modification
9e6f9ef Récit initial

┌──(ketsui㉿Ketsui)-[~/Downloads/HACKAGOU/Histoire_modifiee]
└─$ git show 9e6f9ef:recit.txt
Les Orihena étaient un peuple puissant et prospère. Ils régnaient sur l'océan et maîtrisaient les secrets de la navigation. Leur pouvoir venait de leur lien profond avec l'océan. OPENNC{La_Vraie_Histoire}
```




flag : ``OPENNC{La_Vraie_Histoire}``

