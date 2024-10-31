## Scénario

Dans un temps ancien, bien avant que les hommes n’écrivent l’histoire, les terres de l’Océanie étaient protégées par le demi-dieu Maui. Célèbre pour sa ruse et sa force, Maui a utilisé ses pouvoirs pour capturer le soleil et ralentir sa course, pour pêcher des îles entières du fond de l'océan, et pour voler le secret du feu aux dieux.

Mais peu de gens connaissent l’histoire des "Haches Magiques de Maui". Ces haches, forgées dans les flammes sacrées par les ancêtres des dieux, étaient dotées d'une puissance extraordinaire. Chacune d’elles contenait un fragment de la force vitale de Maui lui-même, ce qui les rendait indestructibles. Pour s'assurer que personne ne puisse s'emparer de ce pouvoir, Maui a scellé les haches avec des énigmes cryptographiques indéchiffrables : les "hashes".

Selon la légende, quiconque réussirait à "casser" ces hashes pourrait obtenir une partie du pouvoir de Maui. Toutefois, ces énigmes ont été chiffrés avec des algorithmes mystiques et différents, dont les secrets sont aussi profonds que les océans et aussi complexes que les contes des anciens.

Format du flag : ``OPENNC{mot}``

**Auteur :** ``Ketsui``

## Résolution

Bien qu'il y ait plusieurs manières de résoudre ce challenge, rien de mieux qu'un petit script python. 

De manière générale quand il s'agit de jouer avec des hash, PyCryptodome est le package python qu'on adore.

https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

Comme nous avons les algos, nous pouvons directement les importer, (ou juste en wildcard* ça dépend) et récupérer notre flag.

```python
from Crypto.Hash import SHA, SHA1, MD2, MD4, MD5, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, TupleHash128, TupleHash256, BLAKE2s, BLAKE2b
algos = [SHA, SHA1, MD2, MD4, MD4, SHA3_256,  MD5, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, TupleHash128, TupleHash256, BLAKE2s, BLAKE2b]
import string
with open("hash.txt", "r") as f:
    hashes = f.readlines()

flag = ""
for i in range(len(hashes)):
    algo, hash = hashes[i].split(" ")
    algo = algos[i]
    for char in string.printable:
        test_hash = algo.new()
        test_hash.update(char.encode())
        if test_hash.hexdigest() in hash:
            flag += char

print(flag)

# pycryptodome
```

flag : ``OPENNC{H@5H_C4SSE!}``