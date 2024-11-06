
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de conversion et reconstitution de fichiers.

Ce script permet de convertir un fichier binaire en une chaîne hexadécimale
puis de reconstituer le fichier d'origine à partir de cette chaîne.
"""

import os
import sys



def convert_hex_to_file(input_filename, output_filename):
    try:
        # Ouvre le fichier texte contenant les nombres hexadécimaux
        with open(input_filename, 'r') as infile:
            # Lit tout le contenu du fichier texte
            hex_content = infile.read()
            hex_content = hex_content[::-1]

        # Convertit le texte hexadécimal en bytes
        file_content = bytes.fromhex(hex_content)

        # Écrit le contenu binaire dans le fichier de sortie
        with open(output_filename, 'wb') as outfile:
            outfile.write(file_content)
        
        print(f"Le fichier '{output_filename}' a été reconstitué à partir de '{input_filename}'.")
    
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")

# Exemple d'utilisation
# Exemple d'utilisation
if __name__=="__main__":
    convert_hex_to_file('fichier_bel_oiseau.txt', 'image_bel_oiseau_reconstituee.png')
