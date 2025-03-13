#!/bin/bash

VERSION="1.0.0"

function ajouter_au_fichier { # clé valeur
    echo "\"$1\": \"$2\"," >> $output
}

function get_info_system {
    ajouter_au_fichier "scriptExecutionCompte" $(whoami)
    ajouter_au_fichier "scriptExecutionEnAdministrateur" $(if [ $(whoami) == "root" ]; then echo "true"; else echo "false"; fi)
    ajouter_au_fichier "systemmanufacturer" $(dmidecode --string system-manufacturer | tr " " _)
    ajouter_au_fichier "scriptVersion" $VERSION
    ajouter_au_fichier "systemeDate" $(date)
    ajouter_au_fichier "systemeDomaineForetNom" $(hostname -d)
    ajouter_au_fichier "systemeDomaineNom" $(hostname -f)
    ajouter_au_fichier "systemeDureeFonctionnement" $(uptime | awk '{print $3}')





    ##ajouter_au_fichier "systemversion" $(dmidecode --string system-version | tr " " _)
    ##ajouter_au_fichier "biosversion" $(dmidecode --string bios-version | tr " " _)
    ##echo "Lancement des commandes sur ${systemmanufacturer} ${systemversion} avec version BIOS ${biosversion}"
}








# main
output="./sortie.json"


echo "{" > $output
get_info_system
echo "}" >> $output

