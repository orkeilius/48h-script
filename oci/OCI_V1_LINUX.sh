#!/bin/bash

VERSION="1.0.0"

function ajouter_au_fichier { # clé valeur

    if [ "$2" = "true" ] || [ "$2" = "false" ]; then
        echo "{\"$1\": $2}," >> $output
    else
        echo "{\"$1\": \"$2\"}," >> $output
    fi
}

function get_info_system {
    ajouter_au_fichier "scriptExecutionCompte" $(whoami)
    ajouter_au_fichier "scriptExecutionEnAdministrateur" $(if [ $(whoami) == "root" ]; then echo "true"; else echo "false"; fi)
    ajouter_au_fichier "scriptExecutionEmplacement" $(pwd)
    ajouter_au_fichier "scriptVersion" $VERSION
    ajouter_au_fichier "systemeDate" $(date +"%Y-%m-%d-%H-%M-%S")
    ajouter_au_fichier "systemeDomaineControleurNom" "null"
    ajouter_au_fichier "systemeDomaineForetNom" $(hostname -d || echo "null")
    ajouter_au_fichier "systemeDomaineNom" $(hostname -f || echo "null")
    ajouter_au_fichier "systemeDureeFonctionnement" $(uptime | awk '{print $3}' | tr -d ',')
    
    # IPs en tableau
    ip_list=($(hostname -I))
    if [ ${#ip_list[@]} -eq 0 ]; then
        echo "    {" >> $output
        echo "        \"systemeInterfaceReseauIpListe\": []" >> $output
        echo "    }," >> $output
    else
        echo "    {" >> $output
        echo "        \"systemeInterfaceReseauIpListe\": [" >> $output
        for ip in "${ip_list[@]}"; do
            echo "            \"$ip\"," >> $output
        done
        sed -i '$ s/,$//' $output
        echo "        ]" >> $output
        echo "    }," >> $output
    fi
    
    ajouter_au_fichier "systemeLangue" $(locale | grep LANG | cut -d= -f2 | cut -d. -f1 || echo "0409")
    ajouter_au_fichier "systemeNom" $(hostname)
    ajouter_au_fichier "systemeSystemeExploitation" "$(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '"')"
    ajouter_au_fichier "systemeSystemeExploitationVersion" "$(uname -r)"
    ajouter_au_fichier "systemeType" "$([ $(uname -m) == "x86_64" ] && echo "0" || echo "1")"
    
    # Liste de correctifs en tableau
    echo "    {" >> $output
    echo "        \"systemeSystemeExploitationCorrectif\": [" >> $output
    if command -v apt &> /dev/null; then
        apt list --installed | head -10 | tail -n +2 | awk -F'/' '{print $1}' | awk '{print "            \"" $1 "\","}' >> $output
    elif command -v dnf &> /dev/null; then
        dnf list installed | head -10 | tail -n +2 | awk '{print "            \"" $1 "\","}' >> $output
    elif command -v yum &> /dev/null; then
        yum list installed | head -10 | tail -n +2 | awk '{print "            \"" $1 "\","}' >> $output
    fi
    sed -i '$ s/,$//' $output
    echo "        ]" >> $output
    echo "    }," >> $output
    
    ajouter_au_fichier "systemeSystemeExploitationCorrectifWsus" "null"
    
    # Informations de chiffrement
    encryption_info=$(lsblk -o NAME,FSTYPE | grep -E 'luks|dm-crypt' | wc -l)
    ajouter_au_fichier "systemeChiffrementDisqueBitlocker" ""
    ajouter_au_fichier "systemeChiffrementDisqueOs" ""
}


function get_info_accounts {
    # Liste des administrateurs
    admin_users=($(getent group sudo wheel | cut -d: -f4 | tr ',' ' '))
    echo "    {" >> $output
    echo "        \"compteAdministrateurListe\": [" >> $output
    for user in "${admin_users[@]}"; do
        echo "            \"$user\"," >> $output
    done
    if [ ${#admin_users[@]} -gt 0 ]; then
        sed -i '$ s/,$//' $output
    fi
    echo "        ]" >> $output
    echo "    }," >> $output
    
    # Liste de tous les comptes
    all_users=($(cut -d: -f1 /etc/passwd | grep -E '/bin/bash|/bin/sh'))
    echo "    {" >> $output
    echo "        \"compteListe\": [" >> $output
    for user in "${all_users[@]}"; do
        echo "            \"$user\"," >> $output
    done
    if [ ${#all_users[@]} -gt 0 ]; then
        sed -i '$ s/,$//' $output
    fi
    echo "        ]" >> $output
    echo "    }," >> $output
    
    # État des comptes spéciaux
    root_access=$(grep -E '^root:' /etc/shadow | grep -c '\!\*')
    ajouter_au_fichier "compteAdministrateurParDefautEtat" "$([ $root_access -eq 0 ] && echo "true" || echo "false")"
    ajouter_au_fichier "compteAdministrateurParDefautNom" "root"
    
    guest_exists=$(grep -c "^guest:" /etc/passwd)
    ajouter_au_fichier "compteInviteEtat" "$([ $guest_exists -eq 1 ] && echo "true" || echo "false")"
    ajouter_au_fichier "compteInviteNom" "guest"
}

function get_info_network {
    # Accès internet
    internet_access=$(ping -c 1 8.8.8.8 >/dev/null 2>&1 && echo "true" || echo "false")
    ajouter_au_fichier "reseauAccessInternet" $internet_access
    ajouter_au_fichier "reseauOrdinateurNomNetBios" "$(hostname)"
    
    # Configuration pare-feu
    if command -v ufw &> /dev/null; then
    firewall_status=$(ufw status | grep -q "active" && echo "true" || echo "false")
    elif command -v firewalld &> /dev/null; then
        firewall_status=$(firewall-cmd --state 2>/dev/null | grep -q "running" && echo "true" || echo "false")
    else
        firewall_status="false"
    fi
    
    ajouter_au_fichier "reseauParefeuDomaine" $firewall_status
    ajouter_au_fichier "reseauParefeuDomaineActionFluxEntrantDefaut" "false"
    ajouter_au_fichier "reseauParefeuPrive" $firewall_status
    ajouter_au_fichier "reseauParefeuPriveActionFluxEntrantDefaut" "false"
    ajouter_au_fichier "reseauParefeuPublique" $firewall_status
    ajouter_au_fichier "reseauParefeuPubliqueActionFluxEntrantDefaut" "false"
    ajouter_au_fichier "reseauProxy" "null"
    ajouter_au_fichier "reseauProxyActive" "false"
    
    # Ports ouverts
    ports=($(ss -tulpn | grep LISTEN | awk '{print $5}' | awk -F':' '{print $2}' | sort -u | grep -v '^$'))
    echo "    {" >> $output
    echo "        \"servicePortsOuvertsListe\": [" >> $output
    for port in "${ports[@]}"; do
        echo "            $port," >> $output
    done
    if [ ${#ports[@]} -gt 0 ]; then
        sed -i '$ s/,$//' $output
    fi
    echo "        ]" >> $output
    echo "    }," >> $output
}

function get_info_applications {
    # Version des navigateurs
    if command -v google-chrome &> /dev/null; then
        chrome_version=$(google-chrome --version | awk '{print $3}')
        ajouter_au_fichier "applicationChromeVersion" "$chrome_version"
    else
        ajouter_au_fichier "applicationChromeVersion" ""
    fi
    
    if command -v firefox &> /dev/null; then
        firefox_version=$(firefox --version | awk '{print $3}')
        ajouter_au_fichier "applicationFirefoxVersion" "$firefox_version"
    else
        ajouter_au_fichier "applicationFirefoxVersion" ""
    fi
    
    # Liste des applications
    echo "{\"applicationListe\": [" >> $output
    if command -v apt &> /dev/null; then
        apt list --installed | tail -n +2 | cut -d/ -f1 | head -20 | awk '{print "\"" $1 "\"" }' | sed 's/$/,/' | sed '$ s/,$//' >> $output
    elif command -v rpm &> /dev/null; then
        rpm -qa --qf "%{NAME}\n" | head -20 | awk '{print "\"" $1 "\"" }' | sed 's/$/,/' | sed '$ s/,$//' >> $output
    fi
    echo "]}," >> $output
}

function get_info_hardware {
    # Informations matérielles
    ajouter_au_fichier "systemeManufacturer" "$(dmidecode --string system-manufacturer 2>/dev/null | tr " " _ || echo "Unknown")"
    ajouter_au_fichier "systemeVersion" "$(dmidecode --string system-version 2>/dev/null | tr " " _ || echo "Unknown")"
    ajouter_au_fichier "biosVersion" "$(dmidecode --string bios-version 2>/dev/null | tr " " _ || echo "Unknown")"
    
    # Informations TPM
    tpm_present=$(test -e /dev/tpm0 && echo "true" || echo "false")
    ajouter_au_fichier "systemeTpm" "$tpm_present"
    
    # Informations CPU et mémoire
    ajouter_au_fichier "systemeCpu" "$(grep -m1 "model name" /proc/cpuinfo | cut -d':' -f2 | xargs)"
    ajouter_au_fichier "systemeMemoireTotal" "$(grep MemTotal /proc/meminfo | awk '{print $2 " KB"}')"
}

function get_info_services {
    # Service d'impression (CUPS)
    cups_running=$(systemctl is-active cups.service 2>/dev/null || echo "inactive")
    ajouter_au_fichier "serviceImpression" "$([ "$cups_running" == "active" ] && echo "true" || echo "false")"
    
    # Service SSH (équivalent RDP)
    ssh_running=$(systemctl is-active sshd.service 2>/dev/null || echo "inactive")
    ajouter_au_fichier "serviceRdp" "$([ "$ssh_running" == "active" ] && echo "true" || echo "false")"
    
    # Service Samba (SMB)
    smb_running=$(systemctl is-active smbd.service 2>/dev/null || echo "inactive")
    ajouter_au_fichier "serviceSmb" "$([ "$smb_running" == "active" ] && echo "true" || echo "false")"
    
    # Version SMB
    if [ "$smb_running" == "active" ]; then
        smb_v1_enabled=$(grep -i "min protocol" /etc/samba/smb.conf 2>/dev/null | grep -c "NT1")
        ajouter_au_fichier "serviceSmbVersion1" "$([ $smb_v1_enabled -gt 0 ] && echo "true" || echo "false")"
        ajouter_au_fichier "serviceSmbVersion23" "true"
    else
        ajouter_au_fichier "serviceSmbVersion1" "false"
        ajouter_au_fichier "serviceSmbVersion23" "false"
    fi
    
    # Service WMI (équivalent Linux : SSH ou autre accès distant)
    ajouter_au_fichier "serviceWmiActive" "$([ "$ssh_running" == "active" ] && echo "true" || echo "false")"
}

function get_info_security {
    # Politique d'exécution (équivalent à PowerShell)
    ajouter_au_fichier "configurationPowershellPolitiqueExecution" "N/A"
    
    # Configuration UAC (équivalent Linux: sudo)
    sudo_present=$(command -v sudo &>/dev/null && echo "1" || echo "0")
    ajouter_au_fichier "configurationUacActive" "$sudo_present"
    
    # Configuration des mots de passe
    passwd_max_days=$(grep PASS_MAX_DAYS /etc/login.defs | grep -v "#" | awk '{print $2}' || echo "99999")
    passwd_min_days=$(grep PASS_MIN_DAYS /etc/login.defs | grep -v "#" | awk '{print $2}' || echo "0")
    passwd_min_len=$(grep PASS_MIN_LEN /etc/login.defs | grep -v "#" | awk '{print $2}' || echo "0")
    
    ajouter_au_fichier "configurationMdpAgeMaximum" "$passwd_max_days"
    ajouter_au_fichier "configurationMdpAgeMinimum" "$passwd_min_days"
    ajouter_au_fichier "configurationMdpLongueurMinimum" "$passwd_min_len"
    ajouter_au_fichier "configurationMdpComplexite" "0"
    
    # Tâches planifiées (cron et systemd)
    echo "{\"configurationTachesPlannifieesListe\": [" >> $output
    if command -v systemctl &>/dev/null; then
        systemctl list-timers --all --no-pager | grep -v NEXT | grep -v "^$" | head -15 | 
        awk '{print "            \"" $5 "\"," }' >> $output
    else
        for user in $(cut -f1 -d: /etc/passwd); do 
            crontab -l -u $user 2>/dev/null | grep -v "^#" | head -15 | 
            awk '{print "            \"" $6 "\"," }' >> $output
        done
    fi
    echo "]}," >> $output
}

function get_info_hardening {
    # Vérifier SELinux/AppArmor
    selinux_status="Désactivé"
    if command -v getenforce &>/dev/null; then
        selinux_status=$(getenforce 2>/dev/null)
    fi
    
    apparmor_status="Désactivé"
    if command -v apparmor_status &>/dev/null; then
        apparmor_status=$(apparmor_status | grep -c "profiles are loaded" >/dev/null && echo "Activé" || echo "Désactivé")
    fi
    
    ajouter_au_fichier "durcissementSEHOP" "$selinux_status"
    ajouter_au_fichier "durcissementEcranIntelligent" "$apparmor_status"
    
    # Information sur les fichiers cachés
    ajouter_au_fichier "durcissementFichierDossierCaches" "$(ls -la ~ | grep -c "^\." >/dev/null && echo "1" || echo "0")"
    
    # NetBIOS
    ajouter_au_fichier "durcissementNetBiosConfiguration" "N/A"
    
    # Auto login
    auto_login=$(grep -c "^autologin" /etc/lightdm/lightdm.conf 2>/dev/null || echo "0")
    ajouter_au_fichier "durcissementAutoAdminLogon" "$auto_login"
    
    # RDP
    ajouter_au_fichier "durcissementRDPActif" "$(systemctl is-active xrdp.service 2>/dev/null | grep -c "active" || echo "0")"
    
    # IPv6
    ipv6_enabled=$(sysctl -a 2>/dev/null | grep -c "net.ipv6.conf.all.disable_ipv6 = 0" || echo "1")
    ajouter_au_fichier "durcissementIpv6Configuration" "$([ $ipv6_enabled -eq 1 ] && echo "Activé" || echo "Désactivé")"
}

function get_info_antivirus {
    # ClamAV
    clamav_installed=$(command -v clamscan &>/dev/null && echo "true" || echo "false")
    ajouter_au_fichier "protectionAntivirusAgent" "$clamav_installed"
    
    if [ "$clamav_installed" == "true" ]; then
        clamav_version=$(clamscan --version | awk '{print $2}')
        clamav_last_update=$(stat -c %y /var/lib/clamav/daily.cvd 2>/dev/null | cut -d' ' -f1 || echo "Unknown")
        ajouter_au_fichier "protectionAntivirusVersion" "$clamav_version"
        ajouter_au_fichier "protectionAntivirusDerniereMaj" "$clamav_last_update"
    else
        ajouter_au_fichier "protectionAntivirusVersion" ""
        ajouter_au_fichier "protectionAntivirusDerniereMaj" ""
    fi
}

# main
output="./sortie.json"


echo "[" > $output
get_info_system
get_info_accounts
get_info_network
get_info_applications
get_info_antivirus
get_info_hardware
get_info_services
get_info_security
get_info_hardening

# supprimer la dernière virgule
sed 's/,\n$//' $output > $output.tmp

echo "]" >> $output

