#  -----------------------------------------------------------------------------
#      _____          ___               _ __        ____        __       
#     / ___/__  ___  / _/__  ______ _  (_) /____   /  _/__  ___/ /_ _____
#    / /__/ _ \/ _ \/ _/ _ \/ __/  ' \/ / __/ -_) _/ // _ \/ _  / // (_-<
#    \___/\___/_//_/_/ \___/_/ /_/_/_/_/\__/\__/ /___/_//_/\_,_/\_,_/___/
#                                                                                                                                                   
#  -----------------------------------------------------------------------------
#  Outil de Conformite Industriel (OCI)
#  Technologie utilisee - Powershell (ps1)
# 
#  Douglas OBERTO, Mars 2023
#  Contact : cybersecurite.vef@veolia.com

#  Conversion du script en powershell par : ZINGRAFF Anthony, Novembre 2024

#  Ce script collecte des donnees relatives au poste de travail puis
#  envoie les donnees de conformite sur un collecteur situe dans une
#  zone demilitarisee industrielle 
#  --------------------------------------------------------------------
#  --------------------------------------------------------------------

#################################################################################
# FONCTION                                                                      #
#################################################################################

# Conversion valeur format CSV : 
function ConversionChaineEnCSV{
    param(
        $nomParam,
        $valParam
    )

    # Cas ou un seul élément dans valParam : 
    if($valParam.Count -eq 1){
        $formatCSV = '"' + $nomParam + '"' + ',' + '"' + $valParam + '",'
    }
    
    # Cas ou il y a plusieurs elt dans valParam :
    if($valParam.Count -gt 1){
        $concat = '"'
        foreach($elt in $valParam){
            $concat = $concat + $elt +','
        }
        $concat = $concat.Substring(0, $concat.Length - 1)
        $formatCSV = '"' + $nomParam + '"' + ',' + $concat + '",'
    }
    return $formatCSV
}

function ConversionChaineEnJSON {
    param(
        [string]$nomParam,
        $valParam
    )

    # Cas où un seul élément dans valParam
    if ($valParam.Count -eq 1) {
        # Retourne une entrée JSON simple
        return @{ $nomParam = $valParam } | ConvertTo-Json -Depth 10 -Compress
    }

    # Cas où il y a plusieurs éléments dans valParam
    if ($valParam.Count -gt 1) {
        # Retourne une entrée JSON avec une liste de valeurs
        return @{ $nomParam = $valParam } | ConvertTo-Json -Depth 10 -Compress
    }
}

function recuperationPlusieursValeurs{
    param(
        $cheminRegistre,
        $tableauDeParametreAChercher,
        $nom
    )

    $tab = @()
    try{
        Get-ItemProperty -Path $cheminRegistre -ErrorAction Stop #>$null
        foreach($param in $tableauDeParametreAChercher){
            try{
                $paramExiste = Get-ItemPropertyValue -Path $cheminRegistre -Name $param -ErrorAction Stop #>$null
                $tab += ,@("$nom$param","$paramExiste")
            }
            catch{
                $tab += ,@("$nom$param","")
            }
        }
    }
    catch{
        foreach($param in $tableauDeParametreAChercher){
            $tab += ,@("$nom$param","")
        }
    }
    return $tab
}

# Conformité du script : 
#Cette fonction permet d'obtenir les valeurs de conformité du script : 
function getConformiteScript{
    $scriptExecutionCompte = @("scriptExecutionCompte", $(whoami).Split('\')[1])  

    #Savoir si script est executée en admin :
    $groupeActuelle = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $scriptExecutionEnAdministrateur = @("scriptExecutionEnAdministrateur", $groupeActuelle.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

    #Savoir l'emplacement du script : 
    $scriptExecutionEmplacement = @("scriptExecutionEmplacement",(pwd).Path)  #String
    $scriptVersion = @("scriptVersion","1.0")

    return @(
        $scriptExecutionCompte,
        $scriptExecutionEnAdministrateur,
        $scriptExecutionEmplacement,
        $scriptVersion
        # scriptExecutionDuree = [System.Diagnostics.Stopwatch]::StartNew() #Int A voir
    )

}

function getConformiteSystem{

    ######## V0 #################
    $systemeDate = @("systemeDate", (Get-Date -Format "yyyy-MM-dd-HH-mm-ss"))

    # Test afin de savoir si le poste est présent dans un domaine ou non : 
    $domainePresent = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    if($domainePresent){
        $systemeDomaineControleurNom = @("systemeDomaineControleurNom","")
        $systemeDomaineForetNom = @("systemeDomaineForetNom","")
        $systemeDomaineNom = @("systemeDomaineNom","")
    }
    #Si ce n'est pas dans un domaine, alors cela prends la valeur null
    else{
        $systemeDomaineControleurNom = @("systemeDomaineControleurNom","null")
        $systemeDomaineForetNom = @("systemeDomaineForetNom","null")
        $systemeDomaineNom = @("systemeDomaineNom","null")
    }

    # Obtenir temps de fonctionnement du PC en seconde :
    $dureeEnSeconde = "$($((Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime)).TotalSeconds)"
    $systemeDureeFonctionnement = @("systemeDureeFonctionnement", (($dureeEnSeconde).Split('.')[0]))

    # Mise en tableau des différentes NIC et de leurs adresse : 
    $listeIntEtIP = @()
    foreach($interface in $(Get-NetIPAddress -AddressFamily IPv4)){
        $listeIntEtIP += $interface.IPAddress
    }
    $systemeInterfaceReseauIpListe = @("systemeInterfaceReseauIpListe",$listeIntEtIP)
    
    $systemeLangue = @("systemeLangue",(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language").InstallLanguage)
    $systemeNom = @("systemeNom", $(hostname))
    $systemeSystemeExploitation = @("systemeSystemeExploitation",(Get-WmiObject -Class Win32_OperatingSystem).Caption)
    $systemeSystemeExploitationVersion = @("systemeSystemeExploitationVersion",(Get-WmiObject -Class Win32_OperatingSystem).Version)
    $systemeType = @("systemeType",(Get-WmiObject -Class Win32_ComputerSystem).DomainRole)
    #############################

    ######## V1 #################
    #Ajout des correctifs systeme : 
    $correctifsSystem = @()
    foreach($correctif in (Get-WmiObject -Class Win32_QuickFixEngineering)){
        $correctifsSystem += $correctif.HotFixID
    }
    $systemeSystemeExploitationCorrectif = @("systemeSystemeExploitationCorrectif",$correctifsSystem)
    # Correctif WSUS : 
    Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue
    if($?){
        $systemeSystemeExploitationCorrectifWsus = @("systemeSystemeExploitationCorrectifWsus",(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate").WUServer)
    }
    else{
        $systemeSystemeExploitationCorrectifWsus = @("systemeSystemeExploitationCorrectifWsus","null")
    }
    #############################

    ######## V2 #################

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -name "UseAdvancedStartUp" -ErrorAction Stop >$null
        $systemeChiffrementDisqueBitlocker = @("systemeChiffrementDisqueBitlocker",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE").UseAdvancedStartUp)
    }
    catch{
        $systemeChiffrementDisqueBitlocker = @("systemeChiffrementDisqueBitlocker","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareException" -ErrorAction Stop >$null
        $systemeChiffrementDisqueOs = @("systemeChiffrementDisqueOs", (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE").OSHardwareException)
    }    
    catch{
        $systemeChiffrementDisqueOs = @("systemeChiffrementDisqueOs","")
    }
    #############################


    return @(
        #Param V0 : 
        $systemeDate,
        $systemeDomaineControleurNom,
        $systemeDomaineForetNom,
        $systemeDomaineNom,
        $systemeDureeFonctionnement,
        $systemeInterfaceReseauIpListe,
        $systemeLangue,
        $systemeNom,
        $systemeSystemeExploitation,
        $systemeSystemeExploitationVersion,
        $systemeType,
        #Param V1 :
        $systemeSystemeExploitationCorrectif,
        $systemeSystemeExploitationCorrectifWsus,
        #Param V2 : 
        $systemeChiffrementDisqueBitlocker,
        $systemeChiffrementDisqueOs
    )
}

function getConformiteCompte{

    $languePoste = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language").InstallLanguage 

    ######## V0 #################
    #Si le poste est en français :
    if($languePoste -eq "040C"){
        $compteAdministrateurListe = @("compteAdministrateurListe", ((Get-LocalGroupMember -Group Administrateurs).Name | foreach{$_.Split('\')[1]}) )
    }
    else{
        $compteAdministrateurListe = @("compteAdministrateurListe", ((Get-LocalGroupMember -Group Administrators).Name | foreach{$_.Split('\')[1]}) )
    }
    $compteListe = @("compteListe",((Get-LocalUser).Name))
    #############################

    ######## V1 #################
    #Si le poste est en français :
    if($languePoste -eq "040C"){
        $compteAdministrateurParDefautEtat = @("compteAdministrateurParDefautEtat",(Get-LocalUser -Name "Administrateur").Enabled)
        $compteAdministrateurParDefautNom = @("compteAdministrateurParDefautNom",(Get-LocalUser -Name "Administrateur").Name)
        $compteInviteEtat = @("compteInviteEtat",(Get-LocalUser -Name "Invité").Enabled)
        $compteInviteNom = @("compteInviteNom",(Get-LocalUser -Name "Invité").Name)
    }
    else{
        $compteAdministrateurParDefautEtat = @("compteAdministrateurParDefautEtat",(Get-LocalUser -Name "Administrator").Enabled)
        $compteAdministrateurParDefautNom = @("compteAdministrateurParDefautNom",(Get-LocalUser -Name "Administrator").Name)
        $compteInviteEtat = @("compteInviteEtat",(Get-LocalUser -Name "Guest").Enabled)
        $compteInviteNom = @("compteInviteNom",(Get-LocalUser -Name "Guest").Name)
    }
    

    return @(
        # Param V0 :
        $compteAdministrateurListe,
        $compteListe,
        # Param V1 : 
        $compteAdministrateurParDefautEtat,
        $compteAdministrateurParDefautNom,
        $compteInviteEtat,
        $compteInviteNom
    )
}

function getConformiteReseau{
    ######## V2 #################
    #Test de l'accès Internet via un ping : 
    ping 8.8.8.8 >$null
    $reseauAccessInternet = @("reseauAccessInternet", $?)
    # $reseauOrdinateurIpPublique = 
    $reseauOrdinateurNomNetBios = @("reseauOrdinateurNomNetBios", $env:COMPUTERNAME)
    
    #Recupération des informations du profile Domaine du pare-feu :
    $pfDomainActif = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\services\SharedAccess\Defaults\FirewallPolicy\DomainProfile\").EnableFirewall
    if($pfDomainActif -eq "1"){
        $reseauParefeuDomaine = @("reseauParefeuDomaine", $true )
    }
    else{
        $reseauParefeuDomaine = @("reseauParefeuDomaine", $false)
    }

    $pfProfileDomain = (Get-NetFirewallProfile | Where-Object{$_.Name -eq "Domain"}).DefaultInboundAction
    if($pfProfileDomain -eq "Block"){
        $reseauParefeuDomaineActionFluxEntrantDefaut = @("reseauParefeuDomaineActionFluxEntrantDefaut",$true)
    }
    else{
        $reseauParefeuDomaineActionFluxEntrantDefaut = @("reseauParefeuDomaineActionFluxEntrantDefaut",$false)  
    }

    #Recupération des informations du profile Privé du pare-feu :
    $pfPriveActif = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\services\SharedAccess\Defaults\FirewallPolicy\StandardProfile\").EnableFirewall
    if($pfPriveActif -eq "1"){
        $reseauParefeuPrive = @("reseauParefeuPrive", $true)
    }   
    else{
        $reseauParefeuPrive = @("reseauParefeuPrive", $false)
    }

    $pfProfilePrivate = (Get-NetFirewallProfile | Where-Object{$_.Name -eq "Private"}).DefaultInboundAction
    if($pfProfilePrivate -eq "Block"){
        $reseauParefeuPriveActionFluxEntrantDefaut = @("reseauParefeuPriveActionFluxEntrantDefaut",$true)
    }
    else{
        $reseauParefeuPriveActionFluxEntrantDefaut = @("reseauParefeuPriveActionFluxEntrantDefaut",$false)  
    }

    #Recupération des informations du profile Public du pare-feu :
    $pfPublicActif = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\services\SharedAccess\Defaults\FirewallPolicy\PublicProfile\").EnableFirewall
    if($pfPublicActif -eq "1"){
        $reseauParefeuPublique = @("reseauParefeuPublique", $true)
    }   
    else{
        $reseauParefeuPublique = @("reseauParefeuPublique", $false)
    }

    $pfProfilePublic = (Get-NetFirewallProfile | Where-Object{$_.Name -eq "Public"}).DefaultInboundAction
    if($pfProfilePublic -eq "Block"){
        $reseauParefeuPubliqueActionFluxEntrantDefaut = @("reseauParefeuPubliqueActionFluxEntrantDefaut",$true)
    }
    else{
        $reseauParefeuPubliqueActionFluxEntrantDefaut = @("reseauParefeuPubliqueActionFluxEntrantDefaut",$false)  
    }

    # Proxy : 
    # Permet de savoir si le proxy est actif :
    $proxyActif = ((Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnabled) -eq "1"
    #Si le proxy est activé alors on prends son @Ip et le port sinon null:
    if($proxyActif){
        $reseauProxyActive = @("reseauProxyActive", $true)
        #Obtenir l'adresse IP et le port du proxy : 
        $reseauProxy = @("reseauProxy",(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer)
    }
    else{
        $reseauProxy = @("reseauProxy","null")
        $reseauProxyActive = @("reseauProxyActive", $true)
    }

    #############################
    return @(
        # Parametre V2 : 
        $reseauAccessInternet,
        $reseauOrdinateurNomNetBios,
        $reseauParefeuDomaine,
        $reseauParefeuDomaineActionFluxEntrantDefaut,
        $reseauParefeuPrive,
        $reseauParefeuPriveActionFluxEntrantDefaut,
        $reseauParefeuPublique,
        $reseauParefeuPubliqueActionFluxEntrantDefaut,
        $reseauProxy,
        $reseauProxyActive
    )
}

function getConformiteService{
    ######## V0 #################
    #Pour le service d'impression : 
    $impressionActive = (Get-WmiObject -Class Win32_Service | Where-Object{$_.Name -eq "Spooler"}).State -eq "Running"
    if($impressionActive){
        $serviceImpression = @("serviceImpression",$true)
    }
    else{
        $serviceImpression = @("serviceImpression",$false)
    }

    # Pour le service RDP : 
    $rdpActif = (Get-WmiObject -Class Win32_Service | Where-Object{$_.Name -eq "TermService"}).State -eq "Running"
    if($rdpActif){
        $serviceRdp = @("serviceRdp",$true)
    }
    else{
        $serviceRdp = @("serviceRdp",$false)
    }

    # Pour le service SMB : 
    $smbActif = (Get-WmiObject -Class Win32_Service | Where-Object{$_.Name -eq "LanmanServer"}).State -eq "Running"
    if($smbActif){
        $serviceSmb = @("serviceSmb",$true)
    }
    else{
        $serviceSmb = @("serviceSmb",$false)
    }

    # Liste des dossier partagé via SMB : 
    try{
        $smbActif = Get-SmbShare -ErrorAction Stop >$null
        $serviceSmbFichierPartageListe = @("serviceSmbFichierPartageListe", $smbActif.Name)    
    }
    catch{
        $serviceSmbFichierPartageListe = @("serviceSmbFichierPartageListe", "")
    }
    # Savoir si le service SMB dispose de la signature : 
    if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").RequireSecuritySignature -eq "1"){
        $serviceSmbSignatureRequise = @("serviceSmbSignatureRequise", $true)
    }
    else{
        $serviceSmbSignatureRequise = @("serviceSmbSignatureRequise", $false)
    }
    #############################

    ######## V1 #################
    # Version V1 de SMB (BOOL):
    $serviceSmbVersion1 = @("serviceSmbVersion1", ((Get-SmbServerConfiguration).EnableSMB1Protocol))

    # Version V2 de SMB (BOOL):
    $serviceSmbVersion23 = @("serviceSmbVersion23", ((Get-SmbServerConfiguration).EnableSMB2Protocol))
    #############################

    ######## V2 #################
    # Obtenir les ports ouverts sur le poste (Pas de prise en compte des ports dynamique):
    $lsPortsOuverts = @()
    foreach($port in (Get-NetTCPConnection -State Listen).LocalPort){
        if($port -lt 49151){
            $lsPortsOuverts += $port
        }
    }
    $servicePortsOuvertsListe = @("servicePortsOuvertsListe", $lsPortsOuverts)


    # Obtenir service W32 : 
    $srvcWin32 = Get-WmiObject -Query "SELECT * FROM Win32_Service" | Select-Object Name
    $tabSrvc = @()
    
    foreach($service in $srvcWin32){
        if($service.Name -ne $null){
            $tabSrvc += $service.Name
        }
    }
    
    if($tabSrvc.Count -gt  0){
        $serviceW32 = @("applicationListe",$tabApp)
    }
    else{
        $serviceW32 = @("applicationListe","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Reliability Analysis\RAC\" -Name "WmiLastTime" -ErrorAction Stop >$null
        $serviceWmiActive = @("serviceWmiActive", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Reliability Analysis\RAC\").WmiLastTime)
    }
    catch{
        $serviceWmiActive = @("serviceWmiActive","")
    }

    #############################

    return @(
        # Param V0 :
        $serviceImpression,
        $serviceRdp,
        $serviceSmb,
        $serviceSmbFichierPartageListe,
        $serviceSmbSignatureRequise,
        # Param V1 :
        $serviceSmbVersion1,
        $serviceSmbVersion23,
        # Param V2 :
        $servicePortsOuvertsListe,
        $serviceW32,
        $serviceWmiActive
    )
}

# a tester pour kaspersky
function getConformiteProtection{
    ######## V1 #################
    #Test présence registre : 
    try{
        $path = "HKLM:\SOFTWARE\KasperskyLab\Components\34\1103\1.0.0.0\Statistics\AVState"
        Get-ItemProperty -Path $path -ErrorAction Stop  >$null
        $protectionAntivirusAgent12Kaspersky32BitsClientInstalle = @("protectionAntivirusAgent12Kaspersky32BitsClientInstalle", (Get-ItemProperty -Path $path).Protection_AvInstalled)
        $protectionAntivirusAgent12Kaspersky32BitsDerniereMaj = @("protectionAntivirusAgent12Kaspersky32BitsDerniereMaj", (Get-ItemProperty -Path $path).Protection_BasesDate)
        $protectionAntivirusAgent12Kaspersky32BitsTempsReelEtat = @("protectionAntivirusAgent12Kaspersky32BitsTempsReelEtat", (Get-ItemProperty -Path $path).Protection_RtpState)
        $protectionAntivirusAgent12Kaspersky32BitsServeurAdministration = @("protectionAntivirusAgent12Kaspersky32BitsServeurAdministration", (Get-ItemProperty -Path $path).Protection_AdmServer)
        $protectionAntivirusAgent12Kaspersky32bitsTempsReelActif = @("protectionAntivirusAgent12Kaspersky32bitsTempsReelActif", (Get-ItemProperty -Path $path).Protection_AvRunning)
    }
    catch{
        $protectionAntivirusAgent12Kaspersky32BitsClientInstalle = @("protectionAntivirusAgent12Kaspersky32BitsClientInstalle", "")
        $protectionAntivirusAgent12Kaspersky32BitsDerniereMaj = @("protectionAntivirusAgent12Kaspersky32BitsDerniereMaj", "")
        $protectionAntivirusAgent12Kaspersky32BitsTempsReelEtat = @("protectionAntivirusAgent12Kaspersky32BitsTempsReelEtat", "")
        $protectionAntivirusAgent12Kaspersky32BitsServeurAdministration = @("protectionAntivirusAgent12Kaspersky32BitsServeurAdministration", "")
        $protectionAntivirusAgent12Kaspersky32bitsTempsReelActif = @("protectionAntivirusAgent12Kaspersky32bitsTempsReelActif", "")
    }

    try{
        $path =  "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\Components\34\1103\1.0.0.0\Statistics\AVState"
        Get-ItemProperty -Path $path -ErrorAction Stop  >$null 
        $protectionAntivirusAgent12Kaspersky64BitsClientInstalle = @("protectionAntivirusAgent12Kaspersky64BitsClientInstalle", (Get-ItemProperty -Path $path ).Protection_AvInstalled)
        $protectionAntivirusAgent12Kaspersky64BitsDerniereMaj = @("protectionAntivirusAgent12Kaspersky64BitsDerniereMaj", (Get-ItemProperty -Path $path ).Protection_BasesDate)
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelEtat = @("protectionAntivirusAgent12Kaspersky64BitsTempsReelEtat", (Get-ItemProperty -Path $path ).Protection_RtpState)
        $protectionAntivirusAgent12Kaspersky64BitsServeurAdministration = @("protectionAntivirusAgent12Kaspersky64BitsServeurAdministration", (Get-ItemProperty -Path $path ).Protection_AdmServer)
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelActif = @("protectionAntivirusAgent12Kaspersky64BitsTempsReelActif", (Get-ItemProperty -Path $path ).Protection_AvRunning)
    }
    catch{
        $protectionAntivirusAgent12Kaspersky64BitsClientInstalle = @("protectionAntivirusAgent12Kaspersky64BitsClientInstalle", "")
        $protectionAntivirusAgent12Kaspersky64BitsDerniereMaj = @("protectionAntivirusAgent12Kaspersky64BitsDerniereMaj", "")
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelEtat = @("protectionAntivirusAgent12Kaspersky64BitsTempsReelEtat", "")
        $protectionAntivirusAgent12Kaspersky64BitsServeurAdministration = @("protectionAntivirusAgent12Kaspersky64BitsServeurAdministration", "")
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelActif = @("protectionAntivirusAgent12Kaspersky64BitsTempsReelActif", "")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES\environment" -ErrorAction Stop >$null
        $protectionAntivirusClient11Kaspersky64BitsVersion = @("protectionAntivirusClient11Kaspersky64BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES\environment").ProductVersion)
        $protectionAntivirusClient11Kaspersky64BitsVersionAffichee = @("protectionAntivirusClient11Kaspersky64BitsVersionAffichee",(Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\KasperskyLab\protected\KES\environment").ProductDisplayVersion)
    }
    catch{
        $protectionAntivirusClient11Kaspersky64BitsVersion = @("protectionAntivirusClient11Kaspersky64BitsVersion","")
        $protectionAntivirusClient11Kaspersky64BitsVersionAffichee = @("protectionAntivirusClient11Kaspersky64BitsVersionAffichee","")
    }
		
    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES\environment" -ErrorAction Stop >$null
        $protectionAntivirusClient11Kaspersky32BitsVersion = @("protectionAntivirusClient11Kaspersky32BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES\environment").ProductVersion)
        $protectionAntivirusClient11Kaspersky32BitsVersionAffichee = @("protectionAntivirusClient11Kaspersky32BitsVersionAffichee",(Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES\environment").ProductDisplayVersion)
    }
    catch{
        $protectionAntivirusClient11Kaspersky32BitsVersion = @("protectionAntivirusClient11Kaspersky32BitsVersion","")
        $protectionAntivirusClient11Kaspersky32BitsVersionAffichee = @("protectionAntivirusClient11Kaspersky32BitsVersionAffichee","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10Kaspersky64BitsVersion = @("protectionAntivirusClient10Kaspersky64BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10Kaspersky64BitsVersion = @("protectionAntivirusClient10Kaspersky64BitsVersion","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10SP1\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10SP1Kaspersky64BitsVersion = @("protectionAntivirusClient10SP1Kaspersky64BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10SP1\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10SP1Kaspersky64BitsVersion = @("protectionAntivirusClient10SP1Kaspersky64BitsVersion","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10SP2\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10SP2Kaspersky64BitsVersion = @("protectionAntivirusClient10SP2Kaspersky64BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\KasperskyLab\protected\KES10SP2\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10SP2Kaspersky64BitsVersion = @("protectionAntivirusClient10SP2Kaspersky64BitsVersion","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10Kaspersky32BitsVersion = @("protectionAntivirusClient10Kaspersky32BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10Kaspersky32BitsVersion = @("protectionAntivirusClient10Kaspersky32BitsVersion","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10SP1\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10SP1Kaspersky32BitsVersion = @("protectionAntivirusClient10SP1Kaspersky32BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10SP1\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10SP1Kaspersky32BitsVersion = @("protectionAntivirusClient10SP1Kaspersky32BitsVersion","")
    }

    try{
        Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10SP2\settings" -ErrorAction Stop >$null
        $protectionAntivirusClient10SP2Kaspersky32BitsVersion = @("protectionAntivirusClient10SP2Kaspersky32BitsVersion",(Get-ItemProperty -Path "HKLM:\SOFTWARE\KasperskyLab\protected\KES10SP2\settings").SettingsVersion)
    }
    catch{
        $protectionAntivirusClient10SP2Kaspersky32BitsVersion = @("protectionAntivirusClient10SP2Kaspersky32BitsVersion","")
    }
    #############################
    ######## V2 #################


    
    #############################
    return @(
        # Param V1 : 
        $protectionAntivirusAgent12Kaspersky32BitsClientInstalle,
        $protectionAntivirusAgent12Kaspersky64BitsClientInstalle,
        $protectionAntivirusAgent12Kaspersky64BitsDerniereMaj,
        $protectionAntivirusAgent12Kaspersky32BitsDerniereMaj,
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelEtat,
        $protectionAntivirusAgent12Kaspersky32BitsTempsReelEtat,
        $protectionAntivirusAgent12Kaspersky64BitsServeurAdministration,
        $protectionAntivirusAgent12Kaspersky32BitsServeurAdministration,
        $protectionAntivirusAgent12Kaspersky64BitsTempsReelActif,
        $protectionAntivirusAgent12Kaspersky32bitsTempsReelActif,
        $protectionAntivirusClient11Kaspersky64BitsVersion,
        $protectionAntivirusClient11Kaspersky64BitsVersionAffichee,
        $protectionAntivirusClient11Kaspersky32BitsVersion,
        $protectionAntivirusClient11Kaspersky32BitsVersionAffichee,
        $protectionAntivirusClient10Kaspersky64BitsVersion,
        $protectionAntivirusClient10SP1Kaspersky64BitsVersion,
        $protectionAntivirusClient10SP2Kaspersky64BitsVersion,
        $protectionAntivirusClient10Kaspersky32BitsVersion,
        $protectionAntivirusClient10SP1Kaspersky32BitsVersion,
        $protectionAntivirusClient10SP2Kaspersky32BitsVersion
    )

}

function getConformiteConfiguration{
    ######## V1 #################
    $lsParamMdp = net accounts
    $tabParam = @()
    foreach ($param in $lsParamMdp) {
        # Diviser chaque ligne en utilisant ":" comme séparateur
        $paramParts = $param.Split(":")

        # Vérifier qu'il y a bien deux parties après le split
        if ($paramParts.Count -eq 2) {
            # Supprimer les espaces autour de la valeur et les espaces multiples à l'intérieur
            $value = $paramParts[1].Trim() -replace '\s+', ''

            # Afficher la valeur nettoyée
            $tabParam += $value
        }
    }
    # Export Politique de mdp : 
    secedit /export /cfg ./polMDPTemp.inf >$null  
    $configurationExecutionAutomatique = @("configurationExecutionAutomatique",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer").NoDriveTypeAutorun)
    $configurationMdpAgeMaximum = @("configurationMdpAgeMaximum",$tabParam[2])
    $configurationMdpAgeMinimum = @("configurationMdpAgeMinimum",$tabParam[1])
    [string]$valMdpChangement = Select-String -Path ./polMDPTemp.inf -Pattern "RequireLogonToChangePassword" 
    $configurationMdpChangementRequis = @("configurationMdpChangementRequis",($valMdpChangement.Split("=")[1]).Trim())

    [string]$valMdpComplexite = Select-String -Path ./polMDPTemp.inf -Pattern "PasswordComplexity" 
    $configurationMdpComplexite = @("configurationMdpComplexite",($valMdpComplexite.Split("=")[1]).Trim())
    $configurationMdpDureeVerrouillage = @("configurationMdpDureeVerrouillage",$tabParam[6])

    [string]$valMdpClair = Select-String -Path ./polMDPTemp.inf -Pattern "ClearTextPassword" 
    $configurationMdpEnClaire = @("configurationMdpEnClaire",($valMdpClair.Split("=")[1]).Trim())
    #Temporaire a voir si polMDPTemp.inf est a utiliser autre part : 
    rm polMDPTemp.inf

    $configurationMdpFenetreObservation = @("configurationMdpFenetreObservation",$tabParam[7])
    $configurationMdpForceDeconnexionHeureExpiration = @("configurationMdpForceDeconnexionHeureExpiration",$tabParam[0])
    $configurationMdpLongueurMinimum = @("configurationMdpLongueurMinimum",$tabParam[3])
    $configurationMdpSeuilVerrouillage = @("configurationMdpSeuilVerrouillage",$tabParam[5])
    $configurationMdpTailleHistorique = @("configurationMdpTailleHistorique",$tabParam[4])
    #############################

    ######## V2 #################

    try{
        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop > $null
        $configurationLdapLiaisonCanal = @("configurationLdapLiaisonCanal", (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters").LdapEnforceChannelBinding )
    }
    catch{
        $configurationLdapLiaisonCanal = @("configurationLdapLiaisonCanal", "")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" -Name "LDAPServerIntegrity" -ErrorAction Stop > $null
        $configurationLdapSignature = @("configurationLdapSignature", (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\").LDAPServerIntegrity)
    }
    catch{
        $configurationLdapSignature = @("configurationLdapSignature","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "TransparentEnabled"  -ErrorAction Stop >$null
        $configurationMppActive = @("configurationMppActive", (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Safer\CodeIdentifiers").TransparentEnabled)
    }
    catch{
        $configurationMppActive = @("configurationMppActive","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "AuthenticodeEnabled" -ErrorAction Stop >$null
        $configurationMppForce = @("configurationMppForce",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers").AuthenticodeEnabled)
    }
    catch{
        $configurationMppForce = @("configurationMppForce", "")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "PolicyScope" -ErrorAction Stop >$null
        $configurationMppPolitique = @("configurationMppPolitique", (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers").PolicyScope)
    }
    catch{
        $configurationMppPolitique = @("configurationMppPolitique","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -ErrorAction Stop >$null
        $configurationPowershellPolitiqueExecution = @("configurationPowershellPolitiqueExecution", (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\").ExecutionPolicy)    
    }
    catch{
        $configurationPowershellPolitiqueExecution = @("configurationPowershellPolitiqueExecution","")
    }
    # Exécuter schtasks et obtenir la sortie
    $schtasksOutput = schtasks /query /fo TABLE /nh
    $tabTache = @()
    # Parcourir chaque ligne de la sortie
    foreach ($line in $schtasksOutput) {
        # Diviser la ligne en colonnes basées sur des espaces
        $columns = $line -split '\s{2,}'

        # Vérifier si la ligne a au moins trois colonnes (Nom de la tâche, Prochaine exécution, Statut)
        if ($columns.Length -ge 3) {
            $taskName = $columns[0]
            $nextRunTime = $columns[1]

            # Vérifier si "Prochaine exécution" est une date valide (et non "N/A")
            if ($nextRunTime -match '^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}$') {
                # Extraire le nom du dossier de la tâche
                $folderName = $taskName -replace '^\\', '' -replace '\\[^\\]+$', ''
                # Afficher le nom du dossier
                $tabTache += $folderName
            }
        }
    }

    $configurationTachesPlannifieesListe = @("configurationTachesPlannifieesListe",$tabTache)

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\" -Name "AllowTelemetry" -ErrorAction Stop > $null
        $configurationTelemetrieNiveau = @("configurationTelemetrieNiveau", (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\").AllowTelemetry)
    }
    catch{
        $configurationTelemetrieNiveau = @("configurationTelemetrieNiveau","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "EnableLUA" -ErrorAction Stop >$null
        $configurationUacActive = @("configurationUacActive", (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\").EnableLUA)
    }
    catch{
        $configurationUacActive = @("configurationUacActive","")
    }
    #############################

    return @(
        # Param V1 : 
        $configurationExecutionAutomatique,
        $configurationMdpAgeMaximum,
        $configurationMdpAgeMinimum,
        $configurationMdpChangementRequis,
        $configurationMdpComplexite,
        $configurationMdpDureeVerrouillage,
        $configurationMdpEnClaire,
        $configurationMdpFenetreObservation,
        $configurationMdpForceDeconnexionHeureExpiration,
        $configurationMdpLongueurMinimum,
        $configurationMdpSeuilVerrouillage,
        $configurationMdpTailleHistorique,
        # Param V2 : 
        $configurationLdapLiaisonCanal,
        $configurationLdapSignature,
        $configurationMppActive,
        $configurationMppForce,
        $configurationMppPolitique, 
        $configurationPowershellPolitiqueExecution,
        $configurationTachesPlannifieesListe,
        $configurationTelemetrieNiveau,
        $configurationUacActive
    )
}

function getConformiteApplication{
    try{
        Get-ItemPropertyValue -Path "HKCU:\Software\Google\Chrome\BLBeacon" -Name "version" -ErrorAction Stop >$null
        $applicationChromeVersion = @("applicationChromeVersion", (Get-ItemProperty -Path "HKCU:\Software\Google\Chrome\BLBeacon").version)
    }
    catch{
        $applicationChromeVersion = @("applicationChromeVersion","")
    }

    try {
        Get-ItemPropertyValue -Path "HKCU:\Software\Mozilla\Mozilla Firefox ESR\" -Name "CurrentVersion" -ErrorAction Stop >$null
        $applicationFirefoxEsrVersion = @("applicationFirefoxEsrVersion", (Get-ItemProperty -Path "HKCU:\Software\Mozilla\Mozilla Firefox ESR\").CurrentVersion)
    }
    catch {
        $applicationFirefoxEsrVersion = @("applicationFirefoxEsrVersion","")
    }

    try {
        Get-ItemPropertyValue -Path "HKCU:\Software\Mozilla\Mozilla Firefox\CurrentVersion" -Name "CurrentVersion" -ErrorAction Stop >$null
        $applicationFirefoxVersion = @("applicationFirefoxVersion",(Get-ItemProperty -Path "HKCU:\Software\Mozilla\Mozilla Firefox\CurrentVersion").CurrentVersion)
    }
    catch { 
        $applicationFirefoxVersion= @("applicationFirefoxVersion","")
    }

    $lsApp = Get-WmiObject -Class Win32_Product | Where-Object {$_.Vendor -ne "Microsoft Corporation"} | Select-Object Name
    $tabApp = @()
    
    foreach($package in $lsApp){
        if($package.Name -ne $null){
            $tabApp += $package.Name
        }
    }
    
    if($tabApp.Count -gt  0){
        $applicationListe = @("applicationListe",$tabApp)
    }
    else{
        $applicationListe = @("applicationListe","")
    }

    return @(
        $applicationChromeVersion,
        $applicationFirefoxEsrVersion,
        $applicationFirefoxVersion,
        $applicationListe
    )
}

function getConformiteDurcissement{
    ######## DURCISSEMENT #################

    try{
        Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -ErrorAction Stop >$null
        $durcissementExtensionCaches = @("durcissementExtensionCaches", (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced").HideFileExt)
    }
    catch{
        $durcissementExtensionCaches = @("durcissementExtensionCaches","")
    }

    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "SmartScreenEnabled" -ErrorAction Stop >$null
        $durcissementEcranIntelligent = @("durcissementEcranIntelligent",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System").SmartScreenEnabled)
    }
    catch{
        $durcissementEcranIntelligent = @("durcissementEcranIntelligent","")
    }

    try{
        Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -ErrorAction Stop >$null
        $durcissementFichierDossierCaches = @("durcissementFichierDossierCaches",(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced").Hidden)
    }
    catch{
        $durcissementFichierDossierCaches = @("durcissementFichierDossierCaches","")
    }

    #Event Log : 
    $dossiers = @("Application", "Security", "Setup", "System")
    $tabAutoSave = @()
    $tabMaxSize = @()
    foreach($dossier in $dossiers){
        try{
            Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EventSystem\Eventlog\$dossier" -ErrorAction Stop >$null
            $tabAutoSave += @("durcissementEventLogSauvAuto$dossier",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EventSystem\Eventlog\$dossier").AutoBackupLogFiles)
        }
        catch{
            $tabAutoSave += @("durcissementEventLogSauvAuto$dossier","")
        }

        try{
            Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EventSystem\Eventlog\$dossier" -ErrorAction Stop >$null
            $tabMaxSize += @("durcissementEventLogMaxSize$dossier",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EventSystem\Eventlog\$dossier").MaxSize)
        }
        catch{
            $tabMaxSize += @("durcissementEventLogMaxSize$dossier","")
        }
    }

    # Autologon : 
    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction Stop >$null
        $durcissementAutoAdminLogon = @("durcissementAutoAdminLogon",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AutoAdminLogon)
    }
    catch{
        $durcissementAutoAdminLogon = @("durcissementAutoAdminLogon","")
    }
    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -ErrorAction Stop >$null
        $durcissementEcranDeVeille = @("durcissementEcranDeVeille",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").ScreenSaverGracePeriod)
    }
    catch{
        $durcissementEcranDeVeille = @("durcissementEcranDeVeille","")
    }

    #Net BIOS Conf : 
    try{
        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetBiosOptions" -ErrorAction Stop >$null
        $durcissementNetBiosConfiguration = @("durcissementNetBiosConfiguration",(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces").NetBiosOptions)
    }
    catch{
        $durcissementNetBiosConfiguration = @("durcissementNetBiosConfiguration","")
    }

    #RDP activer: 
    try {
        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop >$null
        $durcissementRDPActif = @("durcissementRDPActif",(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections)
    }
    catch {
        $durcissementRDPActif = @("durcissementRDPActif","")
    }

    #SSDPSRVConf : 
    # Recup info concernant type de demarrage + si actif ou non 
    $durcissementSSDPSRVService = @("durcissementSSDPSRVService",(Get-Service -Name SSDPSRV).Status)
    $durcissementSSDPSRVTypeDemarrage = @("durcissementSSDPSRVTypeDemarrage",(Get-WmiObject -Class Win32_Service -Filter "Name='SSDPSRV'").StartMode)

    #SEHOP : 
    try {
        Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction Stop >$null
        $durcissementSEHOP = @("durcissementSEHOP",(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel").DisableExceptionChainValidation)
    }
    catch {
        $durcissementSEHOP = @("durcissementSEHOP","")
    }

    #Conf Win Store : 
    try{
        Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction Stop >$null
        $durcissementWindowsStoreConfiguration = @("durcissementWindowsStoreConfiguration",(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore").RemoveWindowsStore)
    }
    catch{
        $durcissementWindowsStoreConfiguration = @("durcissementWindowsStoreConfiguration","")
    }

    #Durcissement lanman service : 
    $durcissementLanmanServerService = @("durcissementLanmanServerService",(Get-Service -Name LanmanServer).Status)

    #durcissement PlugPlay : 
    $durcissementPlugPlayConfiguration = @("durcissementPlugPlayConfiguration",(Get-Service -Name PlugPlay))

    #ip v6:
    try{
        Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -ErrorAction Stop >$null
        $durcissementIpv6Configuration = @("durcissementIpv6Configuration",(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\TCPIP6\Parameters").DisabledComponents)
    }
    catch{
        $durcissementIpv6Configuration = @("durcissementIpv6Configuration","")
    }

    #SMBConfiguration : 
    #Parametre LanManServer a retourner : 
    $tabParamLanmanServer = @("autodisconnect", "enableforcedlogoff", "enablesecuritysignature", "NullSessionPipes", "requiresecuritysignature", "restrictnullsessaccess", "SMB1")
    $durcissementLanManServerParam = recuperationPlusieursValeurs "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" $tabParamLanmanServer "durcissementLanManServerParam"

    #Parametre LanmanWorkstation : 
    $tabParamLanmanWorkstation = @("EnablePlainTextPassword", "EnableSecuritySignature", "RequireSecuritySignature")
    $durcissementLanManWorkstationParam = recuperationPlusieursValeurs "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" $tabParamLanmanWorkstation "durcissementLanManWorkstationParam"

    #Parametre mrxsmbParam : 
    try {
        $mrxsmbParams = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb" -Name "Start" -ErrorAction Stop >$null
        $durcissementMrxsmbParam = @("durcissementMrxsmbParam","$mrxsmbParam")
    }
    catch {
        $durcissementMrxsmbParam = @("durcissementMrxsmbParam","")
    }

    #Param mrxsmb20Param : 
    try {
        $mrxsmb20Params = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb20" -Name "Start" -ErrorAction Stop >$null
        $durcissementMrxsmb20Param = @("durcissementMrxsmb20Param","$mrxsmb20Param")
    }
    catch {
        $durcissementMrxsmb20Param = @("durcissementMrxsmb20Param","")
    }

    #LanmanWorkstationService : 
    #Param LanmanWorkstationService : 
    try {
        $lanmanWorkstationService = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation" -Name "DependOnService" -ErrorAction Stop >$null
        $durcissementlanmanWorkstationService = @("durcissementlanmanWorkstationService","$lanmanWorkstationService")
    }
    catch {
        $durcissementlanmanWorkstationService = @("durcissementlanmanWorkstationService","")
    }

    #LDAP : 
    try{
        $ldapParam = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "ldapclientintegrity" -ErrorAction Stop >$null
        $durcissementLDAPConfiguration = @("durcissementLDAPConfiguration",$ldapParam)
    }
    catch{
        $durcissementLDAPConfiguration = @("durcissementLDAPConfiguration","")
    }

    #RDP : 
    $tabParamRDP = @(
        "DisablePasswordSaving",
        "fDisableCam",
        "fDisableAudioCapture",
        "fDisableClip",
        "fDisableCcm",
        "fDisableCdm",
        "fDisableLPT",
        "fDisablePNPRedir",
        "fForceClientLptDef",
        "fDisableCpm",
        "UserAuthentication",
        "MinEncryptionLevel",
        "SecurityLayer",
        "fResetBroken",
        "MaxConnectionTime",
        "MaxIdleTime",
        "MaxDisconnectionTime"
    )
    $durcissementRDPConfiguration = recuperationPlusieursValeurs "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" $tabParamRDP "durcissementRDPConfiguration"

    #UAC : 
    $tabParamUAC = @(
        "ConsentPromptBehaviorAdmin",
        "ConsentPromptBehaviorUser",
        "EnableInstallerDetection",
        "EnableLUA",
        "EnableSecureUIAPaths",
        "EnableUIADesktopToggle",
        "EnableVirtualization",
        "FilterAdministratorToken",
        "PromptOnSecureDesktop",
        "UndockWithoutLogon",
        "ValidateAdminCodeSignatures",
        "DisableCAD",
        "DontDisplayLastUserName",
        "ScForceOption",
        "ShutdownWithoutLogon"
    )
    $durcissementUACConfiguration = recuperationPlusieursValeurs "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" $tabParamUAC "durcissementUACConfiguration"

    #TCP IP Configuration : 
    $tabParamTCP = @(
        "DisableIPSourceRouting",
        "EnableDeadGWDetect",
        "EnableICMPRedirect",
        "EnablePMTUDiscovery",
        "KeepAliveTime",
        "PerformRouterDiscovery",
        "SynAttackProtect",
        "TcpMaxHalfOpen",
        "TcpMaxHalfOpenRetried"
    )
    $durcissementTCPIPConfiguration = recuperationPlusieursValeurs "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" $tabParamTCP "durcissementTCPIPConfiguration"

    #Policy agent : 
    try{
        $registrePolicyAgent = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "NoDefaultExempt" -ErrorAction Stop >$null
        $durcissementPolicyAgent = @("durcissementPolicyAgent","$registrePolicyAgent")
    }
    catch{
        $durcissementPolicyAgent = @("durcissementPolicyAgent","")
    }

    #Param lanmanserver :  
    $durcissementLanmanServerSetting = recuperationPlusieursValeurs "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" @("AutoShareServer", "AutoShareWks", "Hidden") "durcissementLanmanServerParametre"
    #mrxsmb:
    try{
        $valeur = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb" -Name "RefuseReset" -ErrorAction Stop #>$null
        $durcissementLanmanServerSetting += ,@("durcissementLanmanServerParametreMRXSMB","$valeur")
    }
    catch{
        $durcissementLanmanServerSetting += ,@("durcissementLanmanServerParametreMRXSMB","")
    }
    #dns:
    try{
        $valeur = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -ErrorAction Stop #>$null
        $durcissementLanmanServerSetting += ,@("durcissementLanmanServerParametreDNS","$valeur")
    }
    catch{
        $durcissementLanmanServerSetting += ,@("durcissementLanmanServerParametreDNS","")
    }

    #NTP : 
    $tabNTPW32 = @("NtpServer","Type")
    $durcissementNTPConfigurationW32 = recuperationPlusieursValeurs "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" $tabNTPW32 "durcissementNTPConfigurationW32"

    $tabDateTime = @("'0'","'(Default)'")
    $durcissementNTPConfigurationDateTime = recuperationPlusieursValeurs "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" $tabDateTime "durcissementNTPConfigurationDateTime"

    $durcissementNTPConfigurationServiceW32 = @("durcissementNTPConfigurationServiceW32",(Get-Service -Name w32time).Status)

    #USB :
    try{
        $valeurUSB = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "AllowedUSBDevices" -ErrorAction Stop >$null
        $durcissementUsbStatus = @("durcissementUsbStatus","$valeurUSB")
    }
    catch{
        $durcissementUsbStatus = @("durcissementUsbStatus","")
    }

    #Audit powershell : 
    #Module logging 
    try{    
        $valeurModuleLogging = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction Stop > $null
        $durcissementAuditPowershellModLogging = @("durcissementAuditPowershellModLogging","$valeurModuleLogging")
    }
    catch{
        $durcissementAuditPowershellModLogging = @("durcissementAuditPowershellModLogging","") 
    }

    #Module name 
    try{    
        $valeurModuleNames = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -ErrorAction Stop > $null
        $durcissementAuditPowershellModNames = @("durcissementAuditPowershellModNames","$valeurModuleNames")
    }
    catch{
        $durcissementAuditPowershellModNames = @("durcissementAuditPowershellModNames","") 
    }

    #Module name 
    try{    
        $valeurBlockLogging = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction Stop > $null
        $durcissementAuditPowershellBlockLogging = @("durcissementAuditPowershellBlockLogging","$valeurBlockLogging")
    }
    catch{
        $durcissementAuditPowershellBlockLogging = @("durcissementAuditPowershellBlockLogging","") 
    }

    # Autorun
    try{    
        $valeurAutorun = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "NoDriveTypeAutoRun" -ErrorAction Stop > $null
        $durcissementAutorunConfiguration = @("durcissementAutorunConfiguration","$valeurAutorun")
    }
    catch{
        $durcissementAutorunConfiguration = @("durcissementAutorunConfiguration","") 
    }

    #######################################

    return @(
        #Param durcissement :
        $durcissementExtensionCaches,
        $durcissementEcranIntelligent,
        $durcissementFichierDossierCaches,
        $durcissementAutoAdminLogon,
        $durcissementEcranDeVeille,
        $durcissementNetBiosConfiguration,
        $durcissementRDPActif,
        $durcissementSSDPSRVService,
        $durcissementSSDPSRVTypeDemarrage,
        $durcissementSEHOP,
        $durcissementWindowsStoreConfiguration,
        $durcissementLanmanServerService,
        $durcissementPlugPlayConfiguration,
        $durcissementIpv6Configuration,
        $durcissementLanManServerParam,
        $durcissementLanManWorkstationParam,
        $durcissementMrxsmbParam,
        $durcissementMrxsmb20Param,
        $durcissementlanmanWorkstationService,
        $durcissementLDAPConfiguration,
        $durcissementRDPConfiguration,
        $durcissementUACConfiguration,
        $durcissementTCPIPConfiguration,
        $durcissementPolicyAgent,
        $durcissementLanmanServerSetting,
        $durcissementNTPConfigurationW32,
        $durcissementNTPConfigurationDateTime,
        $durcissementNTPConfigurationServiceW32,
        $durcissementUsbStatus,
        $durcissementAuditPowershellModLogging,
        $durcissementAuditPowershellModNames,
        $durcissementAuditPowershellBlockLogging,
        $durcissementAutorunConfiguration
    )
}

#Fonction qui va convertir les valeurs récupérer dans les différentes fonctions au format json soit : {scriptExecutionCompte:"C:/test",scriptVersion:"1"}
#################################################################################
# MAIN                                                                          #
#################################################################################

# Appel des fonctions qui retourne les valeurs : 
$script = getConformiteScript
$system = getConformiteSystem
$compte = getConformiteCompte
$reseau = getConformiteReseau
$service = getConformiteService
$protection = getConformiteProtection #a tester sur poste disposant de Kaspersky
$configuration = getConformiteConfiguration
$application = getConformiteApplication
$durcissement = getConformiteDurcissement
#  
#Tableau qui va permettre le stockage des autres tableau contenant les informations nécessaire : 
$tabTemp = @($script, $system, $compte, $reseau, $service, $protection, $configuration, $application, $durcissement)
# Création d'un fichier CSV ou XML ? : 
#En-tête du CSV :
$fichierResultat = "$((pwd).Path)\$(hostname)_$(Get-Date -Format 'yyyy-MM-dd')_$(Get-Date -Format 'HH-mm-ss').csv"
Write-Output '"Paramètre","Valeur"' | Out-File -FilePath $fichierResultat -Encoding utf8
foreach($tab in $tabTemp){
    foreach($valeur in $tab){
        if($valeur.Count -gt 2){
            foreach($val in $valeur){
                ConversionChaineEnCSV $val[0] $val[1] | Out-File -Append -FilePath $fichierResultat -Encoding utf8
            }
        }
        else{
            ConversionChaineEnCSV $valeur[0] $valeur[1] | Out-File -Append -FilePath $fichierResultat -Encoding utf8
        }
    }
}

# Chemin pour le fichier JSON
$fichierResultat = "$((pwd).Path)\$(hostname)_$(Get-Date -Format 'yyyy-MM-dd')_$(Get-Date -Format 'HH-mm-ss').json"

# Initialiser une collection pour les données
$donneesJSON = @()

# Parcourir les données
foreach ($tab in $tabTemp) {
    foreach ($valeur in $tab) {
        if ($valeur.Count -gt 2) {
            foreach ($val in $valeur) {
                $entreeJSON = ConversionChaineEnJSON $val[0] $val[1]
                $donneesJSON += $entreeJSON | ConvertFrom-Json
            }
        } else {
            $entreeJSON = ConversionChaineEnJSON $valeur[0] $valeur[1]
            $donneesJSON += $entreeJSON | ConvertFrom-Json
        }
    }
}

# Convertir l’ensemble des données en JSON structuré
$donneesJSON | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $fichierResultat -Encoding utf8
