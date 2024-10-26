## Introduction
Hi, today we will hack the Cronos box from HTB. This is a medium-difficulty machine that was fun to do, with no CVEs and only manual methods. We will gain a foothold by logging into a custom web app with SQLi, which has RCE. After that, we will exploit a cron job to gain elevated privileges. Lets go!
## Discovery
We will start with nmap:

![image](https://github.com/user-attachments/assets/2c57e84d-41b1-4be9-a166-1f06ad4e9029)

Okay so we have three services open:
- ssh
- DNS
- http

Bruteforcing ssh is like banging head against the wall, since there are other ports open we are not that desperate yet, i will start with http:

![image](https://github.com/user-attachments/assets/de0cb98d-a5ef-41ab-a1d5-5615021a9eba)

We can see that it is deafult apache2 page, nothing to do here. I ran dirb and found nothing. So i will move to DNS enumeration:

![image](https://github.com/user-attachments/assets/dfa45ab8-dbd5-47d4-b610-d0a4a233cb53)

I ran nslookup to resolve cronos IPs:

![image](https://github.com/user-attachments/assets/949a764d-9df9-459a-a61d-cc139617848a)

And we obtained subdomain: ```ns1.cronos.htb```, we also got domain name: ```cronos.htb```, when there is TCP DNS its allways worth trying to perform zone transfer:

![image](https://github.com/user-attachments/assets/ad8a520c-28f3-4c97-aa84-00a4cb330a95)

Here we got another two subdomains so we have now:
- ns1.cronos.htb
- www.cronos.htb
- admin.cronos.htb
After adding theese to /etc/hosts, i moved to see what is happening at www.cronos.htb:

![image](https://github.com/user-attachments/assets/0ac63058-06f2-4eb6-a986-7b9f08cdd524)

Not much there, every link go to external web pages and we dont want to fall out of scope, i will look at other subdomains before enumerating each one of them.
