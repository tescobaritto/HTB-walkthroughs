## Introduction 
Hi, today we will hack OpenAdmin box from hack the box, it is rated as easy but people rate it as medium, we will get foothold by exploiting ona(OpenNetAdmin) web application  old version that have rce, we will find credentials in config file as www-data, as user we will use not secure php script to move lateraly to another user and from there we got simple sudo nano priv esc. This box is really fun! 
## Discovery
We will start with nmap:

![image](https://github.com/user-attachments/assets/a4a3bcb6-96b6-4fed-9cb7-4a481c90fb8d)

Flags:
-sV for version
-sC for deafult scripts

On the machine we have two services running:
- ssh (22)
- http (80)
## First web site:
Since bruteforcing ssh is usually bad idea we will see what is happening on port 80

![image](https://github.com/user-attachments/assets/b44b45ae-6a90-4685-a975-a7427a005492)

It is deafult page for apache no input window nothing to inject here, i looked for any CVE for this version found one but it requires speccific setup:
```
Requirements:
1/ mod_cgi enabled (not default but easy)
2/ target binary should be +x (default for /bin/sh)
3/ apache permissions granted for /bin or / (not default and difficult/unrealistic)\
```
I checked for this anyway but it didnt work, so only one thing left to do is to look for subdomains and directories, since we dont even have domain i choose to look for directories first, i used dirb:

![image](https://github.com/user-attachments/assets/3fa94b05-f9be-45f3-8938-afd66d429a7f)

Dirb discovered two directories we will start with /artwork

![image](https://github.com/user-attachments/assets/fdc7c6f4-65e5-4a49-8c4d-173ff019acdf)

Contact is place where we can input something so its allways worth checking for SQLi therefore i opened burp and intercepted traffic.

![image](https://github.com/user-attachments/assets/4d093960-17bc-4e09-bf84-365cff186b4d)

We have POST request but it doesnt really post anything: ```Content-Length=0``` we could try to guess and  write some values in POST request but this is easy level box and there is also one more directory to check.

## Second web site(Foothold):

![image](https://github.com/user-attachments/assets/80e6558e-fdf0-47dc-aa7d-373f7dc8d587)

I clicked login button and got redirected to OpenNetAdmin

![image](https://github.com/user-attachments/assets/b574c994-f44f-4131-8498-122eb8445f8d)

In yellow window they are asking us to update version so our current is not up to date, i looked for CVE and found this github:                         
https://github.com/amriunix/ona-rce?tab=readme-ov-file                    

![image](https://github.com/user-attachments/assets/17473658-c87a-420b-a1a1-7c5945fb1ce3)

We succesfuly got shell on the box!      
Now usually we need to look for config files so thats what i did:

![image](https://github.com/user-attachments/assets/9f08368b-67ac-4070-9825-c68a3f38bad2)

I cat database settings:

![image](https://github.com/user-attachments/assets/950bfee4-8586-4414-9001-dd5efdd4bf55)

We got credentials for database but it may be also password for ssh, we dont know who is user on ssh thats why we ran: ```cat /etc/passwd | grep "bin/bash"```, piped with grep that looks for bin/bash (just user shell)

![image](https://github.com/user-attachments/assets/1ed80484-a632-471d-bb88-032180d05323)

There are three users:
- root
- joanna
- jimmy
So lets try to login through ssh

![image](https://github.com/user-attachments/assets/1dd87f65-92ae-4289-97a9-1b06c43230c4)

I connected to jimmy account and ran linpeas, nothing interesting there besides:

![image](https://github.com/user-attachments/assets/71189d20-977f-4a79-87d2-d591cc2bb995)

Joanna can execute nano with sudo on /opt/priv, which means she is basicly root                                     
Now i took a lot of time but after a while i found interesting script in: /var/www/internal                                 

![image](https://github.com/user-attachments/assets/804b605f-a21f-45ad-b358-944e97721afb)

Okay so this scripts opens id_rsa private key for joanna user we need to figure out how to execute this, we cant run this manually. Since it was in /var/www/ directory i will look for any network connections

![image](https://github.com/user-attachments/assets/3e1e7e09-3352-4d39-b663-df22d7fb3a44)

Now we need to just look for this script with for random ports with curl:

![image](https://github.com/user-attachments/assets/47657e93-393f-47ae-8aa2-35cbcccef48a)

We retrived id_rsa key that is encrypted so we will need to crack it with john:

![image](https://github.com/user-attachments/assets/d7baac6f-0bb0-43e4-9881-63a36fa15486)

Thats why we will use ```ssh2john``` command to compile our key to hash:

![image](https://github.com/user-attachments/assets/29406f43-e2bc-47c7-a8f6-187af3c9a24b)

Now we crack hash with this command:
```
john id_rsa.john --wordlist=/home/andrew/Downloads/rockyou.txt
```
We got passphrase "bloodninjas"

![image](https://github.com/user-attachments/assets/3855b545-0b2e-4110-8f5d-5e057b84ab78)

And we succesfuly obrained user.txt!
## Privlige escalation
As we saw earlier root is really easy

![image](https://github.com/user-attachments/assets/dcd17f1d-74ef-4d4d-8bcd-38ce0a730fc4)

We go to GTFOBins and search for nano, sudo and we got this:
```
sudo nano
^R^X
reset; sh 1>&0 2>&0
```
^ means ctrl key

![image](https://github.com/user-attachments/assets/ea79d8e1-b2e7-4873-a024-82d8eb8236ec)

And we got root!
## Conclusion
This machine had a few rabbit holes, it took some time but eventually we got super user on this box, it was fun becouse there was happening a lot and i wasnt stuck for too long on one thing becoming frustrated, hope you learned something and also had fun!
