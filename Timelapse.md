## Introduction
Lately i am getting into active directory hacking, thats why i decided to make writeup about this box, to be honest every AD box on HTB so far was really well made, good quality and interesting. Timelapse is easy box, we will find in SMB share file that is zipped and to be unzipped it requires password, we will obtain password by bruteforce and we will crack keys that are inside to get footghold, then we will read powershell history where we will find credentials to another user that is able to read from LAPS, the technology that helps to keep local administrator passwords safe and unique. We will pass admin credentials to Evil-WinRM.
## Recon
As allways we will start with nmap

![image](https://github.com/user-attachments/assets/5f6f1e65-4060-4f47-9133-25a67004cbef)

Flags:
```
- sV for service version
- sC for deafult scripts
- A enables aggressive scan, the aggressive scan option supports OS detection
- Pn becouse i know host is up and nmap dont see it
```
From scan above we can see that we are dealing with DC(domain controller), we can conclude becouse there is Kerberos, DNS, SMB, LDAP. This speculation is supported by the hostname identified at the bottom (DC01)
## User.txt
First i will look at SMB shares becouse often we can find interesting things there:

![image](https://github.com/user-attachments/assets/52317948-0332-4a4d-b46d-afa3aee323fd)

We can see that there is Shares Share that looks interesting so i connected to it. There after a while i found interesting file called ```winrm_backup.zip``` in \Dev\ directory so i went ahead and downloaded it

![image](https://github.com/user-attachments/assets/6540aa3e-2c21-43e9-beac-f4f8d610aabb)

I tried to unzip file but it requires password. Every time that i see .zip, .pdf that needs password to get in i allways try to crack it with john so thats what i did, but first we need to extract password hash from file:

![image](https://github.com/user-attachments/assets/0fc6f2b7-9058-4984-8bdf-8ebab25bec99)

Using command:
```
john --wordlist=/home/andrew/Downloads/rockyou.txt hash.txt
```
I almost immediately got it cracked obtaining ```supremelegacy``` password, so i unziped file 

![image](https://github.com/user-attachments/assets/7ec9d2f1-4bae-4966-8cf8-6b97493d3771)

I tried to extract the private key and certificate (public key) from a ```.pfx``` file using openssl but it needs password, since we dont have one we will need to crack it. First we need to extract hash then give it to john.

![image](https://github.com/user-attachments/assets/2f1a9add-c263-4a63-9218-87699ccbcfa9)

When i got password ```thuglegacy``` i extracted private key and public one.

![image](https://github.com/user-attachments/assets/561c38f7-4281-4b35-a1ba-e32ab1efcbb6)

Then only thing left was to connect through Evil-WinRM

![image](https://github.com/user-attachments/assets/70bc4085-5951-4fb7-8677-b92c8b3b67f1)

## svc_deploy
First of all lets look what can we do as legacyy user:

![image](https://github.com/user-attachments/assets/9f3dd25f-d7c0-4fef-889a-92db2e434f0f)

Not much, another thing worth trying is to check powershell history file that is located at:
```
 C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
```
And there it is:

![image](https://github.com/user-attachments/assets/ba16e8a4-e07a-4a3b-9d35-1d73ae1898c5)

We obtained powershell history:
```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
From here we can log in to svc_deploy user:

![image](https://github.com/user-attachments/assets/8b7d38e8-4450-49c6-9e7e-82b66bea20ab)

## Root.txt
Again checking user privileges.

![image](https://github.com/user-attachments/assets/8b43d6dd-6004-4774-9e5a-30b4657e0629)

Looks like svc_deploy is able to read from LAPS, becouse this user is member of LAPS_Readers group.                                                                 
Using LAPS, the domain controller oversees the management of local administrator passwords for the computers within the domain. Often, a group of users is established and granted permissions to access these passwords, enabling designated administrators to view all the local admin passwords.                                                                  
Only thing left is to read LAPS password:

![image](https://github.com/user-attachments/assets/9d502ff1-3b2e-46c4-9751-4883333b5495)

We log in with credentials, but root.txt isnt in Dekstop directory.

![image](https://github.com/user-attachments/assets/4bc1f2cb-f0ae-4101-8ce9-7ffefa9311e1)

So we will need to find it

![image](https://github.com/user-attachments/assets/a738b0a1-c16f-40ec-9deb-76215468eda1)

Command:
```
Get-ChildItem -Path "C:\Users" -Recurse -Filter "root.txt"
```
Worked, successfully finding file at: ```C:\Users\TRX\Desktop```
## Conclusion
AD boxes are refreshing alternative to web app i find them more fun more i do them, maybe it will become my favorite type. This box was fun i learned about LAPS hope you also learned something.
