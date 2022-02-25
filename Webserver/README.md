# Webserver

---

## 1.0 Nmap results IPv4 10.200.57.200

```bash
22/tcp    open   ssh        syn-ack      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfKbbFLiRV9dqsrYQifAghp85qmXpYEHf2g4JJqDKUL316TcAoGj62aamfhx5isIJHtQsA0hVmz
D+4pVH4r8ANkuIIRs6j9cnBrLGpjk8xz9+BE1Vvd8lmORGxCqTv+9LgrpB7tcfoEkIOSG7zeY182kOR72igUERpy0JkzxJm2gIGb7Caz1s5/ScHEOhG
X8VhNT4clOhDc9dLePRQvRooicIsENqQsLckE0eJB7rTSxemWduL+twySqtwN80a7pRzS7dzR4f6fkhVBAhYflJBW3iZ46zOItZcwT2u0wReCrFzxvD
xEOewH7YHFpvOvb+Exuf3W6OuSjCHF64S7iU6z92aINNf+dSROACXbmGnBhTlGaV57brOXzujsWDylivWZ7CVVj1gB6mrNfEpBNE983qZskyVk4eTNT
5cUD+3I/IPOz1bOtOWiraZCevFYaQR5AxNmx8sDIgo1z4VcxOMhrczc7RC/s3KWcoIkI2cI5+KUnDtaOfUClXPBCgYE50=
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFccvYHwpGWYUsw9mTk/mEvzyrY4ghhX2D6o3n/up
TLFXbhJPV6ls4C8O0wH6TyGq7ClV3XpVa7zevngNoqlwzM=
|   256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINLfVtZHSGvCy3JP5GX0Dgzcxz+Y9In0TcQc3vhvMXCP
80/tcp    open   http       syn-ack      Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: Did not follow redirect to https://thomaswreath.thm
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
443/tcp   open   ssl/http   syn-ack      Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
| http-methods:
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
| http-cisco-anyconnect:
|_  ERROR: Not a Cisco ASA or unsupported version
|_http-title: Thomas Wreath | Developer
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=Eas
t Riding Yorkshire/countryName=GB/localityName=Easingwold/emailAddress=me@thomaswreath.thm
| Issuer: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yo
rkshire/countryName=GB/localityName=Easingwold/emailAddress=me@thomaswreath.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-22T12:05:11
| Not valid after:  2023-02-22T12:05:11
| MD5:   b350 a713 f8fb d0a5 3733 8013 850e 8392
| SHA-1: 0b4b 8f12 4679 f268 dc31 d02e 58bb f63f d5ac 63cd
| dXYMI2jXd1npfIRNBJwwKFIn1Bw4Q+09q/pV9ocTdNvH4SJcfiPsQi00IRUaJeXx                                          [0/414]
| xCgPuXyAuigLv5KfiPNLqNtJEGwzvmTKSBHK1PucEROJBXt+rYBgC00EqsVn0jFC
| 2RJ94jQRwIuIppMFsgekiGzdQcsYXv2FmOlbpdRLHDglNWv7ZaOPH4siomS3rIbH
| h7W+tvPrsPQuN9Fj5rYN3hr0sUJ79nYPYEdHY3vuo/Cf5lU8hNFxOe93xQdG/KoB
| e7l8bcTd89DK4icaWxo3gjYkKD+gYcBIL5tKPpaYS5FfezsCAwEAAaNTMFEwHQYD
| VR0OBBYEFAwdk3lG4jq19yYeWbhNGfWuEIxWMB8GA1UdIwQYMBaAFAwdk3lG4jq1
| 9yYeWbhNGfWuEIxWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| ADFbR9KFLSdPzy08Objo0pIRqfd66bVmZvEU/dxztaW7vaEHl+emQkr3wRo3825+
| skEmZU9FQQacbky+0ubiupWghJ4JquN5XB4nstzW5/a92dxbeI7U7aeN4WpIBoBf
| CSpHjUlRSwm6vP+CBoJdxuMg7M/krsSHKMRk4xej4qXgtEeiPPrKpcqkvXB7hjJK
| nv8sEZoifGikOXWmueodsnuMZDrX2ISTewv6BoeJqt5o7nYkSmnmaQGdpEJ6Fq4d
| MvvUqd40mbAgD2JL0QqFoqnOPTC8Kp0PFj+q0BvkdD79v1i3H/QlLAGySmUUoAOL
| vRrwXUl347MA9irDosxqVXw=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
9090/tcp  closed zeus-admin conn-refused
10000/tcp open   http       syn-ack      MiniServ 1.890 (Webmin httpd)
| ndmp-version:
|_  ERROR: Failed to get host information from server
|_http-favicon: Unknown favicon MD5: E91E54F99599BF3DFBE05543D3EC78E0
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Final times for host: srtt: 94308 rttvar: 118180  to: 567028
```

We find out that there’re running 4 ports on this centOS server. 

1. Port 22 for SSH (open SSH 8.0)
2. Port 80 for HTTP (Apache httpd 2.4.37)
3. Port 10000 running a webserver (MiniServ 1.890 (Webmin httpd)
4. Port 443 for HTTPS (Apache httpd 2.4.3)

Also Nmap tells us about an closed port 9090 (connection refused) which may speculate an firewall.

---

## 2.0 Exploiting MiniServ 1.890 Webmin RCE

The service running on port 10000, has a vulnerability in the version 1.890 (****CVE-2019–15107)**** which leads to RCE. Source: [https://medium.com/@foxsin34/webmin-1-890-exploit-unauthorized-rce-cve-2019-15107-23e4d5a9c3b4](https://medium.com/@foxsin34/webmin-1-890-exploit-unauthorized-rce-cve-2019-15107-23e4d5a9c3b4)

Exploit: https://github.com/foxsin34/WebMin-1.890-Exploit-unauthorized-RCE and https://github.com/MuirlandOracle/CVE-2019-15107

### 2.1 PoC (Proof of Concept)

I cloned the https://github.com/MuirlandOracle/CVE-2019-15107 repository and installed the required python libraries. After that I just ran this command to get a shell:

```bash
./CVE-2019-15107.py 10.200.57.200
```

Which lead to this output:

![Untitled](Webserver%204a30c/Untitled.png)

We are now inside the webserver itself. To get a full reverse shell I could use the “shell” command that was programmed inside the exploit.

Target shell:

![Untitled](Webserver%204a30c/Untitled%201.png)

Attacker’s shell:

![Untitled](Webserver%204a30c/Untitled%202.png)

As you can see, I now have a fully working reverse shell running as the user root!

---

### 2.2 get SSH access

To get SSH access I need a password of a hash for the root user. Since we can’t crack the hash in /etc/shadow, I copied the id_rsa hash to my attack machine:

![Untitled](Webserver%204a30c/Untitled%203.png)

Now that I have the hash, I gave it the right permissions and I ran the SSH command to use the hash:

![Untitled](Webserver%204a30c/Untitled%204.png)

---

Let’s start to pivot trough the webserver ;)
[2 ) Pivoting](/Pivoting/README.md)