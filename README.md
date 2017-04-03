# Private Circle
# Warning: Work in progress

[TOC]


# Introduction
Chapters: Hardware, Basic installation, System Hardening, Full Disk Encryption, VPN setup, DynDNS configuration, TLS-Certificate, Webserver installation & Hardening, Nextcloud installation, Nextcloud App configuration,  Prosody installation, Private PGP Server installation, Hidden service configuration, IRC-Server installation, 

# Hardware
The following hardware is recommended:

  * Raspberry Pi 3
  * MicroSD-Card (min. 16G)
  * Network Cable (2m)
  * USB charger
  * Official Raspberry Pi case

# Features
Here is an incomplete list of features:

  * DynDNS
  * TLS
  * Jabber
  * Webserver
  * Nextcloud
  * Private PGP Keyserver
  
  Optional:
  
  * Email
  * ZeroBin?
  * DokuWiki
  * HiddenService
  * IRC-Server + Web Interface
  * (Mumble)

# Installation  
## Download Debian Jessie Lite

https://www.raspberrypi.org/downloads/raspbian/

## Copy to SD-Card
  * Extract the downloaded zip file
  * Delete all partitions on the SD-Card with GParted or an other tool
  * Copy the image to your SD-Card

	sudo dd bs=2M status=progress if=/home/user123/Downloads/2016-11-25-raspbian-jessie-lite.img of=/dev/mmcblk0


**Add a file named "ssh" to the boot partition**

## First Boot
  * Put the SD-Card into your Pi
  * Install Avahi Deamon on your laptop
  * Connect your laptop to the Pi with a network cable
  * Boot the Pi

### Connect to the Pi

	ssh raspberrypi.local
or

	ssh raspberrypi

**Login with the following credentials:**

  * User: pi
  * Password: raspberry

### Create new root user

	adduser privatebox
	adduser privatebox sudo
	//mkdir /home/privatebox/.ssh
	//chown privatebox:privatebox /home/privatebox/.ssh/
	
	exit
	logout
	
Reconnect with:
	ssh privatebox@raspberrypi

Delete old user:

	sudo deluser pi
	
Create new root password:

	sudo passwd root
	
https://gordonlesti.com/change-default-users-on-raspberry-pi/

### Change password //TODO: delete

Enter the following line to change the password:

	passwd

### Wifi setup

#### Generating the network profile
Enter the following to list available wLAN networks:

	sudo iwlist wlan0 scan
	
Use wpa_passphrase to create a network profile:

	wpa_passphrase "SSIDOfYourNetwork" "PasswordForYourNetwork"
	
This should generate an output which might look like the following example:

	network={
  		ssid="SSIDOfYourNetwork"
  		#psk="PasswordForYourNetwork"
  		
  	 	psk=131e1e221f6e06e3911a2d11ff2fac9182665c004de85300f9cac208a6a80531
	}

**Delete the line starting with "#"! Example:**

	network={
  		ssid="SSIDOfYourNetwork"
  	 	psk=131e1e221f6e06e3911a2d11ff2fac9182665c004de85300f9cac208a6a80531
	}

#### Adding the network profile to the configuration
Open the wpa_supplicant configuration file:

	sudo nano /etc/wpa_supplicant/wpa_supplicant.conf
	
Add the previously generated network profile to the end of the file and

  * Press **STRG+O** to save the file and
  * **STRG+X** to close it
  
Now enter the following to make the changes happen:

	sudo wpa_cli reconfigure
  
#### Testing the configuration

Enter the following:

	ifconfig wlan0
	
If the **inet addr** field has an address beside it, the Pi should have connected to the network.

**If not:** Check the SSID and password and retry the previous wifi configuration steps.
	
https://www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md


### Security setup
#### Change ssh port

	sudo nano /etc/ssh/sshd_config
	
Change the port by commenting out the old line and adding a new one:

	#Port 22
	Port 54321
	
To login again using ssh you now have to specify the port:
	
	ssh -p 54321 privatecircle@your-ip

http://codrspace.com/audiojava/changing-ssh-port-number/
#### Firewall configuration with iptables & ufw

	sudo apt-get install ufw
	
Ensure that IPv6 support is enabled:

	sudo nano /etc/default/ufw

Set IPV6 with 'yes':

	...
	IPV6=yes
	...

Setting the default policies:

	sudo ufw default deny incoming
	sudo ufw default allow outgoing

Set the ports to allow for incoming traffic as follows:

	sudo ufw allow <portnumber>
	
Example:

	sudo ufw allow 1234
	
After the configuration of ufw you have to enbale it:

	sudo ufw enable


To check the status and rules of the firewall, enter:

	sudo ufw status verbose
	
https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-14-04
#### Configuration of unattended upgrades

	sudo apt-get install unattended-upgrades apt-listchanges

https://wiki.debian.org/UnattendedUpgrades

#### Automatic system updates with cron and cron-apt
	


#### Logging configuration

#### //TODO: delete Hardening with SELinux

#### Hardening with AppArmor

**Installation:**

	sudo apt-get install apparmor apparmor-profiles apparmor-utils auditd
	
**Enable appArmor LSM:**

	sudo perl -pi -e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX="$1 apparmor=1 security=apparmor",' /etc/default/grub
	sudo update-grub
	sudo reboot

**Inspect current state:**

**List all loaded profiles for applications and processes and their status:**

	sudo aa-status
	
**List running executables which are currently confined by an AppArmor profile:**
	
	sudo aa-unconfined

**Install more profiles:**

	sudo apt-get install apparmor-profiles apparmor-profiles-extra
	

https://wiki.debian.org/AppArmor/HowToUse
https://wiki.ubuntuusers.de/AppArmor/
https://wiki.ubuntuusers.de/AppArmor/Profile_erstellen/
#### Virus protection with ClamAV and RKHunter

**ClamAV:**

**RKHunter:**
https://wiki.ubuntuusers.de/ClamAV/


#### SSH authentication with keypairs

If you don't already have an ssh keypair on your **local** machine, you must create one with the following command:

	ssh-keygen -b 4096
	
Copy the ssh key with the following command(in a terminal on your local machine):

	ssh-copy-id server_admin_user@server_ip
	
**Disable root logins over ssh:**

Open the ssh config:

	nano /etc/ssh/sshd_config

Set the following option:

	PermitRootLogin no
	
**Disable ssh password authentication:**

Open the ssh config:

	nano /etc/ssh/sshd_config

Set the following option:

	PasswordAuthentication no

**Finish with a restart off sshd:**

	sudo systemctl restart sshd

https://www.linode.com/docs/security/securing-your-server/

#### Fail2Ban configuration

Install fail2ban:

	sudo apt-get install fail2ban

Copy fail2ban config:

	sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	
Edit config and add the following:

	ignoreip = 127.0.0.1
	bantime  = 3600
	maxretry = 3
	
	enabled = true
	port    = ssh
	filter  = sshd
	logpath  = /var/log/auth.log
	maxretry = 4
	
Restart fail2ban:

	sudo /etc/init.d/fail2ban restart
	
Enable fail2ban at startup:

	update-rc.d fail2ban enable
	

https://www.thomas-krenn.com/de/wiki/SSH_Login_unter_Debian_mit_fail2ban_absichern
https://www.linode.com/docs/security/securing-your-server/
#### Intrusion detection with ossec
//TODO: move this chapter to the end and create an useful config

https://linode.com/docs/security/ossec-ids-debian-7
https://www.linode.com/docs/security/securing-your-server/

#### remove unused network services
https://www.linode.com/docs/security/securing-your-server/


http://www.makeuseof.com/tag/securing-raspberry-pi-passwords-firewalls/

http://raspberrypi.stackexchange.com/questions/1247/what-should-be-done-to-secure-raspberry-pi

https://www.linode.com/docs/security/securing-your-server/


#### CryptSetup & Unlock via ssh
https://github.com/NicoHood/NicoHood.github.io/wiki/Raspberry-Pi-Encrypt-Root-Partition-Tutorial

https://www.thomas-krenn.com/de/wiki/Voll-verschl%C3%BCsseltes-System_via_SSH_freischalten

https://gist.github.com/meeee/46133155c4afd8bb71c6

## DynDNS setup

Register at a DynDNS provider, e.g.:

  * desec.io
  * no-ip.com
  * dedyn.io

https://jankarres.de/2012/11/raspberry-pi-dyndns-einrichten/
https://www.einplatinencomputer.com/raspberry-pi/raspberry-pi-dyndns-einrichten/
https://www.c-rieger.de/nextcloud-installation-guide/

# Webserver installation and hardening

## Hardening

### Information leakage
#### Apache version and OS identity

Open apache2.conf

	nano /etc/apache2/apache2.conf
	
Add the following:

	ServerSignature Off
	ServerTokens	 Prod

Restart apache:

	service apache2 restart
	
#### Disable directory listing

Open apache2.conf

	nano /etc/apache2/apache2.conf

Add/set the following:

	<Directory /var/www/html>
	Options -Indexes
	</Directory>

### Disable unnecessary modules

Open:

	nano /etc/httpd/conf/httpd.conf

Disable the following modules:

  * //TODO: disable more modules ???
  * mod_imap
  * mod_include
  * mod_info
  * mod_userdir
  * mod_autoindex
  
### Create apache user and group

	groupadd http-web
	useradd -d /var/www/ -g http-web -s /bin/nologin http-web
	//TODO: check and delete
	/*
	groupadd apache
	useradd –G apache apache
	chown –R apache:apache /opt/apache
	*/
	
	nano /etc/apache2/apache2.conf
	
Set the following:
	
	User http-web
	Group http-web
	
Save and exit.

Restart Apache:

	service apache2 restart
	
Verify changes:

	ps –ef |grep http
	
-> apache process should show the apache user

### Restrict access to directories

Open apache configuration file:
	
	nano /etc/apache2/apache2.conf

Set the following:

	<Directory />
	Options None
	Order deny,allow
	Deny from all
	</Directory>

### Use mod_security and mod_evasive Modules

Install mod_security:
	
	sudo apt-get install libapache2-modsecurity
	sudo a2enmod mod-security
	sudo /etc/init.d/apache2 force-reload
	
//TODO: install mod_evasive


### Disable following of Symbolic Links
  
 	nano /etc/apache2/apache2.conf
 
 Set the following:
 
 	Options -FollowSymLinks
 
### Turn off Server Side Includes and CGI Execution

 	nano /etc/apache2/apache2.conf
 
 Set the following:

	Options -Includes
	Options -ExecCGI


### Protect DDOS attacks and Hardening

Lower the following values:

	LimitRequestFields
	LimitRequestFieldSize
	

### Enable Apache Logging
//TODO: is this needed or compromising privacy? delete?

### Securing Apache with SSL Certificates and LetsEncrypt



http://www.tecmint.com/apache-security-tips/
https://geekflare.com/apache-web-server-hardening-security/
http://www.tecmint.com/protect-apache-using-mod_security-and-mod_evasive-on-rhel-centos-fedora/

# MariaDB installation & hardening
//TODO: secure MariaDB (anon users, no password etc)

## Install MariaDB

	apt-get install software-properties-common
	apt-get install python-software-properties
	apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
	add-apt-repository 'deb http://mariadb.biz.net.id//repo/10.1/debian sid main'

Update package list:

	apt-get update

Install MariaDB:

	apt-get install mariadb-server mariadb-client

## MariaDB configuration and hardening

Configuration:

	sudo mysql_install_db

Hardening:

	sudo mysql_secure_installation
	
Edit My.cnf:

	sudo nano /etc/mysql/my.cnf

Set the following values:

	bind-address = 127.0.0.1
	local-infile=0
	log=/var/log/mysql-logfile

Check log file permissions:
The log should not be world readable!

	sudo ls -l /var/log/mysql*
	
Log into MariaDB:

	mysql -u root -p

Delete users without passwords:

List users:

	SELECT User,Host,Password FROM mysql.user;

Change users with host %:

	UPDATE mysql.user SET Host='localhost' WHERE User="demo-user";

Delete users without name or password:

	DELETE FROM mysql.user WHERE User="" OR Password="";
	
Change root user:

	rename user 'root'@'localhost' to 'newAdminUser'@'localhost';

After the changes enter the following to apply changes:

	FLUSH PRIVILEGES;

## Create databases and users for applications

Create nextcloud database:

	create database nextcloud;
	
Create nextcloud user and grant access:

	CREATE USER 'nextcloud-user'@'localhost' IDENTIFIED BY 'password';
	//TODO: GRANT SELECT,UPDATE,DELETE ON nextcloud.* TO 'nextcloud-user'@'localhost';
	//GRANT ALL ON nextcloud.* TO 'nextcloud-user'@'localhost';

Check privileges:

	FLUSH PRIVILEGES;
	show grants for 'nextcloud-user'@'localhost';

//TODO: finished with security??


https://www.digitalocean.com/community/tutorials/how-to-secure-mysql-and-mariadb-databases-in-a-linux-vps
https://mariadb.com/kb/en/mariadb/securing-mariadb/
http://www.tecmint.com/install-mariadb-in-debian/
# Install Mailserver

## Filter to only allow PGP encrypted mails

# Install nextcloud

## Install dependencies

	sudo apt update
	sudo apt full-upgrade
	sudo apt install apache2 mariadb-server php5 libapache2-mod-php5 php5-gd php5-json php5-mysql php5-curl php5-intl php5-mcrypt php5-imagick
	sudo a2enmod rewrite
	sudo a2enmod headers
	sudo service apache2 restart
	

## Create MariaDB database

	mysql -u root -p
	CREATE DATABASE nextcloud;
	CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'superstrongpassword';
	GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost';
	FLUSH PRIVILEGES;
	exit;


## Download nextcloud
Please check if a newer version is available before downloading!

	wget https://download.nextcloud.com/server/releases/nextcloud-11.0.0.tar.bz2
	sudo tar xf nextcloud*.bz2 -C /var/www
	sudo chown -R www-data.www-data /var/www/nextcloud

## Updating Apache Virtual Hosts

	sudo nano /etc/apache2/sites-available/nextcloud.conf

Insert the following:
	
	Alias /nextcloud "/var/www/nextcloud/"
	<Directory /var/www/nextcloud/>
  		Options +FollowSymlinks
  		AllowOverride All
 		<IfModule mod_dav.c>
  			Dav off
 		</IfModule>
 		SetEnv HOME /var/www/nextcloud
 		SetEnv HTTP_HOME /var/www/nextcloud
	</Directory>
---

	sudo a2ensite nextcloud
	sudo service apache2 reload

## Nextcloud installation
Open 

	raspberrypi.local/nextcloud

and follow the instructions.

After clicking the finish button it may take a few minutes for the installation process.

## Activating Memcache
	sudo apt install php5-apcu
	sudo nano /var/www/nextcloud/config/config.php
	
add the following
	
	'memcache.local' => '\OC\Memcache\APCu',

You might have to restart your pi.

## Hardening

https://www.c-rieger.de/nextcloud-installation-guide/

## Adding NextCloud Apps
#### Encryption at rest
#### JSXC
#### Roundcube

## Installing XMPP: Prosody

	apt-get install prosody
	
## Configuration

Open the configuration file:

	sudo nano /etc/prosody/prosody.cfg.lua

Set the domain to use:

	VirtualHost "example.org"
	
Disable registration:

	allow_registration = false
	
In modules_enabled, delete the following:

	"register";
	
Set the authentication to:

	authentication = "internal_hashed"

Set Client2Server and Server2Server encryption:

	c2s_require_encryption = true
	s2s_require_encryption = true

### Hardening

**Client limits:**

Add/change the following:

	limits = {
	  c2s = {
	    rate = "3kb/s";
	    burst = "2s";
	};


### TLS setup

//TODO:

### Log and data path settings

https://prosody.im/doc/configure

### BOSH server setup
Setup the BOSH server by adding the following to modules_enabled:

	"bosh";
	
Edit the configuration by adding the following:

	cross_domain_bosh = {"https://example.org"}
	bosh_ports = 
	{
		 {
		    port = 5280;
		    path = "http-bind";
		 },
		 {
		    port = 5281;
		    path = "http-bind";
		    ssl = {
			     key = "bosh.key";
			     certificate = "bosh.crt"; 
			  }
		 }
      }


### Setup MUC

add/change the following in **/etc/prosody/prosody.cfg.lua**:

	Component "conference.{{ prosody_vhost }}" "muc"
		 restrict_room_creation = "local"
	max_history_messages = 100

https://prosody.im/doc/modules/mod_muc

### Admin user setup

Create an admin account by editing the following account:

	admins = { prosody-admin@example.org }

You also have to create the user for the admin account:

	prosodyctl adduser prosody-admin@example.com





## User management

A list of commands for prosodyctl can be found under the following URL:

https://prosody.im/doc/prosodyctl





	
//TODO: review...
https://wiki.debian.org/InstallingProsody
https://github.com/systemli/ansible-role-prosody

## Installing IRC: 

http://www.admin-magazin.de/Das-Heft/2012/04/Eigenen-IRC-Server-fuer-das-Unternehmen-aufsetzen

## Installing IRC-Web-Client

## Installing IRC Hidden Service

## Installing Mumble-Server

## Installing MarvinIRC

## Installing Private PGP server (Mailvelope)



# Maintenance
## Encrypted Backups to USB-Stick

## Backup of encryption key using SSS
//TODO: c program...

# Credits


# TODOS
## apache hardening subchapters
### Disable ETAG
//TODO: geekflare

### Limit Request Size
//TODO: delete. not compatible with nextcloud?

 	nano /etc/apache2/apache2.conf
 
 Set the following:
 
	<Directory "/var/www/myweb1/user_uploads">
	LimitRequestBody 512000
	</Directory>
	
### Protect binary and configuration directory permission
//TODO: geekflare

### Clickjacking Attack
//TODO: geekflare

### XSS Protection
//TODO: geekf

### Disable HTTP 1.0 Protocol
//TODO: geekf

### Enable Rule Engine
//TODO: geekf
