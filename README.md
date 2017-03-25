# Warning: Work in progress

# Private Circle


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

#### Hardening with SELinux

#### Virus protection

#### Creating limited user accounts
https://www.linode.com/docs/security/securing-your-server/
#### SSH authentication with keypairs
https://www.linode.com/docs/security/securing-your-server/

#### Fail2Ban configuration
https://www.linode.com/docs/security/securing-your-server/
#### Intrusion detection
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



# Webserver isntallation and hardening

## Hardening
http://www.tecmint.com/apache-security-tips/
https://geekflare.com/apache-web-server-hardening-security/

# Install nextcloud

## Install dependencies

	sudo apt update
	sudo apt full-upgrade
	sudo apt install apache2 mariadb-server php5 libapache2-mod-php5 php5-gd php5-json php5-mysql php5-curl php5-intl php5-mcrypt php5-imagick
	sudo a2enmod rewrite
	sudo a2enmod headers
	sudo service apache2 restart
	
//TODO: secure apache

## Create MariaDB database

	mysql -u root -p
	CREATE DATABASE nextcloud;
	CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'superstrongpassword';
	GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost';
	FLUSH PRIVILEGES;
	exit;

//TODO: secure MariaDB (anon users, no password etc)

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


## Adding NextCloud Apps
#### Encryption at rest
#### JSXC
#### Roundcube

## Installing XMPP: Prosody

	apt-get install prosody
	
https://wiki.debian.org/InstallingProsody

## Installing IRC: 

## Installing IRC-Web-Client

## Installing IRC Hidden Service

## Installing Mumble-Server

## Installing MarvinIRC

## Installing Private PGP server (Mailvelope)



# Maintenance
## Encrypted Backups

## Backup of encryption key using SSS
//TODO: c program...

# Credits

