# What does this script do

## This script will install the following programs:

  * Google 2-FA authentication
  * UFW Firewall
  * Fail2Ban Intrusion Detection
  * Various System Settings
  * Clamav Anti-Virus
  * Chrootkint Chrootkit Detection
  * Password Quality
  * Unattended Upgrades
  * Debsums
  * AIDE File system integrity

## This Script will configure the following settings/configurations

  * Secure PROC in `/etc/fstab`
  * Configure password quality in `/etc/pam.d/common-password`
  * Configure fail2ban and add fail2ban jail in `/etc/fail2ban/jail.d/ssh.local`
  * Configure SSH config in `/etc/ssh/sshd_config`
  * Configure SSHD Pam in `/etc/pam.d/sshd`
  * Configure Password hashing rounds in `/etc/login.defs`
  * Configure Core Dump in `/etc/security/limits.conf` and `/etc/sysctl.conf`
  * Add disclaimers to `/etc/ssh/banner`, `/etc/issue` and `/etc/issue.net`
  * Configure Unattended Upgrades in `/etc/apt/apt.conf.d/51custom-unattended-upgrades`

# How to use

The Source Code is available on GitHub, if you want to contribute, create an issue, etc. you can do it there.

This script is intended to run on a freshly installed Debian Linux! Otherwise, it may overwrite existing configurations

## 1. Download

```
git clone https://github.com/marekbeckmann/Secure-Debian-Script.git ~/Secure-Debian
cd ~/Secure-Debian && chmod +x secure-debian.sh
``` 

## 2. Running the script

You have the following options, running the script:

| Option | Description |
|--|--|
| `-h` `--help` | Prints help message, that shows all options and a short description |
| `-u` `--allow-sshuser` `<user1,user2>` | Specifies user(s) that are allowed to login via SSH [default=all] |
| `-g` `--allow-sshgroup` `<group1,group2>` | Specifies group(s) that are allowed to login via SSH [default=all] |
| `-p` `--ssh-port` `<port>` | Sets the port SSH listens on. If not specified, random port is used |
| `-l` `--lock-root` | Disables the root account |
| `-n` `--no-firewall` | Doesn't activate firewall, but rules are generated |
| `-a` `--allow-port` `<portX,portY/proto>` | Specifies port(s) allowed for incoming traffic (you can specify a protocol) |
| `-s` `--strict-firewall` | Denies outgoing traffic, except for nescessary protocols |
| `-c` `--config` `<filepath>` | Specifies path for the configuration file [defaults to ./configs] |

Example: 
```
sudo bash secure-debian.sh -u user1,user2 -g ssh -l -a 80,443
```

After the script ended, it will give you a summary of the installation

## 3. After the Script

After the script, you still have to do two things:

* Create Google 2FA token

* Restart your system

To do the first, run
```
google-authenticator -t -d -f -r 3 -R 30 -W
```
If you want to answer the questions interactively, run google-authenticator without any options. Because some changes were made to the sysctl.conf, aswell as limits.conf, you have to reboot your system. Before you do that, you should make sure, that you can connect via SSH, to prevent locking yourself out of the system.

## 3. Compatibility

This Script was tested on freshly installed Debian 10 and Debian 11 systems repeatedly and should work without any problem. Nevertheless, make sure to leave a root session open, before running the script, just in case.
