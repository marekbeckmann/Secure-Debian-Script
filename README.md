

How to use
The Source Code is available on GitHub, if you want to contribute, create an issue, etc. you can do it there.

This script is intended to run on a freshly installed Debian Linux! Otherwise, it may overwrite existing configurations 

#1. Download
Via Github

git clone https://github.com/mlhbeckmann/automatedlinuxsecurity.git --branch release --single-branch
Via Official Server

curl https://download.bektroid-studios.de/software/scripts/linuxsecurity-currentrelease.zip -o ~/

#2. Running the script
If you downloaded the script via git, change into the automatedlinuxsecurity directory. If you downloaded the script via my official server, you have to unzip the archive and then change into the new directory. Now change the permissions on the script

sudo chmod +x deploySecurity.sh
You have the following options, running the script: 

-h	Quick help
-u	User, that gets added to SSH allowed users. Without the option, every user can connect
-p	Stricter firewall rules, meaning outgoing traffic is blocked. Otherwise outgoing traffic is allowed
So if you want the user user1 to be able to connect via SSH and strict firewall rules, you have to run

./deploySecurity.sh -u user1 -p
After the script ended, if will give you a summary of the installation, along with a log file, which is located in /tmp/securityAutomationScript/automatedsecurityscript-date.log

#3. After the Script
After the script you still have to do two things: 

Create Google 2FA token
Restart your system
To do the first, run

google-authenticator -t -d -f -r 3 -R 30 -W
If you want to answer the questions interactively, run google-authenticator without any options. Because some changes were made to the sysctl.conf, aswell as limits.conf, you have to reboot your system. Before you do that, you should make sure, that you can connect via SSH, to prevent locking yourself out of the system.

 

 

 

Revision #8
Created Thu, Mar 4, 2021 2:45 PM by Marek Beckmann
Updated Sun, Apr 25, 2021 5:40 PM by Marek Beckmann
