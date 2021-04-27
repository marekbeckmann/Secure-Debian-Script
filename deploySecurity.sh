#!/bin/bash
userPrivileges=$(whoami)
if [ "$userPrivileges" = "root" ]; then
    if [[ $1 = "-h" ]]; then
        clear
        printf '
This Script will install and configure some security options on your server! \n
These Changes will be made: \n
\t -Secure SSHD Configuration \n
\t -Google 2-Factor Authentication \n
\t -Password Policy \n
\t -UFW Firewall \n
\t -Freshclam Anti-Virus \n
\t -PSAD Intrusion Prevention \n
\t -Fail2Ban Intrusion Detection \n
\t -Chrootkit Detection \n
\t -Secure PROC \n
You may want to use the following options, when running this Script: \n
\t -u <userName> To add an allowed user to ssh config \n
\t -p to harden the firewall
This Script was created by Marek Beckmann and is documented on https://docs.marekbeckmann.de/books/automated-security-script \n
'
    else
        apt -y update
        apt -y install libpam-google-authenticator ufw fail2ban psad clamav clamav-freshclam clamav-daemon chkrootkit libpam-pwquality curl
        cp --archive /etc/fstab /etc/fstab-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/pam.d/common-password /etc/pam.d/common-password-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/pam.d/sshd /etc/pam.d/sshd-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/psad/psad.conf /etc/psad/psad.conf-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/clamav/freshclam.conf /etc/clamav/freshclam.conf-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/clamav/clamd.conf /etc/clamav/clamd.conf-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/chkrootkit.conf /etc/chkrootkit.conf-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/ssh/sshd_config /etc/ssh/sshd_config-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        mkdir -p /tmp/securityAutomationScript
        cp -v assets/sshd_config /etc/ssh/sshd_config
        sshPort=$(shuf -i 28000-40000 -n 1)
        sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config
        if [[ $1 = "-u" ]]; then
            sed -i "s/yourUser/${2}/g" /etc/ssh/sshd_config
        else
            sed -i "s/AllowUsers yourUser/#AllowUsers yourUser/g" /etc/ssh/sshd_config
        fi
        tee -a /etc/pam.d/sshd >/dev/null <<EOT
auth required pam_unix.so try_first_pass
auth required pam_google_authenticator.so echo_verification_code
EOT
        echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab
        sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
        sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/100000/g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/100000/g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
        sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs
        tee -a /etc/security/limits.conf >/dev/null <<EOT
* hard core 0
* soft core 0
EOT
        echo 'fs.suid_dumpable = 0' >>/etc/sysctl.conf
        sysctl -p
        tee /etc/ssh/banner /etc/issue /etc/issue.net >/dev/null <<EOT
********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOT

        systemctl restart sshd.service
        ufw default deny incoming
        if [[ $1 = -u ]]; then
            if [[ $3 = "-p" ]] || [[ $1 = "-p" ]]; then
                ufw default deny outgoing
                ufw allow out 53
                ufw allow out 123
                ufw allow out http
                ufw allow out https
                ufw allow out ftp
                ufw allow out 67
                ufw allow out 68
            else
                ufw default allow outgoing
            fi

        fi
        ufw allow in "${sshPort}"
        ufw logging Full
        mhostname="$(hostname)"
        sed -i "s/_CHANGEME_/${mhostname}/g" /etc/psad/psad.conf
        sed -i "/^ENABLE_PSADWATCHD/d" /etc/psad/psad.conf
        sed -i "/^ENABLE_AUTO_IDS/d" /etc/psad/psad.conf
        sed -i "/^ENABLE_AUTO_IDS_EMAILS/d" /etc/psad/psad.conf
        sed -i "/^ENABLE_AUTO_IDS_REGEX/d" /etc/psad/psad.conf
        printf 'ENABLE_PSADWATCHD Y;\nENABLE_AUTO_IDS Y;\nENABLE_AUTO_IDS_EMAILS Y;\nENABLE_AUTO_IDS_REGEX Y;' | tee -a /etc/psad/psad.conf
        cp --archive /etc/ufw/before.rules /etc/ufw/before.rules-COPY-"$(date +"%Y%m%d%H%M%S")"
        cp --archive /etc/ufw/before6.rules /etc/ufw/before6.rules-COPY-"$(date +"%Y%m%d%H%M%S")"
        sed -i '/COMMIT/d' /etc/ufw/before.rules
        sed -i '/COMMIT/d' /etc/ufw/before6.rules
        tee -a /etc/ufw/before.rules /etc/ufw/before6.rules >/dev/null <<EOT
-A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
COMMIT
EOT
        ufw reload
        psad -R
        psad --sig-update
        psad -H
        tee -a /etc/fail2ban/jail.d/ssh.local >/dev/null <<EOT
[sshd]
enabled = true
banaction = ufw
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 5
EOT
        fail2ban-client start
        fail2ban-client reload
        fail2ban-client add sshd
        clear

        __summary="
Summary: 
SSH-Port: ${sshPort} 
Run the following commands to conclude setup: 

    google-authenticator -t -d -f -r 3 -R 30 -W 
    sudo ufw enable 

The Script has finished! To apply all changes, you have to reboot your system 
Before rebooting, check, that all configurations are correct and that you can connect via SSH. Otherwise, you might lock yourself out of your system 
Thank you for using my script.
"
echo "$__summary"
    fi

else
    echo "You must be root user to run this script!"
fi
