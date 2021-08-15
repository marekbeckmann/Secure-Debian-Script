#!/bin/bash

function logScript() {
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3
    exec 1>/tmp/secure-debian-script.log 2>&1

}

function getIni() {
    startsection="$1"
    endsection="$2"
    output="$(awk "/$startsection/{ f = 1; next } /$endsection/{ f = 0 } f" configs)"
}

function backupConfigs() {
    cp --archive "$1" "$1"-COPY-"$(date +"%m-%d-%Y")"
}

function logToScreen() {
    clear
    echo "$(tput setaf 2)$1$(tput sgr 0)"
    sleep 1
}

function installPackages() {
    logToScreen "Installing Packages..."
    apt -y update
    apt -y full-upgrade
    apt -y install libpam-google-authenticator ufw fail2ban clamav clamav-freshclam clamav-daemon chkrootkit libpam-pwquality curl unattended-upgrades apt-listchanges apticron debsums apt-show-versions
    logToScreen "Backing up configuration files..."
    backupConfigs "/etc/fstab"
    backupConfigs "/etc/pam.d/common-password"
    backupConfigs "/etc/pam.d/sshd"
    backupConfigs "/etc/clamav/freshclam.conf"
    backupConfigs "/etc/clamav/clamd.conf"
    backupConfigs "/etc/chkrootkit.conf"
    backupConfigs "/etc/ssh/sshd_config"
}

function secure_ssh() {
    logToScreen "Securing SSH..."
    sshuser="$1"
    sshPort=$(shuf -i 28000-40000 -n 1)
    getIni "START_SSHD" "END_SSHD"
    printf "%s" "$output" | tee /etc/ssh/sshd_config
    sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config
    if [[ $sshuser != "" ]]; then
        sed -i "s/yourUser/${sshuser}/g" /etc/ssh/sshd_config
    else
        sed -i "s/AllowUsers yourUser/#AllowUsers yourUser/g" /etc/ssh/sshd_config
    fi
    getIni "START_PAM_SSHD" "END_PAM_SSHD"
    printf "%s" "$output" | tee -a /etc/pam.d/sshd
    systemctl restart sshd.service
    getIni "START_DEFBANNER" "END_DEFBANNER"
    printf "%s" "$output" | tee /etc/ssh/banner /etc/issue /etc/issue.net
}

function secure_system() {
    logToScreen "Securing System..."
    echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab
    sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/100000/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/100000/g' /etc/login.defs

    sed -i '/PASS_MAX_DAYS/s/99999/180/g' /etc/login.defs
    sed -i '/PASS_WARN_AGE/s/7/28/g' /etc/login.defs
    sed -i '/UMASK/s/022/027/g' /etc/login.defs

    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs

    getIni "START_COREDUMP" "END_COREDUMP"
    printf "%s" "$output" | tee -a /etc/security/limits.conf
    echo 'fs.suid_dumpable = 0' >>/etc/sysctl.conf
    sysctl -p
    chmod -R 0700 /home/
}

function secure_firewall() {
    logToScreen "Hardening Firewall..."
    ufw logging full
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow in "${sshPort}"/tcp
    ufw --force enable
}

function secure_fail2ban() {
    getIni "START_F2B_SSH" "END_F2B_SSH"
    printf "%s" "$output" | tee -a /etc/fail2ban/jail.d/ssh.local
    rm -f /etc/fail2ban/jail.d/defaults-debian.conf
    fail2ban-client start
    fail2ban-client reload
    fail2ban-client add sshd
}

function secure_updates(){
    logToScreen "Setting up unattended upgrades..."
    getIni "START_UNATTENDED_UPGRADES" "END_UNATTENDED_UPGRADES"
    printf "%s" "$output" | tee /etc/apt/apt.conf.d/51custom-unattended-upgrades
}

function script_summary() {
    apt -y autoremove
    systemctl restart sshd.service
    systemctl restart fail2ban.service
    ufw reload
    clear
    summary="
    Summary: 
        SSH-Port: ${sshPort} 
        Run the following commands to conclude setup: 
            google-authenticator -t -d -f -r 3 -R 30 -W 
            sudo ufw enable #Establish a new SSH Connection before enabling UFW 
    The Script has finished! To apply all changes, you have to reboot your system 
    Before rebooting, check, that all configurations are correct and that you can connect via SSH. Otherwise, you might lock yourself out of your system 
    Thank you for using my script."
    echo "$summary"
}
function script_init() {
    if [ "$(whoami)" = "root" ]; then
        if [[ $1 = "-h" ]]; then
            getIni "START_HELP" "END_HELP"
            printf "%s" "$output"
        else
            read -rp "Enter User allowed for SSH: " sshuser
            #logScript
            installPackages
            secure_system
            secure_ssh "$sshuser"
            secure_firewall
            secure_fail2ban
            secure_updates
            script_summary
        fi

    else
        echo "You need root prvileges to run this script!"
    fi
}

script_init "$1"
