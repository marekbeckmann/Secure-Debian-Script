#!/bin/bash

function_packages() {

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

}

function_logging() {

    mkdir -p /tmp/securityAutomationScript

}

function_sshconfig() {

    cat assets/default_sshd_config | tee /etc/ssh/sshd_config
    sshPort=$(shuf -i 28000-40000 -n 1)
    sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config
    if [[ $1 = "-u" ]]; then
        sed -i "s/yourUser/${2}/g" /etc/ssh/sshd_config
    else
        sed -i "s/AllowUsers yourUser/#AllowUsers yourUser/g" /etc/ssh/sshd_config
    fi
    cat assets/default_pam_sshd | tee -a /etc/pam.d/sshd
    systemctl restart sshd.service
    cat assets/default_banner | tee /etc/ssh/banner /etc/issue /etc/issue.net

}

function_systemhardening() {

    echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab
    sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/100000/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/100000/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs
    cat assets/default_coredump | tee -a /etc/security/limits.conf
    echo 'fs.suid_dumpable = 0' >>/etc/sysctl.conf
    sysctl -p

}

function_ufwrules() {
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
    cat assets/default_psad | tee -a /etc/psad/psad.conf
    cp --archive /etc/ufw/before.rules /etc/ufw/before.rules-COPY-"$(date +"%Y%m%d%H%M%S")"
    cp --archive /etc/ufw/before6.rules /etc/ufw/before6.rules-COPY-"$(date +"%Y%m%d%H%M%S")"
    sed -i '/COMMIT/d' /etc/ufw/before.rules
    sed -i '/COMMIT/d' /etc/ufw/before6.rules
    cat assets/default_iptable | tee -a /etc/ufw/before.rules /etc/ufw/before6.rules
    ufw reload
    psad -R
    psad --sig-update
    psad -H

}

function_fail2ban() {

    cat assets/default_fail2ban_ssh_jail | tee -a /etc/fail2ban/jail.d/ssh.local
    fail2ban-client start
    fail2ban-client reload
    fail2ban-client add sshd

}

function_summary() {
    clear
    summary="
        Summary: 
        SSH-Port: ${sshPort} 
        Run the following commands to conclude setup: 

            google-authenticator -t -d -f -r 3 -R 30 -W 
            sudo ufw enable 

        The Script has finished! To apply all changes, you have to reboot your system 
        Before rebooting, check, that all configurations are correct and that you can connect via SSH. Otherwise, you might lock yourself out of your system 
        Thank you for using my script."
    echo "$summary"
}

function_init() {
    if [ "$(whoami)" = "root" ]; then
        if [[ $1 = "-h" ]]; then

            clear
            cat assets/default_help

        else

            function_logging
            function_packages
            function_sshconfig "$1" "$2" "$3"
            function_systemhardening
            function_ufwrules "$1" "$2" "$3"
            function_fail2ban
            function_summary
        fi

    else
        echo "You need root prvileges to run this script!"
    fi
}

function_init "$1" "$2" "$3"
