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
    cp -pr --archive "$1" "$1"-COPY-"$(date +"%m-%d-%Y")"
}

function logToScreen() {
    clear
    if [[ "$2" = "--success" ]]; then
        printf '%s\n' "$(tput setaf 2)$1 $(tput sgr 0)"
    elif [[ "$2" = "--error" ]]; then
        printf '%s\n' "$(tput setaf 1)$1 $(tput sgr 0)"
        exit 1
    else
        printf '%s\n' "$(tput setaf 3)$1 $(tput sgr 0)"
    fi
    sleep 1
}

function installPackages() {
    logToScreen "Installing Packages..."
    apt-get -y update
    apt-get -y full-upgrade
    apt-get -y install libpam-google-authenticator ufw aide fail2ban clamav clamav-freshclam clamav-daemon chkrootkit libpam-pwquality curl unattended-upgrades apt-listchanges apticron debsums apt-show-versions
    logToScreen "Backing up configuration files..."
    backupConfigs "/etc/fstab"
    backupConfigs "/etc/pam.d/common-password"
    backupConfigs "/etc/pam.d/sshd"
    backupConfigs "/etc/clamav/freshclam.conf"
    backupConfigs "/etc/clamav/clamd.conf"
    backupConfigs "/etc/chkrootkit.conf"
    backupConfigs "/etc/ssh/sshd_config"
    backupConfigs "/etc/default/aide"
    backupConfigs "/etc/aide"
}

function secure_ssh() {
    logToScreen "Securing SSH..."
    if [[ -z "$sshPort" ]]; then
        sshPort=$(shuf -i 28000-40000 -n 1)
    fi
    getIni "START_SSHD" "END_SSHD"
    printf "%s" "$output" | tee /etc/ssh/sshd_config
    sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config

    if [[ -n "$sshUser" ]]; then
        IFS=',' read -ra ADDR <<<"$sshUser"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowUsers/ s/$/ ${i}/" /etc/ssh/sshd_config
        done
    else
        sed -i "s/AllowUsers yourUser/#AllowUsers yourUser/g" /etc/ssh/sshd_config
    fi
    if [[ -n "$sshGroup" ]]; then
        echo "
AllowGroups" | tee -a /etc/ssh/sshd_config
        IFS=',' read -ra ADDR <<<"$sshGroup"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowGroups/ s/$/ ${i}/" /etc/ssh/sshd_config
        done
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
    sed -i '/#CRON_DAILY_RUN=yes/s/#//g' /etc/default/aide
    getIni "START_COREDUMP" "END_COREDUMP"
    printf "%s" "$output" | tee -a /etc/security/limits.conf
    echo 'fs.suid_dumpable = 0' >>/etc/sysctl.conf
    sysctl -p
    chmod -R 0700 /home/*
    chmod 0644 /etc/passwd
    chmod 0644 /etc/group
    chmod -R 0600 /etc/cron.hourly
    chmod -R 0600 /etc/cron.daily
    chmod -R 0600 /etc/cron.weekly
    chmod -R 0600 /etc/cron.monthly
    chmod -R 0600 /etc/cron.d
    chmod -R 0600 /etc/crontab
    chmod -R 0600 /etc/shadow
    chmod -R 0440 /etc/sudoers.d/*
    chmod 0600 /etc/ssh/sshd_config
    if [[ "$lockRoot" = true ]]; then
        passwd -d root
        passwd -l root
        sed -i '/^root:/s/\/bin\/bash/\/usr\/sbin\/nologin/g' /etc/passwd
    fi
    logToScreen "Initializing AIDE..."
    aideinit -y -f

}

function secure_firewall() {
    logToScreen "Hardening Firewall..."
    ufw logging full
    ufw default deny incoming
    if [[ "$strictFw" = true ]]; then
        ufw default deny outgoing
        ufw allow out 123/udp
        ufw allow out dns
        ufw allow out http
        ufw allow out https
        ufw allow out ftp
    else
        ufw default allow outgoing
    fi
    ufw allow in "${sshPort}"/tcp
    if [[ -n "$fwPort" ]]; then
        IFS=',' read -ra ADDR <<<"$fwPort"
        for i in "${ADDR[@]}"; do
            ufw allow in "$i"
        done
    fi
    if [[ -z "$enableFirewall" ]]; then
        ufw --force enable
    fi
}

function secure_fail2ban() {
    getIni "START_F2B_SSH" "END_F2B_SSH"
    printf "%s" "$output" | tee -a /etc/fail2ban/jail.d/ssh.local
    rm -f /etc/fail2ban/jail.d/defaults-debian.conf
    fail2ban-client start
    fail2ban-client reload
    fail2ban-client add sshd
}

function secure_updates() {
    logToScreen "Setting up unattended upgrades..."
    getIni "START_UNATTENDED_UPGRADES" "END_UNATTENDED_UPGRADES"
    printf "%s" "$output" | tee /etc/apt/apt.conf.d/51custom-unattended-upgrades
}

function script_summary() {
    apt -y autoremove
    systemctl restart sshd.service
    systemctl restart fail2ban.service
    ufw reload
    summary="
    Summary: 
        SSH-Port: ${sshPort} 
        Allowed SSH Users: ${sshUser}
        Allowed SSH Group: ${sshGroup}
        Run the following commands to conclude setup: 
            google-authenticator -t -d -f -r 3 -R 30 -W 
             
    The Script has finished! To apply all changes, you have to reboot your system 
    Before rebooting, check, that all configurations are correct and that you can connect via SSH. Otherwise, you might lock yourself out of your system 
    Thank you for using my script."
    logToScreen "$summary"
}

function get_Params() {
    while test $# -gt 0; do
        case "$1" in
        -h | --help)
            helpMsg
            ;;
        -u | --allow-sshuser)
            sshUser="$2"
            ;;
        -g | --allow-sshgroup)
            sshGroup="$2"
            ;;
        -p | --ssh-port)
            sshPort="$2"
            ;;
        -l | --lock-root)
            lockRoot=true
            ;;
        -n | --no-firewall)
            enableFirewall=false
            ;;
        -a | --allow-port)
            fwPort="$2"
            ;;
        -s | --strict-firewall)
            strictFw=true
            ;;
        --*)
            logToScreen "Unknown option $1" --error
            helpMsg
            exit 1
            ;;
        -*)
            logToScreen "Unknown option $1" --error
            helpMsg
            exit 1
            ;;
        esac
        shift
    done
}

function script_init() {
    get_Params "$@"
    if [ "$(whoami)" = "root" ]; then
        installPackages
        secure_system
        secure_ssh
        secure_firewall
        secure_fail2ban
        secure_updates
        script_summary
    else
        echo "You need root prvileges to run this script!"
    fi
}

script_init "$@"
