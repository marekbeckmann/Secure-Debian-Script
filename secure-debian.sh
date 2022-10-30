#!/bin/bash

shopt -s inherit_errexit nullglob
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="-"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

function getIni() {
    startsection="$1"
    endsection="$2"
    output="$(awk "/$startsection/{ f = 1; next } /$endsection/{ f = 0 } f" "${configFile}")"
}

function backupConfigs() {
    cp -pr --archive "$1" "$1"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
}

function msg_info() {
    local msg="$1"
    echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
    local msg="$1"
    echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function installPackages() {
    msg_info "Updating system"
    apt-get -y update >/dev/null 2>&1
    apt-get -y full-upgrade >/dev/null 2>&1
    apt-get -y install apt-transport-https ca-certificates host gnupg lsb-release >/dev/null 2>&1
    msg_ok "System updated successfully"
    if [[ -n "$auditSystem" ]]; then
        msg_info "Installing Lynis"
        wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key >/dev/null 2>&1 | apt-key add - >/dev/null 2>&1
        echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | tee /etc/apt/sources.list.d/cisofy-lynis.list >/dev/null 2>&1
        apt-get -y update >/dev/null 2>&1
        apt-get -y install lynis host >/dev/null 2>&1
        msg_ok "Lynis installed successfully"
        msg_info "Updating Lynis database"
        lynis update info >/dev/null 2>&1
        msg_ok "Lynis database updated successfully"
        msg_info "Running Lynis audit for base score (this can take a while)"
        lynis audit system --quiet --report-file /tmp/systemaudit-base-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
        base_score="$(grep hardening_index /tmp/systemaudit-base-"$(date +"%m-%d-%Y")" | cut -d"=" -f2)" >/dev/null 2>&1
        msg_ok "Lynis audit completed with a Score of ${base_score}"
    fi

    msg_info "Installing required packages"
    apt-get -y install libpam-google-authenticator ufw fail2ban chkrootkit libpam-pwquality curl unattended-upgrades apt-listchanges apticron debsums apt-show-versions dos2unix rng-tools apt-listbugs needrestart debsecan >/dev/null 2>&1
    msg_ok "Packages installed successfully"

    if [[ -n "$withAide" ]]; then
        msg_info "Installing AIDE"
        apt-get -y install aide aide-common >/dev/null 2>&1
        msg_info "AIDE installed successfully"
        msg_info "Backing up AIDE configuration files"
        backupConfigs "/etc/aide"
        backupConfigs "/etc/default/aide"
        msg_ok "AIDE configuration files backed up successfully"
        msg_info "Configuring AIDE (this can take a while)"
        sed -i '/#CRON_DAILY_RUN=yes/s/#//g' /etc/default/aide >/dev/null 2>&1
        aideinit -y -f >/dev/null 2>&1
        msg_ok "AIDE configured successfully"
    fi

    if [[ -n "$withClamav" ]]; then
        msg_info "Installing Clamav"
        apt-get -y clamav clamav-freshclam clamav-daemon >/dev/null 2>&1
        msg_ok "Clamav installed successfully"
        msg_info "Backing up Clamav configuration files"
        backupConfigs "/etc/clamav/freshclam.conf"
        backupConfigs "/etc/clamav/clamd.conf"
        msg_ok "Clamav configuration files backed up successfully"
    fi
    msg_info "Backing up configuration files"
    backupConfigs "/etc/fstab"
    backupConfigs "/etc/pam.d/common-password"
    backupConfigs "/etc/pam.d/sshd"
    backupConfigs "/etc/chkrootkit.conf"
    backupConfigs "/etc/ssh/sshd_config"
    msg_ok "Configuration files backed up successfully"
}

function secure_ssh() {
    msg_info "Securing SSH"
    if [[ -z "$sshPort" ]]; then
        sshPort=$(shuf -i 28000-40000 -n 1)
    fi
    getIni "START_SSHD" "END_SSHD"
    printf "%s" "$output" | tee /etc/ssh/sshd_config >/dev/null 2>&1
    dos2unix /etc/ssh/sshd_config >/dev/null 2>&1
    sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config

    if [[ -n "$sshUser" ]]; then
        IFS=',' read -ra ADDR <<<"$sshUser"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowUsers/ s/$/ ${i}/" /etc/ssh/sshd_config
        done
    else
        sed -i "s/AllowUsers/#AllowUsers yourUser/g" /etc/ssh/sshd_config
    fi

    if [[ -n "$sshGroup" ]]; then
        IFS=',' read -ra ADDR <<<"$sshGroup"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowGroups/ s/$/ ${i}/" /etc/ssh/sshd_config
        done
    else
        sed -i "s/AllowGroups/#AllowGroups yourGroup/g" /etc/ssh/sshd_config
    fi
    getIni "START_PAM_SSHD" "END_PAM_SSHD"
    printf "%s" "$output" | tee -a /etc/pam.d/sshd >/dev/null 2>&1
    systemctl restart sshd.service >/dev/null 2>&1
    getIni "START_DEFBANNER" "END_DEFBANNER"
    printf "%s" "$output" | tee /etc/issue /etc/issue.net >/dev/null 2>&1
    echo "
    " >>/etc/issue >/dev/null 2>&1
    echo "
    " >>/etc/issue.net >/dev/null 2>&1
    msg_ok "SSH secured successfully"
}

function secure_system() {
    msg_info "Securing System"
    echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab >/dev/null 2>&1
    sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/100000/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/100000/g' /etc/login.defs
    sed -i '/PASS_MAX_DAYS/s/99999/180/g' /etc/login.defs
    sed -i '/PASS_MIN_DAYS/s/0/1/g' /etc/login.defs
    sed -i '/PASS_WARN_AGE/s/7/28/g' /etc/login.defs
    sed -i '/UMASK/s/022/027/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs
    echo "HRNGDEVICE=/dev/urandom" | tee -a /etc/default/rng-tools >/dev/null 2>&1
    systemctl restart rng-tools.service >/dev/null 2>&1
    getIni "START_COREDUMP" "END_COREDUMP"
    printf "%s" "$output" | tee -a /etc/security/limits.conf >/dev/null 2>&1
    echo 'fs.suid_dumpable = 0' >>/etc/sysctl.conf >/dev/null 2>&1
    sysctl -p >/dev/null 2>&1
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
    msg_ok "System secured successfully"
    if [[ "$lockRoot" = true ]]; then
        msg_info "Locking root account"
        passwd -d root >/dev/null 2>&1
        passwd -l root >/dev/null 2>&1
        #sed -i '/^root:/s/\/bin\/bash/\/usr\/sbin\/nologin/g' /etc/passwd
        msg_ok "Root account locked successfully"
    fi
    if [[ -n "$withAide" ]]; then
        msg_info "Initializing AIDE"
        aideinit -y -f >/dev/null 2>&1
        msg_ok "AIDE initialized successfully"
    fi

}

function secure_firewall() {
    msg_info "Hardening Firewall"
    ufw logging full >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    if [[ "$strictFw" = true ]]; then
        if [[ $(who am i) =~ \([-a-zA-Z0-9\.]+\)$ ]]; then
            msg_error "Can't use strict firewall with a remote connection, skipping..."
            ufw allow outgoing >/dev/null 2>&1
        else
            ufw default deny outgoing >/dev/null 2>&1
            ufw allow out 123/udp >/dev/null 2>&1
            ufw allow out dns >/dev/null 2>&1
            ufw allow out http >/dev/null 2>&1
            ufw allow out https >/dev/null 2>&1
            ufw allow out ftp >/dev/null 2>&1
            ufw allow out smtp >/dev/null 2>&1
            ufw allow out smtps >/dev/null 2>&1
            ufw allow out 'Mail submission' >/dev/null 2>&1
            ufw allow out ssh >/dev/null 2>&1
        fi
    else
        ufw default allow outgoing >/dev/null 2>&1
    fi
    ufw allow in "${sshPort}"/tcp >/dev/null 2>&1
    if [[ -n "$fwPort" ]]; then
        IFS=',' read -ra ADDR <<<"$fwPort"
        for i in "${ADDR[@]}"; do
            ufw allow in "$i" >/dev/null 2>&1
        done
    fi
    msg_ok "Configured Firewall successfully"
    if [[ -z "$enableFirewall" ]]; then
        msg_info "Enabling Firewall"
        ufw --force enable >/dev/null 2>&1
        msg_info "Firewall enabled."
    fi
}

function secure_fail2ban() {
    msg_info "Setting up Fail2ban"
    getIni "START_F2B_SSH" "END_F2B_SSH"
    printf "%s" "$output" | tee -a /etc/fail2ban/jail.d/ssh.local >/dev/null 2>&1
    rm -f /etc/fail2ban/jail.d/defaults-debian.conf
    fail2ban-client start >/dev/null 2>&1
    fail2ban-client reload >/dev/null 2>&1
    fail2ban-client add sshd >/dev/null 2>&1
    msg_ok "Fail2ban configured successfully"
}

function secure_updates() {
    msg_info "Configuring unattended updates"
    getIni "START_UNATTENDED_UPGRADES" "END_UNATTENDED_UPGRADES"
    printf "%s" "$output" | tee /etc/apt/apt.conf.d/51custom-unattended-upgrades >/dev/null 2>&1
    msg_ok "Unattended upgrades configured successfully"
}

function script_summary() {
    msg_info "Cleaning up and finalizing"
    apt -y autoremove >/dev/null 2>&1
    systemctl restart sshd.service >/dev/null 2>&1
    systemctl restart fail2ban.service >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
    msg_ok "Script completed successfully"
    if [[ -n "$auditSystem" ]]; then
        msg_info "Running Lynis security audit (this can take a while)"
        lynis audit system --quiet --report-file /tmp/systemaudit-new-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
        new_score="$(grep hardening_index /tmp/systemaudit-new-"$(date +"%m-%d-%Y")" | cut -d"=" -f2)" >/dev/null 2>&1
        msg_ok "Lynis audit completed with a Score of ${new_score}. Old Score: ${base_score}"
    fi

    summary="
Summary: 
SSH-Port: ${sshPort} 
Allowed SSH Users: ${sshUser}
Allowed SSH Group: ${sshGroup}
Run the following command to conclude setup: 
    google-authenticator -t -d -f -r 3 -R 30 -W 
             
The Script has finished! To apply all changes, you have to reboot your system 
Before rebooting, check, that all configurations are correct and that you can connect via SSH. Otherwise, you might lock yourself out of your system 
Thank you for using my script."
    printf '%s\n' "$summary"
}

function helpMsg() {
    printf '%s\n' "Help for Debian Secure Script (Debian 10/11)
You can use the following Options:
  [-h] => Help Dialog
  [-u] [--allow-sshuser] => Specifies user(s) that are allowed to login via SSH [default=all]
  [-g] [--allow-sshgroup] => Specifies group(s) that are allowed to login via SSH [default=all]
  [-p] [--ssh-port] => Specifies the port SSH listens on. If not specified, random port is used
  [-l] [--lock-root] => Disables the root account
  [-n] [--no-firewall] => Doesn't activate firewall, but rules are generated
  [-a] [--allow-port] => Allow port(s) allowed for incoming traffic (you can specify a protocol)
  [-s] [--strict-firewall] => Denies outgoing traffic, except for nescessary protocols
  [-c] [--config] => Specifies path for the configuration file [defaults to ./configs]
  [--with-aide] => Installs and configures AIDE
  [--with-clamav] => Installs and configures ClamAV
  [--audit-system] => Runs Lynis system audit
More Documentation can be found on Github: https://github.com/marekbeckmann/Secure-Debian-Script"

}

function get_Params() {
    while test $# -gt 0; do
        case "$1" in
        -h | --help)
            helpMsg
            exit 0
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
        -c | --config)
            configFile="$2"
            ;;
        --with-aide)
            withAide=true
            ;;
        --with-clamav)
            withClamav=true
            ;;
        --audit-system)
            auditSystem=true
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
    if [[ -z "$configFile" ]]; then
        configFile="config.ini"
    fi
    if [ "$(whoami)" = "root" ]; then
        if [[ -f "$configFile" ]]; then
            installPackages
            secure_system
            secure_ssh
            secure_firewall
            secure_fail2ban
            secure_updates
            script_summary
        else
            logToScreen "Configuration file couldn't be found. Please download \"configs\" from the Git repository, and place it in the same directory as the Script." --error
        fi
    else
        echo "You need root prvileges to run this script!"
    fi
}

script_init "$@"
