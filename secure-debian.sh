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
WARN="${DGN}⚠${CL}"

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

function msg_warn() {
    local msg="$1"
    echo -e "${BFR} ${WARN} ${DGN}${msg}${CL}"
}

function msg_error() {
    local msg="$1"
    echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function errorhandler() {
    msg_error "$1"
    exit 1
}

function installPackages() {
    msg_info "Updating system"
    apt-get -y update >/dev/null 2>&1
    apt-get -y full-upgrade >/dev/null 2>&1
    apt-get -y install apt-transport-https ca-certificates host gnupg lsb-release >/dev/null 2>&1
    msg_ok "System updated successfully"
    if [[ -n "$auditSystem" ]]; then
        msg_info "Installing Lynis"
        curl -s https://packages.cisofy.com/keys/cisofy-software-public.key | apt-key add - >/dev/null 2>&1
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
    apt-get -y install libpam-google-authenticator ufw fail2ban auditd audispd-plugins rsyslog chkrootkit libpam-pwquality curl unattended-upgrades apt-listchanges apticron debsums apt-show-versions dos2unix rng-tools needrestart debsecan >/dev/null 2>&1
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
    elif [[ "$sshPort" -gt 65535 ]]; then
        msg_warn "Invalid SSH port, using random port"
        sshPort=$(shuf -i 28000-40000 -n 1)
    elif [[ "$sshPort" -eq 22 ]]; then
        msg_warn "SSH port is set to 22 (default)"
    fi

    getIni "START_SSHD" "END_SSHD"
    printf "%s" "$output" | tee /etc/ssh/sshd_config >/dev/null 2>&1
    dos2unix /etc/ssh/sshd_config >/dev/null 2>&1
    sed -i "s/20000/${sshPort}/g" /etc/ssh/sshd_config

    if [[ -n "$sshUser" ]]; then
        IFS=',' read -ra ADDR <<<"$sshUser"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowUsers/ s/$/ ${i}/" /etc/ssh/sshd_config
            msg_ok "SSH user ${i} added to allowed users"
        done
    else
        sed -i "s/AllowUsers/#AllowUsers yourUser/g" /etc/ssh/sshd_config
        msg_warn "No SSH users specified, allowing all users to login"
    fi

    if [[ -n "$sshGroup" ]]; then
        IFS=',' read -ra ADDR <<<"$sshGroup"
        for i in "${ADDR[@]}"; do
            sed -i "/^AllowGroups/ s/$/ ${i}/" /etc/ssh/sshd_config
            msg_ok "SSH group ${i} added to allowed groups"
        done
    else
        sed -i "s/AllowGroups/#AllowGroups yourGroup/g" /etc/ssh/sshd_config
    fi
    getIni "START_PAM_SSHD" "END_PAM_SSHD"
    printf "%s" "$output" | tee -a /etc/pam.d/sshd >/dev/null 2>&1
    systemctl restart sshd.service >/dev/null 2>&1
    getIni "START_DEFBANNER" "END_DEFBANNER"
    printf "%s" "$output" | tee /etc/issue /etc/issue.net >/dev/null 2>&1
    echo -en '\n' | tee -a /etc/issue /etc/issue.net >/dev/null 2>&1
    msg_ok "SSH secured successfully"
}

function secure_system() {
    msg_info "Securing System"
    echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab >/dev/null 2>&1
    sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/1000000/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/1000000/g' /etc/login.defs
    sed -i '/PASS_MAX_DAYS/s/99999/180/g' /etc/login.defs
    sed -i '/PASS_MIN_DAYS/s/0/1/g' /etc/login.defs
    sed -i '/PASS_WARN_AGE/s/7/28/g' /etc/login.defs
    sed -i '/UMASK/s/022/027/g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
    sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs
    echo "HRNGDEVICE=/dev/urandom" | tee -a /etc/default/rng-tools >/dev/null 2>&1
    systemctl restart rng-tools.service >/dev/null 2>&1
    systemctl enable rng-tools.service >/dev/null 2>&1
    systemctl restart auditd >/dev/null 2>&1
    systemctl enable auditd >/dev/null 2>&1
    getIni "START_COREDUMP" "END_COREDUMP"
    printf "%s" "$output" | tee -a /etc/security/limits.conf >/dev/null 2>&1
    # Kernel hardening
    echo "kernel.dmesg_restrict = 1" >/etc/sysctl.d/50-dmesg-restrict.conf 2>/dev/null
    echo 'fs.suid_dumpable = 0' >/etc/sysctl.d/50-kernel-restrict.conf 2>/dev/null
    echo "kernel.exec-shield = 2" >/etc/sysctl.d/50-exec-shield.conf 2>/dev/null
    echo "kernel.randomize_va_space=2" >/etc/sysctl.d/50-rand-va-space.conf 2>/dev/null
    echo "dev.tty.ldisc_autoload = 0" >/etc/sysctl.d/50-ldisc-autoload.conf 2>/dev/null
    echo "fs.protected_fifos = 2" >/etc/sysctl.d/50-protected-fifos.conf 2>/dev/null
    echo "kernel.core_uses_pid = 1" >/etc/sysctl.d/50-core-uses-pid.conf 2>/dev/null
    echo "kernel.kptr_restrict = 2" >/etc/sysctl.d/50-kptr-restrict.conf 2>/dev/null
    echo "kernel.sysrq = 0" >/etc/sysctl.d/50-sysrq.conf 2>/dev/null
    echo "kernel.unprivileged_bpf_disabled = 1" >/etc/sysctl.d/50-unprivileged-bpf.conf 2>/dev/null
    echo "kernel.yama.ptrace_scope = 1" >/etc/sysctl.d/50-ptrace-scope.conf 2>/dev/null
    echo "net.core.bpf_jit_harden = 2" >/etc/sysctl.d/50-bpf-jit-harden.conf 2>/dev/null
    # Network hardening
    echo 'net.ipv4.tcp_timestamps = 0' >/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo 'net.ipv4.tcp_syncookies = 1' >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.all.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.all.accept_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.all.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.all.rp_filter = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.all.send_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.default.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    echo "net.ipv4.conf.default.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
    # FS hardening
    echo "fs.protected_hardlinks = 1" >/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null
    echo "fs.protected_symlinks = 1" >>/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null
    sysctl -p >/dev/null 2>&1
    # Disable uncommon filesystems
    echo "install cramfs /bin/true" >/etc/modprobe.d/uncommon-fs.conf
    echo "install freevxfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install jffs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install hfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install hfsplus /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install squashfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install udf /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install fat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install vfat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    echo "install gfs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
    # Disable uncommon network protocols
    echo "install dccp /bin/true" >/etc/modprobe.d/uncommon-net.conf
    echo "install sctp /bin/true" >>/etc/modprobe.d/uncommon-net.conf
    echo "install rds /bin/true" >>/etc/modprobe.d/uncommon-net.conf
    echo "install tipc /bin/true" >>/etc/modprobe.d/uncommon-net.conf
    # Disable Firewire
    echo "install firewire-core /bin/true" >/etc/modprobe.d/firewire.conf
    echo "install firewire-ohci /bin/true" >>/etc/modprobe.d/firewire.conf
    echo "install firewire-sbp2 /bin/true" >>/etc/modprobe.d/firewire.conf
    # Disable Bluetooth
    echo "install bluetooth " >/etc/modprobe.d/bluetooth.conf
    # Disable uncommon sound drivers
    echo "install snd-usb-audio /bin/true" >/etc/modprobe.d/uncommon-sound.conf
    echo "install snd-usb-caiaq /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
    echo "install snd-usb-us122l /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
    echo "install snd-usb-usx2y /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
    echo "install snd-usb-audio /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
    # Disable uncommon input drivers
    echo "install joydev /bin/true" >/etc/modprobe.d/uncommon-input.conf
    echo "install pcspkr /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install serio_raw /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-rawmidi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-seq-midi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-seq-oss /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-seq /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-seq-device /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd-timer /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    echo "install snd /bin/true" >>/etc/modprobe.d/uncommon-input.conf
    # Remove telnet
    apt-get -y --purge remove telnet nis ntpdate >/dev/null 2>&1
    # File permissions
    chown root:root /etc/grub.conf >/dev/null 2>&1
    chown -R root:root /etc/grub.d >/dev/null 2>&1
    chmod og-rwx /etc/grub.conf >/dev/null 2>&1
    chmod og-rwx /etc/grub.conf >/dev/null 2>&1
    chmod -R og-rwx /etc/grub.d >/dev/null 2>&1
    chown root:root /boot/grub2/grub.cfg >/dev/null 2>&1
    chmod og-rwx /boot/grub2/grub.cfg >/dev/null 2>&1
    chown root:root /boot/grub/grub.cfg >/dev/null 2>&1
    chmod og-rwx /boot/grub/grub.cfg >/dev/null 2>&1
    chmod 0700 /home/* >/dev/null 2>&1
    chmod 0644 /etc/passwd
    chmod 0644 /etc/group
    chmod -R 0600 /etc/cron.hourly
    chmod -R 0600 /etc/cron.daily
    chmod -R 0600 /etc/cron.weekly
    chmod -R 0600 /etc/cron.monthly
    chmod -R 0600 /etc/cron.d
    chmod -R 0600 /etc/crontab
    chmod -R 0600 /etc/shadow
    chmod 750 /etc/sudoers.d
    chmod -R 0440 /etc/sudoers.d/*
    chmod 0600 /etc/ssh/sshd_config
    chmod 0750 /usr/bin/w
    chmod 0750 /usr/bin/who
    chmod 0700 /etc/sysctl.conf
    chmod 644 /etc/motd
    chmod 0600 /boot/System.map-* >/dev/null 2>&1
    depmod -ae >/dev/null 2>&1
    update-initramfs -u >/dev/null 2>&1
    msg_ok "System secured successfully"
    if [[ "$lockRoot" = true ]]; then
        msg_info "Locking root account"
        passwd -d root >/dev/null 2>&1
        passwd -l root >/dev/null 2>&1
        if [[ "$disableRoot" = true ]]; then
            sed -i '/^root:/s/\/bin\/bash/\/usr\/sbin\/nologin/g' /etc/passwd
        fi
        msg_ok "Root account locked successfully"
    else
        msg_warn "Root account not locked"
    fi
    if [[ -n "$withAide" ]]; then
        msg_info "Initializing AIDE"
        aideinit -y -f >/dev/null 2>&1
        msg_ok "AIDE initialized successfully"
    fi

}

function secure_firewall() {
    msg_info "Hardening Firewall"
    listening_ports=$(netstat -tulpn | grep LISTEN | awk '{print $4}' | cut -d: -f2 | sort -n | uniq)
    for port in $listening_ports; do
        listening_ports_string="${listening_ports_string},${port}"
    done
    msg_warn "The following ports are listening: ${listening_ports_string:1}"
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
    else
        msg_warn "Firewall not enabled"
    fi
}

function secure_fail2ban() {
    msg_info "Setting up Fail2ban"
    getIni "START_F2B_SSH" "END_F2B_SSH"
    printf "%s" "$output" | tee /etc/fail2ban/jail.d/ssh.local >/dev/null 2>&1
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
    apt -y autoclean >/dev/null 2>&1
    needrestart -q -r a -m e >/dev/null 2>&1
    obsoleteKernel="$(echo "Y" | needrestart -q -k)"
    obsoleteKernel="$(echo "$obsoleteKernel" | grep "expected")"
    if [[ -n "$obsoleteKernel" ]]; then
        msg_warn "Running kernel $(uname -r) is obsolete, please reboot to update"
    fi
    ufw reload >/dev/null 2>&1
    msg_ok "Script completed successfully"
    if [[ -n "$auditSystem" ]]; then
        msg_info "Running Lynis security audit (this can take a while)"
        lynis audit system --quiet --report-file /tmp/systemaudit-new-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
        new_score="$(grep hardening_index /tmp/systemaudit-new-"$(date +"%m-%d-%Y")" | cut -d"=" -f2)" >/dev/null 2>&1
        msg_ok "Lynis audit completed with a Score of ${new_score}. Old Score: ${base_score}"
    fi
    unset DEBIAN_FRONTEND
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
  [-l] [--lock-root] => Locks the root account
  [-d] [--disable-root] => Completly disables the root account
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
        -d | --disable-root)
            disableRoot=true
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
            msg_error "Unknown option $1"
            helpMsg
            exit 1
            ;;
        -*)
            msg_error "Unknown option $1"
            helpMsg
            exit 1
            ;;
        esac
        shift
    done
}

function script_init() {
    export DEBIAN_FRONTEND=noninteractive
    get_Params "$@"
    if [[ -z "$configFile" ]]; then
        configFile="config.ini"
    fi
    if [ "$EUID" = 0 ]; then
        if [[ -f "$configFile" ]]; then
            installPackages
            secure_system
            secure_ssh
            secure_firewall
            secure_fail2ban
            secure_updates
            script_summary
        else
            errorhandler "Configuration file couldn't be found. Please provide \"config.ini\""
        fi
    else
        errorhandler "You need root prvileges to run this script!"
    fi
}

script_init "$@"
