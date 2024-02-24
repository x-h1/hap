#!/bin/bash
wget -q https://raw.githubusercontent.com/x-h1/hap/master/gh -O /root/.gh
source  /root/.gh
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
KANAN="\033[1;32m<\033[1;33m<\033[1;31m<\033[1;31m$NC"
KIRI="\033[1;32m>\033[1;33m>\033[1;31m>\033[1;31m$NC"
clear
export IP=$(curl -sS ipv4.icanhazip.com)
#clear
#clear && clear && clear
#clear;clear;clear
# // IP Address Validating
#if [[ $IP == "" ]]; then
#echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
#else
#echo -e "${OK} IP Address ( ${green}$IP${NC} )"
#fi

function LOGO() {
echo -e "
 ┌─────────────────────────────────────────────────────────┐
─│                        ${BLUE}WELCOME TO${NC}                       │─
─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─
─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─
─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─
 └─────────────────────────────────────────────────────────┘"

}
start=$(date +%s)
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

function print_ok() {
echo -e "\033[36m[XD TUNNEL]${NC}${KIRI}\033[33m $1 ${NC}"
sleep 2
}
judge() {
if [[ 0 -eq $? ]]; then
print_ok "$1 ${FONT}"
sleep 1
fi
}

function print_install() {
echo -e "${green} =============================== ${FONT}"
echo -e "${YELLOW} # $1 ${FONT}"
echo -e "${green} =============================== ${FONT}"
sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
if [[ 0 -eq $? ]]; then
echo -e "${green} =============================== ${FONT}"
echo -e "${Green} # $1 berhasil dipasang"
echo -e "${green} =============================== ${FONT}"
sleep 2
fi
}

function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi

}

function checking_vps() {
if [ "${EUID}" -ne 0 ]; then
print_error "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
print_error "OpenVZ is not supported"
exit 1
fi
if [ -f "/etc/xray/domain" ]; then
print_error "Script Already Installed"
exit 1
fi
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -e ""
else
echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
exit 1
fi
# // Checking OS
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
echo -e ""
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
echo -e ""
else
print_error "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
exit 1
fi
if [ -d "/root/.info" ]; then
rm -rf /root/.info
mkdir -p /root/.info
curl "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
curl "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
curl "ipinfo.io/region?token=7a814b6263b02c" > /root/.info/.region
curl "ipinfo.io/timezone?token=7a814b6263b02c" > /root/.info/.timezone
fi
}

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
    echo "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    sudo apt update -y
    apt-get install --no-install-recommends software-properties-common
    add-apt-repository ppa:vbernat/haproxy-2.0 -y
    apt-get -y install haproxy=2.0.\*
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
    echo "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    curl https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
        http://haproxy.debian.net buster-backports-1.8 main \
        >/etc/apt/sources.list.d/haproxy.list
    sudo apt-get update
    apt-get -y install haproxy=1.8.\*
else
echo -e " Your OS Is Not Supported ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
exit 1
fi
}

clear
function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        judge "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        # // sudo add-apt-repository ppa:nginx/stable -y 
        sudo apt-get install nginx -y 
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        apt -y install nginx 
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
        # // exit 1
    fi
}

# Update and remove packages
function base_package() {
clear
judge "Menginstall Packet Yang Dibutuhkan"
apt install pwgen netcat bash-completion wondershaper -y
apt install figlet -y
apt update -y
apt upgrade -y
apt dist-upgrade -y
systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
gem install lolcat

}
clear
# Fungsi input domain
function pasang_domain() {
clear
echo -e " ┌─────────────────────────────────────────────────────────┐"
echo -e "─│                        ${BLUE}WELCOME TO${NC}                       │─"
echo -e "─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
echo -e "─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
echo -e "─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
echo -e " └─────────────────────────────────────────────────────────┘"
echo -e "               ${Green}SILAHKAN PILIH SUBDOMAIN VPS ANDA${NC}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e "   ${BLUE}[1]${NC} ${RED}• ${NC}Gunakan Subdomain Pribadi"
echo -e "   ${BLUE}[2]${NC} ${RED}• ${NC}Gunakan Subdomain Otomatis"
echo -e "─────────────────────────────────────────────────────────────"
read -p "   Silahkan Pilih Nomor 1 atau 2 : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/xdxl/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
#install cf
wget ${GITHUB_REPO}/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
    fi
}

function notifications(){
clear
echo -e ""
}
clear
# Pasang SSL
function pasang_ssl() {
clear
judge "Installasi SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
rm -rf /etc/user-create/user.log
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/xdxl/limit/vmess/ip
mkdir -p /etc/xdxl/limit/vless/ip
mkdir -p /etc/xdxl/limit/trojan/ip
mkdir -p /etc/xdxl/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
mkdir -p /etc/user-create
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
#echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}
#Instal Xray
function install_xray() {
judge "Core Xray 1.8.1 Latest Version"
clear
mkdir /etc/xray
mkdir /etc/xray/user
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/xdxl >/dev/null 2>&1
# // Ram Information
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # / / Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    # // Ambil Config Server
wget -O /etc/xray/config.json "${GITHUB_REPO}/config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${GITHUB_REPO}/runn.service" >/dev/null 2>&1
#chmod +x /usr/local/bin/xray
domain=$(cat /etc/xray/domain)
clear
judge "Installasi Konfigurasi Packet"
wget -O /etc/haproxy/haproxy.cfg "${GITHUB_REPO}/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${GITHUB_REPO}/xray.conf" >/dev/null 2>&1
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

cat > /etc/nginx/nginx.conf <<-END
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
}
http {
    log_format main '[$time_local] $proxy_protocol_addr "$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    set_real_ip_from 127.0.0.1;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/xray.conf;
}

END
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/xdxl.pem

chmod +x /etc/systemd/system/runn.service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

}

function ssh(){
clear
judge "Installasi Password SSH"
wget -O /etc/pam.d/common-password "${GITHUB_REPO}/password"
chmod +x /etc/pam.d/common-password

DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
}

function Badvpn_install(){
clear
judge "Installasi Service Badvpn"
source <(curl -sL ${GITHUB_REPO}/fv-tunnel)
source <(curl -sL https://raw.githubusercontent.com/x-h1/tunnel/master/ins-badvpn)
}

function ssh_slow(){
clear
judge "Installasi modul SlowDNS Server"
wget -q -O /tmp/nameserver "${GITHUB_REPO}/nameserver" >/dev/null 2>&1
chmod +x /tmp/nameserver
bash /tmp/nameserver
}

clear
function ins_SSHD(){
clear
judge "Installasi SSHD"
wget -q -O /etc/ssh/sshd_config "${GITHUB_REPO}/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
}

clear
function ins_dropbear(){
clear
judge "Menginstall Dropbear"
apt-get install dropbear -y > /dev/null 2>&1
cat > /etc/default/dropbear <<-END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0

# Dropbear Default Port
DROPBEAR_PORT=143

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109"

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/banner.com"
DROPBEAR_BANNER="/etc/banner.com"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END

chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
}

function ins_udpSSH(){
clear
judge "Menginstall Udp-custom"
wget -q https://raw.githubusercontent.com/zhets/project/main/ssh/udp-custom.sh
chmod +x udp-custom.sh 
bash udp-custom.sh
rm -fr udp-custom.sh
}
clear
function ins_vnstat(){
clear
judge "Menginstall Vnstat"
# setting vnstat
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
}

function ins_openvpn(){
clear
judge "Installasi OpenVPN"
wget ${GITHUB_REPO}/openvpn
chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
/etc/init.d/openvpn status
cd
wget -q ${GITHUB_REPO}/menu.zip
unzip menu.zip
chmod +x menu/*
mv menu/* /usr/bin
rm -rf menu
rm -rf menu.zip
}

function ins_backup(){
clear
judge "Installasi Backup Server"
#BackupOption
apt install rclone -y
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${GITHUB_REPO}/rclone.conf"
#Install Wondershaper
cd /bin
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/limit
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77 
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
wget -q -O /etc/ipserver "${GITHUB_REPO}/ipserver" && bash /etc/ipserver
}

clear
function ins_swab(){
clear
judge "Installasi Swap Sebesar 1GB"
curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
    
        # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
wget ${GITHUB_REPO}/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
}

function ins_Fail2ban(){
clear
judge "Installasi Fail2ban"
apt -y install fail2ban > /dev/null 2>&1
sudo systemctl enable --now fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	#exit 0
else
	mkdir /usr/local/ddos
fi

clear
# banner
echo "Banner /etc/banner.com" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.com"@g' /etc/default/dropbear

cat > /etc/banner.com <<-END
<p style="text-align:center"><b>
<br><font color='green'><b>┏━━━━━━━━━━ ✫ ━━━━━━━━━┓</b></font>
<br><font color='#8A95FF'><b>⇱ Xdpy Tunneling ⇲</b></font>
<br><font color='green'><b>┗━━━━━━━━━━━━━━━━━━━━━━┛</b><br></font> 
<br><font color='#FF000E'>&ensp;⇱ RULLES ⇲</font>
<br><font color='#3FFFAD'>&ensp;⇱ MAX 2 DEVICE ⇲</font>
<br><font color='#52fc03'>&ensp;⇱ NO HOTSPOT  ⇲</font>
<br><font color='#0367fc'>&ensp;⇱ NO MULTILOGIN ⇲</font>
<br><font color='green'><b>┏━━━━━━━━━━ ORDER ━━━━━━━━━━┓</b></font>
<br><font color='#8A95FF'><b>⇱ HUBUNGI ⇲</b></font>
<br><font color='yellow'><b>wa.me/×××</b></font>
<br><font color='yellow'><b>wa.me/×××</b></font>   
<br><font color='green'><b>┗━━━━━━━━━━━━━━━━━━━━━━━┛</b><br></font>  

END

}

function ins_epro(){
clear
judge "Installasi SSH WebSocket"

cat > /etc/systemd/system/ws.service <<-END
[Unit]
Description=WebSocket
Documentation=https://github.com
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/ws -f /usr/bin/tun.conf
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

END

cat > /usr/bin/tun.conf <<-END
## verbose level 0=info, 1=verbose, 2=very verbose
verbose: 0
listen:

# // SSH
- target_host: 127.0.0.1
  target_port: 109
  listen_port: 10015

# // OpenVPN 
- target_host: 127.0.0.1
  target_port: 1194
  listen_port: 10012

END

wget -O /usr/bin/ws "${GITHUB_REPO}/ws" >/dev/null 2>&1
chmod +x /usr/bin/ws
chmod 777 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${GITHUB_REPO}/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
}

function ins_restart(){
clear
judge "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
}

function profile(){
clear
cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/bin/xp
	END
	cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/20 * * * * root /usr/bin/clearlog
		END
    chmod 644 /root/.profile
	
    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END
    cat >/etc/cron.d/limit_ip2 <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/11 * * * * root /usr/bin/limit-ip
	END
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

chmod +x /etc/rc.local

AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

}

# Restart layanan after install
function enable_services(){
clear
judge "Enable Service"
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
clear
}

function akhiran2() {
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
#sudo hostnamectl set-hostname $user
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
echo -e "${green} Script Successfull Installed"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot

}

function installasi() {
first_setup
nginx_install
pasang_domain
password_default
pasang_ssl
install_xray
ssh
Badvpn_install
ssh_slow
ins_udpSSH
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
ins_restart
profile
enable_services
notifications
}

checking_vps
base_package
function awalan() {
clear
LOGO
echo -e "    ${RED}JANGAN INSTALL SCRIPT INI MENGGUNAKAN KONEKSI VPN!!!${FONT}"
echo -e "          ${YELLOW}Gunakanlah SCRIPT ini dengan sewajarnya${NC}"
echo -e "                      ${Green}[XDVPN TUNNELING]${NC}"
echo ""
read -p " Lanjutkan untuk menginstall [y/n] : " pilihmenu

case $pilihmenu in
y)
make_folder_xray
installasi
akhiran2
;;
Y)
make_folder_xray
installasi
akhiran2
;;
*)
echo -e "${RED}You wrong command !${FONT}"
rm *
;;
esac
}
awalan