#!/bin/bash
# Program: This for Install Apache + MariaDB + PHP70 + FPM
# History:
# 01-04-2017 hrace009 First created.
clear
PACKAGE_UPDATE="yum -q -y update"
PACKAGE_CLEAN="yum -q clean all"
PACKAGE_INSTALLER="yum -q -y install"
SOFTWARE_PCKG_INITIAL="wget bind-utils jwhois yum-priorities yum-utils curl iptables-services"
SOFTWARE_PCKG="redhat-lsb-core ntpdate MariaDB MariaDB-server httpd httpd-tools mod_fcgid fcgi php php-fpm php-mysqlnd php-gd php-imap php-ldap php-mcrypt php-mbstring php-odbc php-pear php-xml php-xmlrpc php-pecl-imagick php-suhosin php-soap php-pecl-zip php-pecl-rar php-pear php-intl php-ioncube-loader perl perl-Net-SSLeay openssl perl-IO-Tty glibc.i686 glibc.x86_64 libxml2.i686 libxml2.x86_64 compat-libstdc++-33.i686 compat-libstdc++-33.x86_64 libgcc.i686 libgcc.x86_64 pcre.i686 pcre.x86_64 p7zip webmin"
RPM_IMPORT="rpm --import"
RPM_INSTALL="rpm -ivh"
EPEL_FILE="https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm"
EPEL_KEY="https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7"
REMI_FILE="http://rpms.famillecollet.com/enterprise/remi-release-7.rpm"
REMI_KEY="http://rpms.remirepo.net/RPM-GPG-KEY-remi"
WEBMIN_KEY="http://www.webmin.com/jcameron-key.asc"
MARIADB_KEY="https://yum.mariadb.org/RPM-GPG-KEY-MariaDB"
MY_CNF_PATH="/etc/my.cnf"
LOGFILE=$(date +%Y-%m-%d_%H.%M.%S_hrace009_Installer.log)

touch "$LOGFILE"
exec > >(tee "$LOGFILE")
exec 2>&1

#--- Display the 'welcome' splash/user warning info..
echo ""
echo "#############################################################################"
echo "#  This Installer Only for CentOS 7.X, otherwise will not support.          #"
echo "#  Make sure this server is fresh install.                                  #"
echo "#  For more information, please visit: https://www.hrace009.com             #"
echo "#############################################################################"
sleep 5

echo -e "\nChecking that minimal requirements are ok"

# Ensure the OS is compatible with the launcher
if [ -f /etc/centos-release ]; then
    OS="CentOs"
    VERFULL=$(sed 's/^.*release //;s/ (Fin.*$//' /etc/centos-release)
    VER=${VERFULL:0:1} # return 7
fi
ARCH=$(uname -m)

echo "Detected : $OS $VER $ARCH"

if [[ "$OS" = "CentOs" && ("$VER" = "7") ]]; then 
    echo "Your OS Good to go."
else
    echo "Sorry, this OS is not supported by hrace009." 
    exit 1
fi

# Check if the user is 'root' before allowing installation to commence
if [ $UID -ne 0 ]; then
    echo "Install failed: you must be logged in as 'root' to install."
    echo "Use command 'sudo -i', then enter root password and then try again."
    exit 1
fi

echo ""
echo "Please wait a while, we collect some information first."
echo "======================================================="

$PACKAGE_INSTALLER $SOFTWARE_PCKG_INITIAL

iptables --flush
service iptables save
systemctl stop firewalld
systemctl disable firewalld.service
systemctl stop iptables.service

local_ip=$(ip addr show | awk '$1 == "inet" && $3 == "brd" { sub (/\/.*/,""); print $2 }')
extern_ip="$(wget -qO- http://api.sentora.org/ip.txt)"

while getopts d:i:t: opt; do
  case $opt in
  d)
      SVR_FQDN=$OPTARG
      INSTALL="auto"
      ;;
  i)
      PUBLIC_IP=$OPTARG
      if [[ "$PUBLIC_IP" == "local" ]] ; then
          PUBLIC_IP=$local_ip
      elif [[ "$PUBLIC_IP" == "public" ]] ; then
          PUBLIC_IP=$extern_ip
      fi
      ;;
  t)
      echo "$OPTARG" > /etc/timezone
      tz=$(cat /etc/timezone)
      ;;
  esac
done

if [[ ("$SVR_FQDN" != "" && "$PUBLIC_IP" == "") || 
      ("$SVR_FQDN" == "" && "$PUBLIC_IP" != "") ]] ; then
    echo "-d and -i must be both present or both absent."
    exit 2
fi

clear
if [[ "$tz" == "" && "$SVR_FQDN" == "" ]] ; then
    # Propose selection list for the time zone
    echo "Preparing to select timezone, please wait a few seconds..."
    $PACKAGE_INSTALLER tzdata
    # setup server timezone
        # make tzselect to save TZ in /etc/timezone
        echo "echo \$TZ > /etc/timezone" >> /usr/bin/tzselect
        tzselect
        tz=$(cat /etc/timezone)
fi
# clear timezone information to focus user on important notice
clear

# Installer parameters
if [[ "$SVR_FQDN" == "" ]] ; then
    echo -e "\n\e[1;33m=== Informations required to build your server ===\e[0m"
    echo 'The installer requires 4 pieces of information:'
    echo ' 1) the Domain that you want to use for client access on port 80,'
    echo '   - do not use your main domain (like domain.com)'
    echo '   - use a sub-domain, e.g subdomain.domain.com'
    echo '   - or use the server hostname, e.g server1.domain.com'
    echo '   - DNS must already be configured and pointing to the server IP'
    echo ' 2) Special user for your Server.'
    echo ' 3) MySQL Admin User and Password for MySQL (DO NOT USE ROOT USER).'
    echo ' 4) The public IP of the server.'
    echo ''

    SVR_FQDN="$(/bin/hostname)"
    PUBLIC_IP=$extern_ip
    while true; do
        echo ""
		echo "Enter your Domain e.g server.domain.com"
        read -e -p "Domain Server: " -i "$SVR_FQDN" SVR_FQDN

        if [[ "$PUBLIC_IP" != "$local_ip" ]]; then
          echo -e "\nThe public IP of the server is $PUBLIC_IP.\nThe local IP is $local_ip"
          echo "For a production server, the PUBLIC IP must be used."
		  echo "For a development server, the LOCAL IP must be used."
        fi  
        read -e -p "Enter (or confirm) the public IP for this server: " -i "$PUBLIC_IP" PUBLIC_IP
        echo ""

        # Checks if the panel domain is a subdomain
        sub=$(echo "$SVR_FQDN" | sed -n 's|\(.*\)\..*\..*|\1|p')
        if [[ "$sub" == "" ]]; then
            echo -e "\e[1;31mWARNING: $SVR_FQDN is not a subdomain!\e[0m"
            confirm="true"
        fi

        # Checks if the panel domain is already assigned in DNS
        dns_panel_ip=$(host "$SVR_FQDN"|grep address|cut -d" " -f4)
        if [[ "$dns_panel_ip" == "" ]]; then
            echo -e "\e[1;31mWARNING: $SVR_FQDN is not defined in your DNS!\e[0m"
            echo "  You must add records in your DNS manager (and then wait until propagation is done)."
            echo "  If this is a production installation, set the DNS up as soon as possible."
			echo "  If this is a development installation, you can ignore this warning."
            confirm="true"
        else
            echo -e "\e[1;32mOK\e[0m: DNS successfully resolves $SVR_FQDN to $dns_panel_ip"

            # Check if panel domain matches public IP
            if [[ "$dns_panel_ip" != "$PUBLIC_IP" ]]; then
                echo -e -n "\e[1;31mWARNING: $SVR_FQDN DNS record does not point to $PUBLIC_IP!\e[0m"
                echo "  Server will not be reachable from http://$SVR_FQDN"
				echo "  For development use, just ignore this warning"
                confirm="true"
            fi
        fi

        if [[ "$PUBLIC_IP" != "$extern_ip" && "$PUBLIC_IP" != "$local_ip" ]]; then
            echo -e -n "\e[1;31mWARNING: $PUBLIC_IP does not match detected IP !\e[0m"
            echo "  Server will not work with this IP..."
			echo "  For development use, just ignore this warning"
                confirm="true"
        fi
      
        echo ""
        # if any warning, ask confirmation to continue or propose to change
        if [[ "$confirm" != "" ]] ; then
            echo "There are some warnings..."
            echo "Are you really sure that you want to setup Server with these parameters?"
            read -e -p "(y):Accept and install, (n):Change domain or IP, (q):Quit installer? " yn
            case $yn in
                [Yy]* ) break;;
                [Nn]* ) continue;;
                [Qq]* ) exit;;
            esac
        else
            read -e -p "All is ok. Do you want to install Server now (y/n)? " yn
            case $yn in
                [Yy]* ) break;;
                [Nn]* ) exit;;
            esac
        fi
    done
fi

# Function to disable a file by appending its name with _disabled
rename_file() {
    mv "$1" "$1_renamed_by_hrace009" &> /dev/null
}

# Random password generator function
passwordgen() {
    l=$1
    [ "$l" == "" ] && l=16
    tr -dc A-Za-z0-9 < /dev/urandom | head -c ${l} | xargs
}

# Create Random Hash
randomhashes() {
    l=$1
    [ "$l" == "" ] && l=16
    tr -dc a-z0-9 < /dev/urandom | head -c ${l} | xargs
}

# Random username generator function
usernamegen() {
    l=$1
    [ "$l" == "" ] && l=6
    tr -dc a-z < /dev/urandom | head -c ${l} | xargs
}
# Add first parameter in hosts file as local IP domain
add_local_domain() {
    if ! grep -q "127.0.0.1 $1" /etc/hosts; then
        echo "127.0.0.1 $1" >> /etc/hosts;
    fi
}

# Create directory Function
create_directory() {
if [ ! -d /etc/httpd/conf.d/userdata/$CREATE_USER ]; then
  mkdir -p /etc/httpd/conf.d/userdata/$CREATE_USER;
fi
if [ ! -d /home/$CREATE_USER/public_html/default ]; then
  mkdir -p /home/$CREATE_USER/public_html/default;
fi
if [ ! -d /home/$CREATE_USER/tmp ]; then
  mkdir -p /home/$CREATE_USER/tmp;
fi
if [ ! -d /home/$CREATE_USER/logs ]; then
  mkdir -p /home/$CREATE_USER/logs;
fi
if [ ! -d /home/$CREATE_USER/public_html/default/cgi-bin ]; then
  mkdir -p /home/$CREATE_USER/public_html/default/cgi-bin;
fi
}

RANDOM_HASHES=$(randomhashes)

echo -e "\n\e[1;33m=== Special User Information ===\e[0m"
echo -e "NOTE: If empty user, we will use random generate"
read -e -p "Enter OS Username: " -i "$CREATE_USER" CREATE_USER
echo -e "\e[32;3m=== Thank You ===\e[0m"

echo -e "\n\e[1;33m=== MySQL Information ===\e[0m"
echo -e "NOTE: If empty user, pass, we will use random generate"
read -e -p "Enter MySQL Root Username: " -i "$MYSQL_USER" MYSQL_USER
read -e -p "Enter MySQL Root Password: " -i "$MYSQL_PASSWD" MYSQL_PASSWD
echo -e "\e[32;3m=== Thank You ===\e[0m"

if [[ $CREATE_USER == "" ]]; then
	CREATE_USER=$(usernamegen);
	echo "Using SSH user \"$CREATE_USER\""
fi

if [[ "$MYSQL_USER" == "" ]]; then
	MYSQL_USER=$(usernamegen);
	echo "Using mysql root user \"$MYSQL_USER\""
fi

if [[ "$MYSQL_PASSWD" == "" ]]; then
	MYSQL_PASSWD=$(passwordgen);
	echo "Using mysql password \"$MYSQL_PASSWD\""
fi

echo -e "\nInstalling Server\n\e[0mServer Domain: \e[1;33mhttp://$SVR_FQDN\n\e[0mIP: \e[1;33m$PUBLIC_IP\e[0m"
echo -e "OS: \e[1;33m$OS $VER\e[0m"

echo -e "\n\e[1;33m=== Please sit and take coffe break, let me install Server for you ===\e[0m"
sleep 5

#--- Adapt repositories and packages sources
echo -e "\n\e[1;33m=== Updating repositories and packages sources ===\e[0m"

#--- Add MariaDB Repository using singapore digital ocean mirror
{
	echo "# MariaDB 10.1 CentOS7 repository list - created $(date +%Y-%m-%d_%H.%M.%S)"
	echo "# http://downloads.mariadb.org/mariadb/repositories/"
	echo "[mariadb]"
	echo "name = MariaDB"
	echo "#baseurl = http://yum.mariadb.org/10.1/centos7-amd64"
	echo "baseurl = http://sgp1.mirrors.digitalocean.com/mariadb/mariadb-10.1.21/yum/centos7-amd64"
	echo "gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB"
	echo "gpgcheck=1"
} >> /etc/yum.repos.d/MariaDB.repo
$RPM_IMPORT $MARIADB_KEY
#Give Priority MariaDB
sed -i -e 's/\]$/\]\npriority=10/g' "/etc/yum.repos.d/"MariaDB*
sed -i 's|priority=[0-9]\+|priority=10|' "/etc/yum.repos.d/"MariaDB*

#--- Add Webmin Repository
{
	echo "[Webmin]"
	echo "name = Webmin Distribution Neutral"
	echo "#baseurl=http://download.webmin.com/download/yum"
	echo "mirrorlist=http://download.webmin.com/download/yum/mirrorlist"
	echo "enabled=1"
} >> /etc/yum.repos.d/webmin.repo
$RPM_IMPORT $WEBMIN_KEY

#--- Add EPEL Repository
$RPM_INSTALL $EPEL_FILE
$RPM_IMPORT $EPEL_KEY
#Give Priority EPEL Repo
sed -i -e 's/\]$/\]\npriority=10/g' "/etc/yum.repos.d/"epel*
sed -i 's|priority=[0-9]\+|priority=10|' "/etc/yum.repos.d/"epel*

#--- Add REMI Repository
$RPM_INSTALL $REMI_FILE
$RPM_IMPORT $REMI_KEY
#Give Priority Remi
sed -i -e 's/\]$/\]\npriority=10/g' "/etc/yum.repos.d/"remi*
sed -i 's|priority=[0-9]\+|priority=10|' "/etc/yum.repos.d/"remi*

yum-config-manager --enable remi-php70 epel mariadb

# We need to disable SELinux...
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
setenforce 0

#--- List all already installed packages (may help to debug)
#echo -e "\n\e[1;33mListing of all packages installed:\e[0m"
#rpm -qa | sort

#--- Ensures that all packages are up to date
echo -e "\n\e[1;33mUpdating+upgrading system, it may take some time...\e[0m"
$PACKAGE_CLEAN
$PACKAGE_UPDATE

echo -e "\n\e[1;33m=== Installing Software Depedency ===\e[0m"
$PACKAGE_INSTALLER $SOFTWARE_PCKG

#--- Enable Required Services
systemctl enable mariadb.service
systemctl enable httpd.service
systemctl enable php-fpm.service
chkconfig webmin on

#--- Start Required Service
systemctl start mariadb.service
systemctl start httpd.service
systemctl start php-fpm.service
/etc/init.d/webmin start

echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Creating Special Linux Users ===\e[0m"
useradd -m $CREATE_USER -s /usr/sbin/nologin -c "Web Services"
create_directory
chown -R $CREATE_USER:$CREATE_USER /home/$CREATE_USER
chmod 711 /home/$CREATE_USER
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Configure Web Server ===\e[0m"
sed -i -e "s/^/#/" "/etc/httpd/conf.modules.d/00-lua.conf"
sed -i -e "s/^/#/" "/etc/httpd/conf.modules.d/00-dav.conf"
sed -i -e "s/^/#/" "/etc/httpd/conf.modules.d/01-cgi.conf"
sed -i -e "/LoadModule mpm_prefork_module/ s/^#*/# /" "/etc/httpd/conf.modules.d/00-mpm.conf"
sed -i -e "/#LoadModule mpm_event_module/ s/^#*//" "/etc/httpd/conf.modules.d/00-mpm.conf"
sed -i -e "/AddType text\/html .php/ s/^#*/# /" "/etc/httpd/conf.d/php.conf"
sed -i -e "/DirectoryIndex index.php/q" "/etc/httpd/conf.d/php.conf"

rename_file /etc/httpd/conf/httpd.conf

#Create new DEFAULT VHOST using cPanel style
{
echo "###################### DEFAULT VHOST #############################"
echo ""
echo "ServerRoot \"/etc/httpd\""
echo ""
echo "Include conf.modules.d/*.conf"
echo ""
echo "User nobody"
echo "Group nobody"
echo ""
echo "ServerAdmin $CREATE_USER@$SVR_FQDN"
echo ""
echo "ServerName localhost"
echo ""
echo "TraceEnable Off"
echo "ServerSignature Off"
echo "ServerTokens ProductOnly"
echo "FileETag None"
echo ""
echo "<Directory \"/\">"
echo "    AllowOverride All"
echo "   Options ExecCGI FollowSymLinks Includes IncludesNOEXEC Indexes MultiViews SymLinksIfOwnerMatch"
echo "</Directory>"
echo ""
echo "StartServers 5"
echo "<IfModule prefork.c>"
echo "    MinSpareServers 5"
echo "    MaxSpareServers 10"
echo "</IfModule>"
echo ""
echo "ServerLimit 256"
echo "MaxRequestWorkers 1000"
echo "MaxConnectionsPerChild 1000"
echo "KeepAlive On"
echo "KeepAliveTimeout 5"
echo "MaxKeepAliveRequests 100"
echo "Timeout 100"
echo ""
echo "<IfModule dir_module>"
echo "    DirectoryIndex index.php index.php5 index.php4 index.php3 index.perl index.pl index.plx index.ppl index.cgi index.jsp index.js index.jp index.phtml index.shtml index.xhtml index.html index.htm index.wml Default.html Default.htm default.html default.htm home.html home.htm"
echo "</IfModule>"
echo ""
echo "<Directory \"/var/www\">"
echo "    Options All"
echo "    AllowOverride None"
echo "    Require all granted"
echo "</Directory>"
echo ""
echo "<Files ~ \"^error_log$\">"
echo "    Order allow,deny"
echo "    Deny from all"
echo "    Satisfy All"
echo "</Files>"
echo ""
echo "<Files \".ht*\">"
echo "    Require all denied"
echo "</Files>"
echo ""
echo "<IfModule mime_module>"
echo "    TypesConfig /etc/mime.types"
echo ""
echo "    AddType application/x-compress .Z"
echo "    AddType application/x-gzip .gz .tgz"
echo "    AddType text/html .shtml"
echo "    AddType application/x-tar .tgz"
echo "    AddType text/vnd.wap.wml .wml"
echo "    AddType image/vnd.wap.wbmp .wbmp"
echo "    AddType text/vnd.wap.wmlscript .wmls"
echo "    AddType application/vnd.wap.wmlc .wmlc"
echo "    AddType application/vnd.wap.wmlscriptc .wmlsc"
echo ""
echo "    # These extensions are used to redirect incoming requests to WHM"
echo "    AddHandler cgi-script .cgi .pl .plx .ppl .perl"
echo ""
echo "    # This is used for custom error documents"
echo "    AddHandler server-parsed .shtml"
echo "</IfModule>"
echo ""
echo "ErrorLog \"/home/$CREATE_USER/logs/error_log\""
echo ""
echo "LogLevel warn"
echo ""
echo "<IfModule log_config_module>"
echo "    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined"
echo "    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b\" common"
echo ""
echo "    <IfModule logio_module>"
echo "      LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\" %I %O\" combinedio"
echo "    </IfModule>"
echo ""
echo "    CustomLog \"/home/$CREATE_USER/logs/access_log\" combined"
echo "</IfModule>"
echo ""
echo "<IfModule alias_module>"
echo "    ScriptAlias /cgi-bin/ \"/var/www/cgi-bin/\""
echo "</IfModule>"
echo ""
echo "AddDefaultCharset UTF-8"
echo ""
echo "<IfModule mime_magic_module>"
echo "    MIMEMagicFile conf/magic"
echo "</IfModule>"
echo ""
echo "EnableSendfile on"
echo ""
echo "Listen 0.0.0.0:80"
echo "Listen [::]:80"
echo ""
echo "<IfModule ssl_module>"
echo "    SSLCipherSuite ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS"
echo "    SSLProtocol All -SSLv2 -SSLv3"
echo "    SSLPassPhraseDialog  builtin"
echo ""
echo "    <IfModule socache_shmcb_module>"
echo "        SSLUseStapling on"
echo "        SSLStaplingCache shmcb:/run/httpd/stapling_cache_shmcb(256000)"
echo ""
echo "        SSLStaplingReturnResponderErrors off"
echo "        SSLStaplingErrorCacheTimeout 60"
echo "        SSLSessionCache shmcb:/run/httpd/ssl_gcache_data_shmcb(1024000)"
echo "    </IfModule>"
echo "    <IfModule !socache_shmcb_module>"
echo "        SSLSessionCache dbm:/run/httpd/ssl_gcache_data_dbm"
echo "    </IfModule>"
echo ""
echo "    SSLSessionCacheTimeout  300"
echo "    Mutex                   file:/run/httpd ssl-cache"
echo "    SSLRandomSeed startup builtin"
echo "    SSLRandomSeed connect builtin"
echo ""
echo "    Listen 0.0.0.0:443"
echo "    Listen [::]:443"
echo ""
echo "    AddType application/x-x509-ca-cert .crt"
echo "    AddType application/x-pkcs7-crl .crl"
echo "</IfModule>"
echo ""
echo "Include \"conf.d/*.conf\""
echo ""
echo "##################################################"
echo "##################################################"
echo "#"
echo "# Include default vhosts conf for unbound IPs"
echo "#"
echo "##################################################"
echo "##################################################"
echo ""
echo "Include \"conf.d/userdata/$CREATE_USER/$CREATE_USER.conf\""
} >> /etc/httpd/conf/httpd.conf

#Add VHost
{
echo "##################################################"
echo "##################################################"
echo "#"
echo "# Define default vhosts for HTTP"
echo "#"
echo "##################################################"
echo "##################################################"
echo ""
echo "<VirtualHost $PUBLIC_IP:80>"
echo "	ServerName $SVR_FQDN"
echo "	DocumentRoot /home/$CREATE_USER/public_html/default"
echo "	ServerAdmin $CREATE_USER@$SVR_FQDN"
echo "	UseCanonicalName Off"
echo "  ErrorLog \"/home/$CREATE_USER/logs/$SVR_FQDN-error.log\""
echo ""
echo "	<IfModule include_module>"
echo "		<Directory \"/home/CREATE_USER/public_html/default\">"
echo "			SSILegacyExprParser On"
echo "		</Directory>"
echo "	</IfModule>"
echo ""
echo "	<IfModule suphp_module>"
echo "		suPHP_UserGroup $CREATE_USER $CREATE_USER"
echo "	</IfModule>"
echo ""
echo "	<IfModule suexec_module>"
echo "		SuexecUserGroup $CREATE_USER $CREATE_USER"
echo "	</IfModule>"
echo ""
echo "	<IfModule alias_module>"
echo "		ScriptAlias /cgi-bin/ /home/$CREATE_USER/public_html/default/cgi-bin/"
echo "	</IfModule>"
echo ""
echo "############### SSL SETTINGS ##############"
echo "#<IfModule ssl_module>"
echo "# SSLEngine on"
echo ""   
echo "# SSLCertificateFile /etc/letsencrypt/live/$SVR_FQDN/cert.pem"
echo "# SSLCertificateKeyFile /etc/letsencrypt/live/$SVR_FQDN/privkey.pem"
echo "# SSLCertificateChainFile /etc/letsencrypt/live/$SVR_FQDN/chain.pem"
echo "# SSLCACertificateFile /etc/letsencrypt/live/$SVR_FQDN/fullchain.pem"
echo "# SetEnvIf User-Agent \".*MSIE.*\" nokeepalive ssl-unclean-shutdown"
echo "# <Directory \"/home/$SVR_FQDN/public_html/default/cgi-bin\">"
echo "# SSLOptions +StdEnvVars"
echo "# </Directory>"
echo "#</IfModule>"
echo "###########################################"
echo ""
echo "	<IfModule proxy_fcgi_module>"
echo "		<FilesMatch \.(phtml|php[0-9]*)$>"
echo "			SetHandler \"proxy:unix:/var/run/php-fpm/$CREATE_USER-$RANDOM_HASHES.sock|fcgi://$CREATE_USER/\""
echo "		</FilesMatch>"
echo "	</IfModule>"
echo ""
echo "</VirtualHost>"
} >> /etc/httpd/conf.d/userdata/$CREATE_USER/$CREATE_USER.conf

#Configure FPM
rm /etc/php-fpm.d/www.conf
{
    echo "[$CREATE_USER]"
    echo "catch_workers_output = yes"
    echo "chdir = /home/$CREATE_USER"
    echo "group = $CREATE_USER"
    echo "listen = /var/run/php-fpm/$CREATE_USER-$RANDOM_HASHES.sock"
    echo "listen.group = nobody"
    echo "listen.mode = 0660"
    echo "listen.owner = $CREATE_USER"
    echo "php_admin_flag[allow_url_fopen] = on"
    echo "php_admin_flag[log_errors] = on"
    echo "php_admin_value[allow_url_include] = Off"
    echo "php_admin_value[date.timezone] = \"Asia/Jakarta\""
    echo "php_admin_value[enable_dl] = Off"
    echo "php_admin_value[expose_php] = Off"
    echo "php_admin_value[file_uploads] = On"
    echo "php_admin_value[max_execution_time] = 30"
    echo "php_admin_value[max_file_uploads] = 30"
    echo "php_admin_value[max_input_time] = 30"
    echo "php_admin_value[max_input_vars] = 1000"
    echo "php_admin_value[memory_limit] = 128M"
    echo "php_admin_value[post_max_size] = 128M"
    echo "php_admin_value[session.save_handler] = files"
    echo "php_admin_value[session.save_path] = \"/home/$CREATE_USER/tmp\""
    echo "php_admin_value[soap.wsdl_cache_dir] = /home/$CREATE_USER/tmp"
    echo "php_admin_value[upload_max_filesize] = 128M"
    echo "php_admin_value[upload_tmp_dir] = /home/$CREATE_USER/tmp"
    echo "php_admin_value[user_ini.filename] = \"\""
    echo "php_admin_value[disable_functions] = show_source, system, shell_exec, passthru, exec, popen, proc_open"
    echo "php_admin_value[doc_root] = \"/home/$CREATE_USER/public_html/default\""
    echo "php_admin_value[error_log] = /home/$CREATE_USER/logs/$SVR_FQDN-error.log"
    echo "php_admin_value[error_reporting] = E_ALL & ~E_NOTICE"
    echo "php_admin_flag[short_open_tag] = on"
    echo "ping.path = /ping"
    echo "pm = ondemand"
    echo "pm.max_children = 5"
    echo "pm.max_requests = 20"
    echo "pm.max_spare_servers = 5"
    echo "pm.min_spare_servers = 1"
    echo "pm.process_idle_timeout = 10"
    echo "pm.start_servers = 0"
    echo "pm.status_path = /status"
    echo "request_slowlog_timeout = 10s"
    echo "security.limit_extensions = .phtml .php .php3 .php4 .php5 .php6 .php7"
    echo "slowlog = \"/home/$CREATE_USER/logs/$SVR_FQDN-slow.log\""
    echo "user = $CREATE_USER"
} >> /etc/php-fpm.d/$CREATE_USER.conf

echo -e "\n\e[1;33m=== Restarting MariaDB Services ===\e[0m"
    systemctl stop mariadb.service
    echo -e "Please Wait..."
    sleep 5
    systemctl start mariadb.service
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Restarting HTTPD Services ===\e[0m"
chown -R $CREATE_USER:$CREATE_USER /home/$CREATE_USER
chmod 711 /home/$CREATE_USER
    systemctl stop httpd.service
    echo -e "Please Wait..."
    sleep 5
    systemctl start httpd.service
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Restarting HTTPD Services ===\e[0m"
    systemctl stop php-fpm.service
    echo -e "Please Wait..."
    sleep 5
    systemctl start php-fpm.service
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Starting Webmin Services ===\e[0m"
    /etc/init.d/webmin start
    echo -e "Please Wait..."
    sleep 2
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Setup MySQL Data Base ===\e[0m"
mysqlpassword=$(passwordgen);

# setup mysql root password
mysqladmin -u root password "$mysqlpassword"

# small cleaning of mysql access
mysql -u root -p"$mysqlpassword" -e "DELETE FROM mysql.user WHERE User='root' AND Host != 'localhost'";
mysql -u root -p"$mysqlpassword" -e "DELETE FROM mysql.user WHERE User=''";
mysql -u root -p"$mysqlpassword" -e "FLUSH PRIVILEGES";

# remove test table that is no longer used
mysql -u root -p"$mysqlpassword" -e "DROP DATABASE IF EXISTS test";

# secure SELECT "hacker-code" INTO OUTFILE 
sed -i "s|\[mariadb\]|&\nsecure-file-priv = /var/tmp|" "/etc/my.cnf.d/server.cnf"
sed -i "s|\[mariadb-10.1\]|&\nsecure-file-priv = /var/tmp|" "/etc/my.cnf.d/server.cnf"

#Create MYSQL ADMIN USER and Grant All Access like root from all Host
mysql -u root -p"$mysqlpassword" -e "CREATE USER '$MYSQL_USER'@'%' IDENTIFIED BY '$MYSQL_PASSWD'";
mysql -u root -p"$mysqlpassword" -e "GRANT GRANT OPTION ON *.* TO '$MYSQL_USER'@'%'";
mysql -u root -p"$mysqlpassword" -e "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER ON *.* TO '$MYSQL_USER'@'%'";
mysql -u root -p"$mysqlpassword" -e "FLUSH PRIVILEGES";

{
    echo "# Generated by hrace009"
    echo "# Configuration name $SVR_FQDN generated for hrace009@gmail.com at $(date +%Y-%m-%d_%H.%M.%S)"
    echo ""
    echo "[mysql]"
    echo ""
    echo "# CLIENT #"
    echo "port                           = 3306"
    echo "socket                         = /var/lib/mysql/mysql.sock"
    echo "password		                 = \"$mysqlpassword\""
    echo "user                           = root"
    echo "max-allowed-packet 	         = 1073741824"
    echo "no-auto-rehash"
    echo ""
    echo "[mysqld]"
    echo ""
    echo "# GENERAL #"
    echo "user                           = mysql"
    echo "default-storage-engine         = InnoDB"
    echo "socket                         = /var/lib/mysql/mysql.sock"
    echo "pid-file                       = /var/lib/mysql/mysql.pid"
    echo "max-allowed-packet 	         = 1073741824"
    echo ""
    echo "# MyISAM #"
    echo "key-buffer-size                = 32M"
    echo "myisam-recover-options         = FORCE,BACKUP"
    echo ""
    echo "# SAFETY #"
    echo "max-allowed-packet 	         = 1073741824"
    echo "max-connect-errors             = 1000000"
    echo "secure-file-priv               = /var/tmp"
    echo "#skip-name-resolve"
    echo "sysdate-is-now                 = 1"
    echo "local-infile                   = 0"
    echo "skip-external-locking"
    echo "symbolic-links                 = 0"
    echo ""
    echo "# DATA STORAGE #"
    echo "datadir                        = /var/lib/mysql/"
    echo ""
    echo "# CACHES AND LIMITS #"
    echo "tmp-table-size                 = 32M"
    echo "max-heap-table-size            = 32M"
    echo "query-cache-type               = 0"
    echo "query-cache-size               = 0"
    echo "max-connections                = 500"
    echo "thread-cache-size              = 50"
    echo "open-files-limit               = 65535"
    echo "table-definition-cache         = 1024"
    echo "table-open-cache               = 2048"
    echo ""
    echo "# INNODB #"
    echo "innodb-flush-method            = O_DIRECT"
    echo "innodb-log-files-in-group      = 2"
    echo "innodb-log-file-size           = 64M"
    echo "innodb-flush-log-at-trx-commit = 2"
    echo "innodb-file-per-table          = 1"
    echo "innodb-buffer-pool-size        = 592M"
    echo ""
    echo "# LOGGING #"
    echo "log-error                      = /var/log/mysqld/mysql-error.log"
    echo "log-queries-not-using-indexes  = 1"
    echo "slow-query-log                 = 1"
    echo "slow-query-log-file            = /var/log/mysqld/mysql-slow.log"
    echo ""
    echo "[mysql_upgrade]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqladmin]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqlbinlog]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqlcheck]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqldump]"
    echo "quick"
    echo "max-allowed-packet 	           = 1073741824"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqlimport]"
    echo "max-allowed-packet 	           = 1073741824"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqlshow]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
    echo ""
    echo "[mysqlslap]"
    echo "password		               = \"$mysqlpassword\""
    echo "user                           = root"
} >> $MY_CNF_PATH

systemctl stop mariadb.service
echo -e "Please Wait..."
sleep 5
systemctl start mariadb.service
echo -e "\n\e[32;3m=== DONE ===\e[0m"

echo -e "\n\e[1;33m=== Setup Firewall ===\e[0m"
NETWORK_DEVICES=$(ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $7}')
iptables -A INPUT -p icmp -j ACCEPT 
iptables -A INPUT -i lo -j ACCEPT 
iptables -A INPUT -i $NETWORK_DEVICES -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT 
iptables -A INPUT -i $NETWORK_DEVICES -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -i $NETWORK_DEVICES -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT 
iptables -A INPUT -i $NETWORK_DEVICES -p tcp -m tcp --dport 3306 -m state --state NEW -j ACCEPT 
iptables -A INPUT -i $NETWORK_DEVICES -p tcp -m tcp --dport 10000 -m state --state NEW -j ACCEPT 
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 
iptables -A INPUT -j DROP 
iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited

service iptables save
systemctl stop iptables.service
echo -e "Restarting Firewall Please Wait..."
sleep 5
systemctl start iptables.service
systemctl enable iptables.service
echo -e "\n\e[32;3m=== DONE ===\e[0m"
echo ""
echo -e "\n\e[1;33m=== Setup File Permision ===\e[0m"
chown -R $CREATE_USER:$CREATE_USER /home/$CREATE_USER
chmod 711 /home/$CREATE_USER
echo -e "Please Wait..."
sleep 5
echo -e "\n\e[32;3m=== DONE ===\e[0m"
echo ""

#--- Store the passwords for user reference
{
echo "System has been installed"
echo ""
echo "Common Details"
echo "=============="
echo "Server IP address: $PUBLIC_IP"
echo "Server URL: http://$SVR_FQDN"
echo "Webmin URL: https://$SVR_FQDN:10000"
echo ""
echo "Database Details"
echo "================"
echo "MySQL Root User: $MYSQL_USER"
echo "MySQL Root Password: $MYSQL_PASSWD"
echo "MySQL Remote Port: 3306"
echo ""
echo "Website Development Information"
echo "==============================="
echo "Default Path: /home/$CREATE_USER/public_html/default"
} >> /root/Installation_Document.txt

#--- Advise the admin that PW SERVER is now installed and accessible.
{
echo "###########################################################"
echo " System has been installed on your server. "
echo " Please review the log file left in /root/ for "
echo " any errors encountered during installation."
echo "###########################################################"
echo ""
echo -e "\e[1;33mCommon Details\e[0m"
echo -e "\e[1;33m==============\e[0m"
echo "Server IP address: $PUBLIC_IP"
echo "Server URL: http://$SVR_FQDN"
echo "Webmin URL: https://$SVR_FQDN:10000"
echo ""
echo -e "\e[1;33mDatabase Details\e[0m"
echo -e "\e[1;33m================\e[0m"
echo "MySQL Root User: $MYSQL_USER"
echo "MySQL Root Password: $MYSQL_PASSWD"
echo "MySQL Remote Port: 3306"
echo ""
echo -e "\e[1;33mWebsite Development Information\e[0m"
echo -e "\e[1;33m===============================\e[0m"
echo "Default Path: /home/$CREATE_USER/public_html/default"
echo ""
echo -e "\e[1;33m#####################################################################\e[0m"
echo -e "\e[1;33m (theses documentation are saved in /root/Installation_Document.txt)\e[0m"
echo -e "\e[1;33m#####################################################################\e[0m"
echo ""
} &>/dev/tty
shutdown -r now
