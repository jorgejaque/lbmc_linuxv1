#! /bin/bash
#
#####################################################################
# This script attempts to gather information on 
# a variety of Linux hosts.  Files that exist in one distribution of
# Linux may not exist in another distribution (SuSE vs Red Hat).
# Please check the error-log file script_log/misc_err.log.
#
#####################################################################
#
ScriptVER="1.1"
#
#####################################################################

#clean terminal

clear



# So users can run the script using su or sudo
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH


# check for root permissions
#---------------------------
if [ `id -u` -ne 0 ]
then
   echo "This script must be run with root permissions.  Please rerun as root or with sudo."
   exit
fi


# Create root of output bundle 
#-----------------------------
CurDate=`/bin/date +%y%m%d_%H%M%S`
HostName=`uname -n`
LOGNAME="$HostName-$CurDate"
LOGDIR="/tmp/$LOGNAME"


echo "#####################################################################
#LBMC  
#This script attempts to gather information on 
# a variety of Linux hosts. 
#####################################################################"
echo ""
echo "Script starting"
echo "Log data will be stored in $LOGDIR"
echo "Output results will be tar-zipped to $LOGDIR.tgz"
echo ""
mkdir $LOGDIR
mkdir $LOGDIR/script_log
cd $LOGDIR
touch $LOGDIR/script_log/ScriptVersion.$ScriptVER



#-----------------------
echo "Collecting Data:"
echo ""

# Gather OS info 
#-------------------
# paths, variables, & directories needed early in the script 


mkdir $LOGDIR/OS


# OS release & version
#---------------------

UBUNTU=0
XEN=0
SLES=0

echo -n "Gathering OS release & version info "
OS_FILES=`ls /etc/*-release /etc/*_version 2>> $LOGDIR/script_log/misc_err.log`
for file in $OS_FILES
do
   if [ -f $file ]
   then
      cp -p $file $LOGDIR/OS
   fi
done

if [ -f $LOGDIR/OS/redhat-release ]
then
   OSNAME=`cat $LOGDIR/OS/redhat-release`
   if [ -f $LOGDIR/OS/rocks-release ]
   then
      OSNAME="$OSNAME / `cat $LOGDIR/OS/rocks-release`"
   fi
   TSTNM=`cat $LOGDIR/OS/redhat-release | cut -d " " -f 1`
   if [[ $TSTNM = XenServer ]]
   then
      XEN=1
   fi
elif [ -f $LOGDIR/OS/SuSE-release ]
then
   OSNAME=`grep -i suse $LOGDIR/OS/SuSE-release`
   OSVER=`grep VERSION $LOGDIR/OS/SuSE-release`
   OSPATCH=`grep -h PATCH $LOGDIR/OS/*release`
   SLES=1
elif [ -f $LOGDIR/OS/os-release ]
then
   OSNAME=`grep PRETTY $LOGDIR/OS/os-release | cut -d \" -f 2`
   UBUNTU=1
else
   OSNAME="unknown"
fi
echo "... done"


#####################################################################
# Gather info start
#####################################################################


# system
#-------
echo -n "Gathering Basic System info "

mkdir $LOGDIR/misc

if [[ $UBUNTU -eq 1 ]]
then
   dpkg-query -l > $LOGDIR/OS/dpkg-list.txt
else
   rpm -qa  > $LOGDIR/OS/rpm_list.txt
fi

uname -a > $LOGDIR/OS/uname
uptime   > $LOGDIR/misc/uptime.txt
w 	 > $LOGDIR/misc/w.txt



echo "... done"

#####################################################################
# Gather network info
#####################################################################

echo -n "Gathering Network info "
mkdir $LOGDIR/network

iptables --list > $LOGDIR/network/iptables.txt 
ifconfig -a     > $LOGDIR/network/ifconfig.txt 
ip addr show    > $LOGDIR/network/ipaddrshow.txt 
ip -s link show > $LOGDIR/network/iplinkshow.txt 
ss -a           > $LOGDIR/network/ss-s.txt 
netstat -rn     > $LOGDIR/network/netstat.txt
ip route        > $LOGDIR/network/ip-route.txt 

echo "... done"


#####################################################################
# Gather Port info
#####################################################################

echo -n "Gathering Ports info "

mkdir $LOGDIR/ports

netstat -antp 	> $LOGDIR/ports/listening_tcp.txt
netstat -anup   > $LOGDIR/ports/listening_udp.txt

echo "... done"


#####################################################################
# Gather System's Accounts and Groups info
#####################################################################

echo -n "Gathering System Accounts and Groups info "

mkdir $LOGDIR/accounts_groups

cat /etc/passwd > $LOGDIR/accounts_groups/syspasswd.txt
cat /etc/group  > $LOGDIR/accounts_groups/group.txt
cat /etc/hosts  > $LOGDIR/accounts_groups/host.txt
cat /etc/hosts.allow > $LOGDIR/accounts_groups/host.allow.txt
cat /etc/hosts.deny  > $LOGDIR/accounts_groups/hosts.deny.txt
lastlog > $LOGDIR/accounts_groups/lastlog.txt
last > $LOGDIR/accounts_groups/last.txt 

sudo getent shadow | grep '^[^:]*::' | cut -d: -f1 > $LOGDIR/accounts_groups/blankpass.txt

tar cPf $LOGDIR/accounts_groups/pam.d.tar /etc/pam.d/


cat /etc/login.defs > $LOGDIR/accounts_groups/logins.def.txt

cat /etc/login.defs | egrep -v "^\s*(#|$)" > $LOGDIR/accounts_groups/logins_nocomments.txt 

cat /etc/crontab > $LOGDIR/accounts_groups/crontab.txt


getent passwd | grep /home/ | cut -d ':' -f 1 >>$LOGDIR/accounts_groups/allusers_getent_passwd.txt


cat /etc/sudoers >>$LOGDIR/accounts_groups/sudoers.txt



echo "... done"




#####################################################################
# Gather SSH info
#####################################################################

echo -n "Gathering SSH info "

mkdir $LOGDIR/ssh

cat /etc/ssh/sshd_config >$LOGDIR/ssh/sshd_config_raw.txt

echo "... done"


#####################################################################
# Gather Permissions and Logs info
#####################################################################

echo -n "Gathering Permissions and Logs info "

mkdir $LOGDIR/sys_perm_logs



ls -la /etc/ >$LOGDIR/sys_perm_logs/etc_permissions.txt
ls -la / >$LOGDIR/sys_perm_logs/rootdir_permissions.txt
ls -l /var/log/ >$LOGDIR/sys_perm_logs/logfile_dir.txt
tail -n 500 /var/log/auth.log >$LOGDIR/sys_perm_logs/auth500.log.txt

if [ -e /var/log/audit/audit.log ];
then tail -n 500 /var/log/audit/audit.log >$LOGDIR/sys_perm_logs/audit500.log.txt
else ls /var/log/audit/audit.log 2>> $LOGDIR/script_log/misc_err.log
fi

if [ -e /var/log/secure ];
then tail -n 500 /var/log/secure >$LOGDIR/sys_perm_logs/secure500.txt
else ls /var/log/secure 2>> $LOGDIR/script_log/misc_err.log
fi


if [ -e /var/log/yum.log ];
then tail -n 500 /var/log/yum.log >$LOGDIR/sys_perm_logs/yum500.txt & yum check-update >$LOGDIR/sys_perm_logs/yum-check-update.txt
else ls /var/log/yum.log 2>> $LOGDIR/script_log/misc_err.log
fi


tar cPf $LOGDIR/sys_perm_logs/rsyslog.tar /etc/rsyslog.d/

cat /etc/rsyslog.conf >$LOGDIR/sys_perm_logs/rsyslog.conf.raw.txt
cat /etc/rsyslog.conf | egrep -v "^\s*(#|$)" >$LOGDIR/sys_perm_logs/rsyslog.conf_nocomments.txt



echo "... done"


#####################################################################
# Gather Running Processes info
#####################################################################

echo -n "Gathering Running Processes info "

mkdir $LOGDIR/processes

ps -au >$LOGDIR/processes/ps.au.txt
ps -aux >$LOGDIR/processes/ps.aux.txt

echo "... done"


#####################################################################
# Gather Adudit info
#####################################################################

echo -n "Gathering Audit info "

mkdir $LOGDIR/audit


#Audit.rules info:
#The audit packet must be installed first to generate audit.rules
#Debian/Ubuntu: apt-get install auditd audispd-plugins
#Red Hat/CentOS/Fedora: usually already installed (package: audit and audit-libs)'


if [ -e /etc/audit/audit.rules ];
then cat /etc/audit/audit.rules >/$LOGDIR/audit/auditd.rules.txt
else ls /etc/audit/audit.rules 2>> $LOGDIR/script_log/misc_err.log  
fi


echo "... done"



#####################################################################
# Start of dashboard.sh
#####################################################################
#####################################################################

echo -n "Creating dashboard.html "
cd $LOGDIR



#####################################################################
# Create dashboard.html for the script output
#####################################################################
DBH=$LOGDIR/dashboard.html
#
# Header
#
cat > $DBH <<!
<head><title>LBMC Linux Information Gathering Script - Dashboard</title></head> 
<body> 
<font face="Courier New"> 
 <a id="top"></a> 
<div align="center"> 
<b>LBMC Linux Information Gathering Script Dashboard</b><br> 
!
echo `date` >> $DBH
echo "<hr><hr></div>" >> $DBH

#
# Header
#
cat >> $DBH <<!
<pre>Script Version $ScriptVER
<hr> 
Index Info:
!

echo  "<a href=\"#systeminfo\">System Information</a>" >> $DBH
echo  "<a href=\"#networkinfo\">Network Information</a>" >> $DBH
echo  "<a href=\"#portsinfo\">Listening Ports Information</a>" >> $DBH
echo  "<a href=\"#sysloginfo\">System Accounts and Groups Information</a>" >> $DBH
echo  "<a href=\"#sshinfo\">SSH Information</a>" >> $DBH
echo  "<a href=\"#permlogsinfo\">Permissions and Logs Information</a>" >> $DBH
echo  "<a href=\"#runprocess\">Running Processes Information</a>" >> $DBH
echo  "<a href=\"#auditinfo\">Audit Information</a>" >> $DBH



echo "<br>" >> $DBH 

#################################################################
# End of dashboard header section:
#################################################################



# System Information
cat >> $DBH <<!
<hr><a id="systeminfo"></a><b><a href= OS >System Information:</a></b>     <a href="#top">top</a><hr> 
!
HOSTNAME=`cut -d " " -f2 < $LOGDIR/OS/uname`
echo "Host Name:                 $HOSTNAME" >> $DBH
echo "OS Name:                   $OSNAME" >> $DBH

if [ -f $LOGDIR/OS/SuSE-release ]
then
   echo "OS Version:                $OSVER,   $OSPATCH" >> $DBH
fi

KERNELVERSION=`cut -d " " -f3 < $LOGDIR/OS/uname`
echo "Kernel Version:            $KERNELVERSION" >> $DBH
echo "System Up Time:           `cat $LOGDIR/misc/uptime.txt`" >> $DBH



#Network Information
cat >> $DBH <<!
<hr><a id="networkinfo"></a><b><a href= network >Network Information:</a></b>     <a href="#top">top</a><hr>
!

echo -n "Interfaces configuration information:..............." >> $DBH
echo "<a href=\"network/ifconfig.txt\">ifconfig on $HOSTNAME</a>" >> $DBH
echo >> $DBH



#Ports Information
cat >> $DBH <<!
<hr><a id="portsinfo"></a><b><a href= ports >Listening Ports Information:</a></b>     <a href="#top">top</a><hr>
!

echo -n "TCP ports information:.............................." >> $DBH
echo "<a href=\"ports/listening_tcp.txt\">TCP Ports on $HOSTNAME</a>" >> $DBH


#echo -n  "<a href=\"ports/listening_tcp.txt\">TCP Ports</a>" >> $DBH
#echo " : TCP Ports information on" $HOSTNAME >> $DBH
#echo >> $DBH


echo -n "UDP ports information:.............................." >> $DBH
echo "<a href=\"ports/listening_udp.txt\">UDP Ports on $HOSTNAME</a>" >> $DBH
echo >> $DBH


#echo -n  "<a href=\"ports/listening_udp.txt\">UDP Ports</a>" >> $DBH
#echo " : UDP Ports information on" $HOSTNAME >> $DBH
#echo >> $DBH


#HOST Access Information
cat >> $DBH <<!
<hr><a id="sysloginfo"></a><b><a href= accounts_groups >System Accounts and Groups Information:</a></b>     <a href="#top">top</a><hr>
!


rootusers=$(perl -n -e '@user = split /:/ ; print "@user[0]\n" if @user[2] == "0";' < $LOGDIR/accounts_groups/syspasswd.txt)

echo "Users with Root privileges:.........................$rootusers" >> $DBH


sudoers=$(grep -Po '^sudo.+:\K.*$' $LOGDIR/accounts_groups/group.txt)

if [ -z "$sudoers" ]
then echo "Users with SUDO privileges:.........................No sudoers users found" >> $DBH
else echo "Users with SUDO privileges:.........................$sudoers" >> $DBH
fi


echo -n "Users Last Logins Info:............................." >> $DBH
echo "<a href=\"accounts_groups/lastlog.txt\">Last Logins</a>" >> $DBH


cut -f 1 -d: $LOGDIR/accounts_groups/syspasswd.txt | xargs -n 1 -I {} bash -c " echo {} ; chage -l {}" > $LOGDIR/accounts_groups/users_passw_info.txt

echo -n "Users Passwords Expiration:........................." >> $DBH
echo "<a href=\"accounts_groups/users_passw_info.txt\">Users Info found on $HOSTNAME</a>" >> $DBH
echo >> $DBH



#SSH Information
cat >> $DBH <<!
<hr><a id="sshinfo"></a><b><a href= ssh >SSH Information:</a></b>     <a href="#top">top</a><hr>
!


cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" > $LOGDIR/ssh/sshd_config_comments.txt
echo -n "SSH /etc/ssh/sshd_config:..........................." >> $DBH
echo "<a href=\"ssh/sshd_config_comments.txt\">SSH settings found on $HOSTNAME</a>" >> $DBH
echo >> $DBH


#Permissions and Logs Information
cat >> $DBH <<!
<hr><a id="permlogsinfo"></a><b><a href= sys_perm_logs >Permissions and Logs Information:</a></b>     <a href="#top">top</a><hr>
!


grep "authentication failure" /var/log/auth.log > $LOGDIR/sys_perm_logs/failures.txt


grep "authentication failure" $LOGDIR/sys_perm_logs/failures.txt | wc -l > $LOGDIR/sys_perm_logs/failures_counts.txt

failures=$(cat $LOGDIR/sys_perm_logs/failures_counts.txt)


echo -n "Failed Login Attempts:.............................." >> $DBH
echo "<a href=\"sys_perm_logs/failures.txt\">$failures logs found</a>" >> $DBH
echo >> $DBH


echo -n "Root Dir Permissions:..............................." >> $DBH
echo "<a href=\"sys_perm_logs/rootdir_permissions.txt\">listed files on $HOSTNAME</a>" >> $DBH
echo >> $DBH



#Running Processes Information
cat >> $DBH <<!
<hr><a id="runprocess"></a><b><a href= processes >Running Processes Information:</a></b>     <a href="#top">top</a><hr>
!

pstree > $LOGDIR/processes/processes_tree.txt

echo -n "Tree of processes:.................................." >> $DBH
echo "<a href=\"processes/processes_tree.txt\">Display on $HOSTNAME</a>" >> $DBH
echo >> $DBH



#Audit Information
cat >> $DBH <<!
<hr><a id="auditinfo"></a><b><a href= audit >Audit Information:</a></b>     <a href="#top">top</a><hr>
!



#Audit.rules info:
#The audit packet must be installed first to generate audit.rules
#Debian/Ubuntu: apt-get install auditd audispd-plugins
#Red Hat/CentOS/Fedora: usually already installed (package: audit and audit-libs)'




if [ -e /etc/audit/audit.rules ];
then 
	echo -n "Audit Rules Info:       " >> $DBH
	echo "<a href=\"audit/auditd.rules.txt\">Rules found on $HOSTNAME</a>" >> $DBH
	echo >> $DBH

else
	echo -n "Audit Rules Info:       " >> $DBH
	echo "<a>The audit packet must be installed first to generate audit.rules
                        #Debian/Ubuntu: apt-get install auditd audispd-plugins
                        #Red Hat/CentOS/Fedora: usually already installed (package: audit and audit-libs)</a>" >> $DBH
	echo >> $DBH

fi




#
# Wrap it up
#

echo ... done

#####################################################################
# Create compressed archive of results ... then clean up
#####################################################################
echo -n "Creating compressed archive and cleaning up ... "

cd /tmp
tar czf $LOGNAME.tgz ./$LOGNAME
if test $? -ne 0 
then
   echo "*!*! Error while archiving the support data."
   echo "     Please tar and compress $LOGDIR by hand"
   echo "     and Email it to ____@lbmc.com"
else
   rm -rf /tmp/$LOGNAME
   echo "done"
   echo
   echo "Please send us the file: $LOGDIR.tgz to the following email address: __@lbmc.com"
fi

#####################################################################
# All done ...
#####################################################################
exit

