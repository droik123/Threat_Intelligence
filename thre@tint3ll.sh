#!/bin/bash 
#Blacklist/Blocklist Tracker segregated by Threat Actors.    
#Feel free to use and modify as needed   
#   
#Author: Ashis Sahoo
#Special Thanks to Adrian Daucourt for sharing the code in his blog.  Made some minor modifications   
#The modifications have been made to save the files in csv format for use with several different SIEM products such as ArcSight, Qradar, Splunk etc. 
#Also trying to implement a Threat Actor Model on the SIEM platforms. 
#==============================================================================
#Fix error when calling script from Splunk
#==============================================================================

unset LD_LIBRARY_PATH

#==============================================================================
#Make thre@tint3ll Directory
#==============================================================================

mkdir /thre@tint3ll

#==============================================================================
#Emerging Threats - Shadowserver C&C List, Spamhaus DROP Nets, Dshield Top
#Attackers
#==============================================================================

wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O /tmp/emerging-Block-IPs.txt --no-check-certificate -N

echo "# Generated: `date`" > /thre@tint3ll/Feodo.csv

awk '/Feodo/{p=1;print;next} p &&/Zeus/{p=0};p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Feodo/'>>/thre@tint3ll/Feodo.csv

echo "# Generated: `date`" > /thre@tint3ll/Zeus.csv

awk '/Zeus/{p=1;print;next} p &&/Spyeye/{p=0};p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Zeus/'>>/thre@tint3ll/Zeus.csv

echo "# Generated: `date`" > /thre@tint3ll/Spyeye.csv

awk '/Spyeye/{p=1;print;next} p &&/Palevo/{p=0};p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Spyeye/'>>/thre@tint3ll/Spyeye.csv

echo "# Generated: `date`" > /thre@tint3ll/Palevo.csv

awk '/Palevo/{p=1;print;next} p &&/Spamhaus DROP Nets/{p=0};p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Palevo/'>>/thre@tint3ll/Palevo.csv

echo "# Generated: `date`" > /thre@tint3ll/Spamhausdropnets.csv

awk '/Spamhaus DROP Nets/{p=1;print;next} p &&/Spamhaus DROP Nets/{p=0};p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Spamhausdropnets/'>>/thre@tint3ll/Spamhausdropnets.csv

echo "# Generated: `date`" > /thre@tint3ll/Dshield.csv

awk '/Dshield Top Attackers/{p=1;print;next} p'  /tmp/emerging-Block-IPs.txt|sed -n '/^[0-9]/p'|sed 's/$/,Dshield/'>>/thre@tint3ll/Dshield.csv

rm /tmp/emerging-Block-IPs.txt

#==============================================================================
#Emerging Threats - Compromised IP List
#==============================================================================

wget http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O /tmp/compromised-ips.txt --no-check-certificate -N

echo "# Generated: `date`" >/thre@tint3ll/ET_compromised_ips.csv

cat /tmp/compromised-ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,ET_Compromised_IP/' >> /thre@tint3ll/ET_compromised_ips.csv

rm /tmp/compromised-ips.txt

#==============================================================================
#Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
#==============================================================================

wget http://www.binarydefense.com/banlist.txt -O /tmp/binary_defense_ips.txt --no-check-certificate -N

echo "# Generated: `date`" > /thre@tint3ll/BD_ban_list.csv

cat /tmp/binary_defense_ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,BD_Banlist_IP/' >> /thre@tint3ll/BD_ban_list.csv

rm /tmp/binary_defense_ips.txt

#==============================================================================
#AlienVault - IP Reputation Database
#==============================================================================

wget https://reputation.alienvault.com/reputation.snort.gz -P /tmp --no-check-certificate -N

gzip -d /tmp/reputation.snort.gz

echo "# Generated: `date`" > /thre@tint3ll/AlienV_Malicious.csv

sed -n '/Malicious/p' /tmp/reputation.snort|cut -d' ' -f1-1|sed ''s/$/,AlienV_Malicious/''>>/thre@tint3ll/AlienV_Malicious.csv

echo "# Generated: `date`" > /thre@tint3ll/AlienV_Scanning.csv

sed -n '/Scanning/p' /tmp/reputation.snort|cut -d' ' -f1-1|sed ''s/$/,AlienV_Scanning/''>>/thre@tint3ll/AlienV_Scanning.csv

echo "# Generated: `date`" > /thre@tint3ll/AlienV_Spamming.csv

sed -n '/Spamming/p' /tmp/reputation.snort|cut -d' ' -f1-1|sed ''s/$/,AlienV_Spamming/''>>/thre@tint3ll/AlienV_Spamming.csv

rm /tmp/reputation.snort

#==============================================================================
#SSLBL - SSL Blacklist
#==============================================================================

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O /tmp/sslipblacklist.csv --no-check-certificate -N

echo "# Generated: `date`" > /thre@tint3ll/sslipblacklist.csv

cat /tmp/sslipblacklist.csv | sed -n '/^[0-9]/p' | cut -d',' -f1,3 | sed "s/,/ /" |sed 's/ /,/'>> /thre@tint3ll/sslipblacklist.csv

rm /tmp/sslipblacklist.csv

#==============================================================================
#ZeuS Tracker - IP Block List - Removed this, since ET Tracker pulls the same list of Zeus IP Addresses
#==============================================================================

#wget https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist -O /tmp/zeustracker.txt --no-check-certificate -N

#echo "# Generated: `date`" > /thre@tint3ll/zeus_ip_block_list.txt

#cat /tmp/zeustracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ Zeus IP/' >> /thre@tint3ll/zeus_ip_block_list.txt

#rm /tmp/zeustracker.txt

#==============================================================================
#SpyEye Tracker - IP Block List - This list has been stopped
#==============================================================================

#wget https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist -O /tmp/spyeyetracker.txt --no-check-certificate -N

#echo "# Generated: `date`" > /thre@tint3ll/spyeye_ip_block_list.txt

#cat /tmp/spyeyetracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ Spyeye IP/' >> /thre@tint3ll/spyeye_ip_block_list.txt

#rm /tmp/spyeyetracker.txt

#==============================================================================
#Palevo Tracker - IP Block List - Removed this, since ET Tracker pulls the same list of Zeus IP Addresses
#==============================================================================

#wget https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist -O /tmp/palevotracker.txt --no-check-certificate -N

#cat /tmp/palevotracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ ,Palevo_IP/' >> /thre@tint3ll/Palevo.csv

#rm /tmp/palevotracker.txt

#==============================================================================
#Malc0de - Malc0de Blacklist
#==============================================================================

wget http://malc0de.com/bl/IP_Blacklist.txt -O /tmp/IP_Blacklist.txt --no-check-certificate -N

echo "# Generated: `date`" > /thre@tint3ll/malc0de_black_list.csv

cat /tmp/IP_Blacklist.txt | sed -n '/^[0-9]/p' | sed 's/$/,Malc0de_IP/' >> /thre@tint3ll/malc0de_black_list.csv

rm /tmp/IP_Blacklist.txt

#==============================================================================
#Ransomware Trackers
#==============================================================================

wget https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt -O /tmp/Ransomware.txt --no-check-certificate -N

echo "# Generated: `date`" > /thre@tint3ll/Ransomware.csv

cat /tmp/Ransomware.txt | sed -n '/^[0-9]/p' | sed 's/$/,Ransomware/' >> /thre@tint3ll/Ransomware.csv

rm /tmp/Ransomware.txt

