#!/bin/sh
#
# Capture only Jamulus protocol packets, to and from specific IP addresses.
# Modify interface, host list and port range as required.
#
# Includes IP fragments for reassembling split packets.

INTERFACE=eth0
DATE=`date '+%Y%m%d-%H%M%S'`
FILE=jamulus-proto-hosts-$DATE.pkt

cd /var/tmp

tcpdump -C 32 -i $INTERFACE -nn -p -s0 -w $FILE '(host 66.175.211.157 or 172.104.29.25 or 52.49.128.29 or 81.187.94.75 or 62.113.206.102 or 83.171.173.252) and ((ip[6:2]&0x3fff) != 0 or (udp portrange 22120-22139 and (udp[8:2] == 0 and udp[4:2]-17 == (udp[14]<<8)+udp[13])))' </dev/null >/dev/null 2>&1 &
