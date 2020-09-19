#!/bin/sh
#
# Capture only Jamulus protocol packets.
# Modify interface and port range as required.
#
# Includes IP fragments for reassembling split packets.

INTERFACE=eth0
DATE=`date '+%Y%m%d-%H%M%S'`
FILE=jamulus-proto-$DATE.pkt

cd /var/tmp

tcpdump -C 32 -i $INTERFACE -nn -p -s0 -w $FILE '(ip[6:2]&0x3fff) != 0 or (udp portrange 22120-22139 and (udp[8:2] == 0 and udp[4:2]-17 == (udp[14]<<8)+udp[13]))' </dev/null >/dev/null 2>&1 &
