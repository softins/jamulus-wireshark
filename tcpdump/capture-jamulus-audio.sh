#!/bin/sh
#
# Capture only Jamulus audio packets.
# Modify interface and port range as required.

INTERFACE=eth0
DATE=`date '+%Y%m%d-%H%M%S'`
FILE=jamulus-audio-$DATE.pkt

cd /var/tmp

tcpdump -C 128 -i $INTERFACE -nn -p -s0 -w $FILE 'udp portrange 22120-22139 and (udp[8:2] != 0 or udp[4:2]-17 != (udp[14]<<8)+udp[13])' </dev/null >/dev/null 2>&1 &
