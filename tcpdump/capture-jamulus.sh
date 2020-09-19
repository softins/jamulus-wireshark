#!/bin/sh
#
# Capture all Jamulus packets.
# Modify interface and port range as required.

INTERFACE=eth0
DATE=`date '+%Y%m%d-%H%M%S'`
FILE=jamulus-$DATE.pkt

cd /var/tmp

tcpdump -C 128 -i $INTERFACE -nn -p -s0 -w $FILE 'udp portrange 22120-22139' </dev/null >/dev/null 2>&1 &
