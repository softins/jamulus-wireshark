#!/bin/sh
#
# Capture all Jamulus packets, to and from specific IP addresses.
# Modify interface and port range as required.

INTERFACE=eth0
DATE=`date '+%Y%m%d-%H%M%S'`
FILE=jamulus-hosts-$DATE.pkt

cd /var/tmp

tcpdump -C 128 -i $INTERFACE -nn -p -s0 -w $FILE '(host 66.175.211.157 or 172.104.29.25 or 52.49.128.29 or 81.187.94.75 or 62.113.206.102 or 83.171.173.252) and udp portrange 22120-22139' </dev/null >/dev/null 2>&1 &
