! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: kernel dns pcap packet.ethernet packet.ip4 packet.udp ;
IN: packet.layer7.dns

: next-dns-message ( handle hdr -- msg x x x )
next packet>byte-array parse-ethernet drop parse-ip4 drop parse-udp drop parse-message
;
