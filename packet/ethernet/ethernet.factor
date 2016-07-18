! Copyright (C) 2016 Mike Maul.
! See http://factorcode.org/license.txt for BSD license.

USING: math syntax kernel accessors sequences combinators assocs ;

IN: packet.ethernet

CONSTANT: ethertypes H{
    { 0x0800 "IPv4" }
    { 0x0806 "ARP" }
    { 0x0842 "Wake-on-LAN" }
    { 0x22F3 "TRILL" }
    { 0x6003 "DECnet" }
    { 0x8035 "RARP" }
    { 0x809B "AppleTalk" }
    { 0x80F3 "AARP" }
    { 0x8100 "802.1Q" }
    { 0x8137 "IPX" }
    { 0x8204 "Qnet" }
    { 0x86DD "IPv6" }
    { 0x8808 "Ethernet flow control" }
    { 0x8819 "CobraNet" }
    { 0x8847 "MPLS unicast" }
    { 0x8848 "MPLS multicast" }
    { 0x8863 "PPPoE Discovery Stage" }
    { 0x8864 "PPPoE Session Stage" }
    { 0x8870 "Jumbo Frames" }
    { 0x887B "HomePlug 1.0 MME" }
    { 0x888E "EAP" }
    { 0x8892 "PROFINET" }
    { 0x889A "HyperSCSI" }
    { 0x88A2 "ATAoE" }
    { 0x88A4 "EtherCAT" }
    { 0x88A8 "802.1ad" }
    { 0x88AB "Powerlink" }
    { 0x88CC "LLDP" }
    { 0x88CD "SERCOS III" }
    { 0x88E1 "HomePlug AV MME" }
    { 0x88E3 "Media Redundancy Protocol (IEC62439-2)" }
    { 0x88E5 "802.1AE" }
    { 0x88E7 "802.1ah" }
    { 0x88F7 "PTPoE" }
    { 0x88FB "PRP" }
    { 0x8902 "IEEE 802.1ag" }
    { 0x8906 "FCoE Contol" }
    { 0x8914 "FCoE Initialization" }
    { 0x8915 "RoCE" }
    { 0x891D "TTEthernet Protocol Control Frame (TTE)" }
    { 0x892F "HSRP" }
    { 0x9000 "ECTP" }
}

TUPLE: ethernet mac-src mac-dst 8021q-tag ethernet-type ;

: 2octets>number ( seq -- num )
    [ 0 swap nth 8 shift ] keep 1 swap nth + ;

: ethertype>string ( b -- s )
    2octets>number ethertypes at ;

: parse-ethernet ( packet-byte-array -- packet-byte-array ethernet )
    dup ethernet new ! --> bytes hdr byte-array ethernet
    swap ! --> bytes hdr ethernet byte-array
    { [ 0 6 rot subseq >>mac-src ] [  6 12 rot subseq >>mac-dst ] 
      ! [ 0 6 rot subseq >>8021q-tag ] 
      [  12 14 rot subseq ethertype>string >>ethernet-type ] } 2cleave
    2drop ;

