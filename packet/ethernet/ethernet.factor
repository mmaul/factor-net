! Copyright (C) 2016 Mike Maul.
! See http://factorcode.org/license.txt for BSD license.

USING: math syntax kernel accessors sequences combinators assocs locals alien.syntax alien.enums 
    packet.util ;

IN: packet.ethernet

ENUM: ethertypes 
    { IPv4 0x0800 }
    { ARP  0x0806 }
    { Wake-on-LAN 0x0842 }
    { TRILL 0x22F3 }
    { DECnet 0x6003 }
    { RARP 0x8035 }
    { AppleTalk 0x809B }
    { AARP 0x80F3 }
    { 802.1Q 0x8100 }
    { IPX 0x8137 }
    { Qnet 0x8204 }
    { IPv6 0x86DD }
    { Ethernet-Flow-Control 0x8808  }
    { CobraNet 0x8819 }
    { MPLS-unicast 0x8847 }
    { MPLS-multicast 0x8848 }
    { PPPoE-Discovery 0x8863 }
    { PPPoE-Session 0x8864 }
    { Jumbo-Frames 0x8870 }
    { HomePlug 0x887B }
    { EAP 0x888E }
    { PROFINET 0x8892 }
    { HyperSCSI 0x889A }
    { ATAoE 0x88A2 }
    { EtherCAT 0x88A4 }
    { 802.1ad 0x88A8 }
    { Powerlink 0x88AB }
    { LLDP 0x88CC }
    { SERCOS 0x88CD }
    { HomePlug-AV-MME 0x88E1 }
    { Media-Redundancy-Protocol 0x88E3 }
    { 802.1AE 0x88E5 }
    { 802.1ah 0x88E7 }
    { PTPoE 0x88F7 }
    { PRP 0x88FB  }
    { 802.1ag 0x8902 }
    { FCoE-Contol 0x8906 }
    { FCoE-Initialization 0x8914 }
    { RoCE 0x8915 }
    { TTEthernet 0x891D }
    { HSRP 0x892F }
    { ECTP 0x9000 }
;

TUPLE: ethernet mac-src mac-dst 8021q-tag ethernet-type ;


: word>ethertype ( b -- s )
    2octets>number ethertypes number>enum ;

: parse-ethernet-old ( packet-byte-array -- packet-byte-array ethernet )
    dup ethernet new ! --> bytes hdr byte-array ethernet
    swap ! --> bytes hdr ethernet byte-array
    { [ 0 6 rot subseq >>mac-src ] [  6 12 rot subseq >>mac-dst ] 
      ! [ 0 6 rot subseq >>8021q-tag ] 
      [  12 14 rot subseq word>ethertype >>ethernet-type ] } 2cleave
    2drop ;


: parse-ethernet-new-old ( packet-byte-array -- packet-byte-array ethernet  )
    ethernet new ! --> bytes hdr byte-array ethernet
    swap ! --> bytes hdr ethernet byte-array
    { [ 0 6 rot subseq >>mac-src ] [  6 12 rot subseq >>mac-dst ] 
      ! [ 0 6 rot subseq >>8021q-tag ] 
      [  12 14 rot subseq word>ethertype >>ethernet-type ]
      [ 14 tail ] } 2cleave 
      2nip nip swap ;

: parse-ethernet ( packet-byte-array -- packet-byte-array ethernet  )
  [let :> ba
      ethernet new 
           0 6 ba subseq >>mac-src
           6 12 ba subseq >>mac-dst
           12 14 ba subseq >>8021q-tag
           12 14 ba subseq
               word>ethertype >>ethernet-type
      ba 14 tail
  ] swap ;

