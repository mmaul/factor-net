USING: locals math syntax kernel accessors sequences combinators assocs alien.syntax alien.enums ;

IN: packet.ip4
! Value	Protocol	References
ENUM: protocols 
    { HOPOPT 0 } !  Option ! RFC 2460 
    { ICMP 1 } !  Protocol ! RFC 792 
!    { ICMP 1 } !  Protocol ! RFC 792 
!    { ICMP 1 } !  Protocol ! RFC 792 
!    { ICMP 1 } !  Protocol ! RFC 792 
    { GGP 3 } !  Protocol ! RFC 823 
    { IP 4 } ! in encapsulation ! RFC 2003 
    { ST 5 } !  Protocol ! RFC 1190, RFC 1819 
    { TCP 6 } !  Protocol ! RFC 793 
    { UCL 7 } !  CBT  
    { EGP 8 } !  Protocol ! RFC 888 
    { IGRP 9 } !  Protocol  
    { BBN 10 } ! RCC Monitoring  
    { NVP 11 } !  Protocol ! RFC 741 
    { PUP 12 } !  PUP  
    { ARGUS 13 } !  ARGUS  
    { EMCON 14 } !  Protocol  
    { XNET 15 } !  Debugger ! IEN 158 
    { Chaos 16 } !  Chaos  
    { UDP 17 } !  Protocol ! RFC 768 
    { TMux 18 } !  Protocol ! IEN 90 
    { DCN 19 } ! Measurement Subsystems  
    { HMP 20 } !  Protocol ! RFC 869 
    { Packet-Radio-Measurment 21 } ! Radio Measurement  
    { XEROX 22 } ! NS IDP  
    { Trunk-1 23 } !  Trunk-1  
    { Trunk-2 24 } !  Trunk-2  
    { Leaf-1 25 } !  Leaf-1  
    { Leaf-2 26 } !  Leaf-2  
    { RDP 27 } !  Protocol ! RFC 908 
    { IRTP 28 } !  Protocol ! RFC 938 
    { ISO 29 } ! Transport 4 ! RFC 905 
    { NETBLT 30 } !  Transfer  
    { MFE 31 } ! Network Protocol  
    { MERIT 32 } ! Internodal Protocol  
    { DCCP 33 } !  Protocol  
    { Third 34 } ! Party Protocol  
    { IDPR-CM 35 } !  Protocol  
    { XTP 36 } !  Protocol  
    { Datagram 37 } ! Delivery Protocol  
    { IDPR 38 } !  Protocol  
    { TP++ 39 } ! Transport Protocol  
    { IL 40 } ! Transport Protocol  
    { IPv6oIPv4 41 } ! over IPv4 ! RFC 2473 
    { SDRP 42 } !  Protocol  
    { IPv6-RH 43 } ! Routing header  
    { IPv6-FH 44 } ! Fragment header  
    { IDRP 45 } !  Protocol  
    { RSVP 46 } !  Protocol  
    { GRE 47 } !  Encapsulation  
    { DSR 48 } !  Protocol  
    { BNA 49 } !  BNA  
    { ESP 50 } !  Payload  
    { AH 51 } !  Header  
    { I-NLSP 52 } !  TUBA  
    { SWIPE 53 } !  Encryption  
    { NARP 54 } !  Protocol  
    { Minimal 55 } ! Encapsulation Protocol  
    { TLSP 56 } !  management  
    { SKIP 57 } !  SKIP  
 !   { SKIP 57 } !  SKIP  
 !   { SKIP 57 } !  SKIP  
    { IPv6-NH 59 } ! No Header  
    { IPv6-DO 60 } ! Destination Options  
    { AnyHost 61 } ! host protocol  
    { CFTP 62 } !  CFTP  
    { AnyLocal 63 } ! local network  
    { SATNET 64 } ! and EXPAK  
    { Kryptolan 65 } !  Kryptolan  
    { MIT 66 } ! Remote Protocol  
    { Internet-Pluribus 67 } ! Pluribus Core  
    { AnyDist 68 } ! distributed system  
    { SATNET-MON 69 } ! Monitoring Monitoring  
    { VISA 70 } ! Protocol Protocol  
    { Internet-Packet-Utility 71 } ! Packet Utility  
    { Computer-Executive 72 } ! Protocol Executive  
    { Computer-Beat 73 } ! Protocol Beat  
    { Wang 74 } ! Span Network  
    { Packet-Video 75 } ! Video Protocol  
    { Backroom 76 } ! SATNET Monitoring  
    { SUN 77 } ! ND PROTOCOL-Temporary  
    { WIDEBAND-MON 78 } ! Monitoring Monitoring  
    { WIDEBAND 79 } ! EXPAK EXPAK  
    { ISO-IP 80 } !  ISO-IP  
    { VMTP 81 } !  Protocol  
    { SECURE-VMTP 82 } !  SECURE-VMTP  
    { VINES 83 } !  VINES  
    { TTP 84 } !  TTP  
    { NSFNET-IGP 85 } !  NSFNET-IGP  
    { Dissimilar 86 } ! Gateway Protocol  
    { TCF 87 } !  TCF  
    { EIGRP 88 } !  EIGRP  
  !  { EIGRP 88 } !  EIGRP  
  !  { EIGRP 88 } !  EIGRP  
    { Sprite 90 } ! RPC Protocol  
    { Locus 91 } ! Address Protocol  
    { MTP 92 } !  Protocol  
    { AX.25 93 } !  AX.25  
    { IP-within-IP 94 } ! Encapsulation Protocol  
    { Mobile 95 } ! Internetworking Protocol  
    { Semaphore 96 } ! Communications Pro  
    { EtherIP 97 } !  EtherIP  
    { Encapsulation 98 } ! Header Header  
    { Any 99 } ! private scheme  
    { GMTP 100 } !  GMTP  
    { IFMP 101 } !  Protocol  
    { PNNI 102 } ! over IP  
    { PIM 103 } !  Multicast  
    { ARIS 104 } !  ARIS  
    { SCPS 105 } !  SCPS  
    { QNX 106 } !  QNX  
    { Active 107 } ! Networks Networks  
    { IPPCP 108 } !  Protocol ! RFC 2393 
    { SNP 109 } !  Protocol  
    { Compaq 110 } ! Peer Protocol  
    { IPX 111 } ! in IP  
    { VRRP 112 } !  Protocol ! RFC 3768, RFC 5798 
    { PGM 113 } !  Multicast  
    { any 114 } ! 0-hop protocol  
    { L2TP 115 } !  Protocol ! RFC 3931 
    { DDX 116 } !  Exchange  
    { IATP 117 } !  Protocol  
    { ST-Transfer 118 } !  Transfer  
    { SRP 119 } !  Protocol  
    { UTI 120 } !  UTI  
    { SMP 121 } !  Protocol  
    { SM 122 } !  SM  
    { PTP 123 } !  Protocol  
    { ISIS 124 } ! over IPv4  
    { FIRE 125 } !  FIRE  
    { CRTP 126 } !  Protocol  
    { CRUDP 127 } !  Datagram  
    { SSCOPMCE 128 } !  SSCOPMCE  
    { IPLT 129 } !  IPLT  
    { SPS 130 } !  Shield  
    { PIPE 131 } !  IP  
    { SCTP 132 } !  Protocol  
    { Fibre 133 } ! Channel Channel ! RFC 6172 
    { RSVP-E2E-IGNORE 134 } !  RSVP-E2E-IGNORE ! RFC 3175 
    { Mobility 135 } ! Header Header ! RFC 3775 
    { UDP-Lite 136 } !  Protocol ! RFC 3828 
    { MPLS 137 } ! in IP ! RFC 4023 
    { MANET 138 } ! protocols protocols ! RFC 5498 
    { HIP 139 } !  Protocol ! RFC 5201 
    { Shim6 140 } !  IPv6 ! RFC 5533 
    { WESP 141 } !  Payload ! RFC 5840 
    { ROHC 142 } !  Compression ! RFC 5858 
    { Experimentation 254 } ! and testing  
  !  { Experimentation 254 } ! and testing  
    ;

TUPLE: ip4 version header-length fields total-length identification flags fragment-offset ttl protocol checksum source destination ;

: parse-ip4 ( packet-byte-array -- packet-byte-array ethernet  )
  [let :> ba
      ip4 new
          0  1 ba subseq >>version         ! bit field
          0  1 ba subseq >>header-length   ! bit field
          1  2 ba subseq >>fields
          2  4 ba subseq >>total-length
          4  6 ba subseq >>identification
          6  7 ba subseq >>flags           ! bit field
          6  8 ba subseq >>fragment-offset ! bit field
          8  9 ba subseq first >>ttl
          9  10 ba subseq first protocols number>enum >>protocol
          10 12 ba subseq >>checksum
          12 16 ba subseq >>source
          16 20 ba subseq >>destination
      ba 20 tail
  ] swap ;

! packet>byte-array parse-ethernet drop parse-ip4
