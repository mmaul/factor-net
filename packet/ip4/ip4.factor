USING: locals math syntax kernel accessors sequences combinators assocs ;

IN: packet.ip4
! Value	Protocol	References
CONSTANT: protocols H{
    { 0 "HOPOPT, IPv6 Hop-by-Hop Option" } ! RFC 2460
    { 1 "ICMP, Internet Control Message Protocol" } ! RFC 792
    { 2 "IGAP, IGMP for user Authentication Protocol.
    ! IGMP, Internet Group Management Protocol.
    ! RGMP, Router-port Group Management Protocol" } ! RFC 1112
    { 3 "GGP, Gateway to Gateway Protocol" } ! RFC 823
    { 4 "IP in IP encapsulation" } ! RFC 2003
    { 5 "ST, Internet Stream Protocol" } ! RFC 1190, RFC 1819
    { 6 "TCP, Transmission Control Protocol" } ! RFC 793
    { 7 "UCL, CBT" } 
    { 8 "EGP, Exterior Gateway Protocol" } ! RFC 888
    { 9 "IGRP, Interior Gateway Routing Protocol" } 
    { 10 "BBN RCC Monitoring" } 
    { 11 "NVP, Network Voice Protocol" } ! RFC 741
    { 12 "PUP" } 
    { 13 "ARGUS" } 
    { 14 "EMCON, Emission Control Protocol" } 
    { 15 "XNET, Cross Net Debugger" } ! IEN 158
    { 16 "Chaos" } 
    { 17 "UDP, User Datagram Protocol" } ! RFC 768
    { 18 "TMux, Transport Multiplexing Protocol" } ! IEN 90
    { 19 "DCN Measurement Subsystems" } 
    { 20 "HMP, Host Monitoring Protocol" } ! RFC 869
    { 21 "Packet Radio Measurement" } 
    { 22 "XEROX NS IDP" } 
    { 23 "Trunk-1" } 
    { 24 "Trunk-2" } 
    { 25 "Leaf-1" } 
    { 26 "Leaf-2" } 
    { 27 "RDP, Reliable Data Protocol" } ! RFC 908
    { 28 "IRTP, Internet Reliable Transaction Protocol" } ! RFC 938
    { 29 "ISO Transport Protocol Class 4" } ! RFC 905
    { 30 "NETBLT, Network Block Transfer" } 
    { 31 "MFE Network Services Protocol" } 
    { 32 "MERIT Internodal Protocol" } 
    { 33 "DCCP, Datagram Congestion Control Protocol" } 
    { 34 "Third Party Connect Protocol" } 
    { 35 "IDPR, Inter-Domain Policy Routing Protocol" } 
    { 36 "XTP, Xpress Transfer Protocol" } 
    { 37 "Datagram Delivery Protocol" } 
    { 38 "IDPR, Control Message Transport Protocol" } 
    { 39 "TP++ Transport Protocol" } 
    { 40 "IL Transport Protocol" } 
    { 41 "IPv6 over IPv4" } ! RFC 2473
    { 42 "SDRP, Source Demand Routing Protocol" } 
    { 43 "IPv6 Routing header" } 
    { 44 "IPv6 Fragment header" } 
    { 45 "IDRP, Inter-Domain Routing Protocol" } 
    { 46 "RSVP, Reservation Protocol" } 
    { 47 "GRE, General Routing Encapsulation" } 
    { 48 "DSR, Dynamic Source Routing Protocol" } 
    { 49 "BNA" } 
    { 50 "ESP, Encapsulating Security Payload" } 
    { 51 "AH, Authentication Header" } 
    { 52 "I-NLSP, Integrated Net Layer Security TUBA" } 
    { 53 "SWIPE, IP with Encryption" } 
    { 54 "NARP, NBMA Address Resolution Protocol" } 
    { 55 "Minimal Encapsulation Protocol" } 
    { 56 "TLSP, Transport Layer Security Protocol using Kryptonet key management" } 
    { 57 "SKIP" } 
    { 58 "ICMPv6, Internet Control Message Protocol for IPv6" }
    ! MLD, Multicast Listener Discovery" 
    { 59 "IPv6 No Next Header" } 
    { 60 "IPv6 Destination Options" } 
    { 61 "Any host internal protocol" } 
    { 62 "CFTP" } 
    { 63 "Any local network" } 
    { 64 "SATNET and Backroom EXPAK" } 
    { 65 "Kryptolan" } 
    { 66 "MIT Remote Virtual Disk Protocol" } 
    { 67 "Internet Pluribus Packet Core" } 
    { 68 "Any distributed file system" } 
    { 69 "SATNET Monitoring" } 
    { 70 "VISA Protocol" } 
    { 71 "Internet Packet Core Utility" } 
    { 72 "Computer Protocol Network Executive" } 
    { 73 "Computer Protocol Heart Beat" } 
    { 74 "Wang Span Network" } 
    { 75 "Packet Video Protocol" } 
    { 76 "Backroom SATNET Monitoring" } 
    { 77 "SUN ND PROTOCOL-Temporary" } 
    { 78 "WIDEBAND Monitoring" } 
    { 79 "WIDEBAND EXPAK" } 
    { 80 "ISO-IP" } 
    { 81 "VMTP, Versatile Message Transaction Protocol" } 
    { 82 "SECURE-VMTP " } 
    { 83 "VINES" } 
    { 84 "TTP" } 
    { 85 "NSFNET-IGP" } 
    { 86 "Dissimilar Gateway Protocol" } 
    { 87 "TCF" } 
    { 88 "EIGRP" } 
    { 89 "OSPF, Open Shortest Path First Routing Protocol.
    ! MOSPF, Multicast Open Shortest Path First" } 
    { 90 "Sprite RPC Protocol" } 
    { 91 "Locus Address Resolution Protocol" } 
    { 92 "MTP, Multicast Transport Protocol" } 
    { 93 "AX.25" } 
    { 94 "IP-within-IP Encapsulation Protocol" } 
    { 95 "Mobile Internetworking Control Protocol" } 
    { 96 "Semaphore Communications Sec. Pro" } 
    { 97 "EtherIP" } 
    { 98 "Encapsulation Header" } 
    { 99 "Any private encryption scheme" } 
    { 100 "GMTP" } 
    { 101 "IFMP, Ipsilon Flow Management Protocol" } 
    { 102 "PNNI over IP" } 
    { 103 "PIM, Protocol Independent Multicast" } 
    { 104 "ARIS" } 
    { 105 "SCPS" } 
    { 106 "QNX" } 
    { 107 "Active Networks" } 
    { 108 "IPPCP, IP Payload Compression Protocol" } ! RFC 2393
    { 109 "SNP, Sitara Networks Protocol" } 
    { 110 "Compaq Peer Protocol" } 
    { 111 "IPX in IP" } 
    { 112 "VRRP, Virtual Router Redundancy Protocol" } ! RFC 3768, RFC 5798
    { 113 "PGM, Pragmatic General Multicast" } 
    { 114 "any 0-hop protocol" } 
    { 115 "L2TP, Level 2 Tunneling Protocol" } ! RFC 3931
    { 116 "DDX, D-II Data Exchange" } 
    { 117 "IATP, Interactive Agent Transfer Protocol" } 
    { 118 "ST, Schedule Transfer" } 
    { 119 "SRP, SpectraLink Radio Protocol" } 
    { 120 "UTI" } 
    { 121 "SMP, Simple Message Protocol" } 
    { 122 "SM" } 
    { 123 "PTP, Performance Transparency Protocol" } 
    { 124 "ISIS over IPv4" } 
    { 125 "FIRE" } 
    { 126 "CRTP, Combat Radio Transport Protocol" } 
    { 127 "CRUDP, Combat Radio User Datagram" } 
    { 128 "SSCOPMCE" } 
    { 129 "IPLT" } 
    { 130 "SPS, Secure Packet Shield" } 
    { 131 "PIPE, Private IP Encapsulation within IP" } 
    { 132 "SCTP, Stream Control Transmission Protocol" } 
    { 133 "Fibre Channel" } ! RFC 6172
    { 134 "RSVP-E2E-IGNORE" } ! RFC 3175
    { 135 "Mobility Header" } ! RFC 3775
    { 136 "UDP-Lite, Lightweight User Datagram Protocol" } ! RFC 3828
    { 137 "MPLS in IP" } ! RFC 4023
    { 138 "MANET protocols" } ! RFC 5498
    { 139 "HIP, Host Identity Protocol" } ! RFC 5201
    { 140 "Shim6, Level 3 Multihoming Shim Protocol for IPv6" } ! RFC 5533
    { 141 "WESP, Wrapped Encapsulating Security Payload" } ! RFC 5840
    { 142 "ROHC, RObust Header Compression" } ! RFC 5858
    { 254 "Experimentation and testing" } 
    { 255 "reserved" }
}

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
          9  10 ba subseq first protocols at >>protocol
          10 12 ba subseq >>checksum
          12 16 ba subseq >>source
          16 20 ba subseq >>destination
      ba 20 tail
  ] swap ;

! packet>byte-array parse-ethernet drop parse-ip4