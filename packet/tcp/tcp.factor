
! Copyright (C) 2016 Mike Maul
! See http://factorcode.org/license.txt for BSD license.
USING: locals math syntax kernel accessors sequences combinators assocs alien.syntax alien.enums 
    packet.util logging ;
IN: packet.tcp

! 0                   1                   2                   3   
!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  0  |          Source Port          |       Destination Port        |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  4  |                        Sequence Number                        |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  8  |                    Acknowledgment Number                      |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  12 |  Data |           |U|A|P|R|S|F|                               |
!     | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
!     |       |           |G|K|H|T|N|N|                               |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  16 |           Checksum            |         Urgent Pointer        |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  20 |                    Options                    |    Padding    |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  24 |                             data                              |
!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!

TUPLE: tcp source-port destination-port sequence-number acknowledgement-number
    data-offset reserved urg ack psh rst syn fin window checksum urgent-pointer
    options padding data ;

: parse-tcp ( packet-byte-array -- packet-byte-array ethernet )
  [let :> ba
      tcp new
          0  2 ba subseq 2octets>number >>source-port         ! bit field
          2  4 ba subseq 2octets>number >>destination-port   ! bit field
          4  8 ba subseq 4octets>number >>sequence-number
          4  8 ba subseq 4octets>number >>acknowledgement-number
          8  9 ba subseq first 0x15 and >>data-offset
         10 11 ba subseq first 0x20 and 0 > >>urg
         10 11 ba subseq first 0x10 and 0 > >>ack
         10 11 ba subseq first 0x08 and 0 > >>psh
         10 11 ba subseq first 0x04 and 0 > >>rst
         10 11 ba subseq first 0x02 and 0 > >>syn
         10 11 ba subseq first 0x15 and 0 > >>fin
         ! 10 13 ba subseq dup first 0x03 and { } 1sequence swap 1 3 subseq append >>window 
         14 16 ba subseq 2octets>number >>checksum
         16 18 ba subseq >>urgent-pointer
         20 23 ba subseq >>options
         23 24 ba subseq >>padding
      ba 24 tail
  ] swap ;

\ parse-tcp NOTICE add-output-logging
