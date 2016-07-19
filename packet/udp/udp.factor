! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: locals math syntax kernel accessors sequences combinators assocs alien.syntax alien.enums 
    packet.util ;
IN: packet.udp


TUPLE: udp source-port destination-port length checksum ;

: parse-udp ( packet-byte-array -- packet-byte-array ethernet  )
  [let :> ba
      udp new
          0  2 ba subseq 2octets>number >>source-port         ! bit field
          2  4 ba subseq 2octets>number >>destination-port   ! bit field
          4  6 ba subseq 2octets>number >>length
          6  8 ba subseq 2octets>number >>checksum
      ba 8 tail
  ] swap ;
