! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: tools.test packet.tcp pcap packet.ethernet packet.ip4
       io.files.temp io.pathnames kernel logging logging.server accessors ;
IN: packet.tcp.tests



temp-directory [
    "tcp-test" [
        [ B{ 1 3 3 8 1 1 4 2 } 49600 80 ]
        [ "work/factor-net/packet/test.pcap"  resource-path doit
               packet>byte-array
               parse-ethernet drop
               parse-ip4 [ source>> ] [ destination>> ] bi rot 
               parse-tcp [ source-port>> ] [ destination-port>> ] bi
               [ clear ] 3keep
             ] unit-test

    ] with-logging


] with-log-root
