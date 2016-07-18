! Copyright (C) 2016 Mike Maul.
! See http://factorcode.org/license.txt for BSD license.
USING: accessors kernel combinators byte-arrays generalizations pcap.ffi
alien.strings alien.libraries alien.data
io io.encodings.utf8 classes.struct tools.hexdump
math.ranges sequences ;
IN: pcap


: open_offline ( fname -- pcap_t* )
utf8 string>alien 1024 <byte-array> pcap_open_offline ;

: init-pcap ( -- ) "wpcap" load-library drop ;
init-pcap

: lookupdev ( -- 8 )
256 <byte-array> pcap_lookupdev utf8 alien>string ;

: geterr ( handle -- errmsg )
pcap_geterr utf8 alien>string ;

: open-offline ( pcap_file -- handle/f )
utf8 string>alien 256 <byte-array> pcap_open_offline ;

: compile-filter ( handle str -- num filter )
bpf_program (malloc-struct) dup 4 -nrot swap utf8 string>alien 0 0 pcap_compile ;

: set-filter ( handle compiled-filter -- num )
pcap_setfilter ;

: next ( handle hdr -- handle hdr bytes )
2dup pcap_next ;

: doit ( fname -- handle hdr bytes )
open-offline pcap_pkthdr (malloc-struct) next ;

: dumpit ( hdr bytes -- hdr )
swap dup ! duplicatie header
len>> pick swap memory>byte-array hexdump print
swap drop ! remove extra bytes reference
;

! "C:\\Users\\mmaul\\Docs\\crap.pcap" open-offline dup dup "port 80" compile-filter [ 0 = ] [ drop set-filter ] [ print geterr ] if
! "C:\\Users\\mmaul\\Docs\\crap.pcap" open-offline dup pcap_pkthdr dup (malloc-struct) next
! "/home/mmaul/test.pcap"
: donumpn ( handle hdr n -- handle hdr )
[0,b] [ drop next dumpit ] each ;


! : into-ethernet ( tpl ba )
! swap 6 cut swap pick swap ;


: packet>byte-array ( hdr bytes -- hdr bytes byte-array ) 
    swap dup ! --> bytes hdr hdr
    len>> pick swap ! --> bytes hdr bytes l
    memory>byte-array ! --> bytes hdr byte-array
    swapd
;
