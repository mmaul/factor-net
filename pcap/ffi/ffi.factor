! Copyright (C) 2016 Mike Maul.
! See http://factorcode.org/license.txt for BSD license.
USING: kernel system combinators
alien alien.syntax alien.libraries alien.c-types
tools.deploy.libraries classes.struct ;

IN: pcap.ffi

: add-pcap-library ( -- )
"wpcap" { { [ os windows = ] [ "wpcap.dll" find-library-file stdcall ] }
{ [ os linux = ] [ "libpcap.so" find-library-file dup "/usr/lib64/libpcap.so" ? cdecl ] }
{ [ os macosx = ] [ "libpcap.dylib" cdecl ] }
} cond add-library ;

add-pcap-library 
LIBRARY: wpcap

FUNCTION: char* pcap_lookupdev ( char* a )

C-TYPE: pcap_t

FUNCTION: pcap_t* pcap_open_offline ( char* filename, char* errbuf )

C-TYPE: bpf_program

C-TYPE: bpf_insn

STRUCT: bpf_program
{ bf_len uint }
{ bf_insns bpf_insn* } ;

FUNCTION: int pcap_compile ( pcap_t* p, bpf_program* fp, char* str, int optimize, uint netmask )

FUNCTION: int pcap_setfilter ( pcap_t* p, bpf_program* fp )

FUNCTION: char* pcap_geterr ( pcap_t* p )

STRUCT: pcap_hdr
{ magic uint } ! magic
{ version_major ushort } ! major version number
{ version_minor ushort } ! minor version number
{ thiszone uint } ! GMT to local correction
{ sigfigs uint } ! accuracy of timestamps
{ snaplen uint } ! max length of captured packets, in octets
{ network uint } ! data link type
;

! STRUCT: timeval { tvsec uint } { tvusec uint } ;
STRUCT: timeval { tvsec long } { tvusec long } ;

STRUCT: pcap_pkthdr
{ ts timeval }
{ caplen uint32_t }
{ len uint32_t } ;

FUNCTION: uchar* pcap_next ( pcap_t* p, pcap_pkthdr* h )

FUNCTION: pcap_t* pcap_open_live ( char* device, int snaplen, int promisc, int to_ms, char* ebuf )
