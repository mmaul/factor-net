USING: alien alien.syntax alien.libraries alien.c-types system combinators ;

IN: pcap.library
! "libsample" "libsample.so" cdecl add-library
: add-pcap-library ( -- )
  "libpcap" "libpcap.so" cdecl add-library ;
! {
!      ! { [ win32? ] [ "SampleDylib.dll" stdcall ] }
!      ! { [ macosx? ] [ "SampleDylib.dylib" cdecl ] }
!      { [ unix? ] [ "libsample.so" cdecl ] }
!  } cond add-library ;

add-pcap-library

LIBRARY: libpcap

FUNCTION: char* pcap_lookupdev ( char* errbuf )  

C-TYPE: pcap_t
FUNCTION: pcap_t* pcap_open_offline ( char* filename, char* errbuff )
STRUCT timeval
       { tv_sec uint }
       { tv_usec uing } ;
 

STRUCT  pcap_pkthdr 
        { ts rimeval }
	{ caplen uint }	
	bpf_u_int32 len;	
};

FUNCTION: const u_char*	pcap_next( pcap_t* handle , struct pcap_pkthdr *);

