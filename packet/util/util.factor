! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: kernel sequences math ;
IN: packet.util

: 2octets>number ( seq -- num )
    [ 0 swap nth 8 shift ] keep 1 swap nth + ;

: 4octets>number ( seq -- num )
    [ 0 swap nth 24 shift ] keep [ 1 swap nth 16 shift ] keep [ 2 swap nth 8 shift ] keep 3 swap nth + + + ;

