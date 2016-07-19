! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: kernel sequences ;
IN: packet.util

: 2octets>number ( seq -- num )
    [ 0 swap nth 8 shift ] keep 1 swap nth + ;

