! Copyright (C) 2016 Your name.
! See http://factorcode.org/license.txt for BSD license.
USING: kernel hashtables sequences.generalizations concurrency.mailboxes assocs ;
IN: packet


CONSTANT: post-office H{ }



:: push ( source source-port destination destination-port -- )
    [let <mailbox> :> mbox 
     source-port destination destination destination-port 4 nappend :> key
        key mbox post-office set-at 
        [.  ] source key >string mbox spawn-linked-to
        key mbox mailbox-put
