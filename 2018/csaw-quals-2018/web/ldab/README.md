Fuzz for a while, find if search ``*`` and ``)`` would return something different, consider title ``ldab``, guess it's a LDAP injection.

try ``objectclass``, but do not find anything useful, seems flag is in this table, but there add some condition to make it invisible.

So after we closed condition by ``*)))%00``, we will see the flag.
flag{ld4p_inj3ction_i5_a_th1ng}
