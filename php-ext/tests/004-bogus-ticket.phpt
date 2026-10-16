--TEST--
Maât does not authenticate a user merely because of an HTTP bearer string
--EXTENSIONS--
maat
--FILE--
<?php
$_SERVER['HTTP_X_MAAT_TICKET'] = str_repeat('a', 64);
function identity() { return $_AUTH; }
var_dump(identity());
?>
--EXPECT--
NULL
