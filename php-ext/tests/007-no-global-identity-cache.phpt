--TEST--
Maât _AUTH is initialized to NULL without Apache context even if $_SERVER is modified
--EXTENSIONS--
maat
--FILE--
<?php
function read_auth() { return $_AUTH; }
var_dump(read_auth());
$_SERVER['HTTP_X_MAAT_TICKET'] = str_repeat('f', 64);
$_SERVER['HTTP_X_MAAT_USER'] = 'alice';
var_dump(read_auth());
?>
--EXPECT--
NULL
NULL
