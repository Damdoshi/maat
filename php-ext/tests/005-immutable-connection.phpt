--TEST--
Maât auto-global never authenticates from HTTP header mutations
--EXTENSIONS--
maat
--FILE--
<?php
function first() { return $_AUTH; }
var_dump(first());
$_SERVER['HTTP_X_MAAT_TICKET'] = str_repeat('f', 64);
function second() { return $_AUTH; }
var_dump(second());
?>
--EXPECT--
NULL
NULL
