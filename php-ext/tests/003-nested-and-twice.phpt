--TEST--
Maât _AUTH superglobal exists inside nested functions and is request local
--EXTENSIONS--
maat
--FILE--
<?php
function layer1() { return layer2(); }
function layer2() { return $_AUTH; }
var_dump(array_key_exists('_AUTH', $GLOBALS));
var_dump(layer1());
var_dump(layer1());
?>
--EXPECT--
bool(true)
NULL
NULL
