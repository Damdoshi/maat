--TEST--
Maât authenticates no one when no trusted broker ticket is present
--EXTENSIONS--
maat
--FILE--
<?php
function maat_identity_from_nested_function() { return $_AUTH; }
var_dump(maat_identity_from_nested_function());
?>
--EXPECT--
NULL
