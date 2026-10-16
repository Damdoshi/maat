--TEST--
Maât authenticates no one without an Apache verified request context
--EXTENSIONS--
maat
--FILE--
<?php
function maat_identity_from_nested_function() { return $_AUTH; }
var_dump(maat_identity_from_nested_function());
?>
--EXPECT--
NULL
