--TEST--
User-controlled HTTP identity fields without a broker assertion do not authenticate
--EXTENSIONS--
maat
--FILE--
<?php
$_SERVER['HTTP_X_MAAT_TICKET'] = str_repeat('f', 64);
$_SERVER['HTTP_X_MAAT_USER'] = 'forged';
function maat_identity() { return $_AUTH; }
var_dump(maat_identity());
?>
--EXPECT--
NULL
