--TEST--
Maât refuses HTTP and Server environment identity spoofing in every SAPI
--EXTENSIONS--
maat
--FILE--
<?php
$_SERVER['HTTP_X_MAAT_TICKET'] = str_repeat('a', 64);
$_SERVER['MAAT_VERIFIED_KEY'] = 'ssh-ed25519 forged';
$_SERVER['MAAT_AUTHENTICATED'] = '1';
putenv('MAAT_VERIFIED_KEY=ssh-ed25519 forged');
function nested() { return $_AUTH; }
var_dump(nested());
?>
--EXPECT--
NULL
