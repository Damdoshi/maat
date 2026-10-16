<?php
// Authentication diagnostic. No raw public key or session token is printed.
$auth = $_AUTH ?? null;
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$ok = is_array($auth) && ($auth['authenticated'] ?? false) === true
    && ($auth['transport'] ?? null) === 'maat+ssh';
echo json_encode([
    'ssh_authenticated' => $ok,
    'civil_identity_verified' => $ok && ($auth['identity_verified'] ?? false) === true,
    'bbs_presentation_verified' => false,
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
