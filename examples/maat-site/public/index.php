<?php
// Maât 0.20 demonstration: the only authenticated identity source is $_AUTH.
// Never accept identity from $_GET, $_POST, cookies, or HTTP headers.
$auth = $_AUTH ?? null;
$authenticated = is_array($auth) && ($auth['authenticated'] ?? false) === true
    && ($auth['transport'] ?? null) === 'maat+ssh';
$verified = $authenticated && ($auth['identity_verified'] ?? false) === true;
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
function h($value) { return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Maât — démonstration</title></head>
<body><h1>Site de démonstration Maât</h1>
<?php if (!$authenticated): ?>
<p>Vous n'avez pas de session SSH Maât authentifiée.</p>
<?php else: ?>
<p>Clé SSH authentifiée via Maât.</p>
<p>Utilisateur SSH : <?= h($auth['ssh_user'] ?? '') ?></p>
<p>Identité civile vérifiée : <?= $verified ? 'oui' : 'non' ?></p>
<?php endif; ?>
<p>Les justificatifs BBS ne sont pas intégrés à <code>$_AUTH</code> dans cette version.</p>
<p><a href="session.php">Diagnostic de la session</a></p>
</body></html>
