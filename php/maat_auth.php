<?php
/**
 * EXPERIMENTAL PHP bootstrap, not the planned native PHP extension.
 * HTTP_X_MAAT_TICKET is an UNTRUSTED header until the broker redeems it.
 * Only the root broker has access to the OpenSSH verification database.
 * Native PHP extension must eventually initialize the actual $_AUTH
 * auto-global per request (this bootstrap cannot make it a superglobal).
 */
$_AUTH = NULL;
$ticket = $_SERVER['HTTP_X_MAAT_TICKET'] ?? NULL;
if (is_string($ticket) && preg_match('/\A[0-9a-f]{64}\z/D', $ticket)) {
    $socket = @socket_create(AF_UNIX, SOCK_SEQPACKET, 0);
    if ($socket !== false) {
        $ok = @socket_connect($socket, '/run/maat-http/check.sock');
        if ($ok) {
            $field = static function (string $value): string {
                return pack('N', strlen($value)) . $value;
            };
            $packet = $field('MAATCHECK1') . $field($ticket);
            if (@socket_send($socket, $packet, strlen($packet), 0) === strlen($packet)) {
                $reply = '';
                $length = @socket_recv($socket, $reply, 512, 0);
                if (is_int($length) && $length > 0 && $length <= 512) {
                    $offset = 0;
                    $read = static function (string $data, int &$pos, int $max): ?string {
                        if (strlen($data) - $pos < 4) return NULL;
                        $size = unpack('N', substr($data, $pos, 4))[1];
                        $pos += 4;
                        if ($size > $max || $size > strlen($data) - $pos) return NULL;
                        $value = substr($data, $pos, $size);
                        $pos += $size;
                        return $value;
                    };
                    $version = $read($reply, $offset, 20);
                    $user = $read($reply, $offset, 128);
                    $key = $read($reply, $offset, 51);
                    if ($version === 'MAATIDENT1' && is_string($user) && $user !== '' &&
                        is_string($key) && strlen($key) === 51 && $offset === strlen($reply)) {
                        $_AUTH = [
                            'authenticated' => true,
                            'transport' => 'maat+ssh',
                            'ssh_user' => $user,
                            'public_key' => 'ssh-ed25519 ' . base64_encode($key),
                            'identity_verified' => false,
                            'attributes' => [],
                        ];
                    }
                }
            }
        }
        socket_close($socket);
    }
}
// Prevent accidental propagation or exposure of the bearer ticket to PHP apps.
unset($_SERVER['HTTP_X_MAAT_TICKET'], $ticket);
