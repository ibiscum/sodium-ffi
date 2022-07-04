use strict;
use warnings;
use Test::More;
use Sodium::FFI qw(
    crypto_auth_BYTES
    crypto_auth_KEYBYTES
    crypto_auth_PRIMITIVE
	crypto_auth_hmacsha256_BYTES
	crypto_auth_hmacsha256_KEYBYTES
	crypto_auth_hmacsha512_BYTES
	crypto_auth_hmacsha512_KEYBYTES
	crypto_auth_hmacsha512256_BYTES
	crypto_auth_hmacsha512256_KEYBYTES
    crypto_auth_keygen
    crypto_auth_bytes
    crypto_auth_keybytes
    crypto_auth_primitive
    crypto_auth
    crypto_auth_verify
    crypto_auth_hmacsha256_keygen
    crypto_auth_hmacsha256_bytes
    crypto_auth_hmacsha256_keybytes
    crypto_auth_hmacsha256_statebytes
    randombytes_buf
);

ok(crypto_auth_BYTES, 'crypto_auth_BYTES: got the constant');
ok(crypto_auth_KEYBYTES, 'crypto_auth_KEYBYTES: got the constant');
ok(crypto_auth_PRIMITIVE, 'crypto_auth_PRIMITIVE: got the constant');

ok(crypto_auth_hmacsha256_BYTES, 'crypto_auth_hmacsha256_BYTES: got the constant');
ok(crypto_auth_hmacsha256_KEYBYTES, 'crypto_auth_hmacsha256_KEYBYTES: got the constant');

ok(crypto_auth_hmacsha512_BYTES, 'crypto_auth_hmacsha512_BYTES: got the constant');
ok(crypto_auth_hmacsha512_KEYBYTES, 'crypto_auth_hmacsha512_KEYBYTES: got the constant');

ok(crypto_auth_hmacsha512256_BYTES, 'crypto_auth_hmacsha512256_BYTES: got the constant');
ok(crypto_auth_hmacsha512256_KEYBYTES, 'crypto_auth_hmacsha512256_KEYBYTES: got the constant');

my $key = "";
my $msg = "";
my $msg_enc = "";
my $msg_dec = "";
my $msg_bad = "";
my $ok = "";

$msg = randombytes_buf(12); # just 12 bytes of random data

$ok = crypto_auth_bytes();
ok($ok, 'crypto_auth_bytes: got a result');

$ok = crypto_auth_keybytes();
ok($ok, 'crypto_auth_keybytes: got a result');

$ok = crypto_auth_primitive();
ok($ok, 'crypto_auth_primitive: got a result');

$key = crypto_auth_keygen();
ok($key, 'crypto_auth_keygen: got a key');

$msg_enc = crypto_auth($msg, $key);
ok($msg_enc, 'crypto_auth: Got back an encrypted message');

$ok = crypto_auth_verify($msg_enc, $msg, $key);
ok($ok, 'crypto_auth_verify: Verified our message');

$msg_bad = $msg;
substr($msg_bad, 0, 1) = chr(ord(substr($msg_bad, 0, 1)) ^ 0x80);
ok(!crypto_auth_verify($msg_enc, $msg_bad, $key), "crypto_auth_verify: bad msg: not verified");

# hmac sha256
$ok = crypto_auth_hmacsha256_bytes();
ok($ok, 'crypto_auth_hmacsha256_bytes: got a result');

$ok = crypto_auth_hmacsha256_keybytes();
ok($ok, 'crypto_auth_hmacsha256_keybytes: got a result');

$ok = crypto_auth_hmacsha256_statebytes();
ok($ok, 'crypto_auth_hmacsha256_statebytes: got a result');

$key = crypto_auth_hmacsha256_keygen();
ok($key, 'crypto_auth_hmacsha256_keygen: got a key');

done_testing();
