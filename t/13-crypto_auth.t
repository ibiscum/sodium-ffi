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
    crypto_auth_hmacsha256
    crypto_auth_hmacsha256_verify
    crypto_auth_hmacsha512_keygen
    crypto_auth_hmacsha512_bytes
    crypto_auth_hmacsha512_keybytes
    crypto_auth_hmacsha512_statebytes
    crypto_auth_hmacsha512
    crypto_auth_hmacsha512_verify
    randombytes_buf
    sodium_bin2hex
    sodium_hex2bin
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

my $key;
my $msg;
my $msg_bad;
my $dig;
my $ok;

$msg = randombytes_buf(12); # just 12 bytes of random data

$ok = crypto_auth_bytes();
ok($ok, 'crypto_auth_bytes: got a result');

$ok = crypto_auth_keybytes();
ok($ok, 'crypto_auth_keybytes: got a result');

$ok = crypto_auth_primitive();
ok($ok, 'crypto_auth_primitive: got a result');

$key = crypto_auth_keygen();
ok($key, 'crypto_auth_keygen: got a key');

$dig = crypto_auth($msg, $key);
ok($dig, 'crypto_auth: Got back an encrypted message');

$ok = crypto_auth_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_verify: Verified our message');

$msg_bad = $msg;
substr($msg_bad, 0, 1) = chr(ord(substr($msg_bad, 0, 1)) ^ 0x80);
ok(!crypto_auth_verify($dig, $msg_bad, $key), "crypto_auth_verify: bad msg: not verified");

# hmac sha256
$ok = crypto_auth_hmacsha256_bytes();
ok($ok, 'crypto_auth_hmacsha256_bytes: got a result');

$ok = crypto_auth_hmacsha256_keybytes();
ok($ok, 'crypto_auth_hmacsha256_keybytes: got a result');

$ok = crypto_auth_hmacsha256_statebytes();
ok($ok, 'crypto_auth_hmacsha256_statebytes: got a result');

$key = crypto_auth_hmacsha256_keygen();
ok($key, 'crypto_auth_hmacsha256_keygen: got a key');

$dig = crypto_auth_hmacsha256($msg, $key);
ok($dig, 'crypto_auth_hmacsha256: Got back an encrypted message');

$ok = crypto_auth_hmacsha256_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha256_verify: Verified our message');

$key = "0b" x 20 . "00" x 12;
$key = sodium_hex2bin($key);
$msg = "4869205468657265";
$msg = sodium_hex2bin($msg);
$dig = crypto_auth_hmacsha256($msg, $key);
$ok = crypto_auth_hmacsha256_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha256_verify: Verified our message');
$dig = sodium_bin2hex($dig);
ok($dig eq "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 'crypto_auth_hmacsha256: Test Case 1 RFC 4231');

$key = "4a656665" . "00" x 28;
$key = sodium_hex2bin($key);
$msg = "7768617420646f2079612077616e7420666f72206e6f7468696e673f";
$msg = sodium_hex2bin($msg);
$dig = crypto_auth_hmacsha256($msg, $key);
$ok = crypto_auth_hmacsha256_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha256_verify: Verified our message');
$dig = sodium_bin2hex($dig);
ok($dig eq "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 'crypto_auth_hmacsha256: Test Case 2 RFC 4231');

# hmac sha512
$ok = crypto_auth_hmacsha512_bytes();
ok($ok, 'crypto_auth_hmacsha512_bytes: got a result');

$ok = crypto_auth_hmacsha512_keybytes();
ok($ok, 'crypto_auth_hmacsha512_keybytes: got a result');

$ok = crypto_auth_hmacsha512_statebytes();
ok($ok, 'crypto_auth_hmacsha512_statebytes: got a result');

$key = crypto_auth_hmacsha512_keygen();
ok($key, 'crypto_auth_hmacsha512_keygen: got a key');

$dig = crypto_auth_hmacsha512($msg, $key);
ok($dig, 'crypto_auth_hmacsha512: Got back an encrypted message');

$ok = crypto_auth_hmacsha512_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha512_verify: Verified our message');

$key = "0b" x 20 . "00" x 12;
$key = sodium_hex2bin($key);
$msg = "4869205468657265";
$msg = sodium_hex2bin($msg);
$dig = crypto_auth_hmacsha512($msg, $key);
$ok = crypto_auth_hmacsha512_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha512_verify: Verified our message');
$dig = sodium_bin2hex($dig);
ok($dig eq "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", 'crypto_auth_hmacsha512: Test Case 1 RFC 4231');

$key = "4a656665" . "00" x 28;
$key = sodium_hex2bin($key);
$msg = "7768617420646f2079612077616e7420666f72206e6f7468696e673f";
$msg = sodium_hex2bin($msg);
$dig = crypto_auth_hmacsha512($msg, $key);
$ok = crypto_auth_hmacsha512_verify($dig, $msg, $key);
ok($ok, 'crypto_auth_hmacsha512_verify: Verified our message');
$dig = sodium_bin2hex($dig);
ok($dig eq "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", 'crypto_auth_hmacsha512: Test Case 2 RFC 4231');

done_testing();
