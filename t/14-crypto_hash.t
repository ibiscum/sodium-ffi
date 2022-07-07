use strict;
use warnings;
use Test::More;
use Sodium::FFI qw(
    crypto_hash_BYTES
    crypto_hash_PRIMITIVE
    crypto_hash_sha256_BYTES
    crypto_hash_sha512_BYTES
    crypto_hash_bytes
    crypto_hash_primitive
    crypto_hash
    crypto_hash_sha256_bytes
    crypto_hash_sha256_statebytes
    crypto_hash_sha256_init
    randombytes_buf
    sodium_bin2hex
);

ok(crypto_hash_BYTES, 'crypto_hash_BYTES: got the constant');
ok(crypto_hash_PRIMITIVE, 'crypto_hash_PRIMITIVE: got the constant');

ok(crypto_hash_sha256_BYTES, 'crypto_hash_sha256_BYTES: got the constant');
ok(crypto_hash_sha512_BYTES, 'crypto_hash_sha512_BYTES: got the constant');

my $ok;
my $msg;
my $dig;
my $state;

$msg = "abc";

$ok = crypto_hash_bytes();
ok($ok, 'crypto_hash_bytes: got a result');

$ok = crypto_hash_primitive();
ok($ok, 'crypto_hash_primitive: got a result');

$dig = crypto_hash($msg);
$dig = sodium_bin2hex($dig);
ok($dig eq lc("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"), 'crypto_hash: digest verified');

$ok = crypto_hash_sha256_bytes();
ok($ok, 'crypto_hash_sha256_bytes: got a result');

$ok = crypto_hash_sha256_statebytes();
print $ok . "\n";
ok($ok, 'crypto_hash_sha256_statebytes: got a result');

# $state = hash_sha256_state->new();

# $ok = crypto_hash_sha256_init($state);
# print $ok . "\n";
# ok($ok, 'crypto_hash_sha256_init: got a result');

done_testing();
