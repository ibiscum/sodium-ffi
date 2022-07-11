use strict;
use warnings;
use Test::More;
use Data::Dumper qw(Dumper);
use FFI::Platypus::Buffer qw( scalar_to_buffer buffer_to_scalar );
use FFI::Platypus::Memory qw( malloc free );
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
    crypto_hash_sha256_update
    crypto_hash_sha256_final
    crypto_hash_sha256

    crypto_hash_sha512_bytes
    crypto_hash_sha512_statebytes
    crypto_hash_sha512_init
    crypto_hash_sha512_update
    crypto_hash_sha512_final
    crypto_hash_sha512

    randombytes_buf
    sodium_bin2hex
);

my $ok;

ok(crypto_hash_BYTES, 'crypto_hash_BYTES: got the constant');
ok(crypto_hash_PRIMITIVE, 'crypto_hash_PRIMITIVE: got the constant');

ok(crypto_hash_sha256_BYTES, 'crypto_hash_sha256_BYTES: got the constant');
ok(crypto_hash_sha512_BYTES, 'crypto_hash_sha512_BYTES: got the constant');

$ok = crypto_hash_bytes();
ok($ok, 'crypto_hash_bytes: got a result');

$ok = crypto_hash_primitive();
ok($ok, 'crypto_hash_primitive: got a result');

#$dig = crypto_hash($msg);
#$dig = sodium_bin2hex($dig);
#ok($dig eq lc("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"), 'crypto_hash: digest verified');

$ok = crypto_hash_sha256_bytes();
ok($ok, 'crypto_hash_sha256_bytes: got a result');

$ok = crypto_hash_sha256_statebytes();
ok($ok, 'crypto_hash_sha256_statebytes: got a result');

# NIST SHA 256, init, update, final
{
    my $msg = "abc";
    my $state = malloc(crypto_hash_sha256_statebytes());

    my $state_init = crypto_hash_sha256_init($state);
    ok($state_init, 'crypto_hash_sha256_init: got a result');

    my $state_update = crypto_hash_sha256_update($state_init, $msg);
    ok($state_update, 'crypto_hash_sha256_update: got a result');

    my $dig = crypto_hash_sha256_final($state_update);
    $dig = sodium_bin2hex($dig);
    ok($dig eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 'crypto_hash_sha256_final: result equal to reference');

    free $state;
}

# NIST SHA 256
{
    my $msg = "abc";
    my $dig = crypto_hash_sha256($msg);
    $dig = sodium_bin2hex($dig);
    ok($dig eq "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 'crypto_hash_sha256: result equal to reference');
}

$ok = crypto_hash_sha512_bytes();
ok($ok, 'crypto_hash_sha512_bytes: got a result');

$ok = crypto_hash_sha512_statebytes();
ok($ok, 'crypto_hash_sha512_statebytes: got a result');

# NIST SHA 512 init, update, final
{
    my $msg = "abc";
    my $state = malloc(crypto_hash_sha512_statebytes());

    my $state_init = crypto_hash_sha512_init($state);
    ok($state_init, 'crypto_hash_sha512_init: got a result');

    my $state_update = crypto_hash_sha512_update($state_init, $msg);
    ok($ok, 'crypto_hash_sha512_update: got a result');

    my $dig = crypto_hash_sha512_final($state_update);
    $dig = sodium_bin2hex($dig);
    ok($dig eq "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 'crypto_hash_sha512_final: result equal to reference');

    free $state;
}

# NIST SHA 512
{
    my $msg = "abc";
    my $dig = crypto_hash_sha512($msg);
    $dig = sodium_bin2hex($dig);
    ok($dig eq "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 'crypto_hash_sha512_final: result equal to reference');
}

done_testing();
