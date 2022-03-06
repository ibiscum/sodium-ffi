use strict;
use warnings;
use Test::More;
use Sodium::FFI qw(
    crypto_sign_PUBLICKEYBYTES crypto_sign_SECRETKEYBYTES
    crypto_sign_BYTES crypto_sign_SEEDBYTES
    crypto_sign_keypair crypto_sign_seed_keypair
    randombytes_buf
);

ok(crypto_sign_SECRETKEYBYTES, 'crypto_sign_SECRETKEYBYTES: got the constant');
ok(crypto_sign_BYTES, 'crypto_sign_BYTES: got the constant');
ok(crypto_sign_PUBLICKEYBYTES, 'crypto_sign_PUBLICKEYBYTES: got the constant');
ok(crypto_sign_SEEDBYTES, 'crypto_sign_SEEDBYTES: got the constant');

my ($pub, $priv) = crypto_sign_keypair();
is(length($pub), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_keypair: pub is right length');
is(length($priv), crypto_sign_SECRETKEYBYTES, 'crypto_sign_keypair: priv is right length');

my $seed = randombytes_buf(crypto_sign_SEEDBYTES);
($pub, $priv) = crypto_sign_seed_keypair($seed);
is(length($pub), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_seed_keypair: pub is right length');
is(length($priv), crypto_sign_SECRETKEYBYTES, 'crypto_sign_seed_keypair: priv is right length');

done_testing();