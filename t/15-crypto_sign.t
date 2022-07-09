use strict;
use warnings;
use Test::More;
use Sodium::FFI qw(
    crypto_sign_BYTES
    crypto_sign_SEEDBYTES
    crypto_sign_PUBLICKEYBYTES
    crypto_sign_SECRETKEYBYTES
    crypto_sign_MESSAGEBYTES_MAX
    crypto_sign_PRIMITIVE
    crypto_sign_ed25519_BYTES
    crypto_sign_ed25519_SEEDBYTES
    crypto_sign_ed25519_PUBLICKEYBYTES
    crypto_sign_ed25519_SECRETKEYBYTES
    crypto_sign_ed25519_MESSAGEBYTES_MAX
    crypto_sign_statebytes
    crypto_sign_bytes
    crypto_sign_seedbytes
    crypto_sign_publickeybytes
    crypto_sign_secretkeybytes
    crypto_sign_messagebytes_max
    crypto_sign_primitive
    crypto_sign_seed_keypair
    crypto_sign_keypair
    crypto_sign 
    crypto_sign_open
    crypto_sign_detached
    crypto_sign_verify_detached
    crypto_sign_init
    crypto_sign_update
    crypto_sign_final_create
    crypto_sign_final_verify
    crypto_sign_ed25519ph_statebytes
    crypto_sign_ed25519_bytes
    crypto_sign_ed25519_seedbytes
    crypto_sign_ed25519_publickeybytes
    crypto_sign_ed25519_secretkeybytes
    crypto_sign_ed25519_messagebytes_max
    crypto_sign_ed25519
    randombytes_buf
);

#    crypto_sign_ed25519_open
#    crypto_sign_ed25519_detached
#    crypto_sign_ed25519_verify_detached
#    crypto_sign_ed25519_keypair
#    crypto_sign_ed25519_seed_keypair
#    crypto_sign_ed25519_pk_to_curve25519
#    crypto_sign_ed25519_sk_to_curve25519
#    crypto_sign_ed25519_sk_to_seed
#    crypto_sign_ed25519_sk_to_pk
#    crypto_sign_ed25519ph_init
#    crypto_sign_ed25519ph_update
#    crypto_sign_ed25519ph_final_create
#    crypto_sign_ed25519ph_final_verify

ok(crypto_sign_BYTES, 'crypto_sign_BYTES: got the constant');
ok(crypto_sign_SEEDBYTES, 'crypto_sign_SEEDBYTES: got the constant');
ok(crypto_sign_PUBLICKEYBYTES, 'crypto_sign_PUBLICKEYBYTES: got the constant');
ok(crypto_sign_SECRETKEYBYTES, 'crypto_sign_SECRETKEYBYTES: got the constant');
ok(crypto_sign_MESSAGEBYTES_MAX, 'crypto_sign_MESSAGEBYTES_MAX: got the constant');
ok(crypto_sign_PRIMITIVE, 'crypto_sign_PRIMITIVE: got the constant');

ok(crypto_sign_ed25519_BYTES, 'crypto_sign_ed25519_BYTES: got the constant');
ok(crypto_sign_ed25519_SEEDBYTES, 'crypto_sign_ed25519_SEEDBYTES: got the constant');
ok(crypto_sign_ed25519_PUBLICKEYBYTES, 'crypto_sign_ed25519_PUBLICKEYBYTES: got the constant');
ok(crypto_sign_ed25519_SECRETKEYBYTES, 'crypto_sign_ed25519_SECRETKEYBYTES: got the constant');
ok(crypto_sign_ed25519_MESSAGEBYTES_MAX, 'crypto_sign_ed25519_MESSAGEBYTES_MAX: got the constant');

my $ok;

# crypto_sign

$ok = crypto_sign_statebytes();
ok($ok, 'crypto_sign_statebytes: got a result');

$ok = crypto_sign_bytes();
ok($ok, 'crypto_sign_bytes: got a result');

$ok = crypto_sign_seedbytes();
ok($ok, 'crypto_sign_seedbytes: got a result');

$ok = crypto_sign_publickeybytes();
ok($ok, 'crypto_sign_publickeybytes: got a result');

$ok = crypto_sign_secretkeybytes();
ok($ok, 'crypto_sign_secretkeybytes: got a result');

$ok = crypto_sign_messagebytes_max();
ok($ok, 'crypto_sign_messagebytes_max: got a result');

$ok = crypto_sign_primitive();
ok($ok, 'crypto_sign_primitive: got a result');

# crypto_sign_ed25519

$ok = crypto_sign_ed25519ph_statebytes();
ok($ok, 'crypto_sign_ed25519ph_statebytes: got a result');

$ok = crypto_sign_ed25519_bytes();
ok($ok, 'crypto_sign_ed25519_bytes: got a result');

$ok = crypto_sign_ed25519_seedbytes();
ok($ok, 'crypto_sign_ed25519_seedbytes: got a result');

$ok = crypto_sign_ed25519_publickeybytes();
ok($ok, 'crypto_sign_ed25519_publickeybytes: got a result');

# combined, no seed
{
    my ($pub, $priv) = crypto_sign_keypair();
    is(length($pub), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_keypair: pub is right length');
    is(length($priv), crypto_sign_SECRETKEYBYTES, 'crypto_sign_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a secret key, and to be verified using a public key";
    my $msg_signed = crypto_sign($msg, $priv);
    ok($msg_signed, 'crypto_sign: got a result');
    is(length($msg_signed) - length($msg), crypto_sign_BYTES, 'The message length is correct');

    my $open = crypto_sign_open($msg_signed, $pub);
    is($open, $msg, 'crypto_sign_open: Messages are equal');
}

# combined, with seed
{
    my $seed = randombytes_buf(crypto_sign_SEEDBYTES);
    my ($pub, $priv) = crypto_sign_seed_keypair($seed);
    is(length($pub), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_seed_keypair: pub is right length');
    is(length($priv), crypto_sign_SECRETKEYBYTES, 'crypto_sign_seed_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a seeded secret key, and to be verified using a public key";
    my $msg_signed = crypto_sign($msg, $priv);
    ok($msg_signed, 'crypto_sign: got a result');
    is(length($msg_signed) - length($msg), crypto_sign_BYTES, 'The message length is correct');

    my $open = crypto_sign_open($msg_signed, $pub);
    is($open, $msg, 'crypto_sign_open: Messages are equal');
}

# detached, no seed
{
    my ($pub, $priv) = crypto_sign_keypair();
    is(length($pub), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_keypair: pub is right length');
    is(length($priv), crypto_sign_SECRETKEYBYTES, 'crypto_sign_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a secret key, and to be verified using a public key";
    my $signature = crypto_sign_detached($msg, $priv);
    ok($signature, 'crypto_sign_detached: got a result');
    is(length($signature), crypto_sign_BYTES, 'The signature length is correct');

    my $verified = crypto_sign_verify_detached($signature, $msg, $pub);
    ok($verified, 'crypto_sign_verify_detached: Message verified');
}


done_testing();
