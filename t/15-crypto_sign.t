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
    sodium_hex2bin
    sodium_bin2hex
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

$ok = crypto_sign_ed25519_secretkeybytes();
ok($ok, 'crypto_sign_ed25519_secretkeybytes: got a result');

$ok = crypto_sign_ed25519_messagebytes_max();
ok($ok, 'crypto_sign_ed25519_messagebytes_max: got a result');

# combined, no seed
{
    my ($pk, $sk) = crypto_sign_keypair();
    is(length($pk), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_keypair: pub is right length');
    is(length($sk), crypto_sign_SECRETKEYBYTES, 'crypto_sign_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a secret key, and to be verified using a public key";
    my $msg_signed = crypto_sign($msg, $sk);
    ok($msg_signed, 'crypto_sign: got a result');
    is(length($msg_signed) - length($msg), crypto_sign_BYTES, 'crypto_sign: the message length is correct');

    my $open = crypto_sign_open($msg_signed, $pk);
    is($open, $msg, 'crypto_sign_open: the messages are equal');
}

# combined, with seed
{
    my $seed = randombytes_buf(crypto_sign_SEEDBYTES);
    my ($pk, $sk) = crypto_sign_seed_keypair($seed);
    is(length($pk), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_seed_keypair: pub is right length');
    is(length($sk), crypto_sign_SECRETKEYBYTES, 'crypto_sign_seed_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a seeded secret key, and to be verified using a public key";
    my $msg_signed = crypto_sign($msg, $sk);
    ok($msg_signed, 'crypto_sign: got a result');
    is(length($msg_signed) - length($msg), crypto_sign_BYTES, 'crypto_sign: the message length is correct');

    my $open = crypto_sign_open($msg_signed, $pk);
    is($open, $msg, 'crypto_sign_open: messages are equal');
}

# detached, no seed
{
    my ($pk, $sk) = crypto_sign_keypair();
    is(length($pk), crypto_sign_PUBLICKEYBYTES, 'crypto_sign_keypair: pub is right length');
    is(length($sk), crypto_sign_SECRETKEYBYTES, 'crypto_sign_keypair: priv is right length');

    my $msg = "Here is the message, to be signed using a secret key, and to be verified using a public key";
    my $sig = crypto_sign_detached($msg, $sk);
    ok($sig, 'crypto_sign_detached: got a result');
    is(length($sig), crypto_sign_BYTES, 'crypto_sign_detached: the signature length is correct');

    my $verified = crypto_sign_verify_detached($sig, $msg, $pk);
    ok($verified, 'crypto_sign_verify_detached: message verified');
}

# ED25519 TEST 1 RFC 8032
{
    my $pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    my $sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" . $pk;

    $sk = sodium_hex2bin($sk);
    $pk = sodium_hex2bin($pk);

    my $msg = "";
    my $sig_ref = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    my $sig = crypto_sign_detached($msg, $sk);
    $sig = sodium_bin2hex($sig);
    ok($sig eq $sig_ref, 'crypto_sign_detached: ED25519 TEST 1 RFC 8032');
}

# ED25519 TEST 2 RFC 8032
{
    my $pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    my $sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb" . $pk;

    $sk = sodium_hex2bin($sk);
    $pk = sodium_hex2bin($pk);

    my $msg = "72";
    $msg = sodium_hex2bin($msg);

    my $sig_ref = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    my $sig = crypto_sign_detached($msg, $sk);
    $sig = sodium_bin2hex($sig);
    ok($sig eq $sig_ref, 'crypto_sign_detached: ED25519 TEST 2 RFC 8032');
}

# ED25519 TEST 3 RFC 8032
{
    my $pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    my $sk = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7" . $pk;

    $sk = sodium_hex2bin($sk);
    $pk = sodium_hex2bin($pk);

    my $msg = "af82";
    $msg = sodium_hex2bin($msg);

    my $sig_ref = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    my $sig = crypto_sign_detached($msg, $sk);
    $sig = sodium_bin2hex($sig);
    ok($sig eq $sig_ref, 'crypto_sign_detached: ED25519 TEST 3 RFC 8032');
}

# ED25519 TEST SHA(abc) RFC 8032
{
    my $pk = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    my $sk = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42" . $pk;

    $sk = sodium_hex2bin($sk);
    $pk = sodium_hex2bin($pk);

    my $msg = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    $msg = sodium_hex2bin($msg);

    my $sig_ref = "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";

    my $sig = crypto_sign_detached($msg, $sk);
    $sig = sodium_bin2hex($sig);
    ok($sig eq $sig_ref, 'crypto_sign_detached: ED25519 TEST SHA(abc) RFC 8032');
}

done_testing();
