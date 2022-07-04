use strict;
use warnings;
use Test::More;
use Sodium::FFI qw(
    crypto_aead_chacha20poly1305_IETF_KEYBYTES
    crypto_aead_chacha20poly1305_IETF_ABYTES
    crypto_aead_chacha20poly1305_IETF_NPUBBYTES
    crypto_aead_chacha20poly1305_ietf_keygen
    crypto_aead_chacha20poly1305_ietf_encrypt
    crypto_aead_chacha20poly1305_ietf_decrypt
    randombytes_buf
);

ok(crypto_aead_chacha20poly1305_IETF_KEYBYTES, 'crypto_aead_chacha20poly1305_IETF_KEYBYTES: got the constant');
ok(crypto_aead_chacha20poly1305_IETF_ABYTES, 'crypto_aead_chacha20poly1305_IETF_ABYTES: got the constant');
ok(crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 'crypto_aead_chacha20poly1305_IETF_NPUBBYTES: got the constant');

{
    my $key = crypto_aead_chacha20poly1305_ietf_keygen();
    ok($key, 'crypto_aead_chacha20poly1305_ietf_keygen: got a key');

    my $nonce = randombytes_buf(crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    ok($nonce, 'nonce: got it');

    my $msg = randombytes_buf(12); # just 12 bytes of random data
    my $additional_data = randombytes_buf(12);

    my $encrypted = crypto_aead_chacha20poly1305_ietf_encrypt($msg, $additional_data, $nonce, $key);
    ok($encrypted, 'crypto_aead_chacha20poly1305_ietf_encrypt: Got back an encrypted message');

    my $decrypted = crypto_aead_chacha20poly1305_ietf_decrypt($encrypted, $additional_data, $nonce, $key);
    ok($decrypted, 'crypto_aead_chacha20poly1305_ietf_decrypt: Got back an decrypted message');

    is($decrypted, $msg, 'Round-trip got us back our original message');
}

# now with no additional data
{
    my $key = crypto_aead_chacha20poly1305_ietf_keygen();
    ok($key, 'crypto_aead_chacha20poly1305_ietf_keygen: got a key');
    
    my $nonce = randombytes_buf(crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    ok($nonce, 'nonce: got it');
    
    my $msg = randombytes_buf(12); # just 12 bytes of random data
    my $additional_data = undef;

    my $encrypted = crypto_aead_chacha20poly1305_ietf_encrypt($msg, $additional_data, $nonce, $key);
    ok($encrypted, 'crypto_aead_chacha20poly1305_ietf_encrypt: Got back an encrypted message');
    
    my $decrypted = crypto_aead_chacha20poly1305_ietf_decrypt($encrypted, $additional_data, $nonce, $key);
    ok($decrypted, 'crypto_aead_chacha20poly1305_ietf_decrypt: Got back an decrypted message');
    is($decrypted, $msg, 'Round-trip got us back our original message');
}

done_testing();
