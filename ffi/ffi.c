#include <ffi_platypus_bundle.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

#if !defined(SODIUM_LIBRARY_MINIMAL)
#define SODIUM_LIBRARY_MINIMAL 0
#endif
#define _str(name) c->set_str(#name, name)
#define _sint(name) c->set_sint(#name, name)
#define _uint(name) c->set_uint(#name, name)

#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64__) ||          \
     defined(__i386__) || defined(_M_AMD64) || defined(_M_IX86))
#define HAVE_AESGCM 1
#else
#define HAVE_AESGCM 0
#endif
#if SODIUM_LIBRARY_VERSION_MAJOR > 9 ||                                        \
  (SODIUM_LIBRARY_VERSION_MAJOR == 9 && SODIUM_LIBRARY_VERSION_MINOR >= 2)
#define HAVE_AEAD_DETACHED 1
#else
#define HAVE_AEAD_DETACHED 0
#endif

void
ffi_pl_bundle_constant(const char* package, ffi_platypus_constant_t* c)
{
    _str(SODIUM_VERSION_STRING);
    _uint(SIZE_MAX);
    _uint(randombytes_SEEDBYTES);
    _sint(SODIUM_LIBRARY_MINIMAL);
    _sint(SODIUM_LIBRARY_VERSION_MAJOR);
    _sint(SODIUM_LIBRARY_VERSION_MINOR);

    /* base_64 options */
    _sint(sodium_base64_VARIANT_ORIGINAL);
    _sint(sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    _sint(sodium_base64_VARIANT_URLSAFE);
    _sint(sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    /* Crypto Generics */
    _uint(crypto_auth_BYTES);
    _uint(crypto_auth_KEYBYTES);
    _str(crypto_auth_PRIMITIVE);
    _uint(crypto_auth_hmacsha256_BYTES);
    _uint(crypto_auth_hmacsha256_KEYBYTES);
    _uint(crypto_auth_hmacsha512_BYTES);
    _uint(crypto_auth_hmacsha512_KEYBYTES);
    _uint(crypto_auth_hmacsha512256_BYTES);
    _uint(crypto_auth_hmacsha512256_KEYBYTES);

    /* AESGCM stuff */
    _sint(HAVE_AESGCM);
    _sint(HAVE_AEAD_DETACHED);
    _uint(crypto_aead_aes256gcm_KEYBYTES);
    _uint(crypto_aead_aes256gcm_NPUBBYTES);
    _uint(crypto_aead_aes256gcm_ABYTES);

    /* chacha20poly1305 */
    _uint(crypto_aead_chacha20poly1305_KEYBYTES);
    _uint(crypto_aead_chacha20poly1305_NPUBBYTES);
    _uint(crypto_aead_chacha20poly1305_ABYTES);

    /* chacha20poly1305_ietf */
    _uint(crypto_aead_chacha20poly1305_IETF_KEYBYTES);
    _uint(crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    _uint(crypto_aead_chacha20poly1305_IETF_ABYTES);

    /* Public key Crypt - Pub Key Signatures */
    _uint(crypto_sign_BYTES);
    _uint(crypto_sign_SEEDBYTES);
    _uint(crypto_sign_PUBLICKEYBYTES);
    _uint(crypto_sign_SECRETKEYBYTES);
    _uint(crypto_sign_MESSAGEBYTES_MAX);
    _str(crypto_sign_PRIMITIVE);
    _uint(crypto_sign_ed25519_BYTES);
    _uint(crypto_sign_ed25519_SEEDBYTES);
    _uint(crypto_sign_ed25519_PUBLICKEYBYTES);
    _uint(crypto_sign_ed25519_SECRETKEYBYTES);
    _uint(crypto_sign_ed25519_MESSAGEBYTES_MAX);

    /* crypto box */
    _uint(crypto_box_SEALBYTES);
    _uint(crypto_box_PUBLICKEYBYTES);
    _uint(crypto_box_SECRETKEYBYTES);
    _uint(crypto_box_MACBYTES);
    _uint(crypto_box_NONCEBYTES);
    _uint(crypto_box_SEEDBYTES);
    _uint(crypto_box_BEFORENMBYTES);
    
    // generic hash
    _uint(crypto_generichash_BYTES_MIN);
    _uint(crypto_generichash_BYTES_MAX);
    _uint(crypto_generichash_BYTES);
    _uint(crypto_generichash_KEYBYTES_MIN);
    _uint(crypto_generichash_KEYBYTES_MAX);
    _uint(crypto_generichash_KEYBYTES);
    _uint(crypto_generichash_PRIMITIVE);
    
    // crypto hash
    _uint(crypto_hash_BYTES);
    _uint(crypto_hash_sha256_BYTES);
    _uint(crypto_hash_sha512_BYTES);
    _str(crypto_hash_PRIMITIVE);

    // crypto kdf
    _uint(crypto_kdf_BYTES_MIN);
    _uint(crypto_kdf_BYTES_MAX);
    _uint(crypto_kdf_CONTEXTBYTES);
    _uint(crypto_kdf_KEYBYTES);
    _str(crypto_kdf_PRIMITIVE);
    _uint(crypto_kdf_blake2b_BYTES_MIN);
    _uint(crypto_kdf_blake2b_BYTES_MAX);
    _uint(crypto_kdf_blake2b_CONTEXTBYTES);
    _uint(crypto_kdf_blake2b_KEYBYTES);
}

void
ffi_pl_bundle_init(const char* package, int argc, void* argv[])
{
    /* printf("Begin with sodium_init()\n"); */
    if (sodium_init() < 0) {
        printf("Could not initialize libsodium.");
    }
}
