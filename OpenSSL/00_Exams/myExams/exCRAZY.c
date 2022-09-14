/**
 * The specification of the CRAZY protocol includes the following operations:
 *
 * 1. Generate two strong random 128-bit integers, name them rand1 and rand2
 *
 * 2. Obtain the first key as
 * k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
 *
 * 3. Obtain the second key as
 * k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
 *
 * 4. Encrypt k2 using k1 using a stron encryption algorithm (and mode) of your choice
 * call it enc_k2.
 *
 * 5. Generate an RSA keypair with a 2048 bit modulus.
 *
 * 6. Encrypt enc_k2 using the just generated RSA key.
 *
 * Implement in C the protocol steps described above, make the proper decisions when
 * the protocol omits information.
 *
 **/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();

    BIGNUM *rand1 = BN_new();
    BIGNUM *rand2 = BN_new();
    BIGNUM *k1 = BN_new();
    BIGNUM *k2 = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *m = BN_new();

    BN_rand(rand1, 128, 0, 1);
    BN_rand(rand2, 128, 0, 1);

    BIGNUM *add = BN_new();
    BIGNUM *sub = BN_new();
    BN_add(add, rand1, rand2);
    BN_sub(sub, rand1, rand2);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *mul = BN_new();
    BN_mul(mul, add, sub, ctx);

    BN_set_word(base, 2);
    BN_set_word(exp, 128);
    BN_exp(m, base, exp, ctx);

    BN_mod(k1, mul, m, ctx);

    BN_mul(mul, rand1, rand2, ctx);

    BIGNUM *div = BN_new();
    BN_div(div, NULL, mul, sub, ctx);

    BN_mod(k2, div, m, ctx);

    BN_free(rand1);
    BN_free(rand2);
    BN_free(add);
    BN_free(sub);
    BN_free(mul);
    BN_free(m);
    BN_free(base);
    BN_free(exp);
    BN_free(div);

    unsigned char *c_k1 = BN_bn2hex(k1);
    unsigned char *c_k2 = BN_bn2hex(k2);
    unsigned char iv[16];

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(evp_ctx, EVP_aes_128_cbc, c_k1, iv, 1); // 1 ENC <-> 0 DEC

    int update_len, final_len;
    int ciphertext_len = 0;
    unsigned char enc_k2[16];
    EVP_CipherUpdate(evp_ctx, enc_k2, &update_len, c_k2, strlen(c_k2));
    ciphertext_len += update_len;
    printf("update size: %d\n", ciphertext_len);

    EVP_CipherFinal_ex(evp_ctx, enc_k2 + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(evp_ctx);

    RSA *rsa_keypair = NULL;

    BIGNUM *bne = BN_new();

    if (!BN_set_word(bne, RSA_F4))
        handle_errors();

    rsa_keypair = RSA_new();

    if (!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    int enc_data_len;
    unsigned char encrypted_data[RSA_size(rsa_keypair)];
    if ((enc_data_len = RSA_public_encrypt(strlen(enc_k2) + 1, enc_k2, encrypted_data, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        handle_errors();

    BN_free(bne);
    RSA_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}