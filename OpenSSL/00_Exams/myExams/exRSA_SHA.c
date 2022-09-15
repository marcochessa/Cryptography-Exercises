/*
Implement, using the C programming language, the following function:

    int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char *result);

which implements the following operations:
1) double_SHA256 of the concatenation of a message with a symmetric key;
2) RSA encrypt the result of the last step;
3) returns 0 in case of success, 1 in case of errors, and the result of the RSA encryption by reference.

In other words, the function has to implement the following transformation:
RSAencrypt(public_key, SHA_256 ( SHA_256 (message || key) ))
*/

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char *result)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();

    // STEP 1
    if (!EVP_DigestInit(md, EVP_sha_256()))
        return 1;
    if (!EVP_DigestUpdate(md, message, message_len))
        return 1;
    if (!EVP_DigestUpdate(md, key, keylenght))
        return 1;
    unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;
    if (!EVP_DigestFinal(md, md_value, &md_len))
        return 1;

    // STEP 2
    if (!EVP_DigestInit(md, EVP_sha_256()))
        return 1;
    if (!EVP_DigestUpdate(md, md_value, md_len))
        return 1;
    if (!EVP_Digest_Final(md, md_value, &md_len))
        return 1;
    EVP_MD_CTX_free(md);

    // STEP 3

    int enc_data_len;
    if ((enc_data_len = RSA_public_encrypt(md_len + 1, md_value, result, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        return 1;

    RSA_free(rsa_keypair);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}