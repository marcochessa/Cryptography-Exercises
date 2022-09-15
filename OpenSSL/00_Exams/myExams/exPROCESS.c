// A server is listening on a given port where it receives raw bytes
// When a client establishes a connection and sends some data, the server calls
// its internal function process(), which produces the output to send back to the
// client. The prototype of the function is the following one:

// char *process(char *data, int length, RSA *rsa_priv_key)

// The function process():
// Checks if data can be decrypted with rsa_priv_key; if possible,
// obtains decrypted_data by decrypting the data variable (by "manually" implementing
// the RSA decryption algorithm);
// Computes the hash h of decrypted_data using SHA256

// If data can be decrypted, process() returns three bytes:

// As a first byte, the least significant bit of decrypted_data
// As a second byte, the least significant bit of the hash h;
// As a third byte, the XOR of the previous two bytes

// Otherwise, it returns NULL.

// Implement in C the function process() described above using the OpenSSL library.

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

char *process(char *data, int length, RSA *rsa_priv_key)
{
    unsigned char decrypted_data[RSA_size(rsa_priv_key)];

    if (RSA_private_decrypt(data, (unsigned char *)data,
                            (unsigned char *)decrypted_data,
                            rsa_priv_key, RSA_PKCS1_OAEP_PADDING) <= 0)
        return NULL; // Impossibile to use

    // M = C^d mod N. --> N = a private * B public

    // RSA manual decrypt: m^d mod n
    BIGNUM *m_bn = BN_new();
    BN_hex2bn(&m_bn, data);
    BIGNUM *d = RSA_get0_d(rsa_priv_key);
    BIGNUM *p = RSA_get0_p(rsa_priv_key);
    BIGNUM *q = RSA_get0_d(rsa_priv_key);
    BIGNUM *res = BN_new();

    BN_CTX *ctx = BN_CTX_new();
    BN_mul(res, p, q, ctx);

    if (!BN_mod_exp(res, m_bn, d, res, ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    char *dec = BN_bn2hex(res);

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    EVP_DigestInit(md, EVP_sha256());

    EVP_DigestUpdate(md, dec, strlen(dec));

    unsigned char md_value[32];
    int md_len;

    EVP_DigestFinal(md, md_value, &md_len);

    EVP_MD_CTX_free(md);

    unsigned char result[3];
    result[0] = dec[strlen(dec)-1];
    result[1] = md_value[strlen(md_value)-1];
    result[2] = result[0]^result[1];

    return result;
}
