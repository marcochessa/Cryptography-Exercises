// The specification of the NONCENSE protocol includes the following operations:
//
// 1) Generate a random 256-bit number, name it r1
// 2) Generate a random 256-bit number, name it r2
// 3) Obtain a key by XOR-ing the two random numbers r1 and r2, name it key_symm
// 4) Generate an RSA keypair of at least 2048 bit modulus
// 5) Encrypt the generated RSA keypair using AES-256 with key_symm and obtain
// 	  the payload.
// Implement in C the protocol steps described above, make the proper decision when
// the protocol omits information.

#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#define BITS 256
#define ENCRYPT 1

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    unsigned char r1[BITS / 8], r2[BITS / 8], iv[BITS / 8];

    if (RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if ((RAND_bytes(r1, BITS / 8) != 1) || (RAND_bytes(r2, BITS / 8) != 1))
        handle_errors();

    int i;
    unsigned char key_symm[BITS / 8];

    for (i = 0; i < BITS / 8; i++)
    {
        key_symm[i] = r1[i] ^ r2[i];
    }

    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate the RSA key
    bne = BN_new();
    if (!BN_set_word(bne, e))
        handle_errors();

    /*
    int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    */
    rsa_keypair = RSA_new();
    if (!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL)) /* callback not needed for our purposes */
        handle_errors();

    //For reasons of time I will only write this part 
	if(!PEM_write_RSAPrivateKey(stdout, rsa_keypair, EVP_aes_256_cbc(), key_symm, strlen(key_symm), NULL, NULL))
        handle_errors();
	
	RSA_free(rsa_keypair);
    BN_free(bne);
	
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}