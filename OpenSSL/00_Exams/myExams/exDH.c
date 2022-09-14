// Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSl library.
// Imagine you have a client CARL that starts communicating with a server SARA.
// CARL initiates the communication and proposes the public parameters.

// Assume you have access to a set of high-level communication primitives that allow
// you to send and receive big numbers and to properly format them (e.g., based on a BIO)
// so that you don't have to think about the communication issues for this exercise.

// void send_to_sara(BIGNUM b)
// BIGNUM receive_from_sara()
// void send_to_carl(BIGNUM b)
// BIGNUM receive_from_carl()

// Finally answer the following question: what CARL and SARA have to do if they want
// to generate an AES-256 key?

/*********************CARL SIDE************************
****choose and send p,g to SARA
****receive A=g^a mod p from SARA where a is the secret of SARA
****send B=g^b mod p to SARA where b is the secret of CARL
****CARL calculate Kb equals to Ka (session key)
*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

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

    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *A = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *Kb = BN_new();

    /* init the random engine: */
    int rc = RAND_load_file("/dev/random", 64);
    if (rc != 64)
    {
        handle_errors();
    }

    // generate a 16 bit prime (a very small one)
    // BN_generate_prime_ex is deprecated in OpenSSL 3.0 use the one below instead (also has a context for more generic generation)
    // int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb, BN_CTX *ctx);
    if (!BN_generate_prime_ex(p, 256, 0, NULL, NULL, NULL))
        handle_errors();
    if (!BN_generate_prime_ex(g, 256, 0, NULL, NULL, NULL)) // G must be a primitive root of p in a correct case
        handle_errors();

    send_to_sara(p);
    send_to_sara(g);

    A = receive_from_sara();

    BN_CTX *ctx = BN_CTX_new();
    if (!BN_mod_exp(B, g, b, p, ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    send_to_sara(B);

    if (!BN_mod_exp(Kb, A, b, p, ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    printf("The session Key is: %s", BN_bn2dec(Kb));
	
	BN_CTX_free(ctx);
	BN_free(Kb);
	BN_free(p);
	BN_free(g);
	BN_free(A);
	BN_free(b);
	BN_free(B);
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
    return 0;
}