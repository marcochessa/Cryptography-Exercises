/**
 * The specification of the SIGN protocol includes the following operations:
 * - Generate a random 128-bit number, name it r1
 * - Generate a random 128-bit number, name it r2
 * - Concatenate them to obtain a 256-bit AES key name k
 * - Encrypt the content of the FILE *f_in; with AES and k and save it on the file FILE *f_out
 *   (assume both files have been properly opened)
 * - Generate the signature of the encrypted file FILE *f_out with the RSA keypair available
 *   as EVP_PKEY* rsa_key (properly loaded in advance).
 *
 *  Implement the protocol steps above in C, and make the proper decisions when the protocol omits
 *  information.
 **/

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_BUFFER 1024

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // assume I know
    FILE *f_in;
    FILE *f_out;
    EVP_PKEY* rsa_key;

    unsigned char r1[128 / 8];
    unsigned char r2[128 / 8];
    unsigned char iv[16];
    unsigned char k[32];

    int rc = RAND_load_file("/dev/random", 64);
    if (rc != 64)
    {
        handle_errors();
    }

    if (!RAND_bytes(r1, 16) || !RAND_bytes(r2, 16))
        fprintf(stderr, "Error with rand generation\n");

    // CONCATENATION
    int i;
    for (i = 0; i < 16; i++)
    {
        k[i] = r1[i];
    }
    for (i = 0; i < 16; i++)
    {
        k[i + 16] = r2[i];
    }

    if ((f_in = fopen("f1.txt", "r")) == NULL)
    {
        abort();
    }

    if (!RAND_bytes(iv, 16))
    {
        handle_errors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CHIPER_CTX_new();

    if (!EVP_CipherInit(ctx, EVP_aes_256_cbc, k, iv, 1))
        handle_errors();

    int lenght;
    unsigned char ciphertext[MAX_BUFFER + 16];
    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0)
    {
        if (!EVP_CipherUpdate(ctx, ciphertext, &lenght, buffer, n_read))
            handle_errors();
        if (fwrite(ciphertext, 1, lenght, f_out) < lenght)
        {
            abort();
        }
    }

    if (!EVP_CipherFinal_ex(ctx, ciphertext, &lenght))
        handle_errors();

    if (fwrite(ciphertext, 1, lenght, f_out) < lenght)
    {
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, rsa_key))
        handle_errors();

    size_t n_read;

    rewind(f_out);

    while((n_read = fread (buffer, 1, MAX_BUFFER, f_out))>0)
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();


    unsigned char signature [EVP_PKEY_size(rsa_key)];
    size_t sig_len;
    size_t digest_len;

    if(!EVP_DigestSignFinal(sign_ctx, NULL, &digest_len))
        handle_errors();

    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    //SIGN CREATED
	
	fclose(f_out);
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
    EVP_MD_CTX_free(sign_ctx);
    
}