/*
 * 1. Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.
 * The filename is passed as first parameter from the command line, the algorithm is passed as second parameter and must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb).
 */

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAX 64

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (argc != 4)
    {
        printf("Invalid parameters. Usage %s input_file key IV\n", argv[0]);
        exit(-1);
    }

    FILE *f_in;

    if ((f_in = fopen(argv[1], "r")) == NULL)
    {
        printf("Errors opening the input file: %s\n", argv[1]);
        exit(-1);
    }

    FILE *f_out;

    if((f_out=fopen(argv[3],"wb")) == NULL) {
        printf("Errors opening the output file: %s\n", argv[4]);
        exit(-1);
    }

    unsigned char key[MAX], iv[MAX];

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        abort();

    int key_length = 16; //ASCII 16 Bytes = 128 bit
    int iv_length = 16; //ASCII 16 Bytes = 128 bit
    //key_length = EVP_CIPHER_get_key_length(EVP_get_cipherbyname(argv[2]));
    //iv_length = EVP_CIPHER_get_iv_length(EVP_get_cipherbyname(argv[2]));

    if (RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    if ((RAND_bytes(key, key_length) != 1))
        handle_errors();

    if ((RAND_bytes(iv, iv_length) != 1))
        handle_errors();

    printf("key string: ");
    for (int i = 0; i < key_length; i++)
    {
        printf("%02x-", key[i]);
    }

    printf("\n\niv string: ");
    for (int i = 0; i < iv_length; i++)
    {
        printf("%02x-", iv[i]);
    }

  if(!EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[2]), key, iv, ENCRYPT))
        handle_errors();


    unsigned char buffer[MAX];
    int n_read;

    unsigned char ciphertext[MAX+16];
    int length;
    int ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAX, f_in)) > 0) {

        if(!EVP_CipherUpdate(ctx, ciphertext, &length, buffer, n_read))
            handle_errors();

        ciphertext_len+=length;

        if(fwrite(ciphertext,1,length,f_out) < length) {
            fprintf(stderr,"Error writing into the output file.\n");
            abort();
        }
    }

    if(!EVP_CipherFinal(ctx, ciphertext,&length))
        handle_errors();
        
    if(fwrite(ciphertext,1,length,f_out) < length) {
        fprintf(stderr,"Error writing into the output file.\n");
        abort();
    }

    ciphertext_len+=length;

    EVP_CIPHER_CTX_free(ctx);

    printf("\n\nSize of the ciphertext: %d\n", ciphertext_len);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    fclose(f_in);
    fclose(f_out);


    return 0;
}