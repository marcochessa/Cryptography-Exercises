/* 2. Write a program in C that, using the OpenSSL library, computes the hash 
 * of the concatenation of two files using SHA256 (or or SHA 512 or SHA3).
 * The filenames are passed as first and second parameters from the command line.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){
    if(argc != 3){
        fprintf(stderr,"Invalid parameters number usage: %s file1 file2\n", argv[0]);
        exit(-1);
    }

    FILE *f1_in; 
    if((f1_in = fopen (argv[1], "r")) == NULL) {
        printf("Couldn't open the input file, try again \n");
        exit(1);
    }

    
    FILE *f2_in; 
    if((f2_in = fopen (argv[1], "r")) == NULL) {
        printf("Couldn't open the input file, try again \n");
        exit(1);
    }

    // Pointer to the data structure
    EVP_MD_CTX *md;

    // Best practise
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Create data structure 
    md = EVP_MD_CTX_new();

    // Init
    if(!EVP_DigestInit(md, EVP_sha256())) //Algoritmo specificato nel testoo
        handle_errors();

    unsigned char buffer[MAXBUF];
    int n_read;
    while ((n_read = fread(buffer, 1, MAXBUF, f1_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }
    
    while ((n_read = fread(buffer, 1, MAXBUF, f2_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    // Feed the context with data to be used for the operation
    //EVP_DigestUpdate(md, argv[1], strlen(argv[1]));

    // SHA1 gives back 20 bytes = 160 bits. If u don't know
    // allocate larger buffer then use md_len 
    //unsigned char md_value[20]; 
    unsigned char md_value[EVP_MD_size(EVP_sha256())];

    // How many data actually generated
    int md_len;

    // Finalize the digest
    if(!EVP_DigestFinal(md, md_value, &md_len))
        handle_errors();

    // Free memory
    EVP_MD_CTX_free(md);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The digest is: ");
    for(int i=0; i<md_len; i++){
        printf("%02x", md_value[i]);
    }
    printf("\n");

}