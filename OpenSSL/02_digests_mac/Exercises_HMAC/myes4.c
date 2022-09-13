/* 
 * 4. Write a program in C that manually implements the HMAC algorithm using OpenSSL 
 * (i.e., implements all the low-level transformation required to compute the HMAC, don't use the already provided interfaces like EVP_DigestSign_ or HMAC_).  
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>

#include <openssl/evp.h>

#define SIZE 32
// First parameter is the name of the file to hash

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    char message[SIZE] = "This is the message to hash!!!!!";
    char key[SIZE] = "12345678900987654321123456789098";

    char o_key_pad[SIZE], i_key_pad[SIZE];
    // Pointer to the data structure
    EVP_MD_CTX *md;

    // Best practise
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /*
     * Outer padded key --> o_key_pad ← block_sized_key xor [0x5c blockSize]
     *
     * Inner padded key --> i_key_pad ← block_sized_key xor [0x36 blockSize]
     */

    for (int i = 0; i < SIZE; i++)
    {
        o_key_pad[i] = key[i] ^ 0x5c;
        i_key_pad[i] = key[i] ^ 0x36;
    }

    // Create data structure
    md = EVP_MD_CTX_new();

    /******** HASH ALGORITM*********
    * --> hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    * */

    //  Init
    if (!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();

    /* [ikey pad][ message ] 
        <--32-->  <--32-->   */
    if (!EVP_DigestUpdate(md, i_key_pad, SIZE))
        handle_errors();
    if (!EVP_DigestUpdate(md, message, SIZE))
        handle_errors();

    unsigned char md_value[EVP_MD_size(EVP_sha256())];

    // How many data actually generated
    int md_len;

    // Finalize the digest
    if (!EVP_DigestFinal(md, md_value, &md_len))
        handle_errors();

    /* ----------------------------- Second Init ------------------ */
    if (!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();


    /* [okey pad][hashed message] 
        <--32-->  <----32----->   */
    if (!EVP_DigestUpdate(md, o_key_pad, SIZE))
        handle_errors();
    if (!EVP_DigestUpdate(md, md_value, SIZE))
        handle_errors();

    // Finalize the digest
    if (!EVP_DigestFinal(md, md_value, &md_len))
        handle_errors();

    // Free memory
    EVP_MD_CTX_free(md);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("The manually hmac is: ");
    for (int i = 0; i < md_len; i++)
    {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    // Can compare the result with
    // openssl dgst -sha1 input.txt

    return 0;
}