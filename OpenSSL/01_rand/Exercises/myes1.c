/**
* Write a program in C that, using the OpenSSL library, generates two 128 bit random strings. 
* Then, it XOR them (bitwise) and prints the result on the standard output as an hex string.
*/

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX 128

void handle_errors()
{
    // Library for simple err handling
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    // Allocate space in memory to store generated sequence
    unsigned char random_string_1[MAX], random_string_2[MAX];
    int i;

    // To perform initialization of PRNG we do so
    // Load file may fail
    if (RAND_load_file("/dev/random", 64) != 64)
    {
        handle_errors();
    }

    if (RAND_bytes(random_string_1, MAX) != 1 || (RAND_bytes(random_string_2, MAX) != 1))
    {
        handle_errors();
    }

    printf("RANDOM 1 string\n");
    for (i = 0; i < MAX; i++)
    {
        printf("%02x-", random_string_1[i]);
    }

    printf("\n");

    printf("\nRANDOM 2 string\n");
    for (i = 0; i < MAX; i++)
    {
        printf("%02x-", random_string_2[i]);
    }

    printf("\n");

    unsigned char res[MAX];

    for (i = 0; i < MAX; i++)
    {
        res[i] = random_string_1[i] ^ random_string_2[i];
    }

    printf("\n");

    printf("XOR string\n");
    for (i = 0; i < MAX; i++)
    {
        printf("%02x-", res[i]);
    }
    printf("\n");
}