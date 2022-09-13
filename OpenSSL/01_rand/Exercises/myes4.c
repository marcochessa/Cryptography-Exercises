/*
4. Using OpenSSL, generate two 256 bit integers, sum them (modulo 2^256) and print the result.
*/

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <math.h>

#define BITS 256
#define BYTES 32

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    if (RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    unsigned char n1[BYTES], n2[BYTES], res[BYTES];

    if (!RAND_bytes(n1, BYTES))
        handle_errors();

    if (!RAND_bytes(n2, BYTES))
        handle_errors();

    unsigned int rem = 0;

    for (int i = BYTES - 1; i >= 0; i--)
    {
        res[i] = n1[i] + n2[i] + rem;
        rem = n1[i] + n2[i] + rem >> 8;
    }

    printf("N1\n");
    for (int i = 0; i < BYTES; i++)
    {
        printf("%03d -", n1[i]);
    }
    printf("\n");

    printf("N2\n");
    for (int i = 0; i < BYTES; i++)
    {
        printf("%03d -", n2[i]);
    }
    printf("\n");

    printf("RES\n");
    for (int i = 0; i < BYTES; i++)
    {
        printf("%03d -", res[i]);
    }
    printf("\n");

    return 0;
}