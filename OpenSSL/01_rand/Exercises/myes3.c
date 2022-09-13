/* 
    3. Using OpenSSL, generate two 32 bit integers (int), multiply them (modulo 2^32) and print the result.
*/

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <math.h>

#define BITS 32
#define BYTES 4

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {

    if(RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    unsigned char n1[BYTES], n2[BYTES];

    if(!RAND_bytes(n1, BYTES))
        handle_errors();

    if(!RAND_bytes(n2, BYTES))
        handle_errors();

    unsigned int int1 = 0, int2 = 0;

    for(int i=BYTES-1; i>=0; i--){
        int1 += n1[i]*pow(pow(2,8),BYTES-1-i);
        int2 += n2[i]*pow(pow(2,8),BYTES-1-i);
    }

    unsigned int resunsigned = (int1*int2);

    printf("%u * %u = %u \n", int1, int2, resunsigned);

    return 0;
}