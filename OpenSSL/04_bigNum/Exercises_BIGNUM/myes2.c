/*********** DH key exchange**************
 * This program calculates the Key for two persons
using the Diffie-Hellman Key exchange algorithm */
#include <stdio.h>
#include <openssl/bn.h>

// Driver program
int main()
{

    BIGNUM *P = BN_new();
    BIGNUM *G = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *ka = BN_new();
    BIGNUM *kb = BN_new();

    // Both the persons will be agreed upon the
    // public keys G and P
    BN_set_word(P, 23); // A prime number P is taken
    printf("The value of P : %s", BN_bn2dec(P));

    if (BN_is_prime_ex(P, 16, NULL, NULL))
        printf(" ---> It is a prime number\n");
    else
        printf(" ---> It is not a prime number\n");

    BN_set_word(G, 9); // A primitive root for P, G is taken
    printf("The value of G :  %s\n", BN_bn2dec(G));

    // Alice will choose the private key a
    BN_set_word(a, 4); // a is the chosen private key
    printf("The private key a for Alice : %s\n", BN_bn2dec(a));

    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(x, G, a, P, ctx); // gets the generated key x

    // Bob will choose the private key b
    BN_set_word(b, 3); // b is the chosen private key
    printf("The private key b for Bob :  %s\n", BN_bn2dec(b));

    BN_mod_exp(y, G, b, P, ctx); // gets the generated key y

    // Generating the secret key after the exchange
    // of keys
    BN_mod_exp(ka, y, a, P, ctx); // Secret key for Alice
    BN_mod_exp(kb, x, b, P, ctx); // Secret key for Bob


    //SESSION KEYS (shared secrets) kb AND ka MUST BE EQUALS
    printf("Secret key for the Alice is : %s\n", BN_bn2dec(ka));
    printf("Secret Key for the Bob is : %s\n", BN_bn2dec(kb));

    if(BN_cmp(ka, kb) == 0) {
        printf("Secret Key are equal --> Algorithm is ok\n");
    } else {
        printf("Secret Key are different\n");
    }


    BN_free(P);
    BN_free(G);
    BN_free(x);
    BN_free(a);
    BN_free(y);
    BN_free(b);
    BN_free(ka);
    BN_free(kb);
    BN_CTX_free(ctx);
    return 0;
}