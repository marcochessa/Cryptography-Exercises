/*1. Write a program that, using OpenSSL, generates three random strings of 32 bytes each, convert them into Big Numbers bn1,bn2,bn3, then computes:
- sum (bn1+bn2)
- difference (bn1-bn3)
- multiplication (bn1*bn2*bn3)
- integer division (bn3/bn1)
- modulus (bn1 mod bn2)
- modulus-exponentiation (bn1^bn3 mod bn2)*/
#include <stdio.h>
#include <openssl/bn.h>

int main() {
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();
    BIGNUM *bn3 = BN_new();

    BIGNUM *res = BN_new();

    char num_string1[] = "00000000000000000000000000000001";
    char num_string2[] = "00000000000000000000000000000002";
    char num_string3[] = "00000000000000000000000000000010";

    BN_dec2bn(&bn1, num_string1);
    BN_dec2bn(&bn2, num_string2);
    BN_dec2bn(&bn3, num_string3);

    //B1+B2
    BN_add(res, bn1, bn2);
    printf("RES B1+B2 \nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    //B1-B3
    BN_sub(res, bn1, bn3);
    printf("RES B1-B3\nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    
    BN_CTX *ctx = BN_CTX_new();

    //B1*B2*B3
    BN_mul(res, bn1, bn2, ctx);//B1*B2
    BN_mul(res, res, bn3, ctx);//res*B3
    printf("RES B1*B2*B3\nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    // B3/B2
    BN_div(res, NULL, bn3, bn2, ctx); //Reminder null
    printf("RES B3/B2 \nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    //B1 mod B2
    BN_mod(res, bn1, bn2, ctx);
    printf("RES B1 mod B2 \nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    //B1 mod B2
    BN_mod_exp(res, bn1, bn3, bn2, ctx);
    printf("RES B1 exp B3 mod B2 \nExa: ");
    BN_print_fp(stdout, res);
    printf("\nDecimal: %s\n\n", BN_bn2dec(res));

    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    BN_free(res);
    BN_CTX_free(ctx);
    return 0;
}