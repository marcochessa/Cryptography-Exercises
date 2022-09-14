// A server is listening on a given port where it receives raw bytes
// When a client establishes a connection and sends some data, the server calls
// its internal function process(), which produces the output to send back to the
// client. The prototype of the function is the following one:

// char *process(char *data, int length, RSA *rsa_priv_key)

// The function process():
// Checks if data can be decrypted with rsa_priv_key; if possible,
// obtains decrypted_data by decrypting the data variable (by "manually" implementing
// the RSA decryption algorithm);
// Computes the hash h of decrypted_data using SHA256

// If data can be decrypted, process() returns three bytes:

// As a first byte, the least significant bit of decrypted_data
// As a second byte, the least significant bit of the hash h;
// As a third byte, the XOR of the previous two bytes

// Otherwise, it returns NULL.

// Implement in C the function process() described above using the OpenSSL library.

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>