#ifndef ELGAMAL_STANDARD_H
#define ELGAMAL_STANDARD_H

#include <openssl/bn.h>

class ElGamal_standard {
public:
    ElGamal_standard();
    ~ElGamal_standard();

    // Generate key pair
    void generate_key_pair();

    // Encrypt a message
    void encrypt(const BIGNUM *message, BIGNUM *ciphertext1, BIGNUM *ciphertext2);

    // Decrypt a ciphertext
    void decrypt(const BIGNUM *ciphertext1, const BIGNUM *ciphertext2, BIGNUM *message);

    // Re-randomize a ciphertext
    void re_randomize(BIGNUM *ciphertext1, BIGNUM *ciphertext2);

    // Perform multiplicative property of ciphertexts
    void multiply_ciphertexts(const BIGNUM *ciphertext1a, const BIGNUM *ciphertext2a,
                              const BIGNUM *ciphertext1b, const BIGNUM *ciphertext2b,
                              BIGNUM *result1, BIGNUM *result2);

    BIGNUM *p;    // Prime modulus
    BIGNUM *g;    // Generator
    BIGNUM *x;    // Private key
    BIGNUM *y;    // Public key
    BN_CTX *ctx;  // BN_CTX for operations
};

#endif // ELGAMAL_STANDARD_H
