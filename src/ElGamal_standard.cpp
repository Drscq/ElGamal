#include "ElGamal_standard.h"
#include "config.h"
#include <openssl/rand.h>
#include <iostream>

ElGamal_standard::ElGamal_standard() {
    ctx = BN_CTX_new();
    this->p = BN_dup(ElGamalConfig::p.get());
    this->g = BN_dup(ElGamalConfig::g.get());
    this->x = BN_dup(ElGamalConfig::x.get());
    this->y = BN_dup(ElGamalConfig::y.get());
}

ElGamal_standard::~ElGamal_standard() {
    BN_free(p);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
}

void ElGamal_standard::generate_key_pair() {
    BN_rand_range(x, p);
    BN_mod_exp(y, g, x, p, ctx);
}

void ElGamal_standard::encrypt(const BIGNUM *message, BIGNUM *ciphertext1, BIGNUM *ciphertext2) {
    BIGNUM *k = BN_new();
    BIGNUM *temp = BN_new();

    // Generate random k
    BN_rand_range(k, p);
    // Calculate ciphertext1 = g^k mod p
    BN_mod_exp(ciphertext1, g, k, p, ctx);


    // Calculate ciphertext2 = message * y^k mod p
    BN_mod_exp(temp, y, k, p, ctx);
    BN_mod_mul(ciphertext2, message, temp, p, ctx);

    BN_free(k);
    BN_free(temp);
}

void ElGamal_standard::decrypt(const BIGNUM *ciphertext1, const BIGNUM *ciphertext2, BIGNUM *message) {
    BIGNUM *temp = BN_new();

    // Calculate temp = ciphertext1^x mod p
    BN_mod_exp(temp, ciphertext1, x, p, ctx);

    // Calculate temp_inv = temp^-1 mod p
    BIGNUM *temp_inv = BN_mod_inverse(NULL, temp, p, ctx);

    // Calculate message = ciphertext2 * temp_inv mod p
    BN_mod_mul(message, ciphertext2, temp_inv, p, ctx);

    BN_free(temp);
    BN_free(temp_inv);
}

void ElGamal_standard::re_randomize(BIGNUM *ciphertext1, BIGNUM *ciphertext2) {
    BIGNUM *k = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    // Generate random k
    BN_rand_range(k, p);

    // Re-randomize ciphertext1 = ciphertext1 * g^k mod p
    BN_mod_exp(temp1, g, k, p, ctx);
    BN_mod_mul(ciphertext1, ciphertext1, temp1, p, ctx);

    // Re-randomize ciphertext2 = ciphertext2 * y^k mod p
    BN_mod_exp(temp2, y, k, p, ctx);
    BN_mod_mul(ciphertext2, ciphertext2, temp2, p, ctx);

    BN_free(k);
    BN_free(temp1);
    BN_free(temp2);
}

void ElGamal_standard::multiply_ciphertexts(const BIGNUM *ciphertext1a, const BIGNUM *ciphertext2a,
                                            const BIGNUM *ciphertext1b, const BIGNUM *ciphertext2b,
                                            BIGNUM *result1, BIGNUM *result2) {
    // result1 = ciphertext1a * ciphertext1b mod p
    BN_mod_mul(result1, ciphertext1a, ciphertext1b, p, ctx);

    // result2 = ciphertext2a * ciphertext2b mod p
    BN_mod_mul(result2, ciphertext2a, ciphertext2b, p, ctx);
}
