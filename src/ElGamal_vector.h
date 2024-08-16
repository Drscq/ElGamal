#ifndef ELGAMAL_VECTOR_H
#define ELGAMAL_VECTOR_H

#include "ElGamal_standard.h"
#include <vector>

class ElGamal_vector : public ElGamal_standard {
public:
    ElGamal_vector();
    ~ElGamal_vector();

    // Encrypt a vector of chars
    void encrypt_vector(const std::vector<char> &data, std::vector<BIGNUM *> &ciphertext1, std::vector<BIGNUM *> &ciphertext2);

    // Decrypt a vector of ciphertexts
    void decrypt_vector(const std::vector<BIGNUM *> &ciphertext1, const std::vector<BIGNUM *> &ciphertext2, std::vector<char> &data);

    BIGNUM* convert_to_bn(const std::vector<char> &data, size_t start);
    void convert_from_bn(BIGNUM *bn, std::vector<char> &data);
};

#endif // ELGAMAL_VECTOR_H
