#include "ElGamal_vector.h"
#include <openssl/rand.h>
#include <iostream>
#include <cstring>

ElGamal_vector::ElGamal_vector() {}

ElGamal_vector::~ElGamal_vector() {}

BIGNUM* ElGamal_vector::convert_to_bn(const std::vector<char> &data, size_t start) {
    BIGNUM *bn = BN_new();
    uint64_t value = 0;

    size_t end = std::min(start + 8, data.size());

    // Process up to 8 bytes (64 bits) at a time
    for (size_t i = start; i < end; ++i) {
        value = (value << 8) | static_cast<unsigned char>(data[i]);
    }

    BN_set_word(bn, value);
    return bn;
}

void ElGamal_vector::convert_from_bn(BIGNUM *bn, std::vector<char> &data) {
    uint64_t value = BN_get_word(bn);
    std::vector<char> temp;

    // Convert the BIGNUM back into 8 bytes
    for (int i = 7; i >= 0; --i) {
        char byte = static_cast<char>((value >> (i * 8)) & 0xFF);
        temp.push_back(byte);
    }

    // Remove leading null bytes to match the original data length
    // size_t start = 0;
    // while (start < temp.size() && temp[start] == 0) {
    //     ++start;
    // }

    data.insert(data.end(), temp.begin(), temp.end());
}

void ElGamal_vector::encrypt_vector(const std::vector<char> &data, std::vector<BIGNUM *> &ciphertext1, std::vector<BIGNUM *> &ciphertext2) {
    for (size_t i = 0; i < data.size(); i += 8) {
        BIGNUM *message_bn = convert_to_bn(data, i);

        BIGNUM *c1 = BN_new();
        BIGNUM *c2 = BN_new();
        encrypt(message_bn, c1, c2);

        ciphertext1.push_back(c1);
        ciphertext2.push_back(c2);

        BN_free(message_bn);
    }
}

void ElGamal_vector::decrypt_vector(const std::vector<BIGNUM *> &ciphertext1, const std::vector<BIGNUM *> &ciphertext2, std::vector<char> &data) {
    for (size_t i = 0; i < ciphertext1.size(); ++i) {
        BIGNUM *decrypted_bn = BN_new();
        decrypt(ciphertext1[i], ciphertext2[i], decrypted_bn);

        convert_from_bn(decrypted_bn, data);
        BN_free(decrypted_bn);
    }

    // Remove potential padding
    while (!data.empty() && data.back() == 0) {
        data.pop_back();
    }
}
