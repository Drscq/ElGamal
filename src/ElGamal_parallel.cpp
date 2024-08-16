#include "ElGamal_parallel.h"
#include <openssl/rand.h>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <cmath>

ElGamal_parallel::ElGamal_parallel(size_t num_threads, size_t data_size) : num_threads(num_threads), data_size(data_size) {
    this->chunk_size = this->data_size / this->num_threads; // make sure the chunk size is a multiple of 8
    this->total_chunks = this->data_size / this->chunk_size; // chunk_size * total_chunks = data_size
}

ElGamal_parallel::~ElGamal_parallel() {}

BIGNUM* ElGamal_parallel::convert_to_bn(const std::vector<char> &data, size_t start) {
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

void ElGamal_parallel::convert_from_bn(BIGNUM *bn, std::vector<char> &data) {
    uint64_t value = BN_get_word(bn);
    std::vector<char> temp;

    // Convert the BIGNUM back into 8 bytes
    for (int i = 7; i >= 0; --i) {
        char byte = static_cast<char>((value >> (i * 8)) & 0xFF);
        temp.push_back(byte);
    }

    data.insert(data.end(), temp.begin(), temp.end());
}

void ElGamal_parallel::encrypt_vector(const std::vector<char> &data, std::vector<BIGNUM *> &ciphertext1, std::vector<BIGNUM *> &ciphertext2) {
    std::vector<std::vector<std::pair<BIGNUM*, BIGNUM*>>> results(this->total_chunks);
    std::mutex results_mutex;

    std::vector<std::future<void>> futures;

    for (size_t chunk = 0; chunk < this->total_chunks; ++chunk) {
        futures.push_back(std::async(std::launch::async, [this, &data, &results, chunk, &results_mutex] {
            size_t start = chunk * this->chunk_size;
            size_t end = std::min(start + this->chunk_size, data.size());

            std::vector<std::pair<BIGNUM*, BIGNUM*>> chunk_results;
            for (size_t i = start; i < end; i += 8) {
                BIGNUM *message_bn = convert_to_bn(data, i);
                BIGNUM *c1 = BN_new();
                BIGNUM *c2 = BN_new();
                ElGamal_standard elgamal_standard;
                elgamal_standard.encrypt(message_bn, c1, c2);

                chunk_results.emplace_back(c1, c2);
                BN_free(message_bn);
            }

            // Directly store the results in the corresponding position
            {
                std::lock_guard<std::mutex> lock(results_mutex);
                results[chunk] = std::move(chunk_results);
            }
        }));
    }

    // Wait for all tasks to finish
    for (auto &f : futures) {
        f.get();
    }

    // Combine the results into ciphertext vectors
    for (const auto &chunk_results : results) {
        for (const auto &pair : chunk_results) {
            ciphertext1.push_back(pair.first);
            ciphertext2.push_back(pair.second);
        }
    }
}

void ElGamal_parallel::decrypt_vector(const std::vector<BIGNUM *> &ciphertext1, const std::vector<BIGNUM *> &ciphertext2, std::vector<char> &data) {
    std::vector<std::vector<char>> results(this->total_chunks);

    std::vector<std::future<void>> futures;

    for (size_t chunk = 0; chunk < this->total_chunks; ++chunk) {
        futures.push_back(std::async(std::launch::async, [this, &ciphertext1, &ciphertext2, chunk, &results] {
            size_t start = chunk * this->chunk_size;
            size_t end = std::min(start + this->chunk_size, ciphertext1.size());

            std::vector<char> partial_data;
            for (size_t i = start; i < end; ++i) {
                BIGNUM *decrypted_bn = BN_new();
                ElGamal_standard elgamal_standard;
                elgamal_standard.decrypt(ciphertext1[i], ciphertext2[i], decrypted_bn);

                convert_from_bn(decrypted_bn, partial_data);
                BN_free(decrypted_bn);
            }

            // Directly store the results in the corresponding position
            results[chunk] = std::move(partial_data);
        }));
    }

    // Wait for all tasks to finish
    for (auto &f : futures) {
        f.get();
    }

    // Combine the results into the final data vector
    for (const auto &partial_data : results) {
        data.insert(data.end(), partial_data.begin(), partial_data.end());
    }

    // Remove potential padding
    while (!data.empty() && data.back() == 0) {
        data.pop_back();
    }
}


