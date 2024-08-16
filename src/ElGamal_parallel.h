#ifndef ELGAMAL_PARALLEL_H
#define ELGAMAL_PARALLEL_H

#include "ElGamal_standard.h"
#include <vector>
#include <thread>
#include <future>
#include <functional>
#include <mutex>

class ElGamal_parallel : public ElGamal_standard {
public:
    ElGamal_parallel(size_t num_threads = 1, size_t data_size = 1024);
    ~ElGamal_parallel();

    // Encrypt a vector of chars
    void encrypt_vector(const std::vector<char> &data, std::vector<BIGNUM *> &ciphertext1, std::vector<BIGNUM *> &ciphertext2);

    // Decrypt a vector of ciphertexts
    void decrypt_vector(const std::vector<BIGNUM *> &ciphertext1, const std::vector<BIGNUM *> &ciphertext2, std::vector<char> &data);

    BIGNUM* convert_to_bn(const std::vector<char> &data, size_t start);
    void convert_from_bn(BIGNUM *bn, std::vector<char> &data);

    std::mutex mutex_; // Mutex to protect shared resources
    size_t num_threads; // Number of threads to use
    size_t chunk_size; // Chunk size for parallel processing
    size_t total_chunks; // Total number of chunks
    size_t data_size; // Size of the data to encrypt
    
};

#endif // ELGAMAL_PARALLEL_H
