#include <iostream>
#include <vector>
#include <random>
// #include "ElGamal.h"  // Include the header file for the ElGamal class
#include "ECElGamal_parallel.h"
#include "DurationLogger.h"
#include <filesystem>
#include <sys/stat.h>
#include <chrono>
#include <time.h>
#include <cassert>
#include "ElGamal_standard.h"
#include "ElGamal_vector.h"
#include "ElGamal_parallel.h"
#include "../../../../../../../usr/include/openssl/ec.h"
#include "../../../../../../../usr/include/openssl/objects.h"
// extern "C" {
//     // #include "crtgamal_standard_encrypt.h"
//     #include "ecelgamal_standard.h"

// }
using namespace std::chrono;

void listAllSupportedCurves() {
    size_t numCurves;
    EC_builtin_curve *curves;

    // Get the number of built-in curves
    numCurves = EC_get_builtin_curves(nullptr, 0);

    // Allocate memory for the curves
    curves = new EC_builtin_curve[numCurves];
    if (curves == nullptr) {
        std::cerr << "Memory allocation failed" << std::endl;
        return;
    }

    // Get the built-in curves
    if (!EC_get_builtin_curves(curves, numCurves)) {
        std::cerr << "Failed to get built-in curves" << std::endl;
        delete[] curves;
        return;
    }

    // Print the curve names and NIDs
    for (size_t i = 0; i < numCurves; ++i) {
        const char *curveName = OBJ_nid2sn(curves[i].nid);
        std::cout << "Curve Name: " << curveName << ", NID: " << curves[i].nid << std::endl;
    }

    // Free the allocated memory
    delete[] curves;
}
std::string logPath = "../../log";
// check if the config::logPath exists and create it if not via std::filesystem
void createLogDirectory() {
    if (!std::filesystem::exists(logPath)) {
        std::cout << "Creating log directory: " << logPath << std::endl;
        std::filesystem::create_directory(logPath);
    }
}
// Function to generate binary data of a given size in KB
std::vector<char> generate_binary_data(size_t size_in_kb) {
    std::vector<char> data(size_in_kb * 1024);  // Initialize the vector with the specified size
    std::random_device rd;
    std::mt19937 generator(rd());
    
    // Using int8_t to ensure correct range from -128 to 127 (signed char) or 0 to 255 (unsigned char)
    std::uniform_int_distribution<int> distribution(0, 255);

    for (auto &c : data) {
        c = static_cast<char>(distribution(generator));  // Cast the int to char explicitly
    }

    return data;
}
void test_ecelgamal_parallel(ECElGamal_parallel &ecelgamal_parallel) {
    std::vector<char> plaintext = generate_binary_data(1);  // 1 KB of binary data
    std::vector<crtgamal_ciphertext_ptr> ciphertexts = ecelgamal_parallel.encrypt(plaintext);
    // Calculate the size of the ciphertexts
    size_t total_ciphertext_size = 0;
    for (auto &ciphertext : ciphertexts) {
        total_ciphertext_size += crt_get_encoded_ciphertext_size(ciphertext);
    }
    std::cout << "Total ciphertext size: " << total_ciphertext_size << " bytes" << std::endl;
    std::vector<char> decrypted;
    ecelgamal_parallel.decrypt(ciphertexts, plaintext.size(), decrypted);
    if (plaintext == decrypted) {
        std::cout << "Parallel Encryption/Decryption Test: PASSED" << std::endl;
    } else {
        std::cout << "Parallel Encryption/Decryption Test: FAILED" << std::endl;
        std::cout << "The size of the plaintext is: " << plaintext.size() << std::endl;
        std::cout << "The size of the decrypted is: " << decrypted.size() << std::endl;
        for (int i = 0; i < plaintext.size(); i++) {
            if (plaintext[i] != decrypted[i]) {
                std::cout << "The value of i is: " << i << std::endl;
                return;
            }
        }
    }

}
void test_elgamal_standard(ElGamal_standard &elgamal) {
    // Step 1: Generate a key pair (already done in the constructor or manually with generate_key_pair)
    elgamal.generate_key_pair();
    int64_t message_value = 9223372036854775807;
    // Step 2: Test encryption and decryption
    BIGNUM *message = BN_new();
    BN_set_word(message, message_value);  // Example message

    BIGNUM *ciphertext1 = BN_new();
    BIGNUM *ciphertext2 = BN_new();

    // Encrypt the message
    elgamal.encrypt(message, ciphertext1, ciphertext2);

    // Decrypt the ciphertext
    BIGNUM *decrypted_message = BN_new();
    elgamal.decrypt(ciphertext1, ciphertext2, decrypted_message);

    std::cout << "Original Message: " << BN_bn2dec(message) << std::endl;
    std::cout << "Decrypted Message: " << BN_bn2dec(decrypted_message) << std::endl;

    // Verify decryption
    if (BN_cmp(message, decrypted_message) == 0) {
        std::cout << "Encryption/Decryption Test: PASSED" << std::endl;
    } else {
        std::cout << "Encryption/Decryption Test: FAILED" << std::endl;
    }

    // Step 3: Test re-randomization
    BIGNUM *original_ciphertext1 = BN_dup(ciphertext1);
    BIGNUM *original_ciphertext2 = BN_dup(ciphertext2);

    elgamal.re_randomize(ciphertext1, ciphertext2);

    std::cout << "Ciphertext re-randomized." << std::endl;

    // Decrypt the re-randomized ciphertext
    elgamal.decrypt(ciphertext1, ciphertext2, decrypted_message);

    // Verify that the decrypted message is still the same
    if (BN_cmp(message, decrypted_message) == 0) {
        std::cout << "Re-randomization Test: PASSED" << std::endl;
    } else {
        std::cout << "Re-randomization Test: FAILED" << std::endl;
    }

    // Step 4: Test multiplicative property
    BIGNUM *ciphertext1b = BN_new();
    BIGNUM *ciphertext2b = BN_new();

    // Encrypt another message
    BIGNUM *message_b = BN_new();
    BN_set_word(message_b, 54321);  // Another example message
    elgamal.encrypt(message_b, ciphertext1b, ciphertext2b);

    BIGNUM *result1 = BN_new();
    BIGNUM *result2 = BN_new();

    elgamal.multiply_ciphertexts(original_ciphertext1, original_ciphertext2, ciphertext1b, ciphertext2b, result1, result2);

    // Decrypt the multiplied ciphertext
    BIGNUM *multiplied_decrypted_message = BN_new();
    elgamal.decrypt(result1, result2, multiplied_decrypted_message);

    // Calculate expected multiplied plaintext
    BIGNUM *expected_multiplied_message = BN_new();
    BN_mod_mul(expected_multiplied_message, message, message_b, elgamal.p, elgamal.ctx);

    std::cout << "Expected Multiplied Message: " << BN_bn2dec(expected_multiplied_message) << std::endl;
    std::cout << "Decrypted Multiplied Message: " << BN_bn2dec(multiplied_decrypted_message) << std::endl;

    // Verify the multiplication
    if (BN_cmp(expected_multiplied_message, multiplied_decrypted_message) == 0) {
        std::cout << "Multiplicative Property Test: PASSED" << std::endl;
    } else {
        std::cout << "Multiplicative Property Test: FAILED" << std::endl;
    }

    // Clean up
    BN_free(message);
    BN_free(ciphertext1);
    BN_free(ciphertext2);
    BN_free(decrypted_message);
    BN_free(original_ciphertext1);
    BN_free(original_ciphertext2);
    BN_free(ciphertext1b);
    BN_free(ciphertext2b);
    BN_free(result1);
    BN_free(result2);
    BN_free(message_b);
    BN_free(multiplied_decrypted_message);
    BN_free(expected_multiplied_message);
}

void test_elgamal_vector(ElGamal_vector &elgamal_vector) {
    // Example data
    std::vector<char> data = generate_binary_data(4);

    // Encrypt the data
    std::vector<BIGNUM *> ciphertext1;
    std::vector<BIGNUM *> ciphertext2;
    elgamal_vector.encrypt_vector(data, ciphertext1, ciphertext2);

    // Decrypt the data
    std::vector<char> decrypted_data;
    elgamal_vector.decrypt_vector(ciphertext1, ciphertext2, decrypted_data);

    // Output the results
    // std::cout << "Original Data: " << std::string(data.begin(), data.end()) << std::endl;
    std::cout << "The size of the original data is: " << data.size() << std::endl;
    // std::cout << "Decrypted Data: " << std::string(decrypted_data.begin(), decrypted_data.end()) << std::endl;
    std::cout << "The size of the decrypted data is: " << decrypted_data.size() << std::endl;  

    // Verify the results
    if (data == decrypted_data) {
        std::cout << "Vector Encryption/Decryption Test: PASSED" << std::endl;
    } else {
        std::cout << "Vector Encryption/Decryption Test: FAILED" << std::endl;
    }

    // Clean up
    for (auto &bn : ciphertext1) {
        BN_free(bn);
    }
    for (auto &bn : ciphertext2) {
        BN_free(bn);
    }
}

void test_elgamal_parallel(ElGamal_parallel &elgamal_parallel) {
    // Example data
    std::vector<char> data = generate_binary_data(4);  // 1 KB of binary data
    // Encrypt the data using multi-threading
    std::vector<BIGNUM *> ciphertext1;
    std::vector<BIGNUM *> ciphertext2;
    elgamal_parallel.encrypt_vector(data, ciphertext1, ciphertext2);
    // Decrypt the data using multi-threading
    std::vector<char> decrypted_data;
    elgamal_parallel.decrypt_vector(ciphertext1, ciphertext2, decrypted_data);
    // Verify the results
    for (int i = 0; i < data.size(); i++) {
        if (data[i] != decrypted_data[i]) {
            std::cout << "The value of i is: " << i << std::endl;
            return;
        }
    }
    if (data == decrypted_data) {
        std::cout << "Parallel Vector Encryption/Decryption Test: PASSED" << std::endl;
    } else {
        std::cout << "Parallel Vector Encryption/Decryption Test: FAILED" << std::endl;
    }

    // Clean up
    for (auto &bn : ciphertext1) {
        BN_free(bn);
    }
    for (auto &bn : ciphertext2) {
        BN_free(bn);
    }
}
// Helper function to print BIGNUM values
void printBN(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);  // Convert BIGNUM to a hexadecimal string
    std::cout << label << ": " << bn_str << std::endl;
    OPENSSL_free(bn_str);  // Free the string returned by BN_bn2hex
}
int main() {
    // Run the test
    // // 1. test for the standard ElGamal in prime order
    // ElGamal_standard elgamal;
    // test_elgamal_standard(elgamal);
    // // 2. test for the ElGamal in arbitrary input size
    // ElGamal_vector elgamal_vector;
    // test_elgamal_vector(elgamal_vector);
    // test for the ElGamal in parallel
    // ElGamal_parallel elgamal_parallel(32, 4 * 1024);

    // test_elgamal_parallel(elgamal_parallel);
    // listAllSupportedCurves();

    // ECElGamal_parallel ecelgamal_parallel;
    ECElGamal_parallel ecelgamal_parallel(16, 64, 32);
    test_ecelgamal_parallel(ecelgamal_parallel);

    return 0;
}


// int main() {
//     createLogDirectory();
//     // Array of sizes in KB
//     std::vector<size_t> sizes = {4, 8, 16, 32, 64, 128, 256, 512, 1024};

//     // Initialize the ElGamal object with default parameters

//     for (size_t size_in_kb : sizes) {
//         std::cout << "\nTesting with data size: " << size_in_kb << " KB" << std::endl;
//         ECElGamal_parallel ecelgamal_parallel(16, 64, 32);
//         std::string logFile = logPath + "/BlockSize" + std::to_string(size_in_kb) + ".txt";
//         DurationLogger logger(logFile);
//         // Generate binary data of the specified size
//         std::vector<char> plaintext = generate_binary_data(size_in_kb);
//         std::cout << "Generated plaintext data" << std::endl;
//         // Encrypt the data
//         logger.startTiming("encrypt_parallel_ec");
//         std::vector<crtgamal_ciphertext_ptr> ciphertexts = ecelgamal_parallel.encrypt(plaintext);
//         logger.stopTiming("encrypt_parallel_ec");

//         // Decrypt the data
//         logger.startTiming("decrypt_parallel_ec");
//         std::vector<char> decrypted;
//         ecelgamal_parallel.decrypt(ciphertexts, plaintext.size(), decrypted);
//         logger.stopTiming("decrypt_parallel_ec");
//         logger.writeToFile();

//         // Validate the decrypted data
//         if (plaintext == decrypted) {
//             std::cout << "Test passed for size: " << size_in_kb << " KB" << std::endl;
//         } else {
//             std::cout << "Test failed for size: " << size_in_kb << " KB" << std::endl;
//         }
//     }

//     return 0;
// }
