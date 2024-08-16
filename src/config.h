#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/bn.h>
#include <memory>

// Initialize BN_CTX once for all operations
inline BN_CTX* global_ctx = BN_CTX_new();

// Directly define and initialize the shared pointers for BIGNUMs
namespace ElGamalConfig {
    inline std::shared_ptr<BIGNUM> p = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    inline std::shared_ptr<BIGNUM> g = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    inline std::shared_ptr<BIGNUM> x = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
    inline std::shared_ptr<BIGNUM> y = std::shared_ptr<BIGNUM>(BN_new(), BN_free);

    // Static block to initialize p, g, x, and y
    struct Initialize {
        Initialize() {
            // Generate safe prime p and generator g
            BN_generate_prime_ex(p.get(), 2048, 1, NULL, NULL, NULL);
            BN_set_word(g.get(), 2);  // Common choice for the generator

            // Generate private key x
            BN_rand_range(x.get(), p.get());

            // Calculate public key y = g^x mod p
            BN_mod_exp(y.get(), g.get(), x.get(), p.get(), global_ctx);
        }
    };

    // This static instance will ensure the values are initialized only once
    inline Initialize initializer;
}

#endif // CONFIG_H
