#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <vector>
#include <cstdint>
#include <string>

class SimpleCrypto {
private:
    std::string key = "secretkey";  // Repeating XOR key.

public:
    std::vector<uint8_t> xor_encrypt_decrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> out(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            out[i] = static_cast<uint8_t>(data[i] ^ key[i % key.size()]);
        }
        return out;
    }

    // FIXED: Return host-order sum (no htonl—compare hosts, store network).
    uint32_t compute_checksum(const uint8_t* data, size_t len) {
        uint32_t sum = 0;
        for (size_t i = 0; i < len; ++i) {
            sum += data[i];
            // Simplified: No if (overflow wraps naturally in uint32_t).
        }
        return sum & 0xFFFFFFFFU;
    }
};

#endif  // SIMPLE_CRYPTO_H
