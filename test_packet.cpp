#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include <arpa/inet.h>
#include "packet.h"
#include "media_generator.h"
#include "simple_crypto.h"

// htonll/ntohll from packet.h—no dupe!

int main() {
    // Step 1: Create sample packet.
    StreamPacket pkt{};
    std::strcpy(pkt.magic, "STRM");
    pkt.version = htons(1);
    std::strcpy(pkt.sender_id, "remote_cam_01");
    pkt.seq_num = htonll(42);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    pkt.timestamp = htonll(static_cast<uint64_t>(now_ms));

    // Step 1.5: Generate raw frame.
    MediaGenerator gen;
    auto raw_frame = gen.generate_next_frame();
    uint32_t raw_size = static_cast<uint32_t>(raw_frame.size());

    // Step 2: XOR "encrypt".
    SimpleCrypto crypto;
    auto enc_frame = crypto.xor_encrypt_decrypt(raw_frame);
    uint32_t enc_size = static_cast<uint32_t>(enc_frame.size());
    pkt.payload_len = htonl(enc_size);

    // Step 3: Compute checksum (host sum).
    size_t excl_size = sizeof(StreamPacket) - 68;  // Excl. checksum(4)+auth(32)+hmac(32).
    std::vector<uint8_t> check_data(excl_size + enc_size);
    std::memcpy(check_data.data(), &pkt, excl_size);
    std::memcpy(check_data.data() + excl_size, enc_frame.data(), enc_size);
    uint32_t host_checksum = crypto.compute_checksum(check_data.data(), check_data.size());
    pkt.checksum = htonl(host_checksum);  // FIXED: Store network-order.

    // Dummy auth/hmac.
    std::memset(pkt.auth_token, 0, 32);
    std::memset(pkt.hmac, 0, 32);

    // Step 4: Serialize.
    std::vector<uint8_t> buffer(sizeof(StreamPacket) + enc_size);
    std::memcpy(buffer.data(), &pkt, sizeof(StreamPacket));
    std::memcpy(buffer.data() + sizeof(StreamPacket), enc_frame.data(), enc_size);

    // Step 5: Print.
    std::cout << "Header size: " << sizeof(StreamPacket) << " bytes (expect 110)" << std::endl;
    std::cout << "Full packet size: " << buffer.size() << " bytes" << std::endl;
    std::cout << "Hex dump (first 20 bytes): ";
    for (size_t i = 0; i < 20 && i < buffer.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    std::cout << "First 4 enc payload bytes: ";
    size_t payload_start = sizeof(StreamPacket);
    for (size_t i = 0; i < 4; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[payload_start + i]) << " ";
    }
    std::cout << std::dec << std::endl;

    // Step 6: Deserialize, Verify, Decrypt.
    StreamPacket pkt_received{};
    std::memcpy(&pkt_received, buffer.data(), sizeof(StreamPacket));
    pkt_received.seq_num = ntohll(pkt_received.seq_num);
    pkt_received.timestamp = ntohll(pkt_received.timestamp);
    pkt_received.version = ntohs(pkt_received.version);
    pkt_received.payload_len = ntohl(pkt_received.payload_len);
    uint32_t received_checksum = ntohl(pkt_received.checksum);  // FIXED: Host from network.

    std::vector<uint8_t> enc_received(buffer.begin() + sizeof(StreamPacket), 
                                      buffer.begin() + sizeof(StreamPacket) + pkt_received.payload_len);

    // Re-compute (host sum).
    std::vector<uint8_t> verify_data(excl_size + enc_received.size());
    std::memcpy(verify_data.data(), buffer.data(), excl_size);
    std::memcpy(verify_data.data() + excl_size, enc_received.data(), enc_received.size());
    uint32_t computed_checksum = crypto.compute_checksum(verify_data.data(), verify_data.size());  // FIXED: Host sum.

    bool checksum_ok = (computed_checksum == received_checksum);
    std::cout << "Checksum verification: " << (checksum_ok ? "OK" : "FAILED") << std::endl;

    // Tamper test (uncomment).
    // buffer[payload_start] ^= 0xFF;

    bool decrypt_ok = false;
    uint32_t decrypted_frame_id = 0;
    if (checksum_ok) {
        auto dec_frame = crypto.xor_encrypt_decrypt(enc_received);
        decrypted_frame_id = (dec_frame[0] << 24) | (dec_frame[1] << 16) | (dec_frame[2] << 8) | dec_frame[3];
        decrypt_ok = (decrypted_frame_id == gen.get_frame_counter());
    }

    std::cout << "Magic/Seq check: " << (std::memcmp(pkt.magic, pkt_received.magic, 4) == 0 && pkt_received.seq_num == 42 ? "OK" : "FAILED") << std::endl;
    std::cout << "Decrypt success: " << (decrypt_ok ? "YES (Frame ID: " + std::to_string(decrypted_frame_id) + ")" : "NO") << std::endl;

    return 0;
}
