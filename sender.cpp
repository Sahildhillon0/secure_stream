#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "packet.h"
#include "media_generator.h"
#include "simple_crypto.h"

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1;
    }

    std::cout << "Connected to receiver\n";

    MediaGenerator gen;
    SimpleCrypto crypto;

    const int TOTAL_FRAMES = 10;

    for (int i = 0; i < TOTAL_FRAMES; ++i) {
        // ── Build packet (same logic as your test_packet.cpp) ────────────────
        StreamPacket pkt{};
        std::strcpy(pkt.magic, "STRM");
        pkt.version = htons(1);
        std::strcpy(pkt.sender_id, "remote_cam_01");

        uint64_t seq = i + 1;
        pkt.seq_num = htonll(seq);

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        pkt.timestamp = htonll(static_cast<uint64_t>(now_ms));

        auto raw_frame = gen.generate_next_frame();
        auto enc_frame = crypto.xor_encrypt_decrypt(raw_frame);

        pkt.payload_len = htonl(static_cast<uint32_t>(enc_frame.size()));

        // checksum (host-order bytes → sum → network byte order)
        size_t excl_size = sizeof(StreamPacket) - 68; // checksum(4)+auth(32)+hmac(32)
        std::vector<uint8_t> check_data(excl_size + enc_frame.size());
        std::memcpy(check_data.data(), &pkt, excl_size);
        std::memcpy(check_data.data() + excl_size, enc_frame.data(), enc_frame.size());
        uint32_t host_sum = crypto.compute_checksum(check_data.data(), check_data.size());
        pkt.checksum = htonl(host_sum);

        std::memset(pkt.auth_token, 0, 32);
        std::memset(pkt.hmac, 0, 32);

        // ── Serialize ────────────────────────────────────────────────────────
        std::vector<uint8_t> buffer(sizeof(StreamPacket) + enc_frame.size());
        std::memcpy(buffer.data(), &pkt, sizeof(StreamPacket));
        std::memcpy(buffer.data() + sizeof(StreamPacket), enc_frame.data(), enc_frame.size());

        // ── Send with basic retry ────────────────────────────────────────────
        bool acked = false;
        int retries = 0;
        const int MAX_RETRIES = 3;

        while (!acked && retries < MAX_RETRIES) {
            ssize_t sent = send(sock, buffer.data(), buffer.size(), 0);
            if (sent < 0) {
                perror("send failed");
                break;
            }

            std::cout << "Sent seq " << seq << " (try " << (retries+1) << ")\n";

            // Wait for ACK (non-blocking style with timeout)
            uint64_t ack_seq_net;
            auto start = std::chrono::steady_clock::now();

            while (true) {
                ssize_t n = recv(sock, &ack_seq_net, sizeof(ack_seq_net), MSG_DONTWAIT);
                if (n == sizeof(ack_seq_net)) {
                    uint64_t ack_seq = ntohll(ack_seq_net);
                    if (ack_seq == seq) {
                        std::cout << "ACK received for seq " << seq << "\n";
                        acked = true;
                        break;
                    }
                }

                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
                if (elapsed > 1000) { // 1 second timeout
                    std::cout << "Timeout → retransmitting seq " << seq << "\n";
                    retries++;
                    break;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }

        if (!acked) {
            std::cerr << "Giving up on seq " << seq << " after " << MAX_RETRIES << " tries\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(300)); // simulate frame rate
    }

    std::cout << "Finished sending " << TOTAL_FRAMES << " frames.\n";
    close(sock);
    return 0;
}
