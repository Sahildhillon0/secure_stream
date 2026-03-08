#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "packet.h"
#include "media_generator.h"
#include "simple_crypto.h"

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    sockaddr_in receiver_addr{};
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &receiver_addr.sin_addr);

    std::cout << "UDP sender ready (will send to 127.0.0.1:12345)\n";

    MediaGenerator gen;
    SimpleCrypto crypto;

    const int TOTAL_FRAMES = 10;
    int total_retransmits = 0;

    for (int i = 0; i < TOTAL_FRAMES; ++i) {
        uint64_t seq = i + 1;

        // Build packet (same as before)
        StreamPacket pkt{};
        std::strcpy(pkt.magic, "STRM");
        pkt.version = htons(1);
        std::strcpy(pkt.sender_id, "remote_cam_01");
        pkt.seq_num = htonll(seq);

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        pkt.timestamp = htonll(static_cast<uint64_t>(now_ms));

        auto raw_frame = gen.generate_next_frame();
        auto enc_frame = crypto.xor_encrypt_decrypt(raw_frame);

        pkt.payload_len = htonl(static_cast<uint32_t>(enc_frame.size()));

        size_t excl_size = sizeof(StreamPacket) - 68;
        std::vector<uint8_t> check_data(excl_size + enc_frame.size());
        std::memcpy(check_data.data(), &pkt, excl_size);
        std::memcpy(check_data.data() + excl_size, enc_frame.data(), enc_frame.size());
        uint32_t host_sum = crypto.compute_checksum(check_data.data(), check_data.size());
        pkt.checksum = htonl(host_sum);

        std::memset(pkt.auth_token, 0, 32);
        std::memset(pkt.hmac, 0, 32);

        std::vector<uint8_t> buffer(sizeof(StreamPacket) + enc_frame.size());
        std::memcpy(buffer.data(), &pkt, sizeof(StreamPacket));
        std::memcpy(buffer.data() + sizeof(StreamPacket), enc_frame.data(), enc_frame.size());

        // Send + wait for ACK with retries
        bool acked = false;
        int retries = 0;
        const int MAX_RETRIES = 5;           // more generous than TCP version
        const int TIMEOUT_MS = 800;

        while (!acked && retries < MAX_RETRIES) {
            ssize_t sent = sendto(sock, buffer.data(), buffer.size(), 0,
                                  (sockaddr*)&receiver_addr, sizeof(receiver_addr));
            if (sent < 0) {
                perror("sendto failed");
                break;
            }

            std::cout << "Sent seq " << seq << " (try " << (retries+1) << ")\n";

            // Wait for ACK
            uint64_t ack_seq_net;
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);

            auto start = std::chrono::steady_clock::now();

            while (true) {
                ssize_t n = recvfrom(sock, &ack_seq_net, sizeof(ack_seq_net), MSG_DONTWAIT,
                                     (sockaddr*)&from_addr, &from_len);
                if (n == sizeof(ack_seq_net)) {
                    uint64_t ack_seq = ntohll(ack_seq_net);
                    if (ack_seq == seq) {
                        std::cout << "ACK received for seq " << seq << "\n";
                        acked = true;
                        break;
                    } else {
                        std::cout << "Ignoring wrong ACK seq " << ack_seq << "\n";
                    }
                }

                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed_ms > TIMEOUT_MS) {
                    break;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }

            if (!acked) {
                std::cout << "Timeout → retransmitting seq " << seq << "\n";
                total_retransmits++;
                retries++;
            }
        }

        if (!acked) {
            std::cerr << "Failed to get ACK for seq " << seq << " after " << MAX_RETRIES << " tries\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250)); // simulate frame interval
    }

    std::cout << "Finished sending " << TOTAL_FRAMES << " frames. Retransmits: " << total_retransmits << "\n";

    // Optional: send simple END signal
    uint64_t end_seq = 0;
    sendto(sock, &end_seq, sizeof(end_seq), 0, (sockaddr*)&receiver_addr, sizeof(receiver_addr));

    close(sock);
    return 0;
}
