#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "packet.h"
#include "simple_crypto.h"

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sock);
        return 1;
    }

    std::cout << "UDP receiver listening on port 12345 ...\n";

    SimpleCrypto crypto;
    uint64_t expected_seq = 1;
    int received_count = 0;
    const int MAX_FRAMES = 10;

    std::vector<uint8_t> buffer(2048);
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);

    while (received_count < MAX_FRAMES) {
        ssize_t bytes = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                 (sockaddr*)&sender_addr, &addr_len);
        if (bytes <= 0) {
            if (bytes < 0) perror("recvfrom failed");
            continue;
        }

        if (bytes < static_cast<ssize_t>(sizeof(StreamPacket))) {
            std::cerr << "Packet too small\n";
            continue;
        }

        StreamPacket pkt{};
        std::memcpy(&pkt, buffer.data(), sizeof(StreamPacket));

        pkt.version     = ntohs(pkt.version);
        pkt.payload_len = ntohl(pkt.payload_len);
        pkt.seq_num     = ntohll(pkt.seq_num);
        pkt.timestamp   = ntohll(pkt.timestamp);
        uint32_t rcv_checksum = ntohl(pkt.checksum);

        size_t payload_start = sizeof(StreamPacket);
        if (bytes < static_cast<ssize_t>(payload_start + pkt.payload_len)) {
            std::cerr << "Incomplete payload\n";
            continue;
        }

        std::vector<uint8_t> enc_payload(buffer.begin() + payload_start,
                                         buffer.begin() + payload_start + pkt.payload_len);

        // Checksum verification
        size_t excl = sizeof(StreamPacket) - 68;
        std::vector<uint8_t> verify(excl + enc_payload.size());
        std::memcpy(verify.data(), buffer.data(), excl);
        std::memcpy(verify.data() + excl, enc_payload.data(), enc_payload.size());
        uint32_t computed = crypto.compute_checksum(verify.data(), verify.size());

        if (computed != rcv_checksum) {
            std::cout << "Checksum FAIL seq " << pkt.seq_num << "\n";
            continue;
        }

        // Simple duplicate / out-of-order handling: only accept next expected
        if (pkt.seq_num < expected_seq) {
            std::cout << "Duplicate/old seq " << pkt.seq_num << " (expected " << expected_seq << ")\n";
        } else if (pkt.seq_num > expected_seq) {
            std::cout << "Out-of-order seq " << pkt.seq_num << " (expected " << expected_seq << ")\n";
            // For stop-and-wait: we could NACK or just ignore → here we ignore
            continue;
        }

        // Decrypt & validate
        auto dec = crypto.xor_encrypt_decrypt(enc_payload);
        uint32_t frame_id = (dec[0] << 24) | (dec[1] << 16) | (dec[2] << 8) | dec[3];

        std::cout << "Received seq " << pkt.seq_num
                  << " | Frame ID " << frame_id
                  << " | Decrypted OK\n";

        // Send ACK
        uint64_t ack_net = htonll(pkt.seq_num);
        sendto(sock, &ack_net, sizeof(ack_net), 0,
               (sockaddr*)&sender_addr, addr_len);

        expected_seq++;
        received_count++;

        // Optional: exit on special END seq=0
        if (pkt.seq_num == 0) break;
    }

    std::cout << "Received " << received_count << " valid frames.\n";
    close(sock);
    return 0;
}
