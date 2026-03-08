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
#include "simple_crypto.h"

int main() {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket failed");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 1) < 0) {
        perror("listen failed");
        close(server_sock);
        return 1;
    }

    std::cout << "Listening on port 12345 ...\n";

    int client_sock = accept(server_sock, nullptr, nullptr);
    if (client_sock < 0) {
        perror("accept failed");
        close(server_sock);
        return 1;
    }

    std::cout << "Client connected\n";

    SimpleCrypto crypto;
    int received_count = 0;
    const int EXPECTED_FRAMES = 10;

    std::vector<uint8_t> buffer(2048);

    while (received_count < EXPECTED_FRAMES) {
        ssize_t bytes = recv(client_sock, buffer.data(), buffer.size(), 0);

        if (bytes <= 0) {
            if (bytes < 0) perror("recv failed");
            break;
        }
        if (bytes < static_cast<ssize_t>(sizeof(StreamPacket))) {
            std::cerr << "Packet too small\n";
            continue;
        }

        StreamPacket pkt;

        // TEMP: simulate slow processing or packet loss
        //if (pkt.seq_num % 3 == 0) {          // every 3rd packet
        //  std::this_thread::sleep_for(std::chrono::milliseconds(1800)); // > 1s timeout
        //                                                                // or even: continue;   // drop packet → forces retransmit
        //}
        std::memcpy(&pkt, buffer.data(), sizeof(StreamPacket));

        pkt.version       = ntohs(pkt.version);
        pkt.payload_len   = ntohl(pkt.payload_len);
        pkt.seq_num       = ntohll(pkt.seq_num);
        pkt.timestamp     = ntohll(pkt.timestamp);
        uint32_t received_checksum = ntohl(pkt.checksum);

        size_t payload_start = sizeof(StreamPacket);
        if (bytes < static_cast<ssize_t>(payload_start + pkt.payload_len)) {
            std::cerr << "Incomplete payload\n";
            continue;
        }

        std::vector<uint8_t> enc_payload(buffer.begin() + payload_start,
                                        buffer.begin() + payload_start + pkt.payload_len);

        // Verify checksum
        size_t excl_size = sizeof(StreamPacket) - 68;
        std::vector<uint8_t> verify_data(excl_size + enc_payload.size());
        std::memcpy(verify_data.data(), buffer.data(), excl_size);
        std::memcpy(verify_data.data() + excl_size, enc_payload.data(), enc_payload.size());

        uint32_t computed = crypto.compute_checksum(verify_data.data(), verify_data.size());

        if (computed != received_checksum) {
            std::cout << "Checksum FAILED for seq " << pkt.seq_num << "\n";
            continue;
        }

        // Decrypt & check frame ID
        auto dec = crypto.xor_encrypt_decrypt(enc_payload);
        uint32_t frame_id = (dec[0] << 24) | (dec[1] << 16) | (dec[2] << 8) | dec[3];

        std::cout << "seq " << pkt.seq_num
          << " | ts " << pkt.timestamp
          << " | frame ID " << frame_id
          << " | payload " << pkt.payload_len << " B"
          << " | OK\n";

        // Send ACK
        uint64_t ack_net = htonll(pkt.seq_num);
        send(client_sock, &ack_net, sizeof(ack_net), 0);

        received_count++;
    }

std::cout << "Received " << received_count << "/" << EXPECTED_FRAMES
          << " frames successfully.\n";
    close(client_sock);
    close(server_sock);
    return 0;
}
