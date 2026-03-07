#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include "packet.h"

uint64_t htonll(uint64_t val) {
    uint32_t high = htonl(static_cast<uint32_t>(val >> 32));
    uint32_t low  = htonl(static_cast<uint32_t>(val & 0xFFFFFFFF));
    return (static_cast<uint64_t>(low) << 32) | high;
}

uint64_t ntohll(uint64_t val) {
    uint32_t high = ntohl(static_cast<uint32_t>(val >> 32));
    uint32_t low  = ntohl(static_cast<uint32_t>(val & 0xFFFFFFFF));
    return (static_cast<uint64_t>(low) << 32) | high;
}
int main() {
    StreamPacket pkt{};
    std::strcpy(pkt.magic, "STRM");
    pkt.version = htons(1);
    std::strcpy(pkt.sender_id, "remote_cam_01");
    pkt.seq_num = htonll(42);
    
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    pkt.timestamp = htonll(static_cast<uint64_t>(now_ms));
    
    uint32_t payload_size = 1024;
    pkt.payload_len = htonl(payload_size);
    
    std::memset(pkt.auth_token, 0, 32);
    
    std::memset(pkt.hmac, 0, 32);

    std::vector<uint8_t> buffer(sizeof(StreamPacket) + payload_size);
    std::memcpy(buffer.data(), &pkt, sizeof(StreamPacket));
    std::memset(buffer.data() + sizeof(StreamPacket), 0xAA, payload_size);

    std::cout << "Header size: " << sizeof(StreamPacket) << " bytes (expect 106)" << std::endl;
    std::cout << "Full packet size: " << buffer.size() << " bytes" << std::endl;
    std::cout << "Hex dump (first 20 bytes): ";
    for (size_t i = 0; i < 20 && i < buffer.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    StreamPacket pkt_received{};
    std::memcpy(&pkt_received, buffer.data(), sizeof(StreamPacket));
    pkt_received.seq_num = ntohll(pkt_received.seq_num);
    pkt_received.timestamp = ntohll(pkt_received.timestamp);
    pkt_received.version = ntohs(pkt_received.version);
    pkt_received.payload_len = ntohl(pkt_received.payload_len);
    
    if (std::memcmp(pkt.magic, pkt_received.magic, 4) == 0 && pkt_received.seq_num == 42) {
        std::cout << "Deserialization OK: Magic 'STRM', Seq 42 intact!" << std::endl;
    } else {
        std::cout << "Deserialization FAILED!" << std::endl;
    }

    return 0;
}
