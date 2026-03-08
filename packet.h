#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct StreamPacket {
    char magic[4];          // e.g., "STRM"
    uint16_t version;       // 1
    char sender_id[16];     // Auth ID
    uint64_t seq_num;       // Ordering
    uint64_t timestamp;     // ms epoch
    uint32_t payload_len;   // Enc payload size
    uint32_t checksum;      // Integrity over header excl. this + enc_payload
    uint8_t auth_token[32]; // Auth: Dummy for now (pre-shared hash).
    uint8_t hmac[32];       // Integrity: Dummy for now (upgrade to real HMAC).
    uint8_t enc_payload[0]; // Variable
};
#pragma pack(pop)

static_assert(sizeof(StreamPacket) == 110, "Packet header must be 110 bytes");

inline size_t get_packet_size(const StreamPacket& pkt) {
    return sizeof(StreamPacket) + ntohl(pkt.payload_len);
}

// 64-bit endian polyfills
inline uint64_t htonll(uint64_t val) {
    uint32_t high = htonl(static_cast<uint32_t>(val >> 32));
    uint32_t low = htonl(static_cast<uint32_t>(val & 0xFFFFFFFFULL));
    return (static_cast<uint64_t>(high) << 32) | low;
}
inline uint64_t ntohll(uint64_t val) {
    uint32_t high = ntohl(static_cast<uint32_t>(val >> 32));
    uint32_t low = ntohl(static_cast<uint32_t>(val & 0xFFFFFFFFULL));
    return (static_cast<uint64_t>(high) << 32) | low;
}

#endif  // PACKET_H
