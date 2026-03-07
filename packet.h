#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push,1)
struct StreamPacket {
  char magic[4];
  uint16_t version;
  char sender_id[16];
  uint64_t seq_num;
  uint64_t timestamp;
  uint32_t payload_len;
  uint8_t auth_token[32];
  uint8_t hmac[32];
};
#pragma pack(pop)

static_assert(sizeof(StreamPacket) == 106, "Packet header must be 106 bytes");

inline size_t get_packet_size(const StreamPacket& pkt){
  return sizeof(StreamPacket) + ntohl(pkt.payload_len);
}

#endif
