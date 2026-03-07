#include <iostream>
#include <openssl/evp.h>
#include <packet.h>
#ifndef PACKET_H

#endif // !PACKET_H

#pragma pack(1)
struct PacketHeader {
    uint32_t Integrity;
    uint16_t Sender_ID;
    uint64_t Metadata;
    uint32_t Auth;
    long Payload;
    int Extras;
};
#pragma pack()


int main (int argc, char *argv[]) {
  std::cout << "openssl Linked!!";
  return 0;
}
