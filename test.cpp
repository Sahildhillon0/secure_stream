#include <iostream>
#include <openssl/evp.h>
#include "packet.h"

int main(int argc, char *argv[]) {
    std::cout << "openssl Linked!!\n";
    std::cout << sizeof(StremPacket) << std::endl;
    return 0;
}
