#ifndef MEDIA_GENERATOR_H
#define MEDIA_GENERATOR_H

#include <vector>
#include <cstdint>
#include <cstring>

class MediaGenerator {
private:
    uint32_t frame_counter = 0;
    const size_t frame_size = 1024;

public:
    std::vector<uint8_t> generate_next_frame() {
        std::vector<uint8_t> frame(frame_size);
        std::memset(frame.data(), 0xAA, frame_size);  // Base.

        // Embed frame # (big-endian, clean).
        uint32_t num = ++frame_counter;
        frame[0] = (num >> 24) & 0xFF;
        frame[1] = (num >> 16) & 0xFF;
        frame[2] = (num >> 8) & 0xFF;
        frame[3] = num & 0xFF;

        // FIXED: Flip starts after ID (i=4) for uniqueness without corrupting.
        for (size_t i = 4; i < frame_size; ++i) {
            if (i % 64 == frame_counter % 64) {
                frame[i] ^= 0x55;
            }
        }
        return frame;
    }

    size_t get_frame_size() const { return frame_size; }
    uint32_t get_frame_counter() const { return frame_counter; }
};

#endif  // MEDIA_GENERATOR_H
