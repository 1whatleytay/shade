#include <encryption/sha.h>

#include <vector>

#define SWAP_ENDIAN_32(x) ((x >> 24u) & 0xFFu) | ((x >> 8u) & 0x0000FF00u) | ((x << 8u) & 0x00FF0000u) | (x << 24u)

#define ROTR32(shift, x) ((x >> shift) | (x << (32 - shift)))
#define CHOICE(x, y, z) ((x & y) ^ (~x & z))
#define MAJORITY(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SUM0(x) (ROTR32(2u, x) ^ ROTR32(13u, x) ^ ROTR32(22u, x))
#define SUM1(x) (ROTR32(6u, x) ^ ROTR32(11u, x) ^ ROTR32(25u, x))
#define DEV0(x) (ROTR32(7u, x) ^ ROTR32(18u, x) ^ (x >> 3u))
#define DEV1(x) (ROTR32(17u, x) ^ ROTR32(19u, x) ^ (x >> 10u))

namespace encryption {
    using Sha256Block = std::array<uint32_t, 16>; // 512-bits

    static const std::array<uint32_t, 8> initialValue = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    static const std::array<uint32_t, 64> constantValues = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };

    std::array<uint32_t, 8> sha256Hash(uint8_t *data, size_t size) {
        std::array<uint32_t, 8> hash = initialValue;

        // 9 = sizeof(size) + byte for '1' bit at end
        uint64_t numBlocks = (size + 9) / sizeof(Sha256Block) + ((size + 9) % sizeof(Sha256Block) != 0);
        std::vector<Sha256Block> blocks(numBlocks);
        std::memset(blocks.data(), 0, sizeof(Sha256Block) * numBlocks);

        auto *blockData = reinterpret_cast<uint8_t *>(blocks.data());
        std::memcpy(blockData, data, size);
        blockData[size] = 0b10000000u; // after data we have a bit 1

        uint64_t sizeInBits = size * 8;
        uint32_t hiSize = sizeInBits >> 32u;
        uint32_t loSize = sizeInBits & 0xFFFFFFFFu;

        // last 64-bits are the size in bits
        blocks[numBlocks - 1][14] = SWAP_ENDIAN_32(hiSize);
        blocks[numBlocks - 1][15] = SWAP_ENDIAN_32(loSize);

        for (uint32_t a = 0; a < numBlocks; a++) {
            uint32_t messageValues[64];

            for (uint32_t b = 0; b < 16; b++) {
                messageValues[b] = SWAP_ENDIAN_32(blocks[a][b]);
            }

            for (uint32_t b = 16; b < 64; b++) {
                messageValues[b] =
                    DEV1(messageValues[b - 2]) + messageValues[b - 7]
                    + DEV0(messageValues[b - 15]) + messageValues[b - 16];
            }

            uint32_t registers[8];
            for (uint32_t b = 0; b < 8; b++) {
                registers[b] = hash[b];
            }

            for (uint32_t b = 0; b < 64; b++) {
                uint32_t t1 = registers[7] + SUM1(registers[4]) + CHOICE(registers[4], registers[5], registers[6])
                    + constantValues[b] + messageValues[b];
                uint32_t t2 = SUM0(registers[0]) + MAJORITY(registers[0], registers[1], registers[2]);

                registers[7] = registers[6];
                registers[6] = registers[5];
                registers[5] = registers[4];
                registers[4] = registers[3] + t1;
                registers[3] = registers[2];
                registers[2] = registers[1];
                registers[1] = registers[0];
                registers[0] = t1 + t2;
            }

            for (uint32_t c = 0; c < 8; c++) {
                hash[c] += registers[c];
            }
        }

        return hash;
    }
}