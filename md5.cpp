#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdint>

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define FF(a, b, c, d, x, s, ac) { \
    a += F(b, c, d) + x + ac; \
    a = ROTATE_LEFT(a, s); \
    a += b; \
}

#define GG(a, b, c, d, x, s, ac) { \
    a += G(b, c, d) + x + ac; \
    a = ROTATE_LEFT(a, s); \
    a += b; \
}

#define HH(a, b, c, d, x, s, ac) { \
    a += H(b, c, d) + x + ac; \
    a = ROTATE_LEFT(a, s); \
    a += b; \
}

#define II(a, b, c, d, x, s, ac) { \
    a += I(b, c, d) + x + ac; \
    a = ROTATE_LEFT(a, s); \
    a += b; \
}


class MD5
{
private:
    /* data */
    void transform(const uint8_t block[64]);
    void encode(uint8_t *output, const uint32_t *input, size_t length);
    void decode(uint32_t *output, const uint8_t *input, size_t length);

    uint32_t state[4];    // MD5 state (A, B, C, D)
    uint32_t count[2];    // Number of bits, modulo 2^64 (low-order word first)
    uint8_t buffer[64];   // Input buffer
public:
    MD5(/* args */);
    void update(const uint8_t *data, size_t length);
    std::string final();
    ~MD5();
};

const uint8_t padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

MD5::MD5() {
    count[0] = count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
}

void MD5::update(const uint8_t *data, size_t length) {
    uint32_t i, index, partLen;

    // Compute number of bytes mod 64
    index = (count[0] >> 3) & 0x3F;

    // Update number of bits
    if ((count[0] += (length << 3)) < (length << 3))
        count[1]++;
    count[1] += (length >> 29);

    partLen = 64 - index;

    // Transform as many times as possible
    if (length >= partLen) {
        std::memcpy(&buffer[index], data, partLen);
        transform(buffer);

        for (i = partLen; i + 63 < length; i += 64)
            transform(&data[i]);

        index = 0;
    } else {
        i = 0;
    }

    // Buffer remaining input
    std::memcpy(&buffer[index], &data[i], length - i);
}

std::string MD5::final() {
    uint8_t bits[8];
    uint32_t index, padLen;

    // Save number of bits
    encode(bits, count, 8);

    // Pad out to 56 mod 64
    index = (count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLen);

    // Append length (before padding)
    update(bits, 8);

    // Store state in digest
    std::string result;
    result.resize(16);
    encode(reinterpret_cast<uint8_t*>(&result[0]), state, 16);

    return result;
}

void MD5::transform(const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    decode(x, block, 64);

    // Round 1
    FF(a, b, c, d, x[ 0], S11, 0xD76AA478);
    FF(d, a, b, c, x[ 1], S12, 0xE8C7B756);
    FF(c, d, a, b, x[ 2], S13, 0x242070DB);
    FF(b, c, d, a, x[ 3], S14, 0xC1BDCEEE);
    FF(a, b, c, d, x[ 4], S11, 0xF57C0FAF);
    FF(d, a, b, c, x[ 5], S12, 0x4787C62A);
    FF(c, d, a, b, x[ 6], S13, 0xA8304613);
    FF(b, c, d, a, x[ 7], S14, 0xFD469501);
    FF(a, b, c, d, x[ 8], S11, 0x698098D8);
    FF(d, a, b, c, x[ 9], S12, 0x8B44F7AF);
    FF(c, d, a, b, x[10], S13, 0xFFFF5BB1);
    FF(b, c, d, a, x[11], S14, 0x895CD7BE);
    FF(a, b, c, d, x[12], S11, 0x6B901122);
    FF(d, a, b, c, x[13], S12, 0xFD987193);
    FF(c, d, a, b, x[14], S13, 0xA679438E);
    FF(b, c, d, a, x[15], S14, 0x49B40821);

    // Round 2
    GG(a, b, c, d, x[ 1], S21, 0xF61E2562);
    GG(d, a, b, c, x[ 6], S22, 0xC040B340);
    GG(c, d, a, b, x[11], S23, 0x265E5A51);
    GG(b, c, d, a, x[ 0], S24, 0xE9B6C7AA);
    GG(a, b, c, d, x[ 5], S21, 0xD62F105D);
    GG(d, a, b, c, x[10], S22, 0x2441453);
    GG(c, d, a, b, x[15], S23, 0xD8A1E681);
    GG(b, c, d, a, x[ 4], S24, 0xE7D3FBC8);
    GG(a, b, c, d, x[ 9], S21, 0x21E1CDE6);
    GG(d, a, b, c, x[14], S22, 0xC33707D6);
    GG(c, d, a, b, x[ 3], S23, 0xF4D50D87);
    GG(b, c, d, a, x[ 8], S24, 0x455A14ED);
    GG(a, b, c, d, x[13], S21, 0xA9E3E905);
    GG(d, a, b, c, x[ 2], S22, 0xFCEFA3F8);
    GG(c, d, a, b, x[ 7], S23, 0x676F02D9);
    
    // Round 3
    HH(a, b, c, d, x[ 5], S31, 0xFFFA3942);
    HH(d, a, b, c, x[ 8], S32, 0x8771F681);
    HH(c, d, a, b, x[11], S33, 0x6D9D6122);
    HH(b, c, d, a, x[14], S34, 0xFDE5380C);
    HH(a, b, c, d, x[ 1], S31, 0xA4BEEA44);
    HH(d, a, b, c, x[ 4], S32, 0x4BDECFA9);
    HH(c, d, a, b, x[ 7], S33, 0xF6BB4B60);
    HH(b, c, d, a, x[10], S34, 0xBEBFBC70);
    HH(a, b, c, d, x[13], S31, 0x289B7EC6);
    HH(d, a, b, c, x[ 0], S32, 0xEAA127FA);
    HH(c, d, a, b, x[ 3], S33, 0xD4EF3085);
    HH(b, c, d, a, x[ 6], S34, 0x4881D05);
    HH(a, b, c, d, x[ 9], S31, 0xD9D4D039);
    HH(d, a, b, c, x[12], S32, 0xE6DB99E5);
    HH(c, d, a, b, x[15], S33, 0x1FA27CF8);
    HH(b, c, d, a, x[ 2], S34, 0xC4AC5665);

    // Round 4
    II(a, b, c, d, x[ 0], S41, 0xF4292244);
    II(d, a, b, c, x[ 7], S42, 0x432AFF97);
    II(c, d, a, b, x[14], S43, 0xAB9423A7);
    II(b, c, d, a, x[ 5], S44, 0xFC93A039);
    II(a, b, c, d, x[12], S41, 0x655B59C3);
    II(d, a, b, c, x[ 3], S42, 0x8F0CCC92);
    II(c, d, a, b, x[10], S43, 0xFFEFF47D);
    II(b, c, d, a, x[ 1], S44, 0x85845DD1);
    II(a, b, c, d, x[ 8], S41, 0x6FA87E4F);
    II(d, a, b, c, x[15], S42, 0xFE2CE6E0);
    II(c, d, a, b, x[ 6], S43, 0xA3014314);
    II(b, c, d, a, x[13], S44, 0x4E0811A1);
    II(a, b, c, d, x[ 4], S41, 0xF7537E82);
    II(d, a, b, c, x[11], S42, 0xBD3AF235);
    II(c, d, a, b, x[ 2], S43, 0x2AD7D2BB);
    II(b, c, d, a, x[ 9], S44, 0xEB86D391);

    // Update MD5 state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Clear sensitive information
    std::memset(x, 0, sizeof(x));
}

int main() {
    // Example usage
    MD5 md5;
    md5.update(reinterpret_cast<const uint8_t*>("Hello, MD5!"), 11);
    std::string result = md5.final();

    std::cout << "MD5 Hash: " << result << std::endl;

    return 0;
}






