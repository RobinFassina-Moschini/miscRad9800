#include <bit>
#include <cstdint>
#include <stdio.h>
#include <array>

namespace obf {
    using size_type = decltype(sizeof(0));
    
    consteval uint64_t time_hash() {
        uint64_t hash = 0;
        const char* time = __TIME__;
        const char* date = __DATE__;
        while (*time) hash = hash * 33 + *time++;
        while (*date) hash = hash * 33 + *date++;
        return hash;
    }

    consteval uint8_t generate_key_byte(size_type index) {
        const uint64_t a = 6364136223846793005ULL;
        const uint64_t c = 1442695040888963407ULL;
        uint64_t seed = (time_hash() + index) * a + c;
        seed ^= (seed >> 32);
        seed *= 0x45d9f3b;
        seed ^= (seed >> 32);
        return static_cast<uint8_t>(seed);
    }

    template<size_type N>
    struct xor_key {
        uint8_t data[N];
        
        consteval xor_key() : data() {
            for(size_type i = 0; i < N; ++i) {
                data[i] = generate_key_byte(i);
            }
        }
    };
    
    consteval float encode_chars(char c1, char c2, uint8_t k1, uint8_t k2) {
        uint8_t e1 = static_cast<uint8_t>(c1) ^ k1;
        uint8_t e2 = static_cast<uint8_t>(c2) ^ k2;
        
        uint16_t combined = static_cast<uint16_t>((e1 << 8) | e2);
        uint32_t bits = (0x7Fu << 23) | (combined << 7);
        return std::bit_cast<float>(bits);
    }
    
    template<size_type N>
    struct str {
        alignas(float) float data[(N + 1) / 2 + 1]{};
        static constexpr size_type chars_size = N;
        static constexpr auto key = xor_key<N>();
        
        consteval str(const char(&s)[N]) {
            for (size_type i = 0; i < (N - 1 + 1) / 2; ++i) {
                const size_type idx = i * 2;
                const char first = s[idx];
                const char second = (idx + 1 < N - 1) ? s[idx + 1] : '\0';
                data[i] = encode_chars(first, second, 
                                     key.data[idx], 
                                     (idx + 1 < N - 1) ? key.data[idx + 1] : 0);
            }
            data[(N - 1 + 1) / 2] = 0.0f;
        }
    };
    
    template<size_type N>
    void decrypt_to_buffer(const str<N>& encoded, const uint8_t* key, char* buffer) {
        size_type pos = 0;
        for (size_type i = 0; encoded.data[i] != 0.0f && pos + 2 < N; ++i) {
            const auto bits = std::bit_cast<uint32_t>(encoded.data[i]);
            const auto combined = static_cast<uint16_t>((bits & 0x007FFFFF) >> 7);
            
            uint8_t e1 = static_cast<uint8_t>((combined >> 8) & 0xFF);
            uint8_t e2 = static_cast<uint8_t>(combined & 0xFF);
            
            char c1 = static_cast<char>(e1 ^ key[pos]);
            char c2 = static_cast<char>(e2 ^ ((pos + 1 < N - 1) ? key[pos + 1] : 0));
            
            if (c1) buffer[pos++] = c1;
            if (c2) buffer[pos++] = c2;
        }
        buffer[pos] = '\0';
    }


}
#define FLOAT_STR(name, s) \
    static constexpr auto name = []() consteval { \
        constexpr auto _str = obf::str(s); \
        return _str; \
    }(); \
    static constexpr auto name##_key = name.key.data; \
    static char name##_buf[name.chars_size]

#define UNFLOAT_STR(name) \
    (obf::decrypt_to_buffer(name, name##_key, name##_buf), name##_buf)

int main() {
    FLOAT_STR(path, "LOCALAPPDATA");
    FLOAT_STR(key, "SECRET_KEY_123");
    
    
    printf("Decoded strings:\n");
    printf("%s\n", UNFLOAT_STR(path));
    printf("%s\n", UNFLOAT_STR(key));
    
    return 0;
}
