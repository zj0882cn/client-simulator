/*
 * Simplified Util.h for client-simulator standalone build
 * Only contains functions needed by the client
 */

#ifndef _UTIL_H
#define _UTIL_H

#include "Define.h"
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

inline bool Utf8ToUpperOnlyLatin(std::string& utf8String)
{
    for (auto& ch : utf8String)
    {
        if (ch >= 'a' && ch <= 'z')
            ch = static_cast<char>(ch - 32);
    }
    return true;
}

template<typename Container>
std::string ByteArrayToHexStr(Container const& c, bool reverse = false)
{
    std::string result;
    auto size = std::size(c);
    result.reserve(size * 2);
    auto data = std::data(c);
    for (std::size_t i = 0; i < size; ++i)
    {
        uint8 byte = reverse ? data[size - 1 - i] : data[i];
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02x", byte);
        result += hex;
    }
    return result;
}

template<std::size_t Size>
void HexStrToByteArray(std::string_view str, std::array<uint8, Size>& buf, bool reverse = false)
{
    std::size_t strLen = str.size();
    std::size_t byteLen = strLen / 2;
    if (byteLen > Size)
        byteLen = Size;

    for (std::size_t i = 0; i < byteLen; ++i)
    {
        std::size_t hexIdx = i * 2;
        if (hexIdx + 1 >= strLen)
            break;

        uint8 byte = 0;
        char c0 = str[hexIdx];
        char c1 = str[hexIdx + 1];

        auto hexVal = [](char c) -> uint8 {
            if (c >= '0' && c <= '9') return uint8(c - '0');
            if (c >= 'a' && c <= 'f') return uint8(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return uint8(c - 'A' + 10);
            return 0;
        };

        byte = (hexVal(c0) << 4) | hexVal(c1);
        buf[reverse ? (Size - 1 - i) : i] = byte;
    }
}

template<std::size_t Size>
std::array<uint8, Size> HexStrToByteArray(std::string_view str, bool reverse = false)
{
    std::array<uint8, Size> arr{};
    HexStrToByteArray(str, arr, reverse);
    return arr;
}

#endif
