#pragma once
// =============================================================================
// WoW Standalone Client Simulator - 独立魔兽世界客户端模拟器
// 不依赖 AzerothCore 库，不连接数据库
// =============================================================================

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
    #include <cerrno>
    #include <cmath>
    #include <cstdint>
    #include <cstring>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <zlib.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// 类型别名 (与 WoW 代码风格一致)
using uint8  = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;

// 跨平台辅助宏
#ifdef _WIN32
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SOCKET_ERROR_MSG() std::string(WSAGetLastError() == WSAETIMEDOUT ? "Connection timed out" : "Socket error")
    #define SOCKET_INVALID INVALID_SOCKET
    using SocketType = SOCKET;
#else
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERROR_MSG() std::string(strerror(errno))
    #define SOCKET_INVALID (-1)
    using SocketType = int;
#endif

namespace WoWClient
{
    // =========================================================================
    // 常量定义
    // =========================================================================

    constexpr uint16 AUTH_SERVER_PORT   = 3724;
    constexpr uint16 WORLD_SERVER_PORT  = 8085;
    constexpr uint32 WOW_BUILD         = 12340;

    // WoW 3.3.5a SRP6 参数 (N, g) - 以大端序存储 (方便阅读和 BN_bin2bn 转换)
    // 但 WoW 协议使用小端序在网络上传输, 所以需要 LE 版本用于哈希和传输
    static constexpr uint8 SRP6_N[32] = {
        0x89,0x4B,0x64,0x5E,0x89,0xE1,0x53,0x5B,0xBD,0xAD,0x5B,0x8B,0x29,0x06,0x50,0x53,
        0x08,0x01,0xB1,0x8E,0xBF,0xBF,0x5E,0x8F,0xAB,0x3C,0x82,0x87,0x2A,0x3E,0x9B,0xB7
    };
    static constexpr uint8 SRP6_G[1] = { 0x07 };

    // WoW 协议使用小端序传输: BN_lebin2bn / BN_bn2lebinpad
    // AzerothCore 服务器使用 Little-Endian for wire format
    inline BIGNUM* bn_from_le(const uint8* leData, size_t len) {
        return BN_lebin2bn(leData, static_cast<int>(len), nullptr);
    }
    inline BIGNUM* bn_from_be(const uint8* beData, size_t len) {
        return BN_bin2bn(beData, static_cast<int>(len), nullptr);
    }
    inline void bn_to_le(const BIGNUM* bn, uint8* out, size_t len) {
        memset(out, 0, len);
        BN_bn2lebinpad(bn, out, static_cast<int>(len));
    }
    inline void bn_to_be(const BIGNUM* bn, uint8* out, size_t len) {
        memset(out, 0, len);
        BN_bn2binpad(bn, out, static_cast<int>(len));
    }

    // Forward declarations
    class AuthSocket;
    class WorldSocket;

    // Auth opcodes
    constexpr uint8 CMD_AUTH_LOGON_CHALLENGE = 0x00;
    constexpr uint8 CMD_AUTH_LOGON_PROOF      = 0x01;
    constexpr uint8 CMD_REALM_LIST            = 0x10;
    constexpr uint8 WOW_SUCCESS               = 0x00;

    // SMSG_AUTH_RESPONSE 状态码 (对应 AzerothCore ResponseCodes 枚举)
    // 注意: 认证成功的码是 AUTH_OK = 0x0C (12), 而不是 0!
    // 旧代码误将 AUTH_OK 定义为 0, 导致服务器返回 12 (成功) 时被误判为失败
    constexpr uint8 AUTH_OK                   = 0x0C;
    constexpr uint8 AUTH_FAILED               = 0x0D;
    constexpr uint8 AUTH_REJECT               = 0x0E;
    constexpr uint8 AUTH_BAD_SERVER_PROOF     = 0x0F;
    constexpr uint8 AUTH_UNAVAILABLE          = 0x10;
    constexpr uint8 AUTH_SYSTEM_ERROR         = 0x11;
    constexpr uint8 AUTH_BILLING_ERROR        = 0x12;
    constexpr uint8 AUTH_BILLING_EXPIRED      = 0x13;
    constexpr uint8 AUTH_VERSION_MISMATCH     = 0x14;
    constexpr uint8 AUTH_UNKNOWN_ACCOUNT      = 0x15;
    constexpr uint8 AUTH_INCORRECT_PASSWORD   = 0x16;
    constexpr uint8 AUTH_SESSION_EXPIRED      = 0x17;
    constexpr uint8 AUTH_SERVER_SHUTTING_DOWN = 0x18;
    constexpr uint8 AUTH_ALREADY_LOGGING_IN   = 0x19;
    constexpr uint8 AUTH_WAIT_QUEUE           = 0x1B;
    constexpr uint8 AUTH_BANNED               = 0x1C;
    constexpr uint8 AUTH_ALREADY_ONLINE       = 0x1D;
    constexpr uint8 AUTH_NO_TIME              = 0x1E;
    constexpr uint8 AUTH_DB_BUSY              = 0x1F;
    constexpr uint8 AUTH_SUSPENDED            = 0x20;
    constexpr uint8 AUTH_PARENTAL_CONTROL     = 0x21;
    constexpr uint8 AUTH_LOCKED_ENFORCED      = 0x22;
    constexpr uint8 REALM_LIST_REALM_NOT_FOUND = 0x27;

    // 将 SMSG_AUTH_RESPONSE 状态码映射为可读名称
    inline const char* authResponseName(uint8 code) {
        switch (code) {
            case WOW_SUCCESS:               return "WOW_SUCCESS";
            case AUTH_OK:                   return "AUTH_OK";
            case AUTH_FAILED:               return "AUTH_FAILED";
            case AUTH_REJECT:               return "AUTH_REJECT";
            case AUTH_BAD_SERVER_PROOF:     return "AUTH_BAD_SERVER_PROOF";
            case AUTH_UNAVAILABLE:          return "AUTH_UNAVAILABLE";
            case AUTH_SYSTEM_ERROR:         return "AUTH_SYSTEM_ERROR";
            case AUTH_BILLING_ERROR:        return "AUTH_BILLING_ERROR";
            case AUTH_BILLING_EXPIRED:      return "AUTH_BILLING_EXPIRED";
            case AUTH_VERSION_MISMATCH:     return "AUTH_VERSION_MISMATCH";
            case AUTH_UNKNOWN_ACCOUNT:      return "AUTH_UNKNOWN_ACCOUNT";
            case AUTH_INCORRECT_PASSWORD:   return "AUTH_INCORRECT_PASSWORD";
            case AUTH_SESSION_EXPIRED:      return "AUTH_SESSION_EXPIRED";
            case AUTH_SERVER_SHUTTING_DOWN: return "AUTH_SERVER_SHUTTING_DOWN";
            case AUTH_ALREADY_LOGGING_IN:   return "AUTH_ALREADY_LOGGING_IN";
            case AUTH_WAIT_QUEUE:           return "AUTH_WAIT_QUEUE";
            case AUTH_BANNED:               return "AUTH_BANNED";
            case AUTH_ALREADY_ONLINE:       return "AUTH_ALREADY_ONLINE";
            case AUTH_NO_TIME:              return "AUTH_NO_TIME";
            case AUTH_DB_BUSY:              return "AUTH_DB_BUSY";
            case AUTH_SUSPENDED:            return "AUTH_SUSPENDED";
            case AUTH_PARENTAL_CONTROL:     return "AUTH_PARENTAL_CONTROL";
            case AUTH_LOCKED_ENFORCED:      return "AUTH_LOCKED_ENFORCED";
            case REALM_LIST_REALM_NOT_FOUND:return "REALM_LIST_REALM_NOT_FOUND";
            default:                        return "UNKNOWN";
        }
    }

    // 判断 SMSG_AUTH_RESPONSE 状态码是否为成功
    inline bool isAuthResponseOk(uint8 code) {
        return code == AUTH_OK || code == WOW_SUCCESS;
    }

    // World client opcodes (CMSG_*)
    constexpr uint32 CMSG_AUTH_SESSION       = 0x01ED;
    constexpr uint32 CMSG_CHAR_ENUM          = 0x0037;
    constexpr uint32 CMSG_PLAYER_LOGIN       = 0x003D;
    constexpr uint32 CMSG_PING               = 0x01DC;
    constexpr uint32 CMSG_SET_ACTIVE_MOVER   = 0x026A;
    constexpr uint32 CMSG_MESSAGECHAT        = 0x0095;
    constexpr uint32 CMSG_LOGOUT             = 0x004B;
    constexpr uint32 CMSG_TIME_SYNC_RESP     = 0x0391;
    constexpr uint32 CMSG_MOVE_HEARTBEAT     = 0x00EE;
    constexpr uint32 CMSG_NAME_QUERY         = 0x0050;

    // World server opcodes (SMSG_*)
    constexpr uint16 SMSG_AUTH_CHALLENGE    = 0x01EC;
    constexpr uint16 SMSG_AUTH_RESPONSE     = 0x01EE;
    constexpr uint16 SMSG_ADDON_INFO        = 0x02EF;
    constexpr uint16 SMSG_CLIENTCACHE_VERSION = 0x04AB;
    constexpr uint16 SMSG_TUTORIAL_FLAGS    = 0x00FD;
    constexpr uint16 SMSG_CHAR_ENUM         = 0x003B;
    constexpr uint16 SMSG_LOGIN_VERIFY_WORLD = 0x0236;
    constexpr uint16 SMSG_PONG              = 0x01DD;
    constexpr uint16 SMSG_LOGOUT_COMPLETE   = 0x004D;
    constexpr uint16 SMSG_NEW_WORLD         = 0x003E;
    constexpr uint16 SMSG_TRANSFER_PENDING  = 0x003F;
    constexpr uint16 SMSG_TRANSFER_ABORTED = 0x0040;
    constexpr uint16 SMSG_TIME_SYNC_REQ     = 0x0390;

    // =========================================================================
    // 数据结构
    // =========================================================================

    struct Vec3 { float x=0, y=0, z=0; };

    struct AuthResult {
        bool success = false;
        uint8 errorCode = 0;
        uint8 B[32] = {}, N[32] = {}, salt[32] = {}, seed[16] = {};
        uint8 g = 0;
        uint8 M2[20] = {};
        uint32 accountFlags = 0;
        uint8 sessionKey[40] = {};
    };

    struct RealmInfo {
        uint8 type=0, lock=0, flags=0;
        std::string name;
        std::string address;
        uint16 port = 0;
        float population = 0;
        uint8 numChars = 0;
        uint8 timezone = 0;
        uint8 realmId = 0;
    };

    struct CharacterInfo {
        uint64 guid = 0;
        std::string name;
        uint8 level = 0;
        uint8 clazz = 0;
        uint8 race = 0;
        uint8 gender = 0;
        uint8 skin = 0, face = 0, hairStyle = 0, hairColor = 0, facialHair = 0;
        uint32 zone = 0, mapId = 0;
        Vec3 pos;
        uint32 guildId = 0;
        uint32 flags = 0;
    };

    // =========================================================================
    // 工具函数
    // =========================================================================

    inline void writeU16LE(uint8* p, uint16 v) { p[0]=uint8(v); p[1]=uint8(v>>8); }
    inline uint16 readU16LE(const uint8* p) { return uint16(p[0])|(uint16(p[1])<<8); }
    inline uint16 readU16BE(const uint8* p) { return (uint16(p[0])<<8)|uint16(p[1]); }
    inline void writeU32LE(uint8* p, uint32 v) { p[0]=uint8(v); p[1]=uint8(v>>8); p[2]=uint8(v>>16); p[3]=uint8(v>>24); }
    inline void writeU32BE(uint8* p, uint32 v) { p[0]=uint8(v>>24); p[1]=uint8(v>>16); p[2]=uint8(v>>8); p[3]=uint8(v); }
    inline uint32 readU32LE(const uint8* p) { return uint32(p[0])|(uint32(p[1])<<8)|(uint32(p[2])<<16)|(uint32(p[3])<<24); }
    inline uint64 readU64LE(const uint8* p) { return uint64(p[0])|(uint64(p[1])<<8)|(uint64(p[2])<<16)|(uint64(p[3])<<24)|(uint64(p[4])<<32)|(uint64(p[5])<<40)|(uint64(p[6])<<48)|(uint64(p[7])<<56); }
    inline void writeU64LE(uint8* p, uint64 v) { writeU32LE(p,uint32(v)); writeU32LE(p+4,uint32(v>>32)); }
    inline float readFloatLE(const uint8* p) { uint32 raw=readU32LE(p); float f; memcpy(&f,&raw,4); return f; }

    inline void randomBytes(uint8* buf, size_t len) { RAND_bytes(buf, static_cast<int>(len)); }

    inline std::string toUpper(const std::string& s) {
        std::string r = s;
        for (auto& c : r) if (c >= 'a' && c <= 'z') c -= 32;
        return r;
    }

    // =========================================================================
    // ARC4 加密
    // =========================================================================

    class ARC4 {
        uint8 S_[256] = {};
        uint8 i_ = 0;
        uint8 j_ = 0;
        bool initialized_ = false;
    public:
        ARC4() = default;

        void Init(const uint8* key, size_t keyLen) {
            for (int k = 0; k < 256; ++k) S_[k] = static_cast<uint8>(k);
            uint8 jj = 0;
            for (int k = 0; k < 256; ++k) {
                jj = static_cast<uint8>((jj + S_[k] + key[k % keyLen]) & 0xFF);
                uint8 t = S_[k]; S_[k] = S_[jj]; S_[jj] = t;
            }
            i_ = 0; j_ = 0;
            initialized_ = true;
        }

        void UpdateData(uint8* data, size_t len) {
            if (!initialized_) return;
            for (size_t n = 0; n < len; ++n) {
                i_ = static_cast<uint8>((i_ + 1) & 0xFF);
                j_ = static_cast<uint8>((j_ + S_[i_]) & 0xFF);
                uint8 t = S_[i_]; S_[i_] = S_[j_]; S_[j_] = t;
                uint8 k = S_[static_cast<uint8>((S_[i_] + S_[j_]) & 0xFF)];
                data[n] ^= k;
            }
        }
    };

    // =========================================================================
    // SRP6 实现
    // =========================================================================

    class SRP6Calculator {
    public:
        struct ClientProofResult {
            uint8 A[32];
            uint8 M[20];
            uint8 sessionKey[40];
        };

        static ClientProofResult computeClientProof(
            const std::string& username,
            const std::string& password,
            const uint8* salt,
            const uint8* serverB,
            const uint8* serverN,
            const uint8* serverG,
            size_t gLen
        ) {
            ClientProofResult result;

            BIGNUM* bnN = bn_from_le(serverN, 32);
            BIGNUM* bnG = bn_from_le(serverG, gLen);
            BN_CTX* ctx = BN_CTX_new();

            // 1. Client random a (19 bytes)
            uint8 aBytes[19];
            randomBytes(aBytes, 19);
            BIGNUM* bnA = BN_bin2bn(aBytes, 19, nullptr);

            // 2. A = g^a mod N, then convert to LE for wire
            BIGNUM* bnAVal = BN_new();
            BN_mod_exp(bnAVal, bnG, bnA, bnN, ctx);
            bn_to_le(bnAVal, result.A, 32);

            // 3. Parse server's B from LE wire bytes
            BIGNUM* bnB = bn_from_le(serverB, 32);

            // 4. x = SHA1(salt || SHA1(username || ":" || password))
            //    Server interprets SHA1 digest as LE for BigNumber construction
            uint8 innerHash[20];
            SHA_CTX sha;
            SHA1_Init(&sha);
            SHA1_Update(&sha, username.c_str(), username.size());
            SHA1_Update(&sha, ":", 1);
            SHA1_Update(&sha, password.c_str(), password.size());
            SHA1_Final(innerHash, &sha);

            uint8 xBytes[20];
            SHA_CTX sha2;
            SHA1_Init(&sha2);
            SHA1_Update(&sha2, salt, 32);
            SHA1_Update(&sha2, innerHash, 20);
            SHA1_Final(xBytes, &sha2);
            BIGNUM* bnX = BN_lebin2bn(xBytes, 20, nullptr);

            // 5. v = g^x mod N
            BIGNUM* bnV = BN_new();
            BN_mod_exp(bnV, bnG, bnX, bnN, ctx);

            // 6. u = SHA1(A || B) using LE wire format bytes
            uint8 uBytes[20];
            SHA_CTX shaU;
            SHA1_Init(&shaU);
            SHA1_Update(&shaU, result.A, 32);
            SHA1_Update(&shaU, serverB, 32);
            SHA1_Final(uBytes, &shaU);
            BIGNUM* bnU = BN_lebin2bn(uBytes, 20, nullptr);

            // 7. S = ((B - 3v) * v^u)^(a + u*x) mod N
            //    AzerothCore server: B = g^b + 3v, so g^b = B - 3v
            //    Server computes: S = (A * v^u)^b mod N = (g^a * v^u)^b
            //    Client computes: S = (g^b * v^u)^(a + u*x) mod N = ((B - 3v) * v^u)^(a + u*x)
            //    Wait... Let me re-derive:
            //    Server: S = (g^a * v^u)^b = g^(ab) * v^(ub)
            //    Client: S = (g^b * v^u)^(a + ux) = g^(b(a+ux)) * v^(u(a+ux))
            //             = g^(ab + bux) * v^(ua + u²x)
            //             = g^(ab) * g^(bux) * v^(ua + u²x)
            // Hmm, this doesn't directly simplify to g^(ab) * v^(ub)
            // Let me check the actual WoW reference implementation:
            //   S = ((B - k*v)^(a + u*x)) mod N
            // Where k = 3, so B - k*v = g^b
            // S = (g^b)^(a + ux) mod N = g^(b*(a+ux)) mod N = g^(ab + bux) mod N
            //   = (g^a)^b * (g^x)^(ub) mod N = A^b * v^(ub) mod N
            //   = (A * v^u)^b mod N -- YES! This matches the server formula!
            BIGNUM* bn3v = BN_new();
            BN_mul(bn3v, bnV, BN_value_one(), ctx);
            BN_add(bn3v, bn3v, bnV);
            BN_add(bn3v, bn3v, bnV);

            // Compute B_adj = (B - 3v) mod N, ensuring positive result
            BIGNUM* bn3v_mod = BN_new();
            BN_mod(bn3v_mod, bn3v, bnN, ctx);
            BIGNUM* bnB_adj = BN_new();
            BN_add(bnB_adj, bnB, bnN);
            BN_sub(bnB_adj, bnB_adj, bn3v_mod);
            BN_mod(bnB_adj, bnB_adj, bnN, ctx);
            BN_free(bn3v_mod);

            // Compute exponent: a + u*x
            BIGNUM* bnUx = BN_new();
            BN_mul(bnUx, bnU, bnX, ctx);
            BIGNUM* bnExp = BN_new();
            BN_add(bnExp, bnA, bnUx);

            // S = B_adj^(a+u*x) mod N
            // This is algebraically equivalent to server's S = (A * v^u)^b mod N
            BIGNUM* bnS = BN_new();
            BN_mod_exp(bnS, bnB_adj, bnExp, bnN, ctx);

            uint8 SBytes[32];
            bn_to_le(bnS, SBytes, 32);

            // 8. SHA1Interleave(S) -> sessionKey
            computeSessionKey(SBytes, result.sessionKey);

            // 14. M = SHA1(H(N) XOR H(g) || H(U) || s || A || B || K)
            // Use server-provided wire-format N and g for hashing
            uint8 hN[20], hG[20];
            SHA1(serverN, 32, hN);
            SHA1(serverG, gLen, hG);

            uint8 ngHash[20];
            for (int i = 0; i < 20; ++i) ngHash[i] = hN[i] ^ hG[i];

            uint8 hU[20];
            SHA1((unsigned char*)username.c_str(), username.size(), hU);

            SHA_CTX shaM;
            SHA1_Init(&shaM);
            SHA1_Update(&shaM, ngHash, 20);
            SHA1_Update(&shaM, hU, 20);
            SHA1_Update(&shaM, salt, 32);
            SHA1_Update(&shaM, result.A, 32);
            SHA1_Update(&shaM, serverB, 32);
            SHA1_Update(&shaM, result.sessionKey, 40);
            SHA1_Final(result.M, &shaM);

            // Debug output
            auto hexStr = [](const uint8* data, size_t len) -> std::string {
                std::string s;
                char buf[3];
                for (size_t i = 0; i < len; ++i) {
                    snprintf(buf, sizeof(buf), "%02x", data[i]);
                    s += buf;
                }
                return s;
            };
            printf("[SRP6] username: %s\n", username.c_str());
            printf("[SRP6] password: %s\n", password.c_str());
            printf("[SRP6] serverN: %s\n", hexStr(serverN, 32).c_str());
            printf("[SRP6] serverG: %s\n", hexStr(serverG, gLen).c_str());
            printf("[SRP6] innerHash: %s\n", hexStr(innerHash, 20).c_str());
            printf("[SRP6] xBytes: %s\n", hexStr(xBytes, 20).c_str());
            printf("[SRP6] A: %s\n", hexStr(result.A, 32).c_str());
            printf("[SRP6] B: %s\n", hexStr(serverB, 32).c_str());
            printf("[SRP6] u: %s\n", hexStr(uBytes, 20).c_str());
            printf("[SRP6] S: %s\n", hexStr(SBytes, 32).c_str());
            printf("[SRP6] K: %s\n", hexStr(result.sessionKey, 40).c_str());
            printf("[SRP6] hN: %s\n", hexStr(hN, 20).c_str());
            printf("[SRP6] hG: %s\n", hexStr(hG, 20).c_str());
            printf("[SRP6] ngHash: %s\n", hexStr(ngHash, 20).c_str());
            printf("[SRP6] hU: %s\n", hexStr(hU, 20).c_str());
            printf("[SRP6] M: %s\n", hexStr(result.M, 20).c_str());

            // Cleanup
            BN_free(bnN); BN_free(bnG); BN_free(bnA); BN_free(bnAVal);
            BN_free(bnB); BN_free(bnX); BN_free(bnV); BN_free(bnU);
            BN_free(bn3v); BN_free(bnB_adj);
            BN_free(bnS);
            BN_free(bnUx); BN_free(bnExp);
            BN_CTX_free(ctx);

            return result;
        }

    private:
        static void computeSessionKey(const uint8* S, uint8* outK) {
            // Match AzerothCore's SHA1Interleave implementation exactly:
            // 1. Split S (32 bytes) into even-indexed buf0 and odd-indexed buf1 (each 16 bytes)
            // 2. Find first nonzero byte position p in S
            // 3. If p is odd, skip one more byte (p++)
            // 4. p = p/2 (convert to buffer offset)
            // 5. Hash buf0[p:] and buf1[p:]
            // 6. Interleave the two hashes into 40-byte session key

            constexpr size_t EPHEMERAL_KEY_LENGTH = 32;
            constexpr size_t HALF_LENGTH = EPHEMERAL_KEY_LENGTH / 2;  // 16

            uint8 buf0[HALF_LENGTH], buf1[HALF_LENGTH];
            for (size_t i = 0; i < HALF_LENGTH; ++i) {
                buf0[i] = S[2 * i + 0];  // even indices
                buf1[i] = S[2 * i + 1];  // odd indices
            }

            // Find first nonzero byte in S
            size_t p = 0;
            while (p < EPHEMERAL_KEY_LENGTH && !S[p])
                ++p;

            if (p & 1)
                ++p;  // skip one extra byte if p is odd

            p /= 2;  // offset into buffers

            // Hash each half starting from position p
            uint8 hash0[20], hash1[20];
            SHA1(buf0 + p, HALF_LENGTH - p, hash0);
            SHA1(buf1 + p, HALF_LENGTH - p, hash1);

            // Interleave the two hashes
            for (int i = 0; i < 20; ++i) {
                outK[2 * i + 0] = hash0[i];
                outK[2 * i + 1] = hash1[i];
            }
        }

        static void bnToBuf(const BIGNUM* bn, uint8* out, int bufLen) {
            int bnLen = BN_num_bytes(bn);
            memset(out, 0, bufLen);
            if (bnLen <= bufLen) {
                BN_bn2bin(bn, out + (bufLen - bnLen));
            }
        }
    };

    // =========================================================================
    // 工具: PackedGuid 编解码
    // =========================================================================

    inline std::vector<uint8> writePackedGuid(uint64 guid) {
        uint8 bytes[8];
        memcpy(bytes, &guid, 8);
        uint8 mask = 0;
        for (int i = 0; i < 8; ++i) if (bytes[i] != 0) mask |= uint8(1 << i);
        std::vector<uint8> result;
        result.push_back(mask);
        for (int i = 0; i < 8; ++i) if (mask & (1 << i)) result.push_back(bytes[i]);
        return result;
    }

    inline uint64 readPackedGuid(const uint8* p, int& consumed) {
        uint8 mask = p[0];
        uint64 guid = 0;
        int pos = 1;
        for (int i = 0; i < 8; ++i) {
            if (mask & (1 << i)) {
                guid |= uint64(p[pos]) << (i * 8);
                ++pos;
            }
        }
        consumed = pos;
        return guid;
    }

    // =========================================================================
    // AuthSocket - 认证服务器客户端
    // =========================================================================

    class AuthSocket {
    public:
        AuthSocket();
        ~AuthSocket();
        bool Connect(const std::string& host, uint16 port);
        void Disconnect();
        bool Login(const std::string& username, const std::string& password);
        bool FetchRealmList(std::vector<RealmInfo>& realms);
        const AuthResult& GetResult() const;

    private:
        SocketType fd_;
        AuthResult result_;
        std::string host_;
        uint16 port_;
        uint32 build_;
        bool SendAll(const void* data, size_t len);
        bool RecvAll(void* data, size_t len);
        bool SendChallengeRequest(const std::string& username);
        bool RecvChallengeResponse();
        bool SendProofRequest(const std::string& username, const std::string& password);
        bool RecvProofResponse();
        bool SendRealmListRequest();
        bool RecvRealmListResponse(std::vector<RealmInfo>& realms);
    };

    // =========================================================================
    // WorldSocket - 世界服务器客户端
    // =========================================================================

    class WorldSocket {
    public:
        WorldSocket(const std::string& ip, uint16 port);
        ~WorldSocket();
        bool Connect();
        void Disconnect();
        bool IsConnected() const;
        void SetUsername(const std::string& un);

        bool RecvAuthChallenge();
        bool SendAuthSession(const AuthResult& auth, const std::string& username, uint8 realmId);
        bool WaitAuthResponse(uint8& result, uint32& billingFlags);
        bool RecvCharacterList(std::vector<CharacterInfo>& chars);
        bool LoginCharacter(uint64 guid);
        bool WaitWorldEnter();
        bool SendActiveMover(uint64 guid);
        bool SendPing(uint32 seq);
        bool SendTimeSyncResponse(uint32 counter);
        bool SendMoveHeartbeat();
        void SetMover(uint64 guid, const Vec3& pos, float orientation);
        bool SendChatMessage(const std::string& msg, uint8 channel = 0);
        bool HasPendingData(uint32 timeoutMs);
        bool RecvPacketNonBlocking(uint16& cmd, std::vector<uint8>& payload);

    private:
        std::string ip_;
        uint16 port_;
        SocketType fd_;
        bool encrypted_;
        uint8 serverSeed_[4];
        uint8 clientSeed_[4];
        std::vector<uint8> srpSessionKey_;
        std::vector<uint8> sessionKeyDigest_;
        ARC4 sendEncrypt_;
        ARC4 recvDecrypt_;
        std::string username_;
        uint64 moverGuid_ = 0;
        Vec3 moverPos_;
        float moverO_ = 0.0f;
        std::vector<uint8> recvBuf_;   // 非阻塞收包缓冲区
        bool connClosed_ = false;      // 服务器是否已关闭连接

        bool SendPacket(uint16 cmd, const std::vector<uint8>& payload, bool skipEncrypt = false);
        bool RecvPacket(uint16& cmd, std::vector<uint8>& payload);
        bool ReadExact(void* buf, size_t len);
        bool WriteAll(const void* buf, size_t len);
        void InitEncryption();
        void SetEncrypted(bool v) { encrypted_ = v; }
        bool IsEncrypted() const { return encrypted_; }
    };

} // namespace WoWClient