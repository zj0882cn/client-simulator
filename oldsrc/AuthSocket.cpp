#include "AuthSocket.h"
#include "SRP6Helpers.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace ClientSimulator;

namespace ClientSimulator
{
    static constexpr uint32 WOW_BUILD = 12340;
    static constexpr uint8 AUTH_LOGON_CHALLENGE = 0x00;
    static constexpr uint8 AUTH_LOGON_PROOF      = 0x01;
    static constexpr uint8 REALM_LIST            = 0x10;
    static constexpr uint8 AUTH_OK               = 0x00;

    // 写入 uint16 little-endian
    static void writeU16LE(uint8* p, uint16 v) {
        p[0] = uint8(v);
        p[1] = uint8(v >> 8);
    }

    // 读取 uint16 little-endian
    static uint16 readU16LE(uint8 const* p) {
        return uint16(p[0]) | (uint16(p[1]) << 8);
    }

    // 写入 uint32 little-endian
    static void writeU32LE(uint8* p, uint32 v) {
        p[0] = uint8(v);
        p[1] = uint8(v >> 8);
        p[2] = uint8(v >> 16);
        p[3] = uint8(v >> 24);
    }

    AuthSocket::AuthSocket() : _fd(-1), _build(WOW_BUILD) {}

    AuthSocket::~AuthSocket() { Disconnect(); }

    bool AuthSocket::Connect(std::string const& host, uint16 port)
    {
        _host = host;
        _port = port;

        _fd = socket(AF_INET, SOCK_STREAM, 0);
        if (_fd < 0)
        {
            std::cerr << "[AuthSocket] socket() failed\n";
            return false;
        }

        struct hostent* he = gethostbyname(host.c_str());
        if (!he)
        {
            std::cerr << "[AuthSocket] gethostbyname(" << host << ") failed\n";
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

        if (::connect(_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            std::cerr << "[AuthSocket] connect() failed\n";
            return false;
        }

        std::cout << "[AuthSocket] Connected to " << host << ":" << port << "\n";
        return true;
    }

    void AuthSocket::Disconnect()
    {
        if (_fd >= 0)
        {
            close(_fd);
            _fd = -1;
        }
    }

    bool AuthSocket::SendAll(void const* data, size_t len)
    {
        size_t sent = 0;
        while (sent < len)
        {
            ssize_t n = ::send(_fd, (char const*)data + sent, len - sent, 0);
            if (n <= 0)
                return false;
            sent += n;
        }
        return true;
    }

    bool AuthSocket::RecvAll(void* data, size_t len)
    {
        size_t recvd = 0;
        while (recvd < len)
        {
            ssize_t n = ::recv(_fd, (char*)data + recvd, len - recvd, 0);
            if (n <= 0)
                return false;
            recvd += n;
        }
        return true;
    }

    // ========================= 完整登录流程 =========================

    bool AuthSocket::Login(std::string const& username, std::string const& password)
    {
        if (!SendChallengeRequest(username))
            return false;

        if (!RecvChallengeResponse())
            return false;

        std::cout << "[AuthSocket] Challenge received, computing proof...\n";

        if (!SendProofRequest(username, password))
            return false;

        if (!RecvProofResponse())
            return false;

        _result.success = true;
        std::cout << "[AuthSocket] SRP6 authentication success!\n";
        return true;
    }

    bool AuthSocket::FetchRealmList(std::vector<RealmInfo>& realms)
    {
        if (!SendRealmListRequest())
            return false;

        if (!RecvRealmListResponse(realms))
            return false;

        std::cout << "[AuthSocket] Received " << realms.size() << " realm(s)\n";
        return true;
    }

    // ========================= 协议实现 =========================

    bool AuthSocket::SendChallengeRequest(std::string const& username)
    {
        // 总长度: 1(cmd) + 1(error) + 2(size) + 4(game) + 3(ver) + 2(build)
        //         + 4(platform) + 4(os) + 4(country) + 4(tz) + 4(ip) + 1(len) + N(name)
        size_t nameLen = username.size();
        size_t pktSize = 1 + 1 + 2 + 4 + 3 + 2 + 4 + 4 + 4 + 4 + 4 + 1 + nameLen;
        uint16 dataSize = uint16(pktSize - 4); // size 字段不包含 cmd+error+size 自身

        std::vector<uint8> buf(pktSize);
        uint8* p = buf.data();

        *p++ = AUTH_LOGON_CHALLENGE;     // cmd
        *p++ = 0x08;                     // error (0x08 = 无 GRUNT 即旧协议)
        writeU16LE(p, dataSize); p += 2; // size (LE, authserver x86 直接读 struct)

        // Game name "WoW\0"
        memcpy(p, "WoW", 3); p[3] = 0; p += 4;

        // Version 3.3.5
        *p++ = 3; *p++ = 3; *p++ = 5;

        // Build (LE)
        writeU16LE(p, _build); p += 2;

        // Platform "x86\0"
        memcpy(p, "x86", 3); p[3] = 0; p += 4;

        // OS "Lin\0"
        memcpy(p, "Lin", 3); p[3] = 0; p += 4;

        // Country "enUS"
        memcpy(p, "enUS", 4); p += 4;

        writeU32LE(p, 0); p += 4; // timezone bias
        writeU32LE(p, 0x7F000001); p += 4; // IP (127.0.0.1)

        *p++ = uint8(nameLen);
        memcpy(p, username.c_str(), nameLen);

        std::cout << "[AuthSocket] Sending CMD_AUTH_LOGON_CHALLENGE (" << pktSize << " bytes)\n";
        return SendAll(buf.data(), buf.size());
    }

    bool AuthSocket::RecvChallengeResponse()
    {
        // Format: [opcode:1][unknown:1][error:1][B:32][g_len:1][g:1][N_len:1][N:32][salt:32][seed:16][sec:1] = 119B
        uint8 opcode, unknown, result;
        if (!RecvAll(&opcode, 1) || !RecvAll(&unknown, 1) || !RecvAll(&result, 1))
            return false;

        if (opcode != AUTH_LOGON_CHALLENGE || result != AUTH_OK)
        {
            std::cerr << "[AuthSocket] Challenge failed: opcode=" << int(opcode)
                      << " result=" << int(result) << "\n";
            _result.errorCode = result;
            return false;
        }

        // B(32) + g_len(1) + g(1) + N_len(1) + N(32) + salt(32) + seed(16) + security(1) = 116
        uint8 body[116];
        if (!RecvAll(body, sizeof(body)))
            return false;

        size_t off = 0;
        memcpy(_result.B.data(), body + off, 32); off += 32;
        off += 1; // skip g_len
        _result.g = body[off++];
        off += 1; // skip N_len
        memcpy(_result.N.data(), body + off, 32); off += 32;
        memcpy(_result.salt.data(), body + off, 32); off += 32;
        memcpy(_result.seed.data(), body + off, 16); off += 16;
        // skip securityFlags (1 byte)

        printf("[AuthSocket] B=        "); for(int i=0;i<32;++i)printf("%02x",_result.B[i]); printf("\n");
        printf("[AuthSocket] salt=     "); for(int i=0;i<32;++i)printf("%02x",_result.salt[i]); printf("\n");
        printf("[AuthSocket] seed=     "); for(int i=0;i<16;++i)printf("%02x",_result.seed[i]); printf("\n");
        printf("[AuthSocket] N=        "); for(int i=0;i<32;++i)printf("%02x",_result.N[i]); printf("\n");

        return true;
    }

    bool AuthSocket::SendProofRequest(std::string const& username, std::string const& password)
    {
        std::string normUser = NormalizeLogin(username);
        std::string normPass = NormalizeLogin(password);

        // 生成客户端临时私钥 a（19 字节随机）
        BigNumber a;
        a.SetRand(19 * 8);

        // 计算 A = g^a mod N
        auto clientA = BuildClientEphemeralKey(a);

        // 计算 verifier = g^x mod N，用服务端返回的 salt
        SRP6::Verifier v{};
        {
            // x = H(salt, H(username:password))
            auto innerHash = SHA1::GetDigestOf(normUser, ":", normPass);
            printf("[AuthSocket] user:pass sha1= "); for(int i=0;i<20;++i)printf("%02x",innerHash[i]); printf("\n");
            BigNumber x(SHA1::GetDigestOf(_result.salt, innerHash));
            // v = g^x mod N
            BigNumber const g(SRP6::g);
            BigNumber const N(SRP6::N);
            v = g.ModExp(x, N).ToByteArray<32>();
            printf("[AuthSocket] v=         "); for(int i=0;i<32;++i)printf("%02x",v[i]); printf("\n");
        }

        _result.sessionKey = ComputeSessionKey(a, _result.B, normUser, normPass, _result.salt, v);
        printf("[AuthSocket] K=         "); for(int i=0;i<40;++i)printf("%02x",_result.sessionKey[i]); printf("\n");

        // 计算 M1
        auto clientM = ComputeClientProof(clientA, _result.B, normUser, normPass, _result.salt, _result.sessionKey);
        printf("[AuthSocket] M1=        "); for(int i=0;i<20;++i)printf("%02x",clientM[i]); printf("\n");
        printf("[AuthSocket] A=         "); for(int i=0;i<32;++i)printf("%02x",clientA[i]); printf("\n");

        // CRC hash：该字段 authserver 不去验证（为 0 即可）
        std::array<uint8, 20> crcHash{};

        // 构造包: cmd(1) + A(32) + M1(20) + CRC(20) + num_keys(1) + securityFlags(1)
        constexpr size_t pktSize = 1 + 32 + 20 + 20 + 1 + 1;
        uint8 buf[pktSize]{};
        uint8* p = buf;

        *p++ = AUTH_LOGON_PROOF;
        memcpy(p, clientA.data(), 32); p += 32;
        memcpy(p, clientM.data(), 20); p += 20;
        memcpy(p, crcHash.data(), 20); p += 20;
        *p++ = 1;    // num_keys
        *p++ = 0;    // securityFlags

        std::cout << "[AuthSocket] Sending CMD_AUTH_LOGON_PROOF\n";
        return SendAll(buf, sizeof(buf));
    }

    bool AuthSocket::RecvProofResponse()
    {
        // Proof response: [opcode:AUTH_LOGON_PROOF=0x01][error][(M2+flags on success)]
        uint8 opcode;
        if (!RecvAll(&opcode, 1))
            return false;

        if (opcode != AUTH_LOGON_PROOF)
        {
            std::cerr << "[AuthSocket] Proof bad opcode: " << int(opcode) << "\n";
            return false;
        }

        uint8 result;
        if (!RecvAll(&result, 1))
            return false;

        if (result != AUTH_OK)
        {
            std::cerr << "[AuthSocket] Proof failed: result=" << int(result) << "\n";
            _result.errorCode = result;
            return false;
        }

        // 读取 M2(20) + accountFlags(4) + surveyId(4) + loginFlags(2) = 30 bytes
        uint8 body[30];
        if (!RecvAll(body, sizeof(body)))
            return false;

        size_t off = 0;
        memcpy(_result.M2.data(), body + off, 20); off += 20;
        memcpy(&_result.accountFlags, body + off, 4); off += 4;
        memcpy(&_result.surveyId, body + off, 4); off += 4;
        // 最后 2 字节是 loginFlags，可忽略

        std::cout << "[AuthSocket] Proof accepted! accountFlags=" << _result.accountFlags << "\n";
        return true;
    }

    bool AuthSocket::SendRealmListRequest()
    {
        uint8 buf[5]{};
        buf[0] = REALM_LIST; // cmd
        // buf[1..4] = 0 (padding)
        return SendAll(buf, sizeof(buf));
    }

    bool AuthSocket::RecvRealmListResponse(std::vector<RealmInfo>& realms)
    {
        // 读取 cmd + size
        uint8 header[3];
        if (!RecvAll(header, 3))
            return false;

        uint8 cmd = header[0];
        if (cmd != REALM_LIST)
        {
            std::cerr << "[AuthSocket] Unexpected realm list cmd: " << int(cmd) << "\n";
            return false;
        }

        uint16 bodySize = readU16LE(header + 1);

        std::vector<uint8> body(bodySize);
        if (!RecvAll(body.data(), bodySize))
            return false;

        // 解析: body 起始 = 4B padding + 2B count + realms...
        size_t pos = 4; // skip padding
        if (pos + 2 > body.size()) return false;
        uint16 count = readU16LE(body.data() + pos);
        pos += 2;

        std::cout << "[AuthSocket] Parsing " << count << " realms\n";

        for (uint16 i = 0; i < count; ++i)
        {
            RealmInfo r;
            if (pos + 7 > body.size()) break; // need at least type+lock+flag+2 nulls+float+numChars+timezone

            uint8 realmType = body[pos++];   // realm type (0=normal, 1=PvP, etc.)
            uint8 lock      = body[pos++];   // lock (1=locked)
            uint8 flag      = body[pos++];   // realm flags

            // 简化解析：从当前位置读取字符串
            // Name (null-terminated)
            std::string name;
            while (pos < body.size() && body[pos] != 0)
                name += (char)body[pos++];
            pos++; // skip null

            // Address (格式: IP:Port)
            std::string addr;
            while (pos < body.size() && body[pos] != 0)
                addr += (char)body[pos++];
            pos++; // skip null

            // 解析 address:port
            r.name = name;
            auto colon = addr.find(':');
            if (colon != std::string::npos)
            {
                r.address = addr.substr(0, colon);
                r.port = uint16(std::stoi(addr.substr(colon + 1)));
            }
            else
            {
                r.address = addr;
                r.port = 8085;
            }

            // Population float (4B)
            if (pos + 4 <= body.size())
            {
                memcpy(&r.population, body.data() + pos, 4);
                pos += 4;
            }

            // numChars (1B)
            if (pos < body.size()) r.numChars = body[pos++];

            // timezone (1B)
            if (pos < body.size()) r.timezone = body[pos++];

            // realmId (1B) — 3.3.5 always present
            if (pos < body.size())
            {
                r.realmId = body[pos++];
            }

            // REALM_FLAG_SPECIFYBUILD (0x04): 跳过扩展 build 字段
            if (flag & 0x04 && pos + 5 <= body.size())
            {
                pos += 5; // major(1) + minor(1) + bugfix(1) + build(2)
            }

            realms.push_back(r);
            std::cout << "  Realm: " << r.name << " @ " << r.address << ":" << r.port
                      << " realmId=" << int(r.realmId) << "\n";
        }

        return !realms.empty();
    }
}
