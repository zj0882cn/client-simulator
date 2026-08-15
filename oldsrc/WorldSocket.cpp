#include "WorldSocket.h"
#include "Cryptography/CryptoHash.h"
#include "Cryptography/CryptoRandom.h"
#include "Define.h"
#include "Debugging/Errors.h"
#include "Cryptography/HMAC.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

using namespace ClientSimulator;

// ── WotLK 3.3.5 opcodes ──
namespace Opcodes
{
    // Client → Server
    static constexpr uint32 CMSG_AUTH_SESSION       = 0x01ED;
    static constexpr uint32 CMSG_CHAR_ENUM           = 0x0037;
    static constexpr uint32 CMSG_PLAYER_LOGIN        = 0x003D;
    static constexpr uint32 CMSG_PING                = 0x01DC;
    static constexpr uint32 CMSG_MOVE_HEARTBEAT      = 0x00EE;  // MSG_MOVE_HEARTBEAT
    static constexpr uint32 CMSG_SET_ACTIVE_MOVER    = 0x026A;
    static constexpr uint32 CMSG_MOVE_FALL_RESET     = 0x02CA;
    static constexpr uint32 CMSG_STANDSTATECHANGE    = 0x0101;
    static constexpr uint32 CMSG_MESSAGECHAT         = 0x0095;
    static constexpr uint32 CMSG_REPOP_REQUEST       = 0x015A;
    static constexpr uint32 CMSG_RECLAIM_CORPSE      = 0x01D2;
    static constexpr uint32 CMSG_SPIRIT_HEALER_ACTIVATE = 0x021C;
    static constexpr uint32 CMSG_TIME_SYNC_RESP      = 0x0391;
    static constexpr uint32 CMSG_LOGOUT              = 0x004B;

    // Movement (MSG_* = both C→S and S→C share same opcode, same packet format for C→S)
    static constexpr uint32 MSG_MOVE_START_FORWARD   = 0x00B5;
    static constexpr uint32 MSG_MOVE_STOP            = 0x00B7;
    static constexpr uint32 MSG_MOVE_SET_FACING      = 0x00DA;
    static constexpr uint32 MSG_MOVE_TELEPORT_ACK    = 0x00C7;

    // Combat / NPC interaction
    static constexpr uint32 CMSG_SET_SELECTION       = 0x013D;
    static constexpr uint32 CMSG_ATTACKSWING         = 0x0141;
    static constexpr uint32 CMSG_ATTACKSTOP          = 0x0142;
    static constexpr uint32 CMSG_GOSSIP_HELLO        = 0x017B;
    static constexpr uint32 CMSG_QUESTGIVER_HELLO    = 0x0184;
    static constexpr uint32 CMSG_QUESTGIVER_QUERY_QUEST    = 0x0186;
    static constexpr uint32 CMSG_QUESTGIVER_ACCEPT_QUEST  = 0x0189;
    static constexpr uint32 CMSG_QUESTGIVER_COMPLETE_QUEST = 0x018A;

    // Server → Client
    static constexpr uint16 SMSG_AUTH_CHALLENGE       = 0x01EC;
    static constexpr uint16 SMSG_AUTH_RESPONSE        = 0x01EE;
    static constexpr uint16 SMSG_ADDON_INFO           = 0x02EF;
    static constexpr uint16 SMSG_CLIENTCACHE_VERSION  = 0x04AB;
    static constexpr uint16 SMSG_TUTORIAL_FLAGS       = 0x00FD;
    static constexpr uint16 SMSG_CHAR_ENUM            = 0x003B;
    static constexpr uint16 SMSG_LOGIN_VERIFY_WORLD   = 0x0236;
    static constexpr uint16 SMSG_PONG                 = 0x01DD;
    static constexpr uint16 SMSG_LOGOUT_COMPLETE      = 0x004D;
    static constexpr uint16 SMSG_TIME_SYNC_REQ        = 0x0390;
    static constexpr uint16 SMSG_ATTACKSTART          = 0x0143;
    static constexpr uint16 SMSG_ATTACKSTOP           = 0x0144;
    static constexpr uint16 SMSG_GOSSIP_MESSAGE       = 0x017D;
    static constexpr uint16 SMSG_QUESTGIVER_QUEST_LIST    = 0x0185;
    static constexpr uint16 SMSG_QUESTGIVER_QUEST_DETAILS = 0x0188;
    static constexpr uint16 SMSG_QUESTGIVER_QUEST_COMPLETE = 0x018B;
    static constexpr uint16 SMSG_NEW_WORLD             = 0x003E;
    static constexpr uint16 SMSG_TRANSFER_PENDING      = 0x003F;
    static constexpr uint16 SMSG_TRANSFER_ABORTED      = 0x0040;
    static constexpr uint16 SMSG_MOVE_TELEPORT         = 0x00C9;
    static constexpr uint16 SMSG_LOGOUT_RESPONSE       = 0x004C;  // 服务端时间同步请求
    static constexpr uint16 SMSG_CORPSE_RECLAIM_DELAY  = 0x0267;  // 死亡/可以复活
    static constexpr uint16 SMSG_DEATH_RELEASE_LOC     = 0x0257;  // 灵魂释放后位置
}

// ── 移动标志 ──
static constexpr uint32 MOVEMENTFLAG_NONE    = 0x00000000;
static constexpr uint32 MOVEMENTFLAG_FORWARD = 0x00000001;

// Socket 超时（秒），防止 recv/send 永久阻塞
static constexpr int SOCKET_RECV_TIMEOUT_SEC = 10;
static constexpr int SOCKET_SEND_TIMEOUT_SEC = 10;
static constexpr int CONNECT_TIMEOUT_SEC = 5;

// WoW PackedGuid 编码：越小的 GUID 越节省字节
static std::vector<uint8> packGuid(uint64 guid)
{
    std::vector<uint8> result;
    result.push_back(0); // mask placeholder
    uint8 mask = 0;
    for (int i = 0; i < 8; ++i)
    {
        uint8 byte = uint8(guid >> (i * 8)) & 0xFF;
        if (byte != 0)
        {
            mask |= uint8(1 << i);
            result.push_back(byte);
        }
    }
    result[0] = mask;
    return result;
}

static uint16 readU16BE(uint8 const* p)
{
    return (uint16(p[0]) << 8) | uint16(p[1]);
}

static uint32 readU32LE(uint8 const* p)
{
    return uint32(p[0]) | (uint32(p[1]) << 8) | (uint32(p[2]) << 16) | (uint32(p[3]) << 24);
}

static uint64 readU64LE(uint8 const* p)
{
    return uint64(p[0]) | (uint64(p[1]) << 8) | (uint64(p[2]) << 16) | (uint64(p[3]) << 24)
         | (uint64(p[4]) << 32) | (uint64(p[5]) << 40) | (uint64(p[6]) << 48) | (uint64(p[7]) << 56);
}

static void writeU32LE(uint8* p, uint32 v)
{
    p[0] = uint8(v);
    p[1] = uint8(v >> 8);
    p[2] = uint8(v >> 16);
    p[3] = uint8(v >> 24);
}

static void writeU32BE(uint8* p, uint32 v)
{
    p[0] = uint8(v >> 24);
    p[1] = uint8(v >> 16);
    p[2] = uint8(v >> 8);
    p[3] = uint8(v);
}

static void writeU64LE(uint8* p, uint64 v)
{
    writeU32LE(p, uint32(v));
    writeU32LE(p + 4, uint32(v >> 32));
}

static void writeU64BE(uint8* p, uint64 v)
{
    writeU32BE(p, uint32(v >> 32));
    writeU32BE(p + 4, uint32(v));
}

static float readFloatLE(uint8 const* p)
{
    uint32 raw = readU32LE(p);
    float f;
    memcpy(&f, &raw, 4);
    return f;
}

// ── PackedGuid helpers ──
// WoW 3.3.5a PackedGuid: first byte is bitmask (bit i = byte i is present),
// followed by only the non-zero GUID bytes.
// 返回值: PackedGuid 占用字节数（mask + data bytes）
static int unpackGuidLen(uint8 const* p)
{
    uint8 mask = p[0];
    int len = 1; // mask byte
    for (int i = 0; i < 8; ++i)
        if (mask & (1 << i))
            len++;
    return len;
}

static std::vector<uint8> WritePackedGuid(uint64 guid)
{
    uint8 bytes[8];
    memcpy(bytes, &guid, 8);

    uint8 mask = 0;
    for (int i = 0; i < 8; ++i)
        if (bytes[i] != 0)
            mask |= uint8(1 << i);

    std::vector<uint8> result;
    result.push_back(mask);
    for (int i = 0; i < 8; ++i)
        if (mask & (1 << i))
            result.push_back(bytes[i]);

    return result;
}

// ── WorldSocket ──

WorldSocket::WorldSocket(std::string const& ip, uint16 port)
    : _ip(ip), _port(port) {}

WorldSocket::~WorldSocket() { Disconnect(); }

bool WorldSocket::Connect()
{
    _fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_fd < 0)
    {
        std::cerr << "[WorldSocket] socket() failed\n";
        return false;
    }

    struct hostent* he = gethostbyname(_ip.c_str());
    if (!he)
    {
        std::cerr << "[WorldSocket] gethostbyname(" << _ip << ") failed\n";
        close(_fd); _fd = -1;
        return false;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(_port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    // 非阻塞 connect + poll 超时
    {
        int flags = fcntl(_fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(_fd, F_SETFL, flags | O_NONBLOCK);
    }

    int ret = ::connect(_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS)
    {
        std::cerr << "[WorldSocket] connect() to " << _ip << ":" << _port << " failed: "
                  << strerror(errno) << "\n";
        close(_fd); _fd = -1;
        return false;
    }

    {
        struct pollfd pfd;
        pfd.fd = _fd;
        pfd.events = POLLOUT;
        int pollRet = poll(&pfd, 1, CONNECT_TIMEOUT_SEC * 1000);
        if (pollRet <= 0 || !(pfd.revents & POLLOUT))
        {
            std::cerr << "[WorldSocket] connect() timeout/error\n";
            close(_fd); _fd = -1;
            return false;
        }

        int soErr = 0;
        socklen_t len = sizeof(soErr);
        getsockopt(_fd, SOL_SOCKET, SO_ERROR, &soErr, &len);
        if (soErr != 0)
        {
            std::cerr << "[WorldSocket] connect() failed: " << strerror(soErr) << "\n";
            close(_fd); _fd = -1;
            return false;
        }
    }

    // 恢复阻塞 + 设置读写超时
    {
        int flags = fcntl(_fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(_fd, F_SETFL, flags & ~O_NONBLOCK);

        struct timeval tv;
        tv.tv_sec = SOCKET_RECV_TIMEOUT_SEC;
        tv.tv_usec = 0;
        setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        tv.tv_sec = SOCKET_SEND_TIMEOUT_SEC;
        setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    _loginState = LoginState::Connected;
    std::cout << "[WorldSocket] Connected to " << _ip << ":" << _port << "\n";
    return true;
}

void WorldSocket::Disconnect()
{
    if (_fd >= 0)
    {
        close(_fd);
        _fd = -1;
    }
    _loginState = LoginState::Disconnected;
    _cryptInitialized = false;
}

// ── 低级 IO ──

bool WorldSocket::ReadExact(void* buf, size_t len)
{
    size_t received = 0;
    while (received < len)
    {
        ssize_t n = ::recv(_fd, (char*)buf + received, len - received, 0);
        if (n <= 0)
            return false;
        received += n;
    }
    return true;
}

bool WorldSocket::WriteAll(void const* buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = ::send(_fd, (char const*)buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
        {
            std::cerr << "[WorldSocket] send failed: " << strerror(errno) << "\n";
            return false;
        }
        sent += n;
    }
    return true;
}

// ── 加密 ──

void WorldSocket::InitAuthCrypt(std::vector<uint8> const& sessionKey)
{
    // AzerothCore: HMAC_SHA1::GetDigestOf(ServerKey, session)
    // 这里 session 是 data，ServerKey 作为 HMAC 的 seed (key)
    uint8 ServerEncryptionKey[] = { 0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57 };
    uint8 ServerDecryptionKey[] = { 0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE };

    // HMAC_SHA1::GetDigestOf(seed, data) — seed 是 HMAC key, data 是输入
    auto recvKey = Acore::Crypto::HMAC_SHA1::GetDigestOf(ServerEncryptionKey, sessionKey);
    auto sendKey = Acore::Crypto::HMAC_SHA1::GetDigestOf(ServerDecryptionKey, sessionKey);

    // Debug: 打印密钥以验证
    auto hexStr = [](auto const& data) -> std::string {
        std::string result;
        char buf[3];
        for (uint8 b : data) {
            snprintf(buf, sizeof(buf), "%02x", b);
            result += buf;
        }
        return result;
    };
    std::cerr << "[WorldSocket] sessionKey (" << sessionKey.size() << " bytes): "
              << hexStr(sessionKey) << "\n";
    std::cerr << "[WorldSocket] recvKey: " << hexStr(recvKey) << "\n";
    std::cerr << "[WorldSocket] sendKey: " << hexStr(sendKey) << "\n";

    _recvDecrypt.Init(recvKey);
    _sendEncrypt.Init(sendKey);

    // ARC4-drop1024
    std::array<uint8, 1024> syncBuf{};
    _recvDecrypt.UpdateData(syncBuf);
    _sendEncrypt.UpdateData(syncBuf);

    _cryptInitialized = true;
    std::cout << "[WorldSocket] AuthCrypt initialized\n";
}

// ── 发包 ──

bool WorldSocket::SendPacket(uint16 cmd, std::vector<uint8> const& payload)
{
    // Client→Server header: uint16 size(BE) + uint32 cmd(LE) = 6 bytes
    // size = sizeof(cmd) + payload_size
    uint16 payloadSize = uint16(payload.size());
    uint8 header[6];
    header[0] = uint8((sizeof(uint32) + payloadSize) >> 8);
    header[1] = uint8(sizeof(uint32) + payloadSize);
    writeU32LE(header + 2, cmd);

    if (_cryptInitialized)
    {
        // AzerothCore only encrypts the header, not the payload/body.
        _sendEncrypt.UpdateData(header, sizeof(header));
    }

    // Send encrypted header + plaintext payload
    if (!WriteAll(header, sizeof(header)))
        return false;
    if (!payload.empty())
        return WriteAll(payload.data(), payload.size());
    return true;
}

bool WorldSocket::RecvPacket(uint16& cmd, std::vector<uint8>& payload)
{
    // Server→Client header: uint16 size(BE) + uint16 cmd(LE) = 4 bytes
    uint8 header[4];
    if (!ReadExact(header, 4))
    {
        std::cerr << "[WorldSocket] RecvPacket: ReadExact header failed\n";
        return false;
    }

    if (_cryptInitialized)
    {
        // AzerothCore only decrypts the header, not the payload/body.
        _recvDecrypt.UpdateData(header, 4);
        std::cerr << "[WorldSocket] RecvPacket: decrypted hdr: "
                  << std::hex << int(header[0]) << " " << int(header[1])
                  << " " << int(header[2]) << " " << int(header[3])
                  << std::dec << "\n";
    }

    uint16 size = readU16BE(header);
    cmd = uint16(header[2]) | (uint16(header[3]) << 8);

    std::cerr << "[WorldSocket] RecvPacket: cmd=0x" << std::hex << cmd
              << " size=" << size << std::dec << "\n";

    // ServerPktHeader 的 size = sizeof(cmd) + payload_size（最小为 2，只有 cmd 无 payload）
    if (size < sizeof(uint16))
    {
        std::cerr << "[WorldSocket] Invalid packet size: " << size << "\n";
        return false;
    }

    size_t payloadLen = size - sizeof(uint16);
    if (payloadLen == 0)
    {
        payload.clear();
        return true;
    }

    payload.resize(payloadLen);
    if (!ReadExact(payload.data(), payloadLen))
    {
        std::cerr << "[WorldSocket] RecvPacket: ReadExact payload failed ("
                  << payloadLen << " bytes)\n";
        return false;
    }

    // Do NOT decrypt the payload. AzerothCore only encrypts/decrypts headers.
    return true;
}

// ── 登录流程 ──

bool WorldSocket::RecvAuthChallenge()
{
    uint16 cmd;
    std::vector<uint8> body;
    if (!RecvPacket(cmd, body) || cmd != Opcodes::SMSG_AUTH_CHALLENGE)
    {
        std::cerr << "[WorldSocket] Expected SMSG_AUTH_CHALLENGE, got 0x"
                  << std::hex << cmd << std::dec << "\n";
        return false;
    }

    // SMSG_AUTH_CHALLENGE body: [uint32(1):4][serverSeed:4][random:32] = 40 bytes
    // serverSeed 用于 digest 计算
    if (body.size() >= 8)
        memcpy(_serverSeed, body.data() + 4, 4);

    // 生成客户端随机 seed
    Acore::Crypto::GetRandomBytes(_clientSeed);

    _loginState = LoginState::AuthChallengeDone;
    std::cout << "[WorldSocket] Auth challenge received\n";
    return true;
}

bool WorldSocket::SendAuthSession(AuthResult const& auth, std::string const& username, uint8 realmId)
{
    std::string user = username;
    if (user.empty())
        user = _username;
    else
        _username = user;

    std::string normUser = user;
    std::transform(normUser.begin(), normUser.end(), normUser.begin(), ::toupper);

    // digest = SHA1(account + [0,0,0,0] + clientSeed(4) + serverSeed(4) + sessionKey(40))
    // 完全匹配服务端 WorldSocket::HandleAuthSession 的计算
    Acore::Crypto::SHA1::Digest digest;
    {
        Acore::Crypto::SHA1 ctx;
        uint8 zero[4] = { 0, 0, 0, 0 };
        ctx.UpdateData(normUser);
        ctx.UpdateData(zero);
        ctx.UpdateData(_clientSeed);
        ctx.UpdateData(_serverSeed);
        ctx.UpdateData(auth.sessionKey.data(), auth.sessionKey.size());
        ctx.Finalize();
        digest = ctx.GetDigest();
    }

    uint32 build = 12340;
    uint32 serverId = 0;
    uint32 loginServerType = 0; // GRUNT
    uint32 clientSeedVal = readU32LE(_clientSeed);
    uint32 regionId = 2;   // US
    uint32 battlegroupId = 1;
    uint64 dosResponse = 0;

    std::vector<uint8> payload;
    auto pushU32 = [&](uint32 v) {
        uint8 buf[4];
        writeU32LE(buf, v);
        payload.insert(payload.end(), buf, buf + 4);
    };
    auto pushU64 = [&](uint64 v) {
        uint8 buf[8];
        writeU64LE(buf, v);
        payload.insert(payload.end(), buf, buf + 8);
    };

    payload.reserve(4 + 4 + normUser.size() + 1 + 4 + 4 + 4 + 4 + 1 + 8 + 20);
    pushU32(build);
    pushU32(serverId);
    payload.insert(payload.end(), normUser.begin(), normUser.end());
    payload.push_back(0); // null terminator
    pushU32(loginServerType);
    payload.insert(payload.end(), _clientSeed, _clientSeed + 4);
    pushU32(regionId);
    pushU32(battlegroupId);
    payload.push_back(realmId); // WoW 3.3.5: realmId is uint8 (1 byte)
    pushU64(dosResponse);
    payload.insert(payload.end(), digest.data(), digest.data() + digest.size());

    // ── Addon info (required by server) ──
    // 格式: uint32 uncompressed_size + [zlib_compressed_data]
    // 如果 uncompressed_size == 0，ReadAddonsInfo 直接 return（不读取更多数据）
    // 解压后: uint32 addon_count, 然后每个 addon: string name + uint8 enabled + uint32 CRC + uint32 unk1
    {
        // 最简单方式: uncompressed_size = 0, 无压缩数据
        uint8 sizeBuf[4] = { 0, 0, 0, 0 };
        payload.insert(payload.end(), sizeBuf, sizeBuf + 4);
        // 注意: 如果 uncompressed_size=0, ReadAddonsInfo 跳过后续所有数据
    }

    _srpSessionKey.assign(auth.sessionKey.data(), auth.sessionKey.data() + auth.sessionKey.size());
    _sessionKey = digest;

    // Hex dump payload
    std::cerr << "[WorldSocket] CMSG_AUTH_SESSION payload (" << payload.size() << " bytes): ";
    for (size_t i = 0; i < payload.size(); ++i)
    {
        int b = (int)payload[i];
        std::cerr << (b < 16 ? "0" : "") << std::hex << b << " ";
    }
    std::cerr << std::dec << "\n";

    // 先发送明文 CMSG_AUTH_SESSION
    if (!SendPacket(Opcodes::CMSG_AUTH_SESSION, payload))
        return false;

    // 先不初始化加密，等收到 SMSG_AUTH_RESPONSE 后再决定
    // 如果服务端返回错误（如 AUTH_UNKNOWN_ACCOUNT），加密未初始化，响应是明文的
    // 如果服务端返回成功，加密已初始化，响应是加密的

    _loginState = LoginState::AuthSent;
    std::cout << "[WorldSocket] Sending CMSG_AUTH_SESSION user=" << normUser
              << " realmId=" << int(realmId) << " (payload=" << payload.size() << " bytes)\n";
    return true;
}

static char const* GetAuthResultName(uint8 code)
{
    switch (code)
    {
        case 0:  return "AUTH_OK";
        case 1:  return "AUTH_FAIL — 账号/密码错误";
        case 2:  return "AUTH_REJECT — 被封禁";
        case 3:  return "AUTH_BANNED — 永久封禁";
        case 4:  return "AUTH_ALREADYONLINE — 已在线";
        case 5:  return "AUTH_SUSPENDED — 暂停";
        case 6:  return "AUTH_NOACCESS — 无访问权限";
        case 7:  return "AUTH_SUCCESS — 成功";
        case 8:  return "AUTH_FAIL — 失败";
        case 9:  return "AUTH_FAIL — 版本号过低";
        case 10: return "AUTH_DISCONNECT — 断开连接";
        case 11: return "AUTH_FAIL — 版本号过高";
        case 12: return "AUTH_VERSION_NOT_SUPPORTED — 版本不支持";
        case 14: return "AUTH_REJECT — 世界服务器关闭 / Warden OS 检查失败";
        case 15: return "AUTH_FAIL — 摘要校验失败 / IP 锁定 / 国家锁定";
        case 16: return "REALM_LIST_REALM_NOT_FOUND — RealmID 不匹配";
        case 17: return "AUTH_DISABLED — 账号禁用";
        case 18: return "AUTH_CONNECTED — 已连接";
        case 19: return "AUTH_CHALLENGE — 挑战";
        case 20: return "AUTH_SURVEY — 调查问卷";
        case 21: return "AUTH_DISCONNECTED — 已断开";
        case 23: return "AUTH_FAILED — 无可用服务器";
        case 24: return "AUTH_FAILED — 关闭";
        case 25: return "AUTH_SUSPENDED — 被封禁";
        case 26: return "AUTH_NOT_CONNECTED — 未连接";
        case 27: return "AUTH_REJECT — Warden 检查失败";
        case 28: return "AUTH_UNAVAILABLE — 安全等级不足";
        case 29: return "AUTH_FAIL — 令牌无效";
        case 30: return "AUTH_INVALID_PROOF — 证明无效";
        case 31: return "AUTH_NO_HIT — 无命中";
        case 32: return "AUTH_INVALID_PROOF — 证明无效";
        case 33: return "AUTH_INVALID_PROOF — 证明无效";
        case 34: return "AUTH_INVALID_PROOF — 证明无效";
        case 35: return "AUTH_INVALID_PROOF — 证明无效";
        case 36: return "AUTH_INVALID_PROOF — 证明无效";
        case 37: return "AUTH_INVALID_PROOF — 证明无效";
        case 38: return "AUTH_INVALID_PROOF — 证明无效";
        case 39: return "AUTH_INVALID_PROOF — 证明无效";
        case 40: return "AUTH_INVALID_PROOF — 证明无效";
        case 41: return "AUTH_INVALID_PROOF — 证明无效";
        case 42: return "AUTH_INVALID_PROOF — 证明无效";
        default: return "未知错误码";
    }
}

bool WorldSocket::WaitAuthResponse(uint8& result, uint32& billingFlags)
{
    result = 255;
    billingFlags = 0;

    // AzerothCore 服务端逻辑（参考 WorldSocket::HandleAuthSession）：
    //   - 错误响应（AUTH_REJECT 等）在加密初始化前发送 → 明文
    //   - 成功响应（AUTH_OK）也在加密初始化前发送 → 明文
    //   - 只有后续包（SMSG_ADDON_INFO 等）才是加密的
    // 因此 SMSG_AUTH_RESPONSE 应该用明文读取。
    // 但为了兼容不同版本的服务端，我们同时支持两种模式。

    uint8 rawHeader[4];
    if (!ReadExact(rawHeader, 4))
    {
        std::cerr << "[WorldSocket] Failed to read auth response header\n";
        return false;
    }

    // ── 先尝试明文模式 ──
    uint16 sizePlain = readU16BE(rawHeader);
    uint16 cmdPlain  = uint16(rawHeader[2]) | (uint16(rawHeader[3]) << 8);

    std::cerr << "[WorldSocket] raw auth header: ";
    for (int i = 0; i < 4; ++i)
        std::cerr << std::hex << int(rawHeader[i]) << " ";
    std::cerr << std::dec << "\n";
    std::cerr << "[WorldSocket] plaintext try: cmd=0x" << std::hex << cmdPlain
              << " size=" << sizePlain << std::dec << "\n";

    if (cmdPlain == Opcodes::SMSG_AUTH_RESPONSE && sizePlain >= sizeof(uint16))
    {
        size_t bodyLen = sizePlain - sizeof(uint16);
        std::vector<uint8> body;
        if (bodyLen > 0)
        {
            body.resize(bodyLen);
            if (!ReadExact(body.data(), bodyLen))
                return false;

            std::cerr << "[WorldSocket] auth body (" << bodyLen << " bytes): ";
            for (size_t i = 0; i < std::min(bodyLen, size_t(32)); ++i)
                std::cerr << std::hex << int(body[i]) << " ";
            if (bodyLen > 32) std::cerr << "...";
            std::cerr << std::dec << "\n";
        }

        result = body.empty() ? 0 : body[0];
        std::cerr << "[WorldSocket] auth result=" << int(result)
                  << " (" << GetAuthResultName(result) << ") [plaintext]\n";

        if (result != 0)
        {
            std::cerr << "[WorldSocket] Auth rejected: code " << int(result)
                      << " — " << GetAuthResultName(result) << "\n";
            return false;
        }

        // 成功：初始化加密（后续包会是加密的）
        InitAuthCrypt(_srpSessionKey);
        std::cout << "[WorldSocket] Auth response OK (plaintext)\n";
        return true;
    }

    // ── 明文不匹配 → 回退到加密模式 ──
    std::cerr << "[WorldSocket] Plaintext didn't match SMSG_AUTH_RESPONSE, "
              << "trying decryption...\n";

    InitAuthCrypt(_srpSessionKey);

    uint8 decHeader[4];
    memcpy(decHeader, rawHeader, 4);
    _recvDecrypt.UpdateData(decHeader, 4);

    uint16 size = readU16BE(decHeader);
    uint16 cmd  = uint16(decHeader[2]) | (uint16(decHeader[3]) << 8);

    std::cerr << "[WorldSocket] decrypted auth response: cmd=0x"
              << std::hex << cmd << " size=" << size << std::dec << "\n";

    if (cmd != Opcodes::SMSG_AUTH_RESPONSE)
    {
        std::cerr << "[WorldSocket] Expected SMSG_AUTH_RESPONSE (0x1EE), got 0x"
                  << std::hex << cmd << std::dec << " after decryption\n";
        return false;
    }

    size_t bodyLen = (size >= sizeof(uint16)) ? (size - sizeof(uint16)) : 0;
    std::vector<uint8> body;
    if (bodyLen > 0)
    {
        body.resize(bodyLen);
        if (!ReadExact(body.data(), bodyLen))
        {
            std::cerr << "[WorldSocket] Failed to read auth response body ("
                      << bodyLen << " bytes)\n";
            return false;
        }

        std::cerr << "[WorldSocket] auth body (" << bodyLen << " bytes): ";
        for (size_t i = 0; i < std::min(bodyLen, size_t(32)); ++i)
            std::cerr << std::hex << int(body[i]) << " ";
        if (bodyLen > 32) std::cerr << "...";
        std::cerr << std::dec << "\n";
    }

    result = body.empty() ? 0 : body[0];
    std::cerr << "[WorldSocket] auth result=" << int(result)
              << " (" << GetAuthResultName(result) << ") [encrypted]\n";

    if (result != 0)
    {
        std::cerr << "[WorldSocket] Auth rejected: code " << int(result)
                  << " — " << GetAuthResultName(result) << "\n";
        return false;
    }

    std::cout << "[WorldSocket] Auth response OK (encrypted)\n";
    return true;
}

bool WorldSocket::RecvCharacterList(std::vector<CharacterInfo>& chars)
{
    chars.clear();

    std::cerr << "[WorldSocket] Entering RecvCharacterList, cryptInitialized="
              << _cryptInitialized << "\n";

    // Drain any pending packets that arrived after SMSG_AUTH_RESPONSE
    // (server may push SMSG_ADDON_INFO, SMSG_CLIENTCACHE_VERSION, etc.)
    {
        int drainedCount = 0;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (std::chrono::steady_clock::now() < deadline)
        {
            uint16 cmd;
            std::vector<uint8> body;
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(_fd, &fds);
            struct timeval tv{0, 20000};
            int ret = select(_fd + 1, &fds, nullptr, nullptr, &tv);
            if (ret <= 0) break;
            if (!RecvPacket(cmd, body))
            {
                std::cerr << "[WorldSocket] Drain: RecvPacket failed\n";
                break;
            }
            std::cerr << "[WorldSocket] Drain: got cmd=0x" << std::hex << cmd
                      << std::dec << " (" << body.size() << " bytes)\n";
            drainedCount++;
        }
        std::cerr << "[WorldSocket] Drain complete: " << drainedCount << " packets drained\n";
    }

    // 发送 CMSG_CHAR_ENUM
    std::cerr << "[WorldSocket] Sending CMSG_CHAR_ENUM...\n";
    SendPacket(Opcodes::CMSG_CHAR_ENUM, {});

    // 服务端在 CMSG_CHAR_ENUM 之后可能推送额外包，最多读 10 个
    uint16 cmd;
    std::vector<uint8> body;
    for (int i = 0; i < 10; ++i)
    {
        std::cerr << "[WorldSocket] Waiting for packet " << (i+1) << "...\n";
        if (!RecvPacket(cmd, body))
        {
            std::cerr << "[WorldSocket] Failed reading packet after CMSG_CHAR_ENUM\n";
            return false;
        }
        std::cerr << "[WorldSocket] Packet " << (i+1) << ": cmd=0x" << std::hex
                  << cmd << std::dec << " (" << body.size() << " bytes)\n";
        if (cmd == Opcodes::SMSG_CHAR_ENUM)
            break; // 找到角色列表
        std::cerr << "[WorldSocket] Drained intermediate packet 0x"
                  << std::hex << cmd << std::dec << "\n";
    }

    if (cmd != Opcodes::SMSG_CHAR_ENUM)
    {
        std::cerr << "[WorldSocket] Expected SMSG_CHAR_ENUM (0x3B), got 0x"
                  << std::hex << cmd << std::dec << "\n";
        return false;
    }

    if (body.size() < 1)
        return true; // 空列表

    size_t pos = 0;
    uint8 count = body[pos++];

    std::cout << "[WorldSocket] Character list: " << int(count) << "\n";
    // hex dump first 32 bytes
    {
        std::cerr << "[WorldSocket] raw char data (first 32 bytes): ";
        for (size_t j = 0; j < std::min(size_t(32), body.size()); ++j)
        {
            int b = (int)body[j];
            std::cerr << (b < 16 ? "0" : "") << std::hex << b << " ";
        }
        std::cerr << std::dec << "\n";
    }
    for (uint8 i = 0; i < count; ++i)
    {
        if (pos + 9 > body.size()) break;

        CharacterInfo ci;
        ci.guid = readU64LE(body.data() + pos);
        std::cerr << "[WorldSocket] raw guid at pos=" << pos << ": 0x" << std::hex << ci.guid << std::dec << "\n";
        pos += 8;

        // 读取 name (null-terminated string)
        size_t nameEnd = body.size();
        for (size_t j = pos; j < body.size(); ++j)
        {
            if (body[j] == 0) { nameEnd = j; break; }
        }
        ci.name.assign((char*)body.data() + pos, nameEnd - pos);
        pos = nameEnd + 1;

        if (pos + 7 > body.size()) break;

        ci.race   = body[pos++];
        ci.clazz  = body[pos++];
        ci.gender = body[pos++];
        pos += 5; // skip appearance

        if (pos + 1 > body.size()) break;
        ci.level = body[pos++];

        if (pos + 4 > body.size()) break;
        ci.zone = readU32LE(body.data() + pos); pos += 4;

        if (pos + 4 > body.size()) break;
        ci.mapId = readU32LE(body.data() + pos); pos += 4;

        if (pos + 4*3 > body.size()) break;
        ci.x = readFloatLE(body.data() + pos); pos += 4;
        ci.y = readFloatLE(body.data() + pos); pos += 4;
        ci.z = readFloatLE(body.data() + pos); pos += 4;

        // 跳过 guild(4) + flags(4)
        if (pos + 8 > body.size()) break;
        uint32 flags = readU32LE(body.data() + pos + 4);
        pos += 8;

        // 检查 customizeFlags
        // 3.3.5 flags 0x100000 = CHARACTER_FLAG_EXTRA
        if (flags & 0x100000)
        {
            if (pos + 4 > body.size()) break;
            pos += 4;
        }

        // firstLogin(1)
        if (pos + 1 > body.size()) break;
        pos += 1; // skip firstLogin

        // pet displayId(4)+level(4)+family(4) = 12
        if (pos + 12 > body.size()) break;
        pos += 12;

        // equipment: 23 * uint32 = 92 bytes if flags & 0x1000
        if (flags & 0x1000)
        {
            if (pos + 92 > body.size()) break;
            pos += 92;
        }

        chars.push_back(ci);
        std::cout << "  " << ci.name << " Lv" << int(ci.level)
                  << " (" << ci.x << "," << ci.y << "," << ci.z << ")\n";
    }

    _loginState = LoginState::CharListed;
    return true;
}

bool WorldSocket::LoginCharacter(uint64 guid)
{
    std::vector<uint8> payload(8);
    writeU64LE(payload.data(), guid);
    std::cerr << "[WorldSocket] CMSG_PLAYER_LOGIN guid=" << guid
              << " raw:";
    for (int i = 0; i < 8; ++i)
        std::cerr << " " << std::hex << (int)payload[i];
    std::cerr << std::dec << "\n";
    return SendPacket(Opcodes::CMSG_PLAYER_LOGIN, payload);
}

bool WorldSocket::WaitWorldEnter()
{
    // 服务端在 CMSG_PLAYER_LOGIN 后会推送大量初始包（SMSG_POWER_UPDATE,
    // SMSG_COMPRESSED_UPDATE_OBJECT, SMSG_SPELL_GO 等等），排空直到 SMSG_LOGIN_VERIFY_WORLD
    uint16 cmd;
    std::vector<uint8> body;
    for (int i = 0; i < 200; ++i)
    {
        if (!RecvPacket(cmd, body))
        {
            std::cerr << "[WorldSocket] Failed reading packet after CMSG_PLAYER_LOGIN\n";
            return false;
        }
        if (cmd == Opcodes::SMSG_LOGIN_VERIFY_WORLD)
        {
            _loginState = LoginState::InWorld;
            std::cout << "[WorldSocket] Entered world! (after " << i << " drained packets)\n";
            return true;
        }
    }

    std::cerr << "[WorldSocket] SMSG_LOGIN_VERIFY_WORLD not found in first 200 packets\n";
    return false;
}

bool WorldSocket::DrainLoginPackets(uint32 timeoutMs)
{
    // 进入世界后读掉所有初始包
    int drained = 0;
    for (;;)
    {
        if (!HasPendingData(timeoutMs))
            break;

        uint16 cmd;
        std::vector<uint8> body;
        if (!RecvPacket(cmd, body))
            return false;
        drained++;
    }
    if (drained > 0)
        std::cout << "[WorldSocket] Drained " << drained << " login packets\n";
    return true;
}

// ── 游戏层 ──

bool WorldSocket::HasPendingData(uint32 timeoutMs)
{
    if (_fd < 0) return false;
    struct pollfd pfd{};
    pfd.fd = _fd;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, int(timeoutMs));
    // POLLERR/POLLHUP → 连接已断开
    if (ret > 0 && (pfd.revents & (POLLERR | POLLHUP)))
    {
        std::cerr << "[WorldSocket] 连接已断开 (revents=0x" << std::hex << pfd.revents << std::dec << ")\n";
        close(_fd);
        _fd = -1;
        return false;
    }
    return ret > 0 && (pfd.revents & POLLIN);
}

bool WorldSocket::RecvPacketNonBlocking(uint16& cmd, std::vector<uint8>& payload)
{
    if (!HasPendingData(0))
    {
        cmd = 0;
        payload.clear();
        return false;
    }
    return RecvPacket(cmd, payload);
}

bool WorldSocket::SendActiveMover()
{
    // CMSG_SET_ACTIVE_MOVER: raw uint64 guid (8 bytes), NOT PackedGuid
    uint8 buf[8];
    writeU64LE(buf, _botState.guid);
    std::vector<uint8> payload(buf, buf + 8);
    return SendPacket(Opcodes::CMSG_SET_ACTIVE_MOVER, payload);
}

// ── 移动包荷载构建（通用） ──
// 格式: PackedGuid(可变) + MovementInfo(30+)
// MovementInfo: flags(4) + flags2(2) + time(4) + pos(16) + fallTime(4)
std::vector<uint8> WorldSocket::BuildMovementPayload(uint32 flags, Vec3 pos, float orientation)
{
    _botState.moveTime += 100;  // per-bot, 非 static (避免多 bot 竞态)

    std::vector<uint8> payload;
    uint8 buf[8];

    // PackedGuid — 服务端用 recvData >> guid.ReadAsPacked() 解析
    auto pg = packGuid(_botState.guid);
    payload.insert(payload.end(), pg.begin(), pg.end());

    // MovementInfo header
    // flags (4) + flags2 (2) + time (4) = 10 bytes
    uint8 flagBuf[4];
    writeU32LE(flagBuf, flags);
    payload.insert(payload.end(), flagBuf, flagBuf + 4);

    uint8 flag2Buf[2] = { 0, 0 };
    payload.insert(payload.end(), flag2Buf, flag2Buf + 2);

    writeU32LE(buf, _botState.moveTime);
    payload.insert(payload.end(), buf, buf + 4);

    // position: x, y, z, o (4 floats = 16 bytes)
    float vals[4] = { pos.x, pos.y, pos.z, orientation };
    for (float v : vals)
    {
        uint8 fb[4];
        memcpy(fb, &v, 4);
        payload.insert(payload.end(), fb, fb + 4);
    }

    // fallTime (4 bytes)
    memset(buf, 0, 4);
    payload.insert(payload.end(), buf, buf + 4);

    return payload;
}

bool WorldSocket::SendHeartbeat()
{
    uint32 flags = MOVEMENTFLAG_NONE;
    if (_botState.activity == BOT_ACTIVITY_MOVING)
        flags = MOVEMENTFLAG_FORWARD;
    else if (_botState.isDead && _botState.deathRecoveryStage == 3)
        flags = MOVEMENTFLAG_FORWARD; // 幽灵跑尸中
    auto payload = BuildMovementPayload(flags, _botState.pos, _botState.orientation);
    return SendPacket(Opcodes::CMSG_MOVE_HEARTBEAT, payload);
}

bool WorldSocket::SendMoveStartForward(Vec3 const& pos, float orientation)
{
    auto payload = BuildMovementPayload(MOVEMENTFLAG_FORWARD, pos, orientation);
    return SendPacket(Opcodes::MSG_MOVE_START_FORWARD, payload);
}

bool WorldSocket::SendMoveStop(Vec3 const& pos, float orientation)
{
    auto payload = BuildMovementPayload(MOVEMENTFLAG_NONE, pos, orientation);
    return SendPacket(Opcodes::MSG_MOVE_STOP, payload);
}

bool WorldSocket::SendMoveSetFacing(Vec3 const& pos, float orientation)
{
    auto payload = BuildMovementPayload(MOVEMENTFLAG_NONE, pos, orientation);
    return SendPacket(Opcodes::MSG_MOVE_SET_FACING, payload);
}

bool WorldSocket::SendMoveTeleportAck(uint32 counter)
{
    // CMSG_MOVE_TELEPORT_ACK: PackedGuid(0) + uint32 counter + uint32 time
    std::vector<uint8> payload;
    uint8 buf[8];

    // PackedGuid(0) = 1 byte zero
    payload.push_back(0);

    writeU32LE(buf, counter);
    payload.insert(payload.end(), buf, buf + 4);

    writeU32LE(buf, 0); // time
    payload.insert(payload.end(), buf, buf + 4);

    return SendPacket(Opcodes::MSG_MOVE_TELEPORT_ACK, payload);
}

// ── 战斗 / NPC ──

bool WorldSocket::SendSetSelection(uint64 targetGuid)
{
    // CMSG_SET_SELECTION: raw uint64 guid (8 bytes)
    uint8 buf[8];
    writeU64LE(buf, targetGuid);
    std::vector<uint8> payload(buf, buf + 8);
    return SendPacket(Opcodes::CMSG_SET_SELECTION, payload);
}

bool WorldSocket::SendAttackSwing(uint64 targetGuid)
{
    // CMSG_ATTACKSWING: raw uint64 guid (8 bytes)
    uint8 buf[8];
    writeU64LE(buf, targetGuid);
    std::vector<uint8> payload(buf, buf + 8);
    return SendPacket(Opcodes::CMSG_ATTACKSWING, payload);
}

bool WorldSocket::SendAttackStop()
{
    // CMSG_ATTACKSTOP: no payload
    return SendPacket(Opcodes::CMSG_ATTACKSTOP, {});
}

bool WorldSocket::SendQuestGiverHello(uint64 npcGuid)
{
    // CMSG_QUESTGIVER_HELLO: raw uint64 guid (8 bytes)
    uint8 buf[8];
    writeU64LE(buf, npcGuid);
    std::vector<uint8> payload(buf, buf + 8);
    return SendPacket(Opcodes::CMSG_QUESTGIVER_HELLO, payload);
}

bool WorldSocket::SendGossipHello(uint64 npcGuid)
{
    uint8 buf[8];
    writeU64LE(buf, npcGuid);
    std::vector<uint8> payload(buf, buf + 8);
    return SendPacket(Opcodes::CMSG_GOSSIP_HELLO, payload);
}

bool WorldSocket::SendQuestGiverQueryQuest(uint64 guid, uint32 questId)
{
    // CMSG_QUESTGIVER_QUERY_QUEST: raw uint64 guid(8) + uint32 questId(4)
    uint8 buf[8];
    writeU64LE(buf, guid);
    std::vector<uint8> payload(buf, buf + 8);
    writeU32LE(buf, questId);
    payload.insert(payload.end(), buf, buf + 4);
    return SendPacket(Opcodes::CMSG_QUESTGIVER_QUERY_QUEST, payload);
}

bool WorldSocket::SendQuestGiverAcceptQuest(uint64 questGiverGuid, uint32 questId)
{
    // CMSG_QUESTGIVER_ACCEPT_QUEST: raw uint64 guid(8) + uint32 questId(4)
    uint8 buf[8];
    writeU64LE(buf, questGiverGuid);
    std::vector<uint8> payload(buf, buf + 8);
    writeU32LE(buf, questId);
    payload.insert(payload.end(), buf, buf + 4);
    return SendPacket(Opcodes::CMSG_QUESTGIVER_ACCEPT_QUEST, payload);
}

bool WorldSocket::SendQuestGiverCompleteQuest(uint64 questGiverGuid, uint32 questId)
{
    // CMSG_QUESTGIVER_COMPLETE_QUEST: raw uint64 guid(8) + uint32 questId(4)
    uint8 buf[8];
    writeU64LE(buf, questGiverGuid);
    std::vector<uint8> payload(buf, buf + 8);
    writeU32LE(buf, questId);
    payload.insert(payload.end(), buf, buf + 4);
    return SendPacket(Opcodes::CMSG_QUESTGIVER_COMPLETE_QUEST, payload);
}

bool WorldSocket::SendPing(uint32 seq)
{
    // CMSG_PING: uint32 ping_seq + uint32 latency (8 bytes total)
    // 服务端 HandlePing 会读取 ping 和 latency 两个 uint32
    std::vector<uint8> payload(8);
    writeU32LE(payload.data(), seq);
    writeU32LE(payload.data() + 4, _lastLatency);
    return SendPacket(Opcodes::CMSG_PING, payload);
}

bool WorldSocket::SendLogout()
{
    return SendPacket(Opcodes::CMSG_LOGOUT, {});
}

bool WorldSocket::SendTimeSyncResp(uint32 counter, uint32 clientTime)
{
    // CMSG_TIME_SYNC_RESP: uint32 counter + uint32 clientTimestamp
    std::vector<uint8> payload(8);
    writeU32LE(payload.data(), counter);
    writeU32LE(payload.data() + 4, clientTime);
    return SendPacket(Opcodes::CMSG_TIME_SYNC_RESP, payload);
}

bool WorldSocket::SendChatMessage(std::string const& msg, uint8 channel)
{
    // CMSG_MESSAGECHAT: type(4)+lang(4)+channel(?)×string...
    return false; // Phase 1 stub
}

// ── 包处理 ──

void WorldSocket::ProcessPacket(uint16 cmd, std::vector<uint8> const& payload)
{
    switch (cmd)
    {
    case Opcodes::SMSG_AUTH_CHALLENGE:
        break;
    case Opcodes::SMSG_AUTH_RESPONSE:
        break;
    case Opcodes::SMSG_PONG:
        break;
    case Opcodes::SMSG_TIME_SYNC_REQ:
    {
        // uint32 counter (4 bytes)
        if (payload.size() >= 4)
        {
            uint32 counter = readU32LE(payload.data());
            // 用系统时间作为客户端时间戳
            uint32 clientTime = uint32(time(nullptr));
            SendTimeSyncResp(counter, clientTime);
        }
        break;
    }
    case Opcodes::SMSG_ATTACKSTART:
    {
        if (!_botState.combatTarget)
            _botState.combatTarget = _botState.lastAttackedTarget;
        _botState.activity = BOT_ACTIVITY_COMBAT;
        break;
    }
    case Opcodes::SMSG_ATTACKSTOP:
    {
        _botState.combatTarget = 0;
        // 只清除 combatTarget，lastAttackedTarget 和 activity 由主循环处理
        break;
    }
    case Opcodes::SMSG_QUESTGIVER_QUEST_LIST:
    {
        // 收到任务列表 → 自动接任务 783 (A Threat Within)
        // 格式: guid + uint32 count + statuses...
        if (!_botState.questAccepted)
        {
            std::cerr << "[Quest] 收到任务列表, 自动接任务 783\n";
            // 直接发送 accept，跳过 query（服务器对 783 不要求 query 步骤）
            SendQuestGiverAcceptQuest(_botState.talkTarget, 783);
            _botState.questAccepted = true;
        }
        break;
    }
    case Opcodes::SMSG_QUESTGIVER_QUEST_COMPLETE:
    {
        // 任务可提交（questId + rewards + nextQuest）
        // 格式: uint32 questId + uint32 xp + uint32 gold + uint32 rewardCount ...
        uint32 questId = 0;
        if (payload.size() >= 4)
        {
            memcpy(&questId, payload.data(), 4);
            std::cerr << "[Quest] " << _botState.name
                      << " 任务 " << questId << " 可提交! 提交中...\n";
            SendQuestGiverCompleteQuest(_botState.talkTarget, questId);
            _botState.activeQuestId = questId;
        }
        break;
    }
    case Opcodes::SMSG_NEW_WORLD:
    {
        // 服务端通知客户端切换地图
        // 格式: uint32 mapId(4) + float x(4) + float y(4) + float z(4) + float o(4)
        if (payload.size() >= 20)
        {
            uint32 newMapId = readU32LE(payload.data());
            float nx, ny, nz, no;
            memcpy(&nx, payload.data() + 4, 4);
            memcpy(&ny, payload.data() + 8, 4);
            memcpy(&nz, payload.data() + 12, 4);
            memcpy(&no, payload.data() + 16, 4);
            std::cerr << "[Position] SMSG_NEW_WORLD: map=" << newMapId
                      << " pos=(" << nx << "," << ny << "," << nz << ")\n";
            uint32 oldMapId = _botState.mapId;
            _botState.mapId = newMapId;
            _botState.pos = {nx, ny, nz};
            _botState.orientation = no;
            _botState.lastKnownGoodPos = _botState.pos;
            _botState.beenTeleported = true;
            _botState.stuckTicks = 0;
            // 地图切换 → 停止狩猎/战斗，进入 IDLE
            if (newMapId != oldMapId)
            {
                std::cerr << "[Position] " << _botState.name
                          << " 地图切换 " << oldMapId << " → " << newMapId
                          << ", 停止当前行为\n";
                _botState.activity = BOT_ACTIVITY_IDLE;
                _botState.combatTarget = 0;
                _botState.lastAttackedTarget = 0;
                _botState.mapChanged = true;  // 通知主循环重置目标
            }
        }
        break;
    }
    case Opcodes::SMSG_TRANSFER_PENDING:
    {
        // 服务端通知传送挂起（如坐船、飞点）
        // 格式: uint32 mapId(4) + 可能有位置
        if (payload.size() >= 4)
        {
            uint32 destMapId = readU32LE(payload.data());
            std::cerr << "[Position] SMSG_TRANSFER_PENDING: map=" << destMapId << "\n";
            _botState.beenTeleported = true;
        }
        break;
    }
    case Opcodes::SMSG_TRANSFER_ABORTED:
    {
        std::cerr << "[Position] SMSG_TRANSFER_ABORTED\n";
        _botState.beenTeleported = false;
        break;
    }
    case Opcodes::SMSG_MOVE_TELEPORT:
    {
        // 服务端通知客户端因反作弊等原因被传送
        // 格式: PackedGuid + MovementInfo(flags+flags2+time+xyz+o)
        // MovementInfo position offset: guidLen + 4(flags) + 2(flags2) + 4(time) = guidLen + 10
        int guidLen = unpackGuidLen(payload.data());
        if (payload.size() >= size_t(guidLen + 22))
        {
            int off = guidLen + 10;
            float cx, cy, cz;
            memcpy(&cx, payload.data() + off, 4);
            memcpy(&cy, payload.data() + off + 4, 4);
            memcpy(&cz, payload.data() + off + 8, 4);
            std::cerr << "[Position] " << _botState.name
                      << " SMSG_MOVE_TELEPORT 纠正到 ("
                      << cx << "," << cy << "," << cz << ")\n";
            _botState.pos = {cx, cy, cz};
            _botState.lastKnownGoodPos = _botState.pos;
        }
        else
        {
            std::cerr << "[Position] SMSG_MOVE_TELEPORT — 服务端强制传送 (payload too short)\n";
        }
        _botState.beenTeleported = true;
        _botState.stuckTicks = 0;
        _botState.consecutiveBadPos = 0;
        break;
    }
    case Opcodes::SMSG_CORPSE_RECLAIM_DELAY:
    {
        // 死亡通知 或 接近尸体的复活倒计时
        // 格式: uint32 delay(ms)
        uint32 delay = 0;
        if (payload.size() >= 4)
            delay = readU32LE(payload.data());
        std::cerr << "[Death] " << _botState.name
                  << " SMSG_CORPSE_RECLAIM_DELAY delay=" << delay << "ms"
                  << " stage=" << _botState.deathRecoveryStage << "\n";

        if (delay >= 30000 || (_botState.deathRecoveryStage == 0 && !_botState.isDead))
        {
            // 刚刚死亡
            _botState.isDead = true;
            _botState.activity = BOT_ACTIVITY_DEAD;
            _botState.corpsePos = _botState.lastKnownGoodPos;
            _botState.deathRecoveryStage = 1;
            _botState.deathTimer = 3.0f;
            std::cerr << "[Death] " << _botState.name << " 死亡! 尸体位置=("
                      << _botState.corpsePos.x << "," << _botState.corpsePos.y
                      << "," << _botState.corpsePos.z << ")\n";
        }
        else if (delay <= 1 && _botState.deathRecoveryStage >= 2)
        {
            // 已在尸体附近，可立即复活
            std::cerr << "[Death] " << _botState.name << " 在尸体旁，可复活\n";
            _botState.canReclaim = true;
        }
        break;
    }
    case Opcodes::SMSG_DEATH_RELEASE_LOC:
    {
        // 灵魂释放后服务端通知灵魂位置（墓地坐标）
        // 格式: uint32 mapId + 3*float pos
        if (payload.size() >= 16)
        {
            uint32 respawnMap = readU32LE(payload.data());
            float gx, gy, gz;
            memcpy(&gx, payload.data() + 4, 4);
            memcpy(&gy, payload.data() + 8, 4);
            memcpy(&gz, payload.data() + 12, 4);
            std::cerr << "[Death] " << _botState.name
                      << " 灵魂在墓地: map=" << respawnMap
                      << " pos=(" << gx << "," << gy << "," << gz << ")\n";
            _botState.mapId = respawnMap;
            _botState.pos = {gx, gy, gz};
            _botState.lastKnownGoodPos = _botState.pos;
            _botState.beenTeleported = true;
            _botState.deathRecoveryStage = 2;
            _botState.deathTimer = 0.5f;
            _botState.isGhost = true;
        }
        break;
    }
    default:
        // 忽略其他包
        break;
    }
}

// ── 位置验证 ──
// 返回值: true=位置合理, false=位置异常（需恢复）
bool WorldSocket::ValidatePosition(Vec3& pos, uint32 mapId)
{
    static constexpr float MAX_TELEPORT_DIST    = 200.0f;   // 无通知情况下最大跳跃距离
    static constexpr float FALL_THROUGH_Z       = -500.0f;  // 掉出地图的Z阈值
    static constexpr float CEILING_Z            = 2000.0f;  // 天花板Z阈值
    static constexpr float MAX_Z_DROP_PER_TICK  = 10.0f;    // 单次检查(200ms)Z下落超过此值=坠落
    static constexpr int   MAX_STUCK_TICKS      = 25;       // 200ms*25=5秒卡住
    static constexpr int   MAX_FALL_TICKS       = 3;        // 连续3次坠落→异常

    float lastZ = _botState.lastKnownGoodPos.z;

    // 1. 基础合法性: NaN/Inf
    if (std::isnan(pos.x) || std::isnan(pos.y) || std::isnan(pos.z) ||
        std::isinf(pos.x) || std::isinf(pos.y) || std::isinf(pos.z))
    {
        std::cerr << "[Position] " << _botState.name << " 位置 NaN/Inf! 恢复到已知安全位置\n";
        pos = _botState.lastKnownGoodPos;
        _botState.consecutiveBadPos++;
        _botState.stuckTicks = 0;
        _botState.fallTicks = 0;
        return false;
    }

    // 2. 地图一致性: 主循环传入的 mapId 应与最后一次服务端通知的 mapId 一致
    if (mapId != _botState.mapId)
    {
        std::cerr << "[Position] " << _botState.name
                  << " 地图不一致! main_loop.mapId=" << mapId
                  << " bot.mapId=" << _botState.mapId
                  << " — 同步到服务端地图\n";
        // 以服务端通知的 mapId 为准（_botState.mapId 由 SMSG_NEW_WORLD 更新）
        // 通知调用者不要再用旧地图信息
        return false;
    }

    // 3. 快速坠落检测: Z轴在短时间内持续下降（穿模下坠）
    float zDrop = _botState.lastKnownGoodPos.z - pos.z;
    if (_botState.activity == BOT_ACTIVITY_MOVING && zDrop > MAX_Z_DROP_PER_TICK)
    {
        _botState.fallTicks++;
        std::cerr << "[Position] " << _botState.name
                  << " 疑似坠落! zDrop=" << zDrop << " fallTicks=" << _botState.fallTicks
                  << " pos.z=" << pos.z << " lastGood.z=" << _botState.lastKnownGoodPos.z << "\n";
        if (_botState.fallTicks >= MAX_FALL_TICKS)
        {
            std::cerr << "[Position] " << _botState.name
                      << " 确认坠落！恢复到安全位置 ("
                      << _botState.lastKnownGoodPos.x << ","
                      << _botState.lastKnownGoodPos.y << ","
                      << _botState.lastKnownGoodPos.z << ")\n";
            pos = _botState.lastKnownGoodPos;
            _botState.consecutiveBadPos++;
            _botState.fallTicks = 0;
            return false;
        }
        // 不更新 lastKnownGoodPos，也不返回 false（再观察几帧）
    }
    else
    {
        _botState.fallTicks = 0;
    }

    // 4. 掉出地图: Z 过低
    if (pos.z < FALL_THROUGH_Z)
    {
        std::cerr << "[Position] " << _botState.name
                  << " Z轴异常低 (" << pos.z << " < " << FALL_THROUGH_Z
                  << "), 恢复到: (" << _botState.lastKnownGoodPos.x
                  << "," << _botState.lastKnownGoodPos.y
                  << "," << _botState.lastKnownGoodPos.z << ")\n";
        pos = _botState.lastKnownGoodPos;
        _botState.consecutiveBadPos++;
        _botState.fallTicks = 0;
        return false;
    }

    // 5. Z 轴过高
    if (pos.z > CEILING_Z)
    {
        std::cerr << "[Position] " << _botState.name
                  << " Z轴异常高 (" << pos.z << " > " << CEILING_Z << ")\n";
        pos = _botState.lastKnownGoodPos;
        _botState.consecutiveBadPos++;
        _botState.fallTicks = 0;
        return false;
    }

    // 6. 瞬移检测: 未被服务端传送但移动距离异常大
    float d = std::sqrt(
        (pos.x - _botState.lastKnownGoodPos.x) * (pos.x - _botState.lastKnownGoodPos.x) +
        (pos.y - _botState.lastKnownGoodPos.y) * (pos.y - _botState.lastKnownGoodPos.y) +
        (pos.z - _botState.lastKnownGoodPos.z) * (pos.z - _botState.lastKnownGoodPos.z)
    );

    if (!_botState.beenTeleported && d > MAX_TELEPORT_DIST)
    {
        std::cerr << "[Position] " << _botState.name
                  << " 检测到异常瞬移! dist=" << d
                  << " 从 (" << _botState.lastKnownGoodPos.x
                  << "," << _botState.lastKnownGoodPos.y
                  << "," << _botState.lastKnownGoodPos.z
                  << ") 到 (" << pos.x << "," << pos.y << "," << pos.z << ")"
                  << " — 恢复到安全位置\n";
        pos = _botState.lastKnownGoodPos;
        _botState.consecutiveBadPos++;
        _botState.fallTicks = 0;
        return false;
    }

    // 7. 卡住检测: 移动中但位置不变
    if (_botState.activity == BOT_ACTIVITY_MOVING && d < 0.05f)
    {
        _botState.stuckTicks++;
        if (_botState.stuckTicks > MAX_STUCK_TICKS)
        {
            std::cerr << "[Position] " << _botState.name
                      << " 卡住 " << _botState.stuckTicks << " ticks ("
                      << (_botState.stuckTicks * 0.2f) << "s)"
                      << " pos=(" << pos.x << "," << pos.y << "," << pos.z << ")"
                      << " — 轻微偏移尝试解脱\n";
            // 轻微偏移当前目标位置尝试摆脱卡住
            _botState.targetPos.x += (rand() % 10 - 5);
            _botState.targetPos.y += (rand() % 10 - 5);
            _botState.stuckTicks = 0;
        }
    }
    else
    {
        _botState.stuckTicks = 0;
    }

    // 位置合理 → 更新安全位置（只在非坠落状态下更新）
    if (d > 0.1f && _botState.fallTicks == 0)
    {
        _botState.lastKnownGoodPos = pos;
        _botState.consecutiveBadPos = 0;
    }
    _botState.beenTeleported = false; // 重置传送标志

    return true;
}

void WorldSocket::LogState(std::ostream& os) const
{
    os << "[Bot " << _botState.name << " Lv" << int(_botState.level)
       << "] HP:" << _botState.health << "/" << _botState.maxHealth
       << " map=" << int(_botState.mapId) << " zone=" << int(_botState.zoneId)
       << " pos:(" << _botState.pos.x << "," << _botState.pos.y << "," << _botState.pos.z << ")";
}

void WorldSocket::SetCharacterInfo(uint64 guid, std::string const& name,
    uint8 level, uint8 clazz, uint8 race)
{
    _botState.guid  = guid;
    _botState.name  = name;
    _botState.level = level;
    _botState.clazz = clazz;
    _botState.race  = race;
}

// ── 死亡流程 (Phase 1 stub) ──

void WorldSocket::OnDeathDetected()
{
    _botState.isDead = true;
    _botState.activity = BOT_ACTIVITY_DEAD;
}

bool WorldSocket::TickDeathRecovery() { return false; }
bool WorldSocket::SendRepopRequest()
{
    return SendPacket(Opcodes::CMSG_REPOP_REQUEST, {});
}
bool WorldSocket::SendReclaimCorpse()
{
    return SendPacket(Opcodes::CMSG_RECLAIM_CORPSE, {});
}
bool WorldSocket::SendSpiritHealerActivate()
{
    return SendPacket(Opcodes::CMSG_SPIRIT_HEALER_ACTIVATE, {});
}
bool WorldSocket::SendStandStateChange(uint8 state)
{
    std::vector<uint8> p(1, state);
    return SendPacket(Opcodes::CMSG_STANDSTATECHANGE, p);
}
