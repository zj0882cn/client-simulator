#include "wow_client.h"

namespace WoWClient
{
    // =========================================================================
    // WorldSocket implementations
    // =========================================================================

    WorldSocket::WorldSocket(const std::string& ip, uint16 port)
        : ip_(ip), port_(port), fd_(SOCKET_INVALID), encrypted_(false) {}

    WorldSocket::~WorldSocket() { Disconnect(); }

    bool WorldSocket::Connect() {
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ == SOCKET_INVALID) {
            std::cerr << "[World] socket() failed\n";
            return false;
        }

        struct hostent* he = gethostbyname(ip_.c_str());
        if (!he) {
            std::cerr << "[World] gethostbyname(" << ip_ << ") failed\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(fd_, FIONBIO, &mode);
#else
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
#endif

        int ret = ::connect(fd_, (struct sockaddr*)&addr, sizeof(addr));
        if (ret < 0) {
#ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                std::cerr << "[World] connect(" << ip_ << ":" << port_ << ") failed: " << SOCKET_ERROR_MSG() << "\n";
                CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
                return false;
            }
#else
            if (errno != EINPROGRESS) {
                std::cerr << "[World] connect(" << ip_ << ":" << port_ << ") failed: " << SOCKET_ERROR_MSG() << "\n";
                CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
                return false;
            }
#endif
        }

#ifdef _WIN32
        fd_set fdSet;
        FD_ZERO(&fdSet);
        FD_SET(fd_, &fdSet);
        struct timeval tvConnect{5, 0};
        if (select(0, nullptr, &fdSet, nullptr, &tvConnect) <= 0) {
            std::cerr << "[World] connect timeout\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        int soErr = 0;
        int len = sizeof(soErr);
        getsockopt(fd_, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
        if (soErr != 0) {
            std::cerr << "[World] connect error: " << soErr << "\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        mode = 0;
        ioctlsocket(fd_, FIONBIO, &mode);
#else
        struct pollfd pfd{fd_, POLLOUT, 0};
        if (poll(&pfd, 1, 5000) <= 0 || !(pfd.revents & POLLOUT)) {
            std::cerr << "[World] connect timeout\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        int soErr = 0;
        socklen_t len = sizeof(soErr);
        getsockopt(fd_, SOL_SOCKET, SO_ERROR, &soErr, &len);
        if (soErr != 0) {
            std::cerr << "[World] connect error: " << soErr << "\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);
#endif

        #ifdef _WIN32
        DWORD tv = 10000;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv{10, 0};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        encrypted_ = false;
        recvBuf_.clear();
        connClosed_ = false;
        std::cout << "[World] Connected to " << ip_ << ":" << port_ << "\n";
        return true;
    }

    void WorldSocket::Disconnect() {
        if (fd_ != SOCKET_INVALID) { CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID; }
        encrypted_ = false;
        recvBuf_.clear();
        connClosed_ = true;
    }

    bool WorldSocket::IsConnected() const { return fd_ != SOCKET_INVALID && !connClosed_; }

    void WorldSocket::SetUsername(const std::string& un) { username_ = un; }
    void WorldSocket::SetLogPrefix(const std::string& p) { logPrefix_ = p; }

    bool WorldSocket::RecvAuthChallenge() {
        uint16 cmd;
        std::vector<uint8> body;

        for (int attempt = 0; attempt < 5; ++attempt) {
            if (attempt > 0) {
                std::cerr << "[World] Retrying auth challenge (attempt " << (attempt + 1) << "/5)...\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd_, &fds);
            struct timeval tv{0, 500000};
            int ret = select(fd_ + 1, &fds, nullptr, nullptr, &tv);
            if (ret < 0) {
                std::cerr << "[World] select error: " << strerror(errno) << "\n";
                return false;
            }
            if (ret == 0) continue;

            if (RecvPacket(cmd, body)) {
                if (cmd == SMSG_AUTH_CHALLENGE) {
                    if (body.size() >= 8) memcpy(serverSeed_, body.data() + 4, 4);
                    randomBytes(clientSeed_, 4);
                    std::cout << "[World] Auth challenge received\n";
                    return true;
                }
                std::cerr << "[World] Unexpected packet cmd=0x" << std::hex << cmd << std::dec << " (expected SMSG_AUTH_CHALLENGE)\n";
                if (cmd == SMSG_AUTH_RESPONSE) {
                    std::cerr << "[World] Server sent auth response instead of challenge - possible rejection\n";
                    if (!body.empty()) {
                        std::cerr << "[World] Auth response code: " << (int)body[0] << "\n";
                    }
                    return false;
                }
            }
        }
        std::cerr << "[World] Failed to receive SMSG_AUTH_CHALLENGE after 5 attempts\n";
        return false;
    }

    bool WorldSocket::SendAuthSession(const AuthResult& auth, const std::string& username, uint8 realmId) {
        std::string user = username.empty() ? username_ : username;
        username_ = user;
        std::string normUser = toUpper(user);

        uint8 zero[4] = {0,0,0,0};
        uint8 digest[20];
        SHA_CTX sha;
        SHA1_Init(&sha);
        SHA1_Update(&sha, (unsigned char*)normUser.c_str(), normUser.size());
        SHA1_Update(&sha, zero, 4);
        SHA1_Update(&sha, clientSeed_, 4);
        SHA1_Update(&sha, serverSeed_, 4);
        SHA1_Update(&sha, auth.sessionKey, 40);
        SHA1_Final(digest, &sha);

        auto hexStr = [](const uint8* data, size_t len) -> std::string {
            std::string s;
            char buf[3];
            for (size_t i = 0; i < len; ++i) {
                snprintf(buf, sizeof(buf), "%02x", data[i]);
                s += buf;
            }
            return s;
        };
        std::cout << "[World] normUser: " << normUser << "\n";
        std::cout << "[World] clientSeed: " << hexStr(clientSeed_, 4) << "\n";
        std::cout << "[World] serverSeed: " << hexStr(serverSeed_, 4) << "\n";
        std::cout << "[World] sessionKey: " << hexStr(auth.sessionKey, 40) << "\n";
        std::cout << "[World] clientDigest: " << hexStr(digest, 20) << "\n";

        uint32 build = WOW_BUILD;
        uint32 serverId = 0;
        uint32 loginServerType = 0;
        uint32 regionId = 2;
        uint32 battlegroupId = 1;
        uint64 dosResponse = 0;

        std::vector<uint8> payload;
        auto pushU32 = [&](uint32 v) { uint8 b[4]; writeU32LE(b, v); payload.insert(payload.end(), b, b+4); };
        auto pushU64 = [&](uint64 v) { uint8 b[8]; writeU64LE(b, v); payload.insert(payload.end(), b, b+8); };

        pushU32(build);
        pushU32(serverId);
        payload.insert(payload.end(), normUser.begin(), normUser.end());
        payload.push_back(0);
        pushU32(loginServerType);
        payload.insert(payload.end(), clientSeed_, clientSeed_ + 4);
        pushU32(regionId);
        pushU32(battlegroupId);
        pushU32(realmId);
        pushU64(dosResponse);
        payload.insert(payload.end(), digest, digest + 20);

        // AddonInfo: 简化为 uncompressed_size=0，服务端 ReadAddonsInfo 直接 return
        // 这样无需发送复杂的压缩 addon 数据
        uint8 addonSizeBuf[4] = {0, 0, 0, 0};
        payload.insert(payload.end(), addonSizeBuf, addonSizeBuf + 4);

        srpSessionKey_.assign(auth.sessionKey, auth.sessionKey + 40);
        sessionKeyDigest_.assign(digest, digest + 20);

        std::cerr << "[World] CMSG_AUTH_SESSION (" << payload.size() << " bytes)\n";

        if (!SendPacket(CMSG_AUTH_SESSION, payload, /*skipEncrypt=*/true)) return false;
        std::cout << "[World] Sent CMSG_AUTH_SESSION user=" << normUser << " realmId=" << (int)realmId << " (unencrypted)\n";

        return true;
    }

    bool WorldSocket::WaitAuthResponse(uint8& result, uint32& billingFlags) {
        result = 255; billingFlags = 0;

        // 与旧代码一致: 读取 4 字节服务器响应头
        uint8 rawHeader[4];
        if (!ReadExact(rawHeader, 4)) {
            std::cerr << "[World] Failed to read auth response header\n";
            return false;
        }

        std::cerr << "[World] WaitAuthResponse: raw 4 bytes: "
                  << std::hex << int(rawHeader[0]) << " " << int(rawHeader[1]) << " "
                  << int(rawHeader[2]) << " " << int(rawHeader[3]) << std::dec << "\n";

        uint16 cmd;
        std::vector<uint8> body;

        // 阶段 1: 按未加密头解析
        {
            uint8 hdr[4];
            memcpy(hdr, rawHeader, 4);
            uint16 sizeRaw = readU16BE(hdr);
            cmd = uint16(hdr[2]) | (uint16(hdr[3]) << 8);

            std::cerr << "[World] WaitAuthResponse: unencrypted try: cmd=0x" << std::hex << cmd << std::dec << " size=" << sizeRaw << "\n";

            if (cmd == SMSG_AUTH_RESPONSE) {
                size_t bodyLen = (sizeRaw >= sizeof(uint16)) ? (sizeRaw - sizeof(uint16)) : 0;
                if (bodyLen > 0) {
                    body.resize(bodyLen);
                    if (!ReadExact(body.data(), bodyLen)) return false;
                }
                result = body.empty() ? AUTH_OK : body[0];
                std::cerr << "[World] WaitAuthResponse: auth response=" << (int)result
                          << " (" << authResponseName(result) << ") (unencrypted)\n";
                if (isAuthResponseOk(result))
                    InitEncryption();
                return true;
            }
        }

        // 阶段 2: 初始化加密,循环读取直到收到 SMSG_AUTH_RESPONSE
        // 认证成功后服务器可能先发送 SMSG_WARDEN_DATA 等加密包,
        // AUTH_RESPONSE 在异步数据库查询完成后才发送,因此需要跳过非认证包继续等待。
        InitEncryption();

        uint8 hdr[4];
        memcpy(hdr, rawHeader, 4);
        recvDecrypt_.UpdateData(hdr, 4);
        uint16 sizeRaw = readU16BE(hdr);
        cmd = uint16(hdr[2]) | (uint16(hdr[3]) << 8);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (;;) {
            std::cerr << "[World] WaitAuthResponse: decrypted try: cmd=0x" << std::hex << cmd << std::dec << " size=" << sizeRaw << "\n";

            if (cmd == SMSG_AUTH_RESPONSE) {
                size_t bodyLen = (sizeRaw >= sizeof(uint16)) ? (sizeRaw - sizeof(uint16)) : 0;
                if (bodyLen > 0) {
                    body.resize(bodyLen);
                    if (!ReadExact(body.data(), bodyLen)) return false;
                }
                result = body.empty() ? AUTH_OK : body[0];
                std::cerr << "[World] WaitAuthResponse: auth response=" << (int)result
                          << " (" << authResponseName(result) << ") (encrypted)\n";
                return true;
            }

            // 跳过非 AUTH_RESPONSE 包(如 SMSG_WARDEN_DATA): 读取并丢弃 body
            std::cerr << "[World] WaitAuthResponse: skipping packet cmd=0x"
                      << std::hex << cmd << std::dec << " (size=" << sizeRaw << ")\n";
            if (sizeRaw >= sizeof(uint16)) {
                size_t bodyLen = sizeRaw - sizeof(uint16);
                std::vector<uint8> skipBody(bodyLen);
                if (bodyLen > 0 && !ReadExact(skipBody.data(), bodyLen)) return false;
            }

            // 读取下一个包头
            uint8 nextHdr[4];
            if (!ReadExact(nextHdr, 4)) return false;
            recvDecrypt_.UpdateData(nextHdr, 4);
            sizeRaw = readU16BE(nextHdr);
            cmd = uint16(nextHdr[2]) | (uint16(nextHdr[3]) << 8);

            if (std::chrono::steady_clock::now() > deadline) {
                std::cerr << "[World] WaitAuthResponse: timed out waiting for SMSG_AUTH_RESPONSE\n";
                return false;
            }
        }
    }

    bool WorldSocket::RecvCharacterList(std::vector<CharacterInfo>& chars) {
        chars.clear();

        // Drain any pending packets
        {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
            while (std::chrono::steady_clock::now() < deadline) {
                uint16 cmd;
                std::vector<uint8> body;
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd_, &fds);
                struct timeval tv{0, 50000};
                int ret = select(fd_ + 1, &fds, nullptr, nullptr, &tv);
                if (ret <= 0) break;
                if (!RecvPacket(cmd, body)) break;
                std::cerr << "[World] Drain: got cmd=0x" << std::hex << cmd << std::dec << " (" << body.size() << " bytes), continuing drain...\n";
            }
        }

        SendPacket(CMSG_CHAR_ENUM, {});

        uint16 cmd;
        std::vector<uint8> body;
        for (int i = 0; i < 5; ++i) {
            if (!RecvPacket(cmd, body)) return false;
            if (cmd == SMSG_CHAR_ENUM) break;
        }

        if (cmd != SMSG_CHAR_ENUM) {
            std::cerr << "[World] Expected SMSG_CHAR_ENUM, got 0x" << std::hex << cmd << std::dec << "\n";
            return false;
        }

        if (body.empty()) return false;
        uint8 count = body[0];
        size_t pos = 1;

        for (uint8 i = 0; i < count; ++i) {
            CharacterInfo ch;

            ch.guid = readU64LE(body.data() + pos);
            pos += 8;

            size_t nameEnd = body.size();
            for (size_t j = pos; j < body.size(); ++j) {
                if (body[j] == 0) { nameEnd = j; break; }
            }
            ch.name.assign((char*)body.data() + pos, nameEnd - pos);
            pos = nameEnd + 1;

            if (pos + 1 > body.size()) break;
            ch.race = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.clazz = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.gender = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.skin = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.face = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.hairStyle = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.hairColor = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.facialHair = body[pos++];
            if (pos + 1 > body.size()) break;
            ch.level = body[pos++];
            if (pos + 4 > body.size()) break;
            ch.zone = readU32LE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.mapId = readU32LE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.pos.x = readFloatLE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.pos.y = readFloatLE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.pos.z = readFloatLE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.guildId = readU32LE(body.data() + pos); pos += 4;
            if (pos + 4 > body.size()) break;
            ch.flags = readU32LE(body.data() + pos); pos += 4;

            if (pos + 224 > body.size()) break;
            pos += 224;

            chars.push_back(ch);
            std::cout << "  Char: " << ch.name << " Lv" << (int)ch.level
                      << " Race:" << (int)ch.race << " Class:" << (int)ch.clazz
                      << " Map:" << ch.mapId << " GUID:" << ch.guid << "\n";
        }

        return true;
    }

    bool WorldSocket::LoginCharacter(uint64 guid) {
        uint8 guidBytes[8];
        writeU64LE(guidBytes, guid);
        std::vector<uint8> payload(guidBytes, guidBytes + 8);
        SendPacket(CMSG_PLAYER_LOGIN, payload);
        std::cout << "[World] Sent CMSG_PLAYER_LOGIN, guid=" << guid << "\n";
        return true;
    }

    bool WorldSocket::WaitWorldEnter() {
        uint16 cmd;
        std::vector<uint8> body;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (std::chrono::steady_clock::now() < deadline) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd_, &fds);
            struct timeval tv{0, 50000};
            int ret = select(fd_ + 1, &fds, nullptr, nullptr, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                std::cerr << "[World] WaitWorldEnter: select error: " << strerror(errno) << "\n";
                return false;
            }
            if (ret == 0) continue;

            if (!RecvPacket(cmd, body)) continue;

            if (cmd == SMSG_LOGIN_VERIFY_WORLD) {
                std::cout << "[World] Received SMSG_LOGIN_VERIFY_WORLD - entered world!\n";
                return true;
            }
            if (cmd == SMSG_NEW_WORLD || cmd == SMSG_TRANSFER_PENDING) {
                std::cout << "[World] Received world transition opcode: 0x" << std::hex << cmd << std::dec << "\n";
            }
            if (cmd == SMSG_LOGOUT_COMPLETE) {
                std::cerr << "[World] Received SMSG_LOGOUT_COMPLETE - login rejected\n";
                return false;
            }
        }

        std::cerr << "[World] World enter wait timed out (no SMSG_LOGIN_VERIFY_WORLD received)\n";
        return false;
    }

    bool WorldSocket::SendActiveMover(uint64 guid) {
        uint8 guidBytes[8];
        writeU64LE(guidBytes, guid);
        std::vector<uint8> payload(guidBytes, guidBytes + 8);
        SendPacket(CMSG_SET_ACTIVE_MOVER, payload);
        std::cout << "[World] Sent CMSG_SET_ACTIVE_MOVER, guid=" << guid << "\n";
        return true;
    }

    bool WorldSocket::SendPing(uint32 seq) {
        // CMSG_PING 格式: uint32 ping(序号) + uint32 latency(延迟)
        // 服务器 HandlePing 读取 ping + latency 两个 uint32, 缺失会导致解析异常
        std::vector<uint8> payload(8);
        writeU32LE(payload.data(), seq);
        writeU32LE(payload.data() + 4, 0);  // latency
        if (!SendPacket(CMSG_PING, payload)) return false;

        // 注意: 这里【只发送, 不等待 PONG】。
        // 之前在此循环等 PONG 会同步消费主循环的收包, 位置更新风暴(SMSG_UPDATE_OBJECT)
        // 会挤占/淹没 PONG, 甚至吞掉 SMSG_TIME_SYNC_REQ, 导致 ping 超时误判掉线 (P-013)。
        // PONG 现在由主循环收包处检测 (main.cpp: cmd == SMSG_PONG)。
        return true;
    }

    // 响应服务器的 SMSG_TIME_SYNC_REQ: 发送 CMSG_TIME_SYNC_RESP
    // 格式: uint32 counter + uint32 clientTimestamp(客户端毫秒时间戳)
    // 服务器每 5~10 秒发送一次, 若长时间不响应可能被视为异常连接
    bool WorldSocket::SendTimeSyncResponse(uint32 counter) {
        std::vector<uint8> payload(8);
        writeU32LE(payload.data(), counter);
        uint32 clientTime = uint32(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        writeU32LE(payload.data() + 4, clientTime);
        if (!SendPacket(CMSG_TIME_SYNC_RESP, payload)) return false;
        std::cout << (logPrefix_.empty() ? std::string("[World]") : logPrefix_) << " TimeSync response sent (counter=" << counter << ")\n";
        return true;
    }

    void WorldSocket::SetMover(uint64 guid, const Vec3& pos, float orientation) {
        moverGuid_ = guid;
        moverPos_ = pos;
        moverO_ = orientation;
    }

    // 发送 CMSG_MOVE_HEARTBEAT 移动心跳包
    // 正常客户端即使角色静止也会周期发送移动包, 服务器据此判断客户端存活。
    // 模拟器若不发送, 服务器可能判定角色卡死/无响应而踢出。
    // 格式: uint64 guid + MovementInfo{ flags=0, time, x,y,z,o, fallTime=0 }
    bool WorldSocket::SendMoveHeartbeat() {
        if (moverGuid_ == 0) {
            std::cerr << "[World] SendMoveHeartbeat: moverGuid_ == 0\n";
            return false;
        }

        std::vector<uint8> payload;
        auto pushU32 = [&](uint32 v) { uint8 b[4]; writeU32LE(b, v); payload.insert(payload.end(), b, b+4); };
        auto pushU16 = [&](uint16 v) { uint8 b[2]; writeU16LE(b, v); payload.insert(payload.end(), b, b+2); };
        auto pushF32 = [&](float f) { uint8 b[4]; writeU32LE(b, *reinterpret_cast<uint32*>(&f)); payload.insert(payload.end(), b, b+4); };

        // 3.3.5 movement opcode 的 guid 用 packed 格式（服务器 readPackGUID）：
        // 首字节 guidmark（bit i=1 表示第 i 字节存在）+ 按序输出非零字节。
        // 例如 guid=17(0x11) → [0x01][0x11]；旧版 writeU64LE 原始 8 字节
        // 会让 readPackGUID 解析错乱 → 位置永不更新。
        uint64 raw = moverGuid_;
        uint8 guidmark = 0;
        uint8 gbytes[8];
        for (int i = 0; i < 8; ++i) {
            gbytes[i] = uint8((raw >> (i * 8)) & 0xFF);
            if (gbytes[i]) guidmark |= (uint8(1) << i);
        }
        payload.push_back(guidmark);
        for (int i = 0; i < 8; ++i)
            if (gbytes[i]) payload.push_back(gbytes[i]);

        pushU32(0);  // MOVEMENTFLAG_NONE (flags)
        pushU16(0);  // flags2 —— 服务器 MovementInfo::flags2 是 uint16（2 字节）！
                     // 缺了/多字节都会让服务器 ReadMovementInfo 按
                     // flags(4)+flags2(2)+time(4) 读错位 → time/pos 错乱 → 位置不更新。
        uint32 moveTime = uint32(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() & 0xFFFFFFFF);
        pushU32(moveTime);
        pushF32(moverPos_.x);
        pushF32(moverPos_.y);
        pushF32(moverPos_.z);
        pushF32(moverO_);
        pushU32(0);  // fallTime

        if (!SendPacket(CMSG_MOVE_HEARTBEAT, payload)) {
            std::cerr << "[World] SendMoveHeartbeat: SendPacket failed\n";
            return false;
        }
        return true;
    }

    bool WorldSocket::SendChatMessage(const std::string& msg, uint8 channel) {
        std::vector<uint8> payload;
        auto pushU32 = [&](uint32 v) { uint8 b[4]; writeU32LE(b, v); payload.insert(payload.end(), b, b+4); };

        if (channel == 1) {
            pushU32(14);   // CHAT_MSG_CHANNEL
            pushU32(7);    // LANG_COMMON (频道消息用通用语, 避免 LANG_UNIVERSAL=0 被服务器拒)
            const char* channelName = "General";
            payload.insert(payload.end(), channelName, channelName + strlen(channelName) + 1);
        } else {
            pushU32(0);   // CHAT_MSG_SAY
            // WoW 语言枚举: LANG_UNIVERSAL=0, LANG_COMMON=7
            // 发 0(universal) 会被服务器判为 hack-attempt 拒绝, 必须用 7(LANG_COMMON)
            pushU32(7);
        }
        payload.insert(payload.end(), msg.begin(), msg.end());
        payload.push_back(0);
        if (!SendPacket(CMSG_MESSAGECHAT, payload)) return false;
        std::cout << "[ChatDBG] type=" << (int)readU32LE(payload.data())
                  << " lang=" << (int)readU32LE(payload.data() + 4)
                  << " msg='" << msg << "'\n" << std::flush;
        std::cout << "[ChatHex] ";
        for (uint8 b : payload) std::cout << std::hex << int(b) << " ";
        std::cout << std::dec << "\n" << std::flush;
        std::cout << "[World] Chat sent: " << msg << "\n";
        return true;
    }

    bool WorldSocket::HasPendingData(uint32 timeoutMs) {
        if (fd_ == SOCKET_INVALID) return false;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd_, &fds);
        struct timeval tv{0, (long)(timeoutMs * 1000)};
        int ret = select((int)fd_ + 1, &fds, nullptr, nullptr, timeoutMs > 0 ? &tv : nullptr);
        return ret > 0;
    }

    bool WorldSocket::RecvPacketNonBlocking(uint16& cmd, std::vector<uint8>& payload) {
        // 1. 非阻塞读取所有可用数据到接收缓冲区
        uint8 tmp[4096];
        for (;;) {
#ifdef _WIN32
            int flags = 0;
#else
            int flags = MSG_DONTWAIT;
#endif
            ssize_t n = ::recv(fd_, tmp, sizeof(tmp), flags);
            if (n > 0) {
                recvBuf_.insert(recvBuf_.end(), tmp, tmp + n);
            } else if (n == 0) {
                // 服务器关闭连接
                connClosed_ = true;
                return false;
            } else {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) break;
                if (err == WSAEINTR) continue;
#else
                int err = errno;
                if (err == EAGAIN || err == EWOULDBLOCK) break;
                if (err == EINTR) continue;
#endif
                return false;
            }
        }

        // 2. 检查缓冲区中是否有完整包 (至少 4 字节 header)
        if (recvBuf_.size() < 4) return false;

        // 3. 解密 header (WoW 只加密 header 4 字节)
        uint8 hdr[4];
        memcpy(hdr, recvBuf_.data(), 4);
        if (encrypted_) recvDecrypt_.UpdateData(hdr, 4);

        uint16 size = readU16BE(hdr);
        cmd = uint16(hdr[2]) | (uint16(hdr[3]) << 8);
        if (size < sizeof(uint16)) return false;

        // 4. 包总长 = header(4) + body(size-2), 检查是否完整
        size_t totalLen = 4 + (size - sizeof(uint16));
        if (recvBuf_.size() < totalLen) return false;  // 包不完整, 等待更多数据

        // 5. 解析 payload (body 为明文)
        size_t bodyLen = size - sizeof(uint16);
        payload.assign(recvBuf_.begin() + 4, recvBuf_.begin() + 4 + bodyLen);

        // 6. 从缓冲区移除已消费的包
        recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + totalLen);

        return true;
    }

    // ---- Private implementations ----

    bool WorldSocket::SendPacket(uint16 cmd, const std::vector<uint8>& payload, bool skipEncrypt) {
        // Client→Server header (6 bytes): uint16 size(BE) + uint32 cmd(LE)
        uint16 payloadSize = uint16(payload.size());
        uint8 header[6];
        header[0] = uint8((sizeof(uint32) + payloadSize) >> 8);
        header[1] = uint8(sizeof(uint32) + payloadSize);
        header[2] = uint8(cmd);
        header[3] = uint8(cmd >> 8);
        header[4] = 0;
        header[5] = 0;

        if (encrypted_ && !skipEncrypt) {
            uint8 cryptedHeader[6];
            memcpy(cryptedHeader, header, 6);
            sendEncrypt_.UpdateData(cryptedHeader, 6);
            if (!WriteAll(cryptedHeader, 6)) return false;
        } else {
            if (!WriteAll(header, 6)) return false;
        }

        if (!payload.empty()) {
            if (!WriteAll(payload.data(), payload.size())) return false;
        }
        return true;
    }

    bool WorldSocket::RecvPacket(uint16& cmd, std::vector<uint8>& payload) {
        // Server→Client header: 固定 4 字节
        uint8 header[4];
        if (!ReadExact(header, 4)) {
            std::cerr << "[World] RecvPacket: ReadExact failed for header (4 bytes)\n";
            return false;
        }

        if (encrypted_) {
            recvDecrypt_.UpdateData(header, 4);
        }

        auto hexStr = [](const uint8* d, size_t l) -> std::string {
            std::string s; char b[4];
            for (size_t i = 0; i < l; ++i) { snprintf(b, sizeof(b), "%02x", d[i]); s += b; }
            return s;
        };

        uint16 size = readU16BE(header);
        cmd = uint16(header[2]) | (uint16(header[3]) << 8);

        std::cerr << "[World] RecvPacket: hdr (4 bytes): " << hexStr(header, 4)
                  << " cmd=0x" << std::hex << cmd << std::dec << " size=" << size << "\n";

        if (size < sizeof(uint16)) {
            std::cerr << "[World] RecvPacket: invalid size: " << size << "\n";
            return false;
        }

        size_t payloadLen = size - sizeof(uint16);
        if (payloadLen == 0) {
            payload.clear();
            return true;
        }

        payload.resize(payloadLen);
        if (!ReadExact(payload.data(), payloadLen)) {
            std::cerr << "[World] RecvPacket: ReadExact failed for payload (len=" << payloadLen << ", rawSize=" << size << ")\n";
            return false;
        }
        return true;
    }

    bool WorldSocket::ReadExact(void* buf, size_t len) {
        size_t received = 0;
        int blockWaitCount = 0;
        auto readStart = std::chrono::steady_clock::now();
        while (received < len) {
            // 总超时保护: 单个包读取超过 3 秒则放弃, 避免无限阻塞主循环
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - readStart).count() > 3000) {
                std::cerr << "[World] ReadExact: total 3s timeout reading " << len
                          << " bytes, got " << received << "\n";
                return false;
            }
            ssize_t n = ::recv(fd_, (char*)buf + received, len - received, 0);
            if (n < 0) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) {
#else
                int err = errno;
                if (err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT) {
#endif
                    // 短等待 100ms 重试, 避免长时间阻塞主循环导致无法发送心跳/Ping
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(fd_, &fds);
                    struct timeval tv{0, 100000};
                    int ret = select((int)fd_ + 1, &fds, nullptr, nullptr, &tv);
                    if (ret <= 0) {
                        if (ret == 0) {
                            ++blockWaitCount;
                            if (blockWaitCount <= 3)
                                std::cerr << "[World] ReadExact: waiting for data (" << received << "/" << len << " bytes) block#" << blockWaitCount << "\n";
                        } else {
                            std::cerr << "[World] ReadExact: select error: " << SOCKET_ERROR_MSG() << "\n";
                        }
                        return false;
                    }
                    continue;
                }
                std::cerr << "[World] ReadExact: recv error: " << SOCKET_ERROR_MSG() << "\n";
                return false;
            }
            if (n == 0) {
                std::cerr << "[World] ReadExact: connection closed by peer (" << received << "/" << len << " bytes)\n";
                return false;
            }
            received += n;
        }
        return true;
    }

    bool WorldSocket::WriteAll(const void* buf, size_t len) {
        size_t sent = 0;
        while (sent < len) {
#ifdef _WIN32
            ssize_t n = ::send(fd_, (const char*)buf + sent, len - sent, 0);
#else
            ssize_t n = ::send(fd_, (const char*)buf + sent, len - sent, MSG_NOSIGNAL);
#endif
            if (n <= 0) {
#ifdef _WIN32
                std::cerr << "[World] send failed: " << SOCKET_ERROR_MSG() << "\n";
#else
                std::cerr << "[World] send failed: " << strerror(errno) << "\n";
#endif
                return false;
            }
            sent += n;
        }
        return true;
    }

    void WorldSocket::InitEncryption() {
        uint8 serverEncKey[16] = {
            0xCC,0x98,0xAE,0x04,0xE8,0x97,0xEA,0xCA,
            0x12,0xDD,0xC0,0x93,0x42,0x91,0x53,0x57
        };
        uint8 recvKey[20];
        HMAC_CTX* hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, serverEncKey, 16, EVP_sha1(), nullptr);
        HMAC_Update(hctx, srpSessionKey_.data(), srpSessionKey_.size());
        unsigned int hlen = 20;
        HMAC_Final(hctx, recvKey, &hlen);
        HMAC_CTX_free(hctx);
        recvDecrypt_.Init(recvKey, 20);

        uint8 serverDecKey[16] = {
            0xC2,0xB3,0x72,0x3C,0xC6,0xAE,0xD9,0xB5,
            0x34,0x3C,0x53,0xEE,0x2F,0x43,0x67,0xCE
        };
        uint8 sendKey[20];
        hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, serverDecKey, 16, EVP_sha1(), nullptr);
        HMAC_Update(hctx, srpSessionKey_.data(), srpSessionKey_.size());
        hlen = 20;
        HMAC_Final(hctx, sendKey, &hlen);
        HMAC_CTX_free(hctx);
        sendEncrypt_.Init(sendKey, 20);

        uint8 dropBuf[1024] = {0};
        recvDecrypt_.UpdateData(dropBuf, sizeof(dropBuf));
        sendEncrypt_.UpdateData(dropBuf, sizeof(dropBuf));

        encrypted_ = true;
        std::cout << "[World] Encryption initialized (ARC4-drop1024 synced)\n";
    }

} // namespace WoWClient
