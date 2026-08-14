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
        // Windows: use select for non-blocking connect
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
        // Windows: use select to wait for connection
        fd_set fdSet;
        FD_ZERO(&fdSet);
        FD_SET(fd_, &fdSet);
        struct timeval tvConnect{5, 0};
        if (select(0, nullptr, &fdSet, nullptr, &tvConnect) <= 0) {
            std::cerr << "[World] connect timeout\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        // Check for connection error
        int soErr = 0;
        int len = sizeof(soErr);
        getsockopt(fd_, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
        if (soErr != 0) {
            std::cerr << "[World] connect error: " << soErr << "\n";
            CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID;
            return false;
        }

        // Set back to blocking mode
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

        struct timeval tv{10, 0};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        encrypted_ = false;
        std::cout << "[World] Connected to " << ip_ << ":" << port_ << "\n";
        return true;
    }

    void WorldSocket::Disconnect() {
        if (fd_ != SOCKET_INVALID) { CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID; }
        encrypted_ = false;
    }

    bool WorldSocket::IsConnected() const { return fd_ != SOCKET_INVALID; }

    void WorldSocket::SetUsername(const std::string& un) { username_ = un; }

    bool WorldSocket::RecvAuthChallenge() {
        uint16 cmd;
        std::vector<uint8> body;
        if (!RecvPacket(cmd, body) || cmd != SMSG_AUTH_CHALLENGE) {
            std::cerr << "[World] Expected SMSG_AUTH_CHALLENGE, got 0x" << std::hex << cmd << std::dec << "\n";
            return false;
        }
        if (body.size() >= 8) memcpy(serverSeed_, body.data() + 4, 4);
        randomBytes(clientSeed_, 4);
        std::cout << "[World] Auth challenge received\n";
        return true;
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
        std::cout << "[World] normUser: " << normUser << "\n";
        std::cout << "[World] clientSeed: " << hexStr(clientSeed_, 4) << "\n";
        std::cout << "[World] serverSeed: " << hexStr(serverSeed_, 4) << "\n";
        std::cout << "[World] sessionKey: " << hexStr(auth.sessionKey, 40) << "\n";
        std::cout << "[World] clientDigest: " << hexStr(digest, 20) << "\n";

        uint32 build = WOW_BUILD;
        uint32 serverId = 0;
        uint32 loginServerType = 0;
        uint32 clientSeedVal = readU32LE(clientSeed_);
        uint32 regionId = 2;
        uint32 battlegroupId = 1;
        uint64 dosResponse = 0;

        std::vector<uint8> payload;
        payload.reserve(40 + normUser.size());

        auto pushU32 = [&](uint32 v) { uint8 b[4]; writeU32LE(b, v); payload.insert(payload.end(), b, b+4); };
        auto pushU64 = [&](uint64 v) { uint8 b[8]; writeU64LE(b, v); payload.insert(payload.end(), b, b+8); };

        pushU32(build);
        pushU32(serverId);
        // WoW 3.3.5 format: account is null-terminated string
        payload.insert(payload.end(), normUser.begin(), normUser.end());
        payload.push_back(0);  // null terminator
        pushU32(loginServerType);
        payload.insert(payload.end(), clientSeed_, clientSeed_ + 4);
        pushU32(regionId);
        pushU32(battlegroupId);
        pushU32(realmId);
        pushU64(dosResponse);
        payload.insert(payload.end(), digest, digest + 20);

        // AddonInfo: WoW 3.3.5 uses zlib-compressed addon list
        // The server reads: [uint32 compressed_size][compressed_data]
        // We build uncompressed addon data, compress it, then prepend compressed_size.
        std::vector<uint8> addonRaw;
        auto pushAddonStr = [&](const std::string& s) {
            addonRaw.insert(addonRaw.end(), s.begin(), s.end());
            addonRaw.push_back(0);  // null terminator
        };
        auto pushAddonU32 = [&](uint32 v) {
            uint8 b[4]; writeU32LE(b, v);
            addonRaw.insert(addonRaw.end(), b, b+4);
        };
        auto pushAddonU8 = [&](uint8 v) { addonRaw.push_back(v); };

        uint32 addonCount = 1;
        pushAddonU32(addonCount);
        // Addon entry: [name\0][enabled:1][crc:4][unk1:4]
        pushAddonStr("BlizzardInterface");  // addon name
        pushAddonU8(1);   // enabled
        pushAddonU32(0);  // crc
        pushAddonU32(0);  // unk1
        // After all addon entries: [currentTime:4]
        pushAddonU32(0);  // currentTime (server reads this after parsing all addons)

        // zlib-compress the addon data
        uLongf compressedSize = compressBound(addonRaw.size());
        std::vector<uint8> addonCompressed(compressedSize);
        int rc = compress2(addonCompressed.data(), &compressedSize,
                           addonRaw.data(), addonRaw.size(), Z_DEFAULT_COMPRESSION);
        if (rc != Z_OK) {
            std::cerr << "[World] Addon compression failed: " << rc << "\n";
        } else {
            addonCompressed.resize(compressedSize);
            std::cerr << "[World] Addon: raw=" << addonRaw.size() << " compressed=" << compressedSize << "\n";
        }

        // Server format: [uint32 uncompressed_size][compressed_data]
        // NOTE: server reads the first uint32 as the UNCOMPRESSED size for uncompress()
        pushU32((uint32)addonRaw.size());
        payload.insert(payload.end(), addonCompressed.begin(), addonCompressed.end());

        srpSessionKey_.assign(auth.sessionKey, auth.sessionKey + 40);
        sessionKeyDigest_.assign(digest, digest + 20);

        // Do NOT encrypt CMSG_AUTH_SESSION: server initializes _authCrypt AFTER
        // processing this packet, so it cannot decrypt it.
        std::cerr << "[World] CMSG_AUTH_SESSION (" << payload.size() << " bytes)\n";

        if (!SendPacket(CMSG_AUTH_SESSION, payload, /*skipEncrypt=*/true)) return false;
        std::cout << "[World] Sent CMSG_AUTH_SESSION user=" << normUser << " realmId=" << (int)realmId << " (unencrypted)\n";

        // Read SMSG_AUTH_RESPONSE (unencrypted) before initializing our cipher.
        return true;
    }

    bool WorldSocket::WaitAuthResponse(uint8& result, uint32& billingFlags) {
        result = 255; billingFlags = 0;

        // Server sends SMSG_AUTH_RESPONSE unencrypted BEFORE initializing _authCrypt.
        // We must read it unencrypted here. Use a polling loop since the server
        // may still be flushing when we try to read.
        uint8 rawHeader[4];
        size_t totalRead = 0;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (totalRead < 4 && std::chrono::steady_clock::now() < deadline) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd_, &fds);
            struct timeval tv{0, 100000}; // 100ms
            int ret = select(fd_ + 1, &fds, nullptr, nullptr, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                std::cerr << "[World] WaitAuthResponse: select error: " << strerror(errno) << "\n";
                return false;
            }
            if (ret == 0) continue;

            ssize_t n = ::recv(fd_, (char*)rawHeader + totalRead, 4 - totalRead, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EINTR)
                    continue;
                std::cerr << "[World] WaitAuthResponse: recv error: " << strerror(errno) << "\n";
                return false;
            }
            if (n == 0) {
                std::cerr << "[World] WaitAuthResponse: connection closed by peer\n";
                return false;
            }
            totalRead += n;
        }
        if (totalRead < 4) {
            std::cerr << "[World] WaitAuthResponse: timeout or partial header (" << totalRead << "/4 bytes)\n";
            return false;
        }
        // NO decryption - response is unencrypted

        uint16 rawSize = (uint16(rawHeader[0]) << 8) | uint16(rawHeader[1]);
        uint16 cmd = uint16(rawHeader[2]) | (uint16(rawHeader[3]) << 8);
        uint16 size = (rawSize >= 2) ? (rawSize - 2) : 0;

        std::cerr << "[World] WaitAuthResponse: rawSize=" << rawSize << " cmd=0x" << std::hex << cmd << std::dec << " size=" << size << "\n";

        if (cmd == SMSG_AUTH_RESPONSE) {
            if (size > 0) {
                std::vector<uint8> body(size);
                if (!ReadExact(body.data(), size)) return false;
                result = body.empty() ? 0 : body[0];
            }
            // Server enables _authCrypt AFTER sending this unencrypted response,
            // so we must initialize our cipher NOW to match server's state for
            // subsequent encrypted exchanges (CMSG_CHAR_ENUM, etc.).
            InitEncryption();
            return true;
        }

        std::cerr << "[World] Expected SMSG_AUTH_RESPONSE, got cmd=0x" << std::hex << cmd << std::dec << "\n";
        return false;
    }

    bool WorldSocket::RecvCharacterList(std::vector<CharacterInfo>& chars) {
        chars.clear();

        // Drain any pending packets (e.g. SMSG_ADDON_INFO) that were queued
        // before we sent CMSG_CHAR_ENUM. Use a short non-blocking loop.
        {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
            while (std::chrono::steady_clock::now() < deadline) {
                uint16 cmd;
                std::vector<uint8> body;
                // Try non-blocking read
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd_, &fds);
                struct timeval tv{0, 50000}; // 50ms
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

            // ObjectGuid is serialized as raw 8-byte uint64 (not packed)
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

            // Skip remaining fields to reach the next character:
            //   customizeFlags (uint32=4) + firstLogin (uint8=1)
            //   petDisplayId (uint32=4) + petLevel (uint32=4) + petFamily (uint32=4)
            //   Equipment cache: INVENTORY_SLOT_BAG_END(23) slots * (uint32+uint8+uint32=9 bytes)
            //   Total = 4 + 1 + 4 + 4 + 4 + 23*9 = 224 bytes
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
        // Server expects ObjectGuid as raw 8-byte uint64 (same as serialization)
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
        std::vector<uint8> payload(4);
        writeU32LE(payload.data(), seq);
        if (!SendPacket(CMSG_PING, payload)) return false;

        uint16 cmd;
        std::vector<uint8> body;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (RecvPacket(cmd, body)) {
                if (cmd == SMSG_PONG) return true;
            }
        }
        return false;
    }

    bool WorldSocket::SendChatMessage(const std::string& msg, uint8 channel) {
        // WoW 3.3.5 CMSG_MESSAGECHAT format:
        //   For SAY (type=0): [type:uint32][lang:uint32][message\0]
        //   For CHANNEL (type=14): [type:uint32][lang:uint32][channelName\0][message\0]
        // channel=0 -> SAY (type=0, lang=7=LANG_COMMON)
        // channel=1 -> CHANNEL (type=14, lang=0)
        std::vector<uint8> payload;
        auto pushU32 = [&](uint32 v) { uint8 b[4]; writeU32LE(b, v); payload.insert(payload.end(), b, b+4); };

        if (channel == 1) {
            // Channel chat
            pushU32(14);  // CHAT_MSG_CHANNEL
            pushU32(0);   // lang (ignored for channel)
            const char* channelName = "General";
            payload.insert(payload.end(), channelName, channelName + strlen(channelName) + 1);
        } else {
            // Say chat
            pushU32(0);   // CHAT_MSG_SAY
            pushU32(7);   // LANG_COMMON
        }
        payload.insert(payload.end(), msg.begin(), msg.end());
        payload.push_back(0);
        if (!SendPacket(CMSG_MESSAGECHAT, payload)) return false;
        std::cout << "[World] Chat sent: " << msg << "\n";
        return true;
    }

    bool WorldSocket::HasPendingData(uint32 timeoutMs) {
        if (fd_ < 0) return false;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd_, &fds);
        struct timeval tv{0, (long)(timeoutMs * 1000)};
        int ret = select(fd_ + 1, &fds, nullptr, nullptr, timeoutMs > 0 ? &tv : nullptr);
        return ret > 0;
    }

    bool WorldSocket::RecvPacketNonBlocking(uint16& cmd, std::vector<uint8>& payload) {
        if (!HasPendingData(0)) return false;
        return RecvPacket(cmd, payload);
    }

    // ---- Private implementations ----

    bool WorldSocket::SendPacket(uint16 cmd, const std::vector<uint8>& payload, bool skipEncrypt) {
        // AzerothCore ClientPktHeader wire format (6 bytes):
        //   uint16 size  = payload_size + 4  (BIG-endian on wire, server reverses)
        //   uint32 cmd   = opcode            (LITTLE-endian on wire)
        // Server does: EndianConvertReverse(size) -> swaps bytes on LE host
        //              EndianConvert(cmd)        -> no-op on LE host
        uint32 totalSize = payload.size() + 4;
        uint8 header[6];
        header[0] = uint8(totalSize >> 8);  // BE size high
        header[1] = uint8(totalSize);       // BE size low
        header[2] = uint8(cmd);             // LE cmd byte 0
        header[3] = uint8(cmd >> 8);        // LE cmd byte 1
        header[4] = 0;                      // cmd byte 2 (unused)
        header[5] = 0;                      // cmd byte 3 (unused)

        bool encrypt = !skipEncrypt && encrypted_;
        // NOTE: AzerothCore server only encrypts the HEADER, not the payload.
        // To keep cipher state in sync, we also only encrypt the header.
        if (encrypt) {
            uint8 cryptedHeader[6];
            memcpy(cryptedHeader, header, 6);
            sendEncrypt_.UpdateData(cryptedHeader, 6);
            if (!WriteAll(cryptedHeader, 6)) return false;
        } else {
            if (!WriteAll(header, 6)) return false;
        }

        if (!payload.empty()) {
            // Payload is sent UNENCRYPTED to match server behavior.
            // Server only decrypts the header (see WorldSocket::ReadHeaderHandler).
            if (!WriteAll(payload.data(), payload.size())) return false;
        }
        return true;
    }

    bool WorldSocket::RecvPacket(uint16& cmd, std::vector<uint8>& payload) {
        // AzerothCore ServerPktHeader wire format (server->client, after decryption):
        //   Small:  [size_hi] [size_lo] [cmd_lo] [cmd_hi]         (4 bytes)
        //   Large:  [0x80|size_mid] [size_hi] [size_lo] [cmd_lo] [cmd_hi] (5 bytes)
        //
        // CRITICAL: We must decrypt the first 2 bytes BEFORE determining header length,
        // because RC4 encryption can set bit 7 in the first byte even when the
        // unencrypted header doesn't have it. The server encrypts exactly
        // getHeaderLength() bytes (4 or 5), so we must decrypt exactly the same amount.
        uint8 hdrBuf[5];

        // Step 1: Read the first 2 encrypted bytes
        if (!ReadExact(hdrBuf, 2)) {
            std::cerr << "[World] RecvPacket: ReadExact failed for header (2 bytes)\n";
            return false;
        }

        auto hexStr = [](const uint8* d, size_t l) -> std::string {
            std::string s; char b[4];
            for (size_t i = 0; i < l; ++i) { snprintf(b, sizeof(b), "%02x", d[i]); s += b; }
            return s;
        };

        // Step 2: Decrypt the first 2 bytes to check bit 7 (large packet marker)
        if (encrypted_) {
            recvDecrypt_.UpdateData(hdrBuf, 2);
        }

        // Step 3: Now determine header length from DECRYPTED first byte
        uint8 hdrLen = (hdrBuf[0] & 0x80) ? 5 : 4;

        // Step 4: Read and decrypt the remaining bytes
        if (hdrLen == 5) {
            if (!ReadExact(hdrBuf + 2, 3)) {
                std::cerr << "[World] RecvPacket: ReadExact failed for large header\n";
                return false;
            }
            if (encrypted_) {
                recvDecrypt_.UpdateData(hdrBuf + 2, 3);
            }
        } else {
            if (!ReadExact(hdrBuf + 2, 2)) {
                std::cerr << "[World] RecvPacket: ReadExact failed for cmd\n";
                return false;
            }
            if (encrypted_) {
                recvDecrypt_.UpdateData(hdrBuf + 2, 2);
            }
        }

        // Now the full header is decrypted
        std::cerr << "[World] RecvPacket: decrypted hdr (" << (int)hdrLen << " bytes): "
                  << hexStr(hdrBuf, hdrLen) << "\n";

        // Step 5: Parse the decrypted header
        uint32 rawSize;
        if (hdrLen == 5) {
            rawSize = (uint32(hdrBuf[0] & 0x7F) << 16) | (uint32(hdrBuf[1]) << 8) | uint32(hdrBuf[2]);
            cmd = uint16(hdrBuf[3]) | (uint16(hdrBuf[4]) << 8);
        } else {
            rawSize = (uint32(hdrBuf[0]) << 8) | uint32(hdrBuf[1]);
            cmd = uint16(hdrBuf[2]) | (uint16(hdrBuf[3]) << 8);
        }

        uint16 size = (rawSize >= 2) ? (rawSize - 2) : 0;

        if (rawSize == 0) {
            std::cerr << "[World] RecvPacket: zero header\n";
            return false;
        }

        payload.resize(size);
        if (size > 0) {
            if (!ReadExact(payload.data(), size)) {
                std::cerr << "[World] RecvPacket: ReadExact failed for payload (len=" << size << ", rawSize=" << rawSize << ")\n";
                return false;
            }
        }
        std::cerr << "[World] RecvPacket: cmd=0x" << std::hex << cmd << " rawSize=" << std::dec << rawSize << " payloadLen=" << size << " hdrLen=" << (int)hdrLen << "\n";
        return true;
    }

    bool WorldSocket::ReadExact(void* buf, size_t len) {
        size_t received = 0;
        while (received < len) {
            ssize_t n = ::recv(fd_, (char*)buf + received, len - received, 0);
            if (n <= 0) return false;
            received += n;
        }
        return true;
    }

    bool WorldSocket::WriteAll(const void* buf, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd_, (const char*)buf + sent, len - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                std::cerr << "[World] send failed: " << strerror(errno) << "\n";
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
        // recvDecrypt_ on client: corresponds to server's _serverEncrypt
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
        // sendEncrypt_ on client: corresponds to server's _clientDecrypt
        sendEncrypt_.Init(sendKey, 20);

        // WoW uses ARC4-drop1024: both sides must drop 1024 bytes of keystream
        // after initialization so their cipher states are aligned.
        uint8 dropBuf[1024] = {0};
        recvDecrypt_.UpdateData(dropBuf, sizeof(dropBuf));
        sendEncrypt_.UpdateData(dropBuf, sizeof(dropBuf));

        encrypted_ = true;
        std::cout << "[World] Encryption initialized (ARC4-drop1024 synced)\n";
    }

} // namespace WoWClient