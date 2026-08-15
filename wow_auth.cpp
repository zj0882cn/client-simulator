#include "wow_client.h"

namespace WoWClient
{
    // =========================================================================
    // AuthSocket implementations
    // =========================================================================

    AuthSocket::AuthSocket() : fd_(SOCKET_INVALID), build_(WOW_BUILD) {}
    AuthSocket::~AuthSocket() { Disconnect(); }

    bool AuthSocket::Connect(const std::string& host, uint16 port) {
        host_ = host;
        port_ = port;

        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ == SOCKET_INVALID) {
            std::cerr << "[Auth] socket() failed\n";
            return false;
        }

        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            std::cerr << "[Auth] gethostbyname(" << host << ") failed\n";
            CLOSE_SOCKET(fd_);
            fd_ = SOCKET_INVALID;
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

        if (::connect(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[Auth] connect(" << host << ":" << port << ") failed: " << SOCKET_ERROR_MSG() << "\n";
            CLOSE_SOCKET(fd_);
            fd_ = SOCKET_INVALID;
            return false;
        }

        std::cout << "[Auth] Connected to " << host << ":" << port << "\n";
        return true;
    }

    void AuthSocket::Disconnect() {
        if (fd_ != SOCKET_INVALID) { CLOSE_SOCKET(fd_); fd_ = SOCKET_INVALID; }
    }

    bool AuthSocket::Login(const std::string& username, const std::string& password) {
        if (!SendChallengeRequest(username)) return false;
        if (!RecvChallengeResponse()) return false;

        std::cout << "[Auth] Challenge received, computing proof...\n";

        if (!SendProofRequest(username, password)) return false;
        if (!RecvProofResponse()) return false;

        result_.success = true;
        std::cout << "[Auth] SRP6 authentication success!\n";
        return true;
    }

    bool AuthSocket::FetchRealmList(std::vector<RealmInfo>& realms) {
        if (!SendRealmListRequest()) return false;
        if (!RecvRealmListResponse(realms)) return false;
        std::cout << "[Auth] Received " << realms.size() << " realm(s)\n";
        return true;
    }

    const AuthResult& AuthSocket::GetResult() const { return result_; }

    bool AuthSocket::SendAll(const void* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd_, (const char*)data + sent, len - sent, 0);
            if (n <= 0) return false;
            sent += n;
        }
        return true;
    }

    bool AuthSocket::RecvAll(void* data, size_t len) {
        size_t recvd = 0;
        while (recvd < len) {
            ssize_t n = ::recv(fd_, (char*)data + recvd, len - recvd, 0);
            if (n <= 0) return false;
            recvd += n;
        }
        return true;
    }

    bool AuthSocket::SendChallengeRequest(const std::string& username) {
        // Convert username to uppercase (WoW protocol requirement)
        std::string upperUsername = username;
        for (auto& c : upperUsername) c = toupper((unsigned char)c);
        
        size_t nameLen = upperUsername.size();
        size_t pktSize = 4 + 4 + 3 + 2 + 4 + 4 + 4 + 4 + 4 + 1 + nameLen;
        uint16 dataSize = uint16(pktSize - 4);

        std::vector<uint8> buf(pktSize);
        uint8* p = buf.data();

        *p++ = CMD_AUTH_LOGON_CHALLENGE;  // 0x00
        *p++ = 0x00;                       // error
        writeU16LE(p, dataSize); p += 2;

        // gamename "WoW\0"
        memcpy(p, "WoW", 3); p[3] = 0; p += 4;
        // version 3.3.5
        *p++ = 3; *p++ = 3; *p++ = 5;
        // build
        writeU16LE(p, build_); p += 2;
        // platform "x86\0"
        memcpy(p, "x86", 3); p[3] = 0; p += 4;
        // os: AzerothCore reverses bytes on storage, so we send reversed: "Win\0" -> "\0niW"
        p[0] = 0;    // reverse of "Win\0"
        p[1] = 'n';
        p[2] = 'i';
        p[3] = 'W';
        p += 4;
        // country "enUS"
        memcpy(p, "enUS", 4); p += 4;
        // timezone bias
        writeU32LE(p, 0); p += 4;
        // IP (0.0.0.0)
        writeU32LE(p, 0); p += 4;
        // username length + username (uppercase)
        *p++ = uint8(nameLen);
        memcpy(p, upperUsername.c_str(), nameLen);

        std::cout << "[Auth] Sending LOGON_CHALLENGE (" << pktSize << " bytes)\n";
        return SendAll(buf.data(), buf.size());
    }

    bool AuthSocket::RecvChallengeResponse() {
        // AzerothCore LOGON_CHALLENGE response format:
        // opcode(1) + err_placeholder(1) + err(1) + B(32) + gLen(1) + g(gLen) + NLen(1) + N(NLen) + salt(32) + versionChallenge(16) + securityFlags(1)
        
        char peekBuf[256];
        int peekLen = ::recv(fd_, peekBuf, sizeof(peekBuf), MSG_PEEK);
        if (peekLen > 0) {
            std::cerr << "[Auth] Received " << peekLen << " bytes:";
            for (int i = 0; i < peekLen && i < 80; ++i)
                printf(" %02x", (uint8)peekBuf[i]);
            std::cerr << "\n";
        }
        
        uint8 opcode, errPlaceholder, errorCode;
        if (!RecvAll(&opcode, 1) || !RecvAll(&errPlaceholder, 1) || !RecvAll(&errorCode, 1))
            return false;

        if (opcode != CMD_AUTH_LOGON_CHALLENGE || errorCode != AUTH_OK) {
            std::cerr << "[Auth] Challenge failed: opcode=" << int(opcode) << " err_ph=" << int(errPlaceholder) << " error=" << int(errorCode) << "\n";
            result_.errorCode = errorCode;
            return false;
        }

        // Read B (32 bytes)
        uint8 B[32];
        if (!RecvAll(B, 32)) return false;
        memcpy(result_.B, B, 32);

        // Read g (variable length)
        uint8 gLen;
        if (!RecvAll(&gLen, 1)) return false;
        std::cerr << "[Auth] gLen=" << (int)gLen << "\n";
        std::vector<uint8> gData(gLen);
        if (gLen > 0 && !RecvAll(gData.data(), gLen)) return false;
        if (gLen > 0) result_.g = gData[0];

        // Read N (variable length) - must be 32 bytes
        uint8 NLen;
        if (!RecvAll(&NLen, 1)) return false;
        if (NLen != 32) {
            std::cerr << "[Auth] Unexpected N length: " << (int)NLen << " (hex: " << std::hex << (int)NLen << ")\n";
            return false;
        }
        if (!RecvAll(result_.N, 32)) return false;

        // Read salt (32 bytes)
        uint8 salt[32];
        if (!RecvAll(salt, 32)) return false;
        memcpy(result_.salt, salt, 32);

        // Read version challenge (16 bytes)
        uint8 versionChallenge[16];
        if (!RecvAll(versionChallenge, 16)) return false;
        memcpy(result_.seed, versionChallenge, 16);

        // Read security flags (1 byte)
        uint8 securityFlags;
        if (!RecvAll(&securityFlags, 1)) return false;

        printf("[Auth] B=  "); for(int i=0;i<32;++i) printf("%02x", result_.B[i]); printf("\n");
        printf("[Auth] N=  "); for(int i=0;i<32;++i) printf("%02x", result_.N[i]); printf("\n");
        printf("[Auth] g= %02x\n", (int)result_.g);
        printf("[Auth] salt= "); for(int i=0;i<32;++i) printf("%02x", result_.salt[i]); printf("\n");
        printf("[Auth] securityFlags=%d\n", (int)securityFlags);

        return true;
    }

    bool AuthSocket::SendProofRequest(const std::string& username, const std::string& password) {
        std::string normUser = toUpper(username);
        std::string normPass = toUpper(password);

        std::cerr << "[Auth] Computing SRP6 proof..." << std::endl;
        auto proof = SRP6Calculator::computeClientProof(
            normUser, normPass, result_.salt, result_.B, result_.N, &result_.g, 1);
        std::cerr << "[Auth] SRP6 proof computed" << std::endl;

        memcpy(result_.sessionKey, proof.sessionKey, 40);

        std::array<uint8, 20> crcHash{};

        constexpr size_t pktSize = 1 + 32 + 20 + 20 + 1 + 1;
        uint8 buf[pktSize];
        uint8* p = buf;

        *p++ = CMD_AUTH_LOGON_PROOF;
        memcpy(p, proof.A, 32); p += 32;
        memcpy(p, proof.M, 20); p += 20;
        memcpy(p, crcHash.data(), 20); p += 20;
        *p++ = 1;
        *p++ = 0;

        std::cerr << "[Auth] Sending LOGON_PROOF (" << pktSize << " bytes)" << std::endl;
        bool ret = SendAll(buf, sizeof(buf));
        std::cerr << "[Auth] SendAll returned: " << ret << std::endl;
        return ret;
    }

    bool AuthSocket::RecvProofResponse() {
        uint8 opcode;
        if (!RecvAll(&opcode, 1)) return false;
        if (opcode != CMD_AUTH_LOGON_PROOF) {
            std::cerr << "[Auth] Proof bad opcode: " << int(opcode) << "\n";
            return false;
        }

        uint8 result;
        if (!RecvAll(&result, 1)) return false;
        if (result != AUTH_OK) {
            std::cerr << "[Auth] Proof failed: result=" << int(result) << "\n";
            result_.errorCode = result;
            return false;
        }

        // AUTH_LOGON_PROOF_S: M2(20) + AccountFlags(4) + SurveyId(4) + LoginFlags(2) = 30 bytes
        uint8 body[30];
        if (!RecvAll(body, sizeof(body))) return false;

        memcpy(result_.M2, body, 20);
        memcpy(&result_.accountFlags, body + 20, 4);

        std::cerr << "[Auth] Proof accepted! accountFlags=" << result_.accountFlags << std::endl;
        return true;
    }

    bool AuthSocket::SendRealmListRequest() {
        uint8 buf[5]{};
        buf[0] = CMD_REALM_LIST;
        std::cerr << "[Auth] Sending REALM_LIST request (5 bytes)" << std::endl;
        return SendAll(buf, sizeof(buf));
    }

    bool AuthSocket::RecvRealmListResponse(std::vector<RealmInfo>& realms) {
        // AzerothCore REALM_LIST response format (POST_BC):
        // header: opcode(1) + sizeLE(2)
        // body: padding(4) + countLE(2) + [realm entries] + trailing(2)[0x10,0x00]
        // Entry (POST_BC): type(1) + lock(1) + flag(1) + name(null-term) + address(null-term) + population(4 LE float) + chars(1) + timezone(1) + realmId(1)
        
        std::cerr << "[Auth] Waiting for REALM_LIST response..." << std::endl;
        
        uint8 header[3];
        if (!RecvAll(header, 3)) {
            std::cerr << "[Auth] Failed to read REALM_LIST header" << std::endl;
            return false;
        }
        std::cerr << "[Auth] REALM_LIST header: cmd=" << (int)header[0] << " bytes=" << (int)header[1] << "," << (int)header[2] << std::endl;
        
        uint8 cmd = header[0];
        if (cmd != CMD_REALM_LIST) {
            std::cerr << "[Auth] Unexpected realm list cmd: " << int(cmd) << "\n";
            return false;
        }
        
        uint16_t packetSize = readU16LE(header + 1);
        
        std::cerr << "[Auth] REALM_LIST: packetSize(LE)=" << packetSize << std::endl;
        
        std::vector<uint8> body(packetSize);
        if (!RecvAll(body.data(), packetSize)) {
            std::cerr << "[Auth] Failed to read REALM_LIST body" << std::endl;
            return false;
        }
        
        // Dump body for debugging
        std::cerr << "[Auth] Body hex: ";
        for (size_t i = 0; i < std::min(size_t(30), body.size()); i++) {
            std::cerr << std::hex << (int)body[i] << " ";
        }
        std::cerr << std::dec << std::endl;
        
        // body[0..3]: padding (uint32 0)
        // body[4..5]: count (uint16 LE)
        uint16_t count = readU16LE(body.data() + 4);
        
        std::cerr << "[Auth] REALM_LIST: packetSize=" << packetSize << " count=" << count << std::endl;
        
        // Entries start at body[6] (padding(4) + count(2))
        // Trailing 2 bytes (0x10, 0x00 for POST_BC) are at the END after all entries
        size_t pos = 6;
        for (uint16_t i = 0; i < count; ++i) {
            RealmInfo r;
            
            // Entry: type(1) + lock(1) + flag(1)
            if (pos + 3 > body.size()) break;
            uint8 type = body[pos++];
            uint8 lock = body[pos++];
            uint8 flag = body[pos++];
            
            (void)type;
            (void)lock;
            
            r.flags = flag;
            
            // Read null-terminated name
            std::string name;
            while (pos < body.size() && body[pos] != 0) { name += (char)body[pos++]; }
            if (pos < body.size()) pos++;
            
            // Read null-terminated address
            std::string address;
            while (pos < body.size() && body[pos] != 0) { address += (char)body[pos++]; }
            if (pos < body.size()) pos++;
            
            // Population (float, 4 bytes LE)
            if (pos + sizeof(float) <= body.size()) {
                memcpy(&r.population, body.data() + pos, sizeof(float));
                pos += sizeof(float);
            }
            
            // Character count
            if (pos < body.size()) { r.numChars = body[pos++]; }
            
            // Timezone
            if (pos < body.size()) { r.timezone = body[pos++]; }
            
            // Realm ID
            if (pos < body.size()) { r.realmId = body[pos++]; }
            
            r.name = name;
            r.address = address;
            
            // Parse port from address (format: "host:port")
            auto colon = address.find(':');
            if (colon != std::string::npos) {
                r.address = address.substr(0, colon);
                r.port = uint16(std::stoi(address.substr(colon + 1)));
            }
            
            std::cerr << "[Auth] Realm: " << r.name << " (" << r.address << ":" << r.port << ") pop=" << r.population << " chars=" << (int)r.numChars << std::endl;
            realms.push_back(r);
        }
        
        // Skip trailing 2 bytes (0x10, 0x00 for POST_BC)
        if (pos + 2 <= body.size()) {
            pos += 2;
        }
        
        std::cerr << "[Auth] Parsed " << realms.size() << " realms, remaining bytes=" << (body.size() - pos) << std::endl;
        
        return !realms.empty();
    }

} // namespace WoWClient