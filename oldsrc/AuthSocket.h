#pragma once

#include "Define.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ClientSimulator
{
    // Auth server 认证结果
    struct AuthResult
    {
        bool success = false;
        uint8 errorCode = 0;

        // 从 CMD_AUTH_LOGON_CHALLENGE 响应获取
        std::array<uint8, 32> B;   // 服务端公钥
        uint8 g = 0;
        std::array<uint8, 32> N;   // 模数
        std::array<uint8, 32> salt;
        std::array<uint8, 16> seed; // 服务端种子（后续 world 认证用）

        // 从 CMD_AUTH_LOGON_PROOF 响应获取
        std::array<uint8, 20> M2;   // 服务端证明
        uint32 accountFlags = 0;
        uint32 surveyId = 0;

        // 计算结果
        std::array<uint8, 40> sessionKey{}; // SRP6 会话密钥
    };

    // Realm 信息
    struct RealmInfo
    {
        uint8 type = 0;
        uint8 locked = 0;
        uint8 flags = 0;
        std::string name;
        std::string address;
        uint16 port = 0;
        float population = 0;
        uint8 numChars = 0;
        uint8 timezone = 0;
        uint8 realmId = 0;
    };

    class AuthSocket
    {
    public:
        AuthSocket();
        ~AuthSocket();

        // 连接到 authserver 并完成 SRP6 认证
        bool Connect(std::string const& host, uint16 port);
        bool Login(std::string const& username, std::string const& password);
        bool FetchRealmList(std::vector<RealmInfo>& realms);
        void Disconnect();

        AuthResult const& GetResult() const { return _result; }
        uint32_t GetBuild() const { return _build; }

    private:
        bool SendChallengeRequest(std::string const& username);
        bool RecvChallengeResponse();
        bool SendProofRequest(std::string const& username, std::string const& password);
        bool RecvProofResponse();
        bool SendRealmListRequest();
        bool RecvRealmListResponse(std::vector<RealmInfo>& realms);

        bool SendAll(void const* data, size_t len);
        bool RecvAll(void* data, size_t len);

        int _fd;
        AuthResult _result;
        std::string _host;
        uint16 _port;
        uint32 _build;
    };
}
