#pragma once

#include "Cryptography/ARC4.h"
#include "AuthSocket.h"
#include "BotState.h"
#include "Cryptography/HMAC.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ClientSimulator
{
    class WorldSocket
    {
    public:
        WorldSocket(std::string const& ip, uint16 port);
        ~WorldSocket();

        // ── 连接 / 登录 ──

        bool Connect();
        void Disconnect();

        bool RecvAuthChallenge();
        bool SendAuthSession(AuthResult const& auth, std::string const& username, uint8 realmId);
        bool WaitAuthResponse(uint8& result, uint32& billingFlags);
        bool RecvCharacterList(std::vector<CharacterInfo>& chars);
        bool LoginCharacter(uint64 guid);
        bool WaitWorldEnter();
        bool DrainLoginPackets(uint32 timeoutMs = 2000);

        // 多 bot 支持
        void SetUsername(std::string const& un) { _username = un; }
        BotState const& GetBotState() const { return _botState; }
        BotState& GetBotState() { return _botState; }

        // ── 游戏层 ──

        bool SendActiveMover();
        bool SendHeartbeat();          // 用当前 botState.pos 发送心跳（自动包含移动标志）
        bool SendMoveStartForward(Vec3 const& pos, float orientation);
        bool SendMoveStop(Vec3 const& pos, float orientation);
        bool SendMoveSetFacing(Vec3 const& pos, float orientation);
        bool SendMoveTeleportAck(uint32 counter);
        bool SendPing(uint32 seq);
        bool SendLogout();
        bool SendTimeSyncResp(uint32 counter, uint32 clientTime);
        bool SendChatMessage(std::string const& msg, uint8 channel = 0);

        // ── 战斗 / NPC 交互 ──
        bool SendSetSelection(uint64 targetGuid);
        bool SendAttackSwing(uint64 targetGuid);
        bool SendAttackStop();
        bool SendGossipHello(uint64 npcGuid);
        bool SendQuestGiverHello(uint64 npcGuid);
        bool SendQuestGiverQueryQuest(uint64 guid, uint32 questId);
        bool SendQuestGiverAcceptQuest(uint64 questGiverGuid, uint32 questId);
        bool SendQuestGiverCompleteQuest(uint64 questGiverGuid, uint32 questId);

        // 非阻塞收包
        bool HasPendingData(uint32 timeoutMs = 0);
        bool RecvPacketNonBlocking(uint16& cmd, std::vector<uint8>& payload);

        void ProcessPacket(uint16 cmd, std::vector<uint8> const& payload);
        void LogState(std::ostream& os) const;
        void SetCharacterInfo(uint64 guid, std::string const& name, uint8 level, uint8 clazz, uint8 race);

        // ── 死亡流程 ──

        void OnDeathDetected();
        bool TickDeathRecovery();
        bool SendRepopRequest();
        bool SendReclaimCorpse();
        bool SendSpiritHealerActivate();
        bool SendStandStateChange(uint8 state);

        // ── 位置验证 ──
        bool ValidatePosition(Vec3& pos, uint32 mapId);

        bool RecvPacket(uint16& cmd, std::vector<uint8>& payload);

        bool IsConnected() const { return _fd >= 0; }

    private:
        bool SendPacket(uint16 cmd, std::vector<uint8> const& payload);
        bool ReadExact(void* buf, size_t len);
        bool WriteAll(void const* buf, size_t len);

        void InitAuthCrypt(std::vector<uint8> const& sessionKey);
        void SendAddonInfo();
        std::vector<uint8> BuildMovementPayload(uint32 flags, Vec3 pos, float orientation);

        struct ClientPktHeader
        {
            uint16 size;
            uint32 cmd;
        };

        struct ServerPktHeader
        {
            uint16 size;
            uint16 cmd;
        };

        std::string _ip;
        uint16      _port;
        int         _fd = -1;

        enum class LoginState
        {
            Disconnected,
            Connected,
            AuthChallengeDone,
            AuthSent,
            AuthOk,
            CharListed,
            InWorld,
            Failed,
        };
        LoginState _loginState = LoginState::Disconnected;

        bool _cryptInitialized = false;
        Acore::Crypto::ARC4 _recvDecrypt;
        Acore::Crypto::ARC4 _sendEncrypt;

        BotState _botState;
        std::string _username;
        uint32 _lastLatency = 0;
        uint8 _serverSeed[4]{};      // 服务端发来的 4 字节 seed（SMSG_AUTH_CHALLENGE）
        uint8 _clientSeed[4]{};      // 客户端生成的 4 字节随机 seed
        std::vector<uint8> _srpSessionKey;  // 40 字节 SRP6 会话密钥
        Acore::Crypto::SHA1::Digest _sessionKey;
    };
} // namespace ClientSimulator
