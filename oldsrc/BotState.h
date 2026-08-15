#pragma once

#include <cstdint>
#include <string>
#include <vector>

// AzerothCore compatible type aliases (if not already defined)
#ifndef ACCORE_TYPES_DEFINED
#define ACCORE_TYPES_DEFINED
using uint8  = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;
#endif

namespace ClientSimulator
{
    struct Vec3
    {
        float x = 0.0f, y = 0.0f, z = 0.0f;
    };

    struct CharacterInfo
    {
        uint64 guid     = 0;
        std::string name;
        uint8 race      = 0;
        uint8 clazz     = 0;   // class
        uint8 gender    = 0;
        uint8 level     = 1;
        uint32 zone     = 0;
        uint32 mapId    = 0;
        float x = 0, y = 0, z = 0;
    };

    enum BotActivity
    {
        BOT_ACTIVITY_IDLE = 0,
        BOT_ACTIVITY_MOVING,
        BOT_ACTIVITY_COMBAT,
        BOT_ACTIVITY_DEAD,
        BOT_ACTIVITY_LOOTING,
    };

    struct BotState
    {
        uint64 guid     = 0;
        std::string name;
        uint8 level     = 1;
        uint8 clazz     = 0;
        uint8 race      = 0;

        Vec3 pos;
        float orientation = 0.0f;

        uint32 health   = 0;
        uint32 maxHealth = 1;
        uint32 mana     = 0;
        uint32 maxMana  = 0;

        uint32 xp       = 0;
        uint32 maxXp    = 1;

        bool isDead     = false;
        bool isGhost    = false;
        BotActivity activity = BOT_ACTIVITY_IDLE;

        // 移动目标
        Vec3 targetPos;
        float moveSpeed = 7.0f;

        // 战斗
        uint64 combatTarget = 0;   // 当前攻击目标 GUID (0=无目标)
        uint64 lastAttackedTarget = 0; // 上一个攻击目标 (用于检测战斗结束)

        // NPC / 任务
        uint64 talkTarget = 0;     // 当前对话 NPC GUID
        bool questAccepted = false; // 是否已接受任务
        uint32 activeQuestId = 0;   // 当前任务 ID

        // ── 位置监控 ──
        Vec3 lastKnownGoodPos;       // 上一次确认合理的位置
        uint32 mapId = 0;            // 当前地图 ID
        int stuckTicks = 0;          // 卡住计数（移动但位置不变）
        int fallTicks = 0;           // 连续坠落计数
        bool beenTeleported = false; // 刚被服务端传送（收到 NEW_WORLD）
        bool mapChanged = false;     // 地图改变，需要重置狩猎目标
        int consecutiveBadPos = 0;   // 连续异常位置次数
        uint32 zoneId = 0;           // 当前区域 ID

        // ── 死亡恢复 ──
        Vec3 corpsePos;                    // 尸体位置
        int deathRecoveryStage = 0;        // 0=正常, 1=刚死, 2=灵魂释放等待, 3=幽灵跑尸, 4=等待复活
        float deathTimer = 0.0f;           // 当前阶段倒计时(秒)
        bool canReclaim = false;           // 可在尸体处复活
        bool ghostMoveStarted = false;     // 幽灵已发送过 MSG_MOVE_START_FORWARD

        // ── 任务交互 ──
        float questTurnInCooldown = 0.0f;  // 任务交还冷却，防止重复触发

        // ── 移动时间 ──
        uint32 moveTime = 0;               // per-bot 移动时间戳（非 static，避免多 bot 竞态）
    };
} // namespace ClientSimulator
