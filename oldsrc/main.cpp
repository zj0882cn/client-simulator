/*
 * client-simulator main.cpp — 轻量登录客户端
 *
 * 用法: ./client-simulator [config_file] [bot_count]
 *
 * 职责: 仅完成 auth 登录 → world 登录 → 保持在线 (ping)
 * 角色控制权全部由 mod-bot 模块在服务端接管:
 *   移动 → MotionMaster::MovePoint (mmap 寻路, 贴地)
 *   战斗 → MoveChase + CastSpell
 *   死亡 → 服务端自动处理
 * 客户端只负责 TCP 保活, 不发送任何移动/战斗包
 *
 * 配置: bot_secrets.conf
 */

#include "AuthSocket.h"
#include "Cryptography/OpenSSLCrypto.h"
#include "WorldSocket.h"
#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ClientSimulator;

static std::atomic<bool> g_running{true};
static std::atomic<int>  g_activeBots{0};

void signalHandler(int) { g_running = false; }

// ── 读取 bot_secrets.conf ──

struct BotConfig
{
    int count = 5;
    std::string prefix = "BOT";
    std::string password;
    int spawnIntervalMs = 500;
};

static BotConfig LoadConfig(std::string const& filePath)
{
    BotConfig conf;
    std::ifstream f(filePath);
    if (!f)
    {
        std::cerr << "[Main] 无法打开配置文件: " << filePath << "\n";
        return conf;
    }

    std::string line;
    while (std::getline(f, line))
    {
        if (line.empty() || line[0] == '#')
            continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!key.empty() && key.front() == ' ') key.erase(0, 1);
        while (!val.empty() && val.back() == ' ') val.pop_back();
        while (!val.empty() && val.front() == ' ') val.erase(0, 1);

        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);

        if (key == "BOT_COUNT")              conf.count = std::stoi(val);
        else if (key == "BOT_USERNAME_PREFIX") conf.prefix = val;
        else if (key == "BOT_PASSWORD")      conf.password = val;
        else if (key == "BOT_SPAWN_INTERVAL_MS") conf.spawnIntervalMs = std::stoi(val);
    }
    return conf;
}

// ── 单个 bot 线程 ──

static constexpr int MAX_RECONNECT_RETRIES = 10;
static constexpr int INITIAL_RETRY_WAIT_SEC = 2;
static constexpr int MAX_RETRY_WAIT_SEC = 60;

void BotThread(int botIndex, BotConfig const& conf, std::string const& authHost, uint16 authPort)
{
    g_activeBots++;

    // 构造用户名: BOT001, BOT002, ...
    std::string username = conf.prefix + (botIndex < 10 ? "00" : botIndex < 100 ? "0" : "") + std::to_string(botIndex);
    std::cout << "\n=== Bot #" << botIndex << " [" << username << "] 启动 ===\n";

    int retryCount = 0;
    bool cleanExit = false;

    // ── 自动重连循环 ──
    while (g_running && !cleanExit && retryCount < MAX_RECONNECT_RETRIES)
    {
        if (retryCount > 0)
        {
            int waitSec = std::min(INITIAL_RETRY_WAIT_SEC * retryCount, MAX_RETRY_WAIT_SEC);
            std::cout << "[Bot " << botIndex << "] 重连等待 " << waitSec << "s (第" << retryCount << "次)\n";
            for (int i = 0; i < waitSec && g_running; ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!g_running) break;
        }

        // ── Step 1: Auth 连接 ──
        AuthSocket auth;
        if (!auth.Connect(authHost, authPort))
        {
            std::cerr << "[Bot " << botIndex << "] Auth 连接失败\n";
            retryCount++;
            continue;
        }

        if (!auth.Login(username, conf.password))
        {
            std::cerr << "[Bot " << botIndex << "] Auth 登录失败\n";
            auth.Disconnect();
            retryCount++;
            continue;
        }

        std::vector<RealmInfo> realms;
        if (!auth.FetchRealmList(realms))
        {
            std::cerr << "[Bot " << botIndex << "] 无法获取 realm 列表\n";
            auth.Disconnect();
            retryCount++;
            continue;
        }

        if (realms.empty())
        {
            std::cerr << "[Bot " << botIndex << "] 无可用 realm\n";
            auth.Disconnect();
            retryCount++;
            continue;
        }

        RealmInfo realm = realms[0];
        AuthResult authResult = auth.GetResult();
        auth.Disconnect();

        // ── Step 2: World 连接 ──
        WorldSocket world(realm.address, realm.port);
        world.SetUsername(username);

        if (!world.Connect())
        {
            std::cerr << "[Bot " << botIndex << "] World 连接失败\n";
            retryCount++;
            continue;
        }

        if (!world.RecvAuthChallenge())
        {
            std::cerr << "[Bot " << botIndex << "] Auth challenge 失败\n";
            retryCount++;
            continue;
        }

        if (!world.SendAuthSession(authResult, username, realm.realmId))
        {
            std::cerr << "[Bot " << botIndex << "] Auth session 发送失败\n";
            retryCount++;
            continue;
        }

        uint8 authResp;
        uint32 billingFlags;
        if (!world.WaitAuthResponse(authResp, billingFlags))
        {
            std::cerr << "[Bot " << botIndex << "] Auth response 失败:" << int(authResp) << "\n";
            retryCount++;
            continue;
        }

        // Step 3: 角色列表
        std::vector<CharacterInfo> chars;
        if (!world.RecvCharacterList(chars))
        {
            std::cerr << "[Bot " << botIndex << "] 获取角色列表失败\n";
            retryCount++;
            continue;
        }

        if (chars.empty())
        {
            std::cerr << "[Bot " << botIndex << "] 此账号无角色（需要先 .bot spawn）\n";
            // 无角色不可恢复，不重试
            break;
        }

        // 选第一个角色
        CharacterInfo& chosen = chars[0];
        world.SetCharacterInfo(chosen.guid, chosen.name, chosen.level, chosen.clazz, chosen.race);

        if (!world.LoginCharacter(chosen.guid))
        {
            std::cerr << "[Bot " << botIndex << "] 角色登录失败\n";
            retryCount++;
            continue;
        }

        if (!world.WaitWorldEnter())
        {
            std::cerr << "[Bot " << botIndex << "] 进入世界失败\n";
            retryCount++;
            continue;
        }

        // 发送 CMSG_SET_ACTIVE_MOVER
        world.SendActiveMover();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 吃掉初始世界包
        world.DrainLoginPackets(500);

        std::cout << "[Bot " << botIndex << "] " << chosen.name
                  << " (Lv" << int(chosen.level) << ") 已进入世界! "
                  << "(重连#" << retryCount << ")\n";

        retryCount = 0;  // 成功登录，重置重连计数

        // ── Step 4: 保活循环 ──
        auto lastPing = std::chrono::steady_clock::now();
        int  pingSeq  = 0;
        int  pingFailCount = 0;

        while (g_running && world.IsConnected())
        {
            // 处理接收包
            uint16 cmd;
            std::vector<uint8> payload;
            while (world.RecvPacketNonBlocking(cmd, payload))
            {
                if (cmd == 0x004D) // SMSG_LOGOUT_COMPLETE
                {
                    std::cout << "[Bot " << botIndex << "] 被踢出\n";
                    cleanExit = true;
                    goto session_end;
                }
                world.ProcessPacket(cmd, payload);
            }

            // 检查连接是否已断开（recv 超时/错误）
            if (!world.IsConnected())
            {
                std::cerr << "[Bot " << botIndex << "] 连接已断开\n";
                goto session_end;
            }

            auto now = std::chrono::steady_clock::now();

            // 每 30s 发送 ping 保活
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPing).count() >= 30000)
            {
                if (!world.SendPing(pingSeq++))
                {
                    pingFailCount++;
                    std::cerr << "[Bot " << botIndex << "] SendPing 失败 (" << pingFailCount << "/3)\n";
                    if (pingFailCount >= 3)
                        goto session_end;
                }
                else
                {
                    pingFailCount = 0;
                }
                lastPing = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

session_end:
        // 直接断开 TCP（不送 CMSG_LOGOUT）
        // LOGOUT_COMPLETE 需等服务端 20s 倒计时，实际不可用
        // TCP close 后服务端检测断连 → 自然设置 online=0
        std::cout << "[Bot " << botIndex << "] " << chosen.name << " 断开连接\n";
        world.Disconnect();

        retryCount++;
    }

    g_activeBots--;
    if (!cleanExit && retryCount >= MAX_RECONNECT_RETRIES)
        std::cerr << "[Bot " << botIndex << "] 已达最大重连次数，退出\n";
}

// ── main ──

int main(int argc, char** argv)
{
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    OpenSSLCrypto::threadsSetup();

    std::string confPath = "bot_secrets.conf";
    if (argc > 1)
        confPath = argv[1];

    BotConfig conf = LoadConfig(confPath);
    if (conf.password.empty())
    {
        std::cerr << "错误: 无法读取配置文件或密码为空: " << confPath << "\n";
        return 1;
    }

    std::cout << "[Main] 配置加载: " << conf.count << " 个 bot 账号\n";
    std::cout << "[Main] 前缀: " << conf.prefix << "\n";

    int botCount = conf.count;
    if (argc > 2)
        botCount = std::atoi(argv[2]);

    if (botCount <= 0 || botCount > conf.count)
        botCount = conf.count;

    std::string authHost = "127.0.0.1";
    uint16 authPort = 3724;

    char const* envHost = getenv("AUTH_HOST");
    if (envHost) authHost = envHost;
    char const* envPort = getenv("AUTH_PORT");
    if (envPort) authPort = uint16(std::atoi(envPort));

    std::cout << "[Main] Auth 服务器: " << authHost << ":" << authPort << "\n";
    std::cout << "[Main] 启动 " << botCount << " 个 bot (登录后由 mod-bot 模块接管 AI)...\n\n";

    std::vector<std::thread> threads;
    for (int i = 1; i <= botCount; ++i)
    {
        threads.emplace_back(BotThread, i, std::ref(conf), authHost, authPort);
        std::this_thread::sleep_for(std::chrono::milliseconds(conf.spawnIntervalMs));
    }

    for (auto& t : threads)
    {
        if (t.joinable())
            t.join();
    }

    std::cout << "\n[Main] 所有 bot 已退出\n";

    // 兜底清理：确保所有 bot 角色的 online 标志为 0
    {
        std::string cmd = "mysql -h 127.0.0.1 -u acore -pacore -N -e \""
            "UPDATE acore_characters.characters SET online=0 "
            "WHERE account IN (SELECT id FROM acore_auth.account WHERE username LIKE '"
            + conf.prefix + "%')\" 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0)
            std::cout << "[Main] DB 在线标志已清理\n";
    }

    return 0;
}
