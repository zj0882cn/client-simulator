#include "wow_client.h"
#include <csignal>

using namespace WoWClient;

// =========================================================================
// main.cpp - WoW 客户端模拟器主入口
// =========================================================================

static std::atomic<bool> g_running{true};

void signalHandler(int) {
    std::cout << "\n[Main] Signal received, shutting down...\n";
    g_running = false;
}

void printHelp() {
    std::cout << R"(
WoW Standalone Client Simulator (无数据库版)

Usage:
    ./wow_client login --account <account> --password <password> [--character <name>] [--host <ip>] [--port <port>]
    ./wow_client list  --account <account> --password <password> [--host <ip>]
    ./wow_client test  --account <account> --password <password> [--host <ip>]

Options:
    --account       账号用户名
    --password      密码
    --character     角色名（可选，不指定则选第一个角色）
    --host          Auth 服务器地址 (默认: 119.3.216.43)
    --port          Auth 服务器端口 (默认: 3724)
    --bot-target    Bot 模式目标玩家名 (可选)

Examples:
    ./wow_client login --account MYACC --password mypass --character MyHero
    ./wow_client login --account MYACC --password mypass --host 119.3.216.43
    ./wow_client list --account MYACC --password mypass
    ./wow_client test --account MYACC --password mypass
)";
}

struct Args {
    std::string action = "login";
    std::string account;
    std::string password;
    std::string character;
    std::string host = "119.3.216.43";
    uint16 port = AUTH_SERVER_PORT;
    std::string botTarget;
    bool listOnly = false;
    bool testOnly = false;
};

Args parseArgs(int argc, char** argv) {
    Args args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "login" || arg == "list" || arg == "test") {
            args.action = arg;
            if (arg == "list") args.listOnly = true;
            if (arg == "test") args.testOnly = true;
        }
        else if (i + 1 < argc) {
            std::string next = argv[++i];
            if (arg == "--account" || arg == "-a") args.account = next;
            else if (arg == "--password" || arg == "-p") args.password = next;
            else if (arg == "--character" || arg == "-c") args.character = next;
            else if (arg == "--host" || arg == "-H") args.host = next;
            else if (arg == "--port" || arg == "-P") args.port = uint16(std::atoi(next.c_str()));
            else if (arg == "--bot-target" || arg == "-t") args.botTarget = next;
        }
        else if (arg == "--help" || arg == "-?") {
            printHelp();
            exit(0);
        }
    }

    return args;
}

// =========================================================================
// Bot 主循环
// =========================================================================

int runLoginLoop(const Args& args) {
    std::cout << "\n========================================\n";
    std::cout << "  WoW Standalone Client Simulator\n";
    std::cout << "========================================\n\n";
    std::cout << "Account: " << args.account << "\n";
    std::cout << "Host:    " << args.host << ":" << args.port << "\n";
    if (!args.character.empty())
        std::cout << "Char:    " << args.character << "\n";
    if (!args.botTarget.empty())
        std::cout << "Target:  " << args.botTarget << "\n";
    std::cout << "\n";

    // ---- Step 1: Auth 认证 ----
    std::cout << "[*] Connecting to Auth Server...\n";
    AuthSocket auth;
    if (!auth.Connect(args.host, args.port)) {
        std::cerr << "[-] Auth connection failed\n";
        return 1;
    }

    if (!auth.Login(args.account, args.password)) {
        std::cerr << "[-] Auth login failed\n";
        auth.Disconnect();
        return 1;
    }

    std::vector<RealmInfo> realms;
    if (!auth.FetchRealmList(realms)) {
        std::cerr << "[-] No realms available\n";
        auth.Disconnect();
        return 1;
    }

    std::cout << "[+] Auth login successful!\n";
    std::cout << "[*] Realms available: " << realms.size() << "\n";
    for (auto& r : realms) {
        std::cout << "    - " << r.name << " (" << r.address << ":" << r.port << ")" << "\n";
    }

    // Test mode: stop here
    if (args.testOnly) {
        auth.Disconnect();
        std::cout << "\n[+] Test PASSED - Auth connection and login successful!\n";
        return 0;
    }

    RealmInfo realm = realms[0];
    AuthResult authResult = auth.GetResult();
    auth.Disconnect();

    // ---- Step 2: World 服务器连接 ----
    std::cout << "\n[*] Connecting to World Server " << realm.address << ":" << realm.port << "...\n";
    WorldSocket world(realm.address, realm.port);
    world.SetUsername(args.account);

    if (!world.Connect()) {
        std::cerr << "[-] World connection failed\n";
        return 1;
    }

    if (!world.RecvAuthChallenge()) {
        std::cerr << "[-] Auth challenge failed\n";
        return 1;
    }

    if (!world.SendAuthSession(authResult, args.account, realm.realmId)) {
        std::cerr << "[-] Auth session send failed\n";
        return 1;
    }

    uint8 authResp;
    uint32 billingFlags;
    if (!world.WaitAuthResponse(authResp, billingFlags)) {
        std::cerr << "[-] Auth response failed: " << (int)authResp << "\n";
        return 1;
    }

    if (authResp != 0) {
        std::cerr << "[-] Auth response error: " << (int)authResp << "\n";
        return 1;
    }

    std::cout << "[+] World server authenticated!\n";

    // ---- Step 3: 角色列表 ----
    std::vector<CharacterInfo> chars;
    if (!world.RecvCharacterList(chars)) {
        std::cerr << "[-] Failed to get character list\n";
        return 1;
    }

    if (chars.empty()) {
        std::cerr << "[-] No characters on this account\n";
        return 1;
    }

    for (const auto& ch : chars) {
        std::cout << "  [" << ch.name << "] Lv" << (int)ch.level
                  << " Race:" << (int)ch.race << " Class:" << (int)ch.clazz
                  << " Map:" << ch.mapId << "\n";
    }

    if (args.listOnly) {
        std::cout << "\n[+] Character list retrieved successfully!\n";
        return 0;
    }

    // 选择角色
    std::string charName = args.character;
    if (charName.empty()) charName = chars[0].name;

    CharacterInfo* chosen = nullptr;
    for (auto& ch : chars) {
        if (ch.name == charName) { chosen = &ch; break; }
    }

    if (!chosen) {
        std::cerr << "[-] Character '" << charName << "' not found\n";
        return 1;
    }

    std::cout << "\n[*] Selecting character: " << chosen->name << " (Lv" << (int)chosen->level << ")...\n";

    // ---- Step 4: 进入世界 ----
    if (!world.LoginCharacter(chosen->guid)) {
        std::cerr << "[-] Character login failed\n";
        return 1;
    }

    if (!world.WaitWorldEnter()) {
        std::cerr << "[-] Failed to enter world\n";
        return 1;
    }

    world.SendActiveMover(chosen->guid);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Drain initial login packets
    std::cout << "[*] Draining login packets...\n";
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    while (std::chrono::steady_clock::now() < deadline) {
        uint16 cmd;
        std::vector<uint8> payload;
        if (!world.RecvPacketNonBlocking(cmd, payload)) break;
        if (cmd == SMSG_LOGOUT_COMPLETE) {
            std::cerr << "[-] Kicked during login\n";
            return 1;
        }
    }

    std::cout << "\n[+] " << chosen->name << " entered the world!\n";

    // ---- Bot 模式 ----
    if (!args.botTarget.empty()) {
        std::cout << "[*] Setting bot mode target: " << args.botTarget << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        world.SendChatMessage("/bot set " + args.botTarget);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        world.SendChatMessage("/bot list");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    } else {
        world.SendChatMessage("/bot list");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    // ---- Step 5: 保活循环 ----
    std::cout << "\n[*] Starting keep-alive loop (Ctrl+C to stop)...\n\n";

    uint32 pingSeq = 0;
    int pingFailCount = 0;
    auto lastPing = std::chrono::steady_clock::now();

    while (g_running && world.IsConnected()) {
        uint16 cmd;
        std::vector<uint8> payload;
        while (world.RecvPacketNonBlocking(cmd, payload)) {
            if (cmd == SMSG_LOGOUT_COMPLETE) {
                std::cout << "\n[*] Logout complete, exiting...\n";
                return 0;
            }
        }

        if (!world.IsConnected()) {
            std::cerr << "[-] Connection lost\n";
            break;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPing);
        if (elapsed.count() >= 30000) {
            if (world.SendPing(pingSeq++)) {
                pingFailCount = 0;
                auto nowStr = std::chrono::system_clock::now();
                auto timeT = std::chrono::system_clock::to_time_t(nowStr);
                char timeBuf[64];
                strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", localtime(&timeT));
                std::cout << "[" << timeBuf << "] Ping OK (seq=" << pingSeq - 1 << ")\n";
            } else {
                pingFailCount++;
                std::cerr << "[-] Ping failed (" << pingFailCount << "/3)\n";
                if (pingFailCount >= 3) break;
            }
            lastPing = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    world.Disconnect();
    std::cout << "\n[+] Client disconnected. Goodbye!\n";
    return 0;
}

int main(int argc, char** argv) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    if (argc < 2) {
        printHelp();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    Args args = parseArgs(argc, argv);

    if (args.account.empty() || args.password.empty()) {
        std::cerr << "Error: --account and --password are required\n";
        printHelp();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    int result = runLoginLoop(args);

#ifdef _WIN32
    WSACleanup();
#endif

    return result;
}