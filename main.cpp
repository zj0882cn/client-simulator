#include "wow_client.h"
#include <csignal>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>

using namespace WoWClient;

static std::atomic<bool> g_running{true};

void signalHandler(int) {
    std::cout << "\n[Main] Signal received, shutting down...\n";
    g_running = false;
}

void printHelp() {
    std::cout << R"(
WoW Standalone Client Simulator

Usage:
    wow_client.exe                      (读取 config.ini 配置运行)
    wow_client.exe --config <file>      (指定配置文件)
    wow_client.exe login --account <account> --password <password> [--character <name>] [--host <ip>]
    wow_client.exe list  --account <account> --password <password> [--host <ip>]
    wow_client.exe test  --account <account> --password <password> [--host <ip>]

Options:
    --account       账号用户名
    --password      密码
    --character     角色名（可选，不指定则选第一个角色）
    --host          Auth 服务器地址 (默认: 127.0.0.1)
    --port          Auth 服务器端口 (默认: 3724)
    --bot-target    Bot 模式目标玩家名 (可选)
    --config        指定配置文件路径 (默认: config.ini)

Config File Format (config.ini):
    [Client]
    username = your_account
    password = your_password
    host = 127.0.0.1
    port = 3724
    character = MyHero
    bot_target = BotTarget

Examples:
    wow_client.exe                          (从 config.ini 读取)
    wow_client.exe login --account MYACC --password mypass --character MyHero
    wow_client.exe --config D:\config.ini
)";
}

struct Args {
    std::string action = "login";
    std::string account;
    std::string password;
    std::string character;
    std::string host = "127.0.0.1";
    uint16 port = AUTH_SERVER_PORT;
    std::string botTarget;
    std::string configFile = "config.ini";
    // For action=create: name of the character to create.
    std::string createName;
    // Optional: invite this player to group after entering world.
    std::string inviteTarget;
    // Optional: simulate walking toward this target ("x,y,z") to test
    // bot follow behaviour. Only the master should use this.
    std::string moveTo;
    // Optional: send one or more chat commands (comma-separated) after
    // entering the world, e.g. ".bot stay, .bot follow".
    std::string chatCommand;
    bool listOnly = false;
    bool testOnly = false;
};

std::string trimString(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

void loadConfig(const std::string& filename, Args& args) {
    std::ifstream file(filename);
    if (!file.is_open()) return;

    std::string line;
    std::string section;
    while (std::getline(file, line)) {
        line = trimString(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        if (line[0] == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trimString(line.substr(0, eq));
        std::string value = trimString(line.substr(eq + 1));

        if (section == "Client" || section == "client" || section == "auth") {
            if (key == "username" || key == "account") args.account = value;
            else if (key == "password") args.password = value;
            else if (key == "host") args.host = value;
            else if (key == "port") args.port = uint16(std::atoi(value.c_str()));
            else if (key == "character") args.character = value;
            else if (key == "bot_target") args.botTarget = value;
            else if (key == "invite_target") args.inviteTarget = value;
            else if (key == "move_to") args.moveTo = value;
            else if (key == "chat_command") args.chatCommand = value;
            else if (key == "create_name") args.createName = value;
            else if (key == "action") {
                args.action = value;
                if (value == "list") { args.listOnly = true; args.action = "list"; }
                else if (value == "test") { args.testOnly = true; args.action = "test"; }
                else if (value == "create") { args.action = "create"; }
                else args.action = "login";
            }
        }
    }

    std::cout << "[Config] Loaded config from: " << filename << "\n";
}

Args parseArgs(int argc, char** argv) {
    Args args;
    std::string configFile;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-?") {
            printHelp();
            exit(0);
        }
        if (arg == "--config" && i + 1 < argc) {
            configFile = argv[++i];
            args.configFile = configFile;
        }
    }

    if (!configFile.empty() || argc <= 2) {
        std::string cfgPath = configFile.empty() ? args.configFile : configFile;
        std::ifstream testFile(cfgPath);
        if (testFile.good()) {
            testFile.close();
            loadConfig(cfgPath, args);
        }
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) { ++i; continue; }

        if (arg == "login" || arg == "list" || arg == "test" || arg == "create") {
            args.action = arg;
            if (arg == "list") args.listOnly = true;
            if (arg == "test") args.testOnly = true;
        }
        else if (i + 1 < argc) {
            std::string next = argv[++i];
            if (arg == "--account" || arg == "-a") args.account = next;
            else if (arg == "--password" || arg == "-p") args.password = next;
            else if (arg == "--character" || arg == "-c") args.character = next;
            else if (arg == "--create-name") args.createName = next;
            else if (arg == "--host" || arg == "-H") args.host = next;
            else if (arg == "--port" || arg == "-P") args.port = uint16(std::atoi(next.c_str()));
            else if (arg == "--bot-target" || arg == "-t") args.botTarget = next;
            else if (arg == "--invite" || arg == "-i") args.inviteTarget = next;
            else if (arg == "--move-to") args.moveTo = next;
            else if (arg == "--chat") args.chatCommand = next;
        }
    }

    return args;
}

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
        std::cout << "    - " << r.name << " (" << r.address << ":" << r.port << ")\n";
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

    // IMPORTANT: Auth Server updates session_key asynchronously.
    // We need to wait for the database write to complete before
    // connecting to World Server, otherwise session_key may be NULL.
    std::cout << "[*] Waiting for session_key sync (2s)...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

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

    if (!isAuthResponseOk(authResp)) {
        std::cerr << "[-] Auth response error: " << (int)authResp
                  << " (" << authResponseName(authResp) << ")\n";
        if (authResp == AUTH_REJECT) {
            std::cerr << "    [提示] 服务器拒绝认证 (AUTH_REJECT),常见原因:\n";
            std::cerr << "    - 世界服务器 (worldserver) 未运行,或处于关闭/维护状态\n";
            std::cerr << "    - Warden 检查失败(账号 OS 字段不是 Win/OSX)\n";
            std::cerr << "    - 客户端 IP 被服务器封禁\n";
            std::cerr << "    建议检查服务器端 worldserver 进程状态和日志。\n";
        } else if (authResp == AUTH_VERSION_MISMATCH) {
            std::cerr << "    [提示] 客户端版本与服务器不匹配,请检查 WOW_BUILD (当前: " << WOW_BUILD << ")\n";
        } else if (authResp == AUTH_UNKNOWN_ACCOUNT) {
            std::cerr << "    [提示] 账号不存在或 worldserver 数据库中无此账号\n";
        } else if (authResp == AUTH_INCORRECT_PASSWORD) {
            std::cerr << "    [提示] 密码错误或 SRP6 会话密钥不匹配\n";
        } else if (authResp == AUTH_ALREADY_ONLINE) {
            std::cerr << "    [提示] 该账号已在世界服务器在线\n";
        }
        return 1;
    }

    std::cout << "[+] World server authenticated!\n";

    // ---- Step 3: 角色列表 ----
    std::vector<CharacterInfo> chars;
    if (!world.RecvCharacterList(chars)) {
        std::cerr << "[-] Failed to get character list\n";
        return 1;
    }

    // action=create: 如果账号没有角色（或想新建），发送 CMSG_CHAR_CREATE 建一个，
    // 然后重新获取角色列表继续登录流程。
    if (args.action == "create") {
        std::string createName = args.createName.empty() ? args.character : args.createName;
        if (createName.empty()) {
            std::cerr << "[-] action=create 需要 --create-name 或 --character 指定角色名\n";
            return 1;
        }

        bool exists = false;
        for (const auto& ch : chars) {
            if (ch.name == createName) { exists = true; break; }
        }

        if (exists) {
            std::cout << "[*] Character '" << createName << "' already exists, skipping creation\n";
        } else {
            // 人族(Human) 战士(Warrior) 男性: race=1, class=1, gender=0
            if (!world.CreateCharacter(createName, 1, 1, 0, 1, 0, 1, 0, 0)) {
                std::cerr << "[-] Character creation failed\n";
                return 1;
            }
            // 重新获取角色列表
            chars.clear();
            if (!world.RecvCharacterList(chars)) {
                std::cerr << "[-] Failed to get character list after creation\n";
                return 1;
            }
        }
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
    world.SetMover(chosen->guid, chosen->pos, 0.0f);
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
        if (cmd == SMSG_TIME_SYNC_REQ && payload.size() >= 4) {
            world.SendTimeSyncResponse(readU32LE(payload.data()));
        }
    }

    std::cout << "\n[+] " << chosen->name << " entered the world!\n";

    // Prefix periodic output with "[account/Char]" so multiple simulator
    // instances are distinguishable in a shared log.
    std::string logTag = "[" + args.account + "/" + chosen->name + "]";
    world.SetLogPrefix(logTag);

    // ---- 组队邀请 ----
    if (!args.inviteTarget.empty()) {
        // invite_target 支持逗号分隔多个角色名
        std::stringstream ss(args.inviteTarget);
        std::string target;
        while (std::getline(ss, target, ',')) {
            target = trimString(target);
            if (target.empty()) continue;
            std::cout << "[*] Inviting group member: " << target << "\n";
            world.SendGroupInvite(target);
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        }
    }

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

    // ---- 通用聊天命令（宠物式命令等）----
    if (!args.chatCommand.empty()) {
        std::stringstream ss(args.chatCommand);
        std::string oneCmd;
        while (std::getline(ss, oneCmd, ',')) {
            oneCmd = trimString(oneCmd);
            if (oneCmd.empty()) continue;
            std::cout << "[*] Chat command: " << oneCmd << "\n";
            world.SendChatMessage(oneCmd);
            std::this_thread::sleep_for(std::chrono::milliseconds(600));
        }
    }

    // ---- Step 5: 保活循环 ----
    std::cout << "\n[*] Starting keep-alive loop (Ctrl+C to stop)...\n\n";

    // 进入世界后立即发送一次移动心跳, 验证客户端→服务器加密发送正常
    std::cout << "[*] Test immediate move heartbeat...\n" << std::flush;
    if (world.SendMoveHeartbeat()) {
        std::cout << "[+] Immediate move heartbeat OK\n" << std::flush;
    } else {
        std::cerr << "[-] Immediate move heartbeat FAILED\n" << std::flush;
    }

    uint32 pingSeq = 0;
    int pingFailCount = 0;
    auto lastPing = std::chrono::steady_clock::now();
    auto lastMove = std::chrono::steady_clock::now();
    int heartbeatCount = 0;

    long loopCount = 0;

    // Disconnect diagnostics: track uptime and recently received opcodes so we
    // can tell WHY a session dropped (server kick / connection lost / ping).
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint16> lastPkt;
    auto dumpDrop = [&](const char* reason) {
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - t0).count();
        std::cerr << logTag << " DISCONNECT reason=" << reason
                  << " uptime_s=" << sec
                  << " loop=" << loopCount
                  << " heartbeat=" << heartbeatCount
                  << " ping_seq=" << pingSeq
                  << " ping_fail=" << pingFailCount << "\n";
        std::cerr << logTag << " last packets:";
        for (uint16 c : lastPkt)
            std::cerr << " " << std::hex << c << std::dec;
        std::cerr << "\n";
    };

    // Parse optional move target ("x,y,z") for follow testing.
    Vec3 moveTarget{0,0,0};
    bool hasMoveTarget = false;
    if (!args.moveTo.empty()) {
        std::stringstream ss(args.moveTo);
        std::string tok;
        int idx = 0;
        while (std::getline(ss, tok, ',')) {
            float v = (float)std::atof(tok.c_str());
            if (idx == 0) moveTarget.x = v;
            else if (idx == 1) moveTarget.y = v;
            else if (idx == 2) moveTarget.z = v;
            ++idx;
        }
        hasMoveTarget = idx >= 2;
        if (hasMoveTarget)
            std::cout << "[*] Simulating walk toward " << moveTarget.x
                      << "," << moveTarget.y << "," << moveTarget.z << "\n";
    }

    while (g_running && world.IsConnected()) {
        ++loopCount;

        // 内层循环每轮最多处理 32 个包, 避免被持续到达的更新包
        // (如 SMSG_MONSTER_MOVE) 阻塞, 确保能执行移动心跳和 Ping
        int processed = 0;
        uint16 cmd;
        std::vector<uint8> payload;
        while (processed < 32 && world.RecvPacketNonBlocking(cmd, payload)) {
            ++processed;
            lastPkt.push_back(cmd);
            if (lastPkt.size() > 20) lastPkt.erase(lastPkt.begin());
            if (cmd == SMSG_LOGOUT_COMPLETE) {
                std::cout << logTag << "\n[*] Logout complete, exiting...\n";
                dumpDrop("server_kick_logout");
                return 0;
            }
            // 响应服务器时间同步请求, 避免被判定为异常连接
            if (cmd == SMSG_TIME_SYNC_REQ && payload.size() >= 4) {
                world.SendTimeSyncResponse(readU32LE(payload.data()));
            }
            // 打印服务器聊天消息（.bot 命令返回等）, 便于测试验证
            if (cmd == SMSG_MESSAGE_CHAT) {
                std::cout << "[DBG] SMSG_MESSAGE_CHAT size=" << payload.size() << "\n" << std::flush;
                if (payload.size() <= 30) continue;
                size_t off = 0;
                uint8 chatType = payload[off++];
                off += 4;                     // language
                off += 8;                     // sender guid
                off += 4;                     // unk
                off += 8;                     // target guid
                if (off + 4 <= payload.size()) {
                    uint32 nameLen = readU32LE(payload.data() + off);
                    off += 4;
                    off += std::min<size_t>(nameLen, payload.size() - off);
                    if (off + 4 <= payload.size()) {
                        uint32 textLen = readU32LE(payload.data() + off);
                        off += 4;
                        size_t avail = payload.size() - off;
                        uint32 n = std::min(textLen, (uint32)avail);
                        std::string text((const char*)payload.data() + off, n);
                        if (!text.empty())
                            std::cout << "[Chat] type=" << int(chatType) << " " << text << "\n" << std::flush;
                    }
                }
            }
        }

        if (!world.IsConnected()) {
            std::cerr << logTag << "[-] Connection lost\n";
            dumpDrop("connection_lost");
            break;
        }

        auto now = std::chrono::steady_clock::now();

        // 定期发送移动心跳包, 模拟正常客户端行为(即使角色静止也持续上报移动状态)
        auto moveElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastMove);
        if (moveElapsed.count() >= 2000) {
            // If walking to a target, advance the position a bit each tick.
            if (hasMoveTarget) {
                Vec3 cur = world.GetMoverPos();
                float dx = moveTarget.x - cur.x;
                float dy = moveTarget.y - cur.y;
                float dz = moveTarget.z - cur.z;
                float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
                if (dist > 1.0f) {
                    float step = 8.0f; // move ~8 yards per tick
                    float nx = cur.x + dx / dist * step;
                    float ny = cur.y + dy / dist * step;
                    float nz = cur.z + dz / dist * step;
                    world.SetMover(world.GetMoverGuid(), Vec3{nx, ny, nz}, 0.0f);
                    std::cout << logTag << " Moved to " << nx << "," << ny << "," << nz << "\n" << std::flush;
                }
            }
            if (world.SendMoveHeartbeat()) {
                if (++heartbeatCount % 3 == 0)
                    std::cout << logTag << " Move heartbeat sent (" << heartbeatCount << ")\n" << std::flush;
            } else {
                std::cerr << logTag << " Move heartbeat FAILED (guid=" << chosen->guid << ")\n" << std::flush;
            }
            lastMove = now;
        }

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
                std::cerr << logTag << "[-] Ping failed (" << pingFailCount << "/3)\n";
                if (pingFailCount >= 3) {
                    dumpDrop("ping_timeout");
                    break;
                }
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
        std::ifstream testFile("config.ini");
        if (testFile.good()) {
            testFile.close();
            std::cout << "[Info] No arguments, using config.ini\n\n";
        } else {
            printHelp();
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }

    Args args = parseArgs(argc, argv);

    if (args.account.empty() || args.password.empty()) {
        std::cerr << "Error: --account and --password are required (or set in config.ini)\n";
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
