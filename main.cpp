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

Options:
    --account       账号用户名
    --password      密码
    --character     角色名（可选，不指定则选第一个角色）
    --host          Auth 服务器地址 (默认: 127.0.0.1)
    --port          Auth 服务器端口 (默认: 3724)
    --config        指定配置文件路径 (默认: config.ini)

Config File Format (config.ini):
    [Client]
    username = your_account
    password = your_password
    host = 127.0.0.1
    port = 3724
    character = MyHero

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
    std::string configFile = "config.ini";
    bool listOnly = false;
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
            else if (key == "action") {
                args.action = value;
                if (value == "list") { args.listOnly = true; args.action = "list"; }
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

        if (arg == "login" || arg == "list") {
            args.action = arg;
            if (arg == "list") args.listOnly = true;
        }
        else if (i + 1 < argc) {
            std::string next = argv[++i];
            if (arg == "--account" || arg == "-a") args.account = next;
            else if (arg == "--password" || arg == "-p") args.password = next;
            else if (arg == "--character" || arg == "-c") args.character = next;
            else if (arg == "--host" || arg == "-H") args.host = next;
            else if (arg == "--port" || arg == "-P") args.port = uint16(std::atoi(next.c_str()));
        }
    }

    return args;
}

int runLoginLoop(const Args& args) {
    // 自动重连（合理版，遵循真实客户端机制）：
    //  - 只在 TCP 真断(connection_lost)或连接类失败时重连；服务器明确登出则正常退出
    //  - PONG 超时已不做任何动作(fire-and-forget)，绝不因此断线(P-013)
    //  - 重连先重建 TCP/IP：重新走 auth→realm→world→进世界，带阶梯退避
    static const int backoffSec[] = {5, 15, 30, 60, 60, 60};
    const int backoffCount = (int)(sizeof(backoffSec) / sizeof(backoffSec[0]));
    int reconnectAttempt = 0;

retry_login:
    if (!g_running) return 0;
    if (reconnectAttempt > 0) {
        int idx = (reconnectAttempt - 1 < backoffCount) ? (reconnectAttempt - 1) : (backoffCount - 1);
        int waitSec = backoffSec[idx];
        std::cerr << "\n[reconnect] attempt #" << reconnectAttempt
                  << " (previous session dropped), reconnecting in " << waitSec << "s...\n";
        for (int i = 0; i < waitSec && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_running) return 0;
    }
    ++reconnectAttempt;

    std::cout << "\n========================================\n";
    std::cout << "  WoW Standalone Client Simulator\n";
    std::cout << "========================================\n\n";
    std::cout << "Account: " << args.account << "\n";
    std::cout << "Host:    " << args.host << ":" << args.port << "\n";
    if (!args.character.empty())
        std::cout << "Char:    " << args.character << "\n";
    std::cout << "\n";

    // ---- Step 1: Auth 认证 ----
    std::cout << "[*] Connecting to Auth Server...\n";
    AuthSocket auth;
    if (!auth.Connect(args.host, args.port)) {
        std::cerr << "[-] Auth connection failed\n";
        goto retry_login;   // 连接类失败 → 重建 TCP 重连
    }

    if (!auth.Login(args.account, args.password)) {
        std::cerr << "[-] Auth login failed\n";
        auth.Disconnect();
        goto retry_login;   // 认证失败(含服务器临时不可用) → 重连(保留日志便于诊断)
    }

    std::vector<RealmInfo> realms;
    if (!auth.FetchRealmList(realms)) {
        std::cerr << "[-] No realms available\n";
        auth.Disconnect();
        goto retry_login;   // 连接类失败 → 重连
    }

    std::cout << "[+] Auth login successful!\n";
    std::cout << "[*] Realms available: " << realms.size() << "\n";
    for (auto& r : realms) {
        std::cout << "    - " << r.name << " (" << r.address << ":" << r.port << ")\n";
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
        goto retry_login;   // 连接类失败 → 重建 TCP 重连
    }

    if (!world.RecvAuthChallenge()) {
        std::cerr << "[-] Auth challenge failed\n";
        goto retry_login;   // 连接类失败 → 重连
    }

    if (!world.SendAuthSession(authResult, args.account, realm.realmId)) {
        std::cerr << "[-] Auth session send failed\n";
        goto retry_login;   // 连接类失败 → 重连
    }

    uint8 authResp;
    uint32 billingFlags;
    if (!world.WaitAuthResponse(authResp, billingFlags)) {
        std::cerr << "[-] Auth response failed: " << (int)authResp << "\n";
        goto retry_login;   // 连接类失败 → 重连
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
        goto retry_login;   // 连接类失败 → 重建 TCP 重连
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
        goto retry_login;   // 连接类失败 → 重建 TCP 重连
    }

    if (!world.WaitWorldEnter()) {
        std::cerr << "[-] Failed to enter world\n";
        goto retry_login;   // 连接类失败 → 重建 TCP 重连
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
            goto retry_login;   // 进世界被踢(可能是旧会话占用) → 重连
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

    // ---- 组队邀请 / Bot 模式 / 通用聊天命令（测试辅助）已移除 ----

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
    bool pingAwait = false;   // 已发送 CMSG_PING, 等待服务器 SMSG_PONG
    bool pongOk = false;      // 主循环收包处收到 SMSG_PONG
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
            // 服务器回应客户端 ping (SMSG_PONG): 由状态机判定 ping 成功。
            // PONG 必须在主循环正常收包处检测, 不能在 SendPing 里同步等待
            // (等待循环会吞掉位置更新/TimeSync 包, 位置更新风暴挤掉 PONG 导致误判掉线)。
            if (cmd == SMSG_PONG) {
                pongOk = true;
                pingAwait = false;
            }
            // 打印服务器聊天消息（.bot 命令返回等）, 便于测试验证
            if (cmd == SMSG_MESSAGE_CHAT) {
                std::cout << "[DBG] SMSG_MESSAGE_CHAT size=" << payload.size() << "\n" << std::flush;
                if (payload.size() <= 12) continue;
                size_t off = 0;
                uint8 chatType = payload[off++];
                off += 4;                     // language (int32)
                // sender guid: packed(可变), 非固定8字节
                int consumed = 0;
                if (off >= payload.size()) continue;
                readPackedGuid(payload.data() + off, consumed);
                off += consumed;
                if (off + 4 > payload.size()) continue;
                off += 4;                     // flags
                // receiver guid: packed
                if (off >= payload.size()) continue;
                readPackedGuid(payload.data() + off, consumed);
                off += consumed;
                // message: len(4) + text
                if (off + 4 > payload.size()) continue;
                uint32 textLen = readU32LE(payload.data() + off);
                off += 4;
                size_t avail = payload.size() - off;
                uint32 n = std::min(textLen, (uint32)avail);
                std::string text((const char*)payload.data() + off, n);
                if (!text.empty())
                    std::cout << "[Chat] type=" << int(chatType) << " " << text << "\n" << std::flush;
            }
            // GM 命令返回(SMSG_GM_MESSAGECHAT 0x3B3): 同 MESSAGE_CHAT 但 senderGUID 为 packed
            if (cmd == SMSG_GM_MESSAGECHAT) {
                if (payload.size() <= 12) continue;
                size_t off = 0;
                uint8 gtype = payload[off++];
                off += 4;                     // language
                int consumed = 0;
                if (off >= payload.size()) continue;
                readPackedGuid(payload.data() + off, consumed);
                off += consumed;
                if (off + 4 > payload.size()) continue;
                off += 4;                     // flags
                if (off >= payload.size()) continue;
                readPackedGuid(payload.data() + off, consumed);
                off += consumed;
                if (off + 4 > payload.size()) continue;
                uint32 textLen = readU32LE(payload.data() + off);
                off += 4;
                size_t avail = payload.size() - off;
                uint32 n = std::min(textLen, (uint32)avail);
                std::string text((const char*)payload.data() + off, n);
                if (!text.empty())
                    std::cout << "[GM] type=" << int(gtype) << " " << text << "\n" << std::flush;
            }
            // 服务器通知(SMSG_NOTIFICATION 0x1CB): len(4)+text, 用于定位命令被拦截原因
            if (cmd == SMSG_NOTIFICATION) {
                if (payload.size() >= 4) {
                    uint32 nlen = readU32LE(payload.data());
                    uint32 n = std::min(nlen, (uint32)(payload.size() - 4));
                    std::string text((const char*)payload.data() + 4, n);
                    if (!text.empty())
                        std::cout << "[Notify] " << text << "\n" << std::flush;
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
            if (world.SendMoveHeartbeat()) {
                if (++heartbeatCount % 3 == 0)
                    std::cout << logTag << " Move heartbeat sent (" << heartbeatCount << ")\n" << std::flush;
            } else {
                std::cerr << logTag << " Move heartbeat FAILED (guid=" << chosen->guid << ")\n" << std::flush;
            }
            lastMove = now;
        }

        // 异步 Ping 状态机: 每 30 秒发 CMSG_PING, 主循环收包检测 SMSG_PONG。
        // 原则（遵循真实客户端 fire-and-forget 机制，杜绝"TCP 没断却自断"）：
        //   - 只负责发 ping；PONG 收到与否只记日志，绝不因 PONG 未到主动断线
        //   - 服务器判活只看 client 是否持续发 CMSG_PING（HandlePing 更新 _LastPingTime），
        //     PONG 未及时收到不代表连接有问题（位置更新风暴会使 recv-q 积压、PONG 排队延迟）
        //   - TCP 真断统一由主循环 IsConnected() 检测（connection_lost）处理，PONG 超时
        //     不属于断线（P-013 根因：同步等待/超时判定误判主动断）
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPing);
        if (!pingAwait) {
            if (elapsed.count() >= 30000) {
                if (world.SendPing(pingSeq++)) {
                    pingAwait = true;
                    pongOk = false;
                    lastPing = now;   // 记录发送时刻, 用于超时提示
                } else {
                    // SendPing 发送失败: 仅提示, 不断线。
                    // TCP 若真断, 下一次 recv 会失败, 由 connection_lost 统一处理。
                    std::cerr << logTag << "[-] Ping send failed (ignored)\n";
                    lastPing = now;
                }
            }
        } else if (pongOk) {
            pingFailCount = 0;
            pingAwait = false;
            auto nowStr = std::chrono::system_clock::now();
            auto timeT = std::chrono::system_clock::to_time_t(nowStr);
            char timeBuf[64];
            strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", localtime(&timeT));
            std::cout << "[" << timeBuf << "] Ping OK (seq=" << pingSeq - 1 << ")\n";
        } else if (elapsed.count() >= 30000 + 10000) {
            // PONG 超时(10s): 保留日志, 但不做任何动作（不断线/不重连/不 dumpDrop）。
            // 遵循真实客户端 fire-and-forget 机制: PONG 未及时收到不代表连接异常
            // （位置更新风暴会使 recv-q 积压、PONG 在缓冲排队延迟）。P-013 根因修复。
            std::cerr << logTag << "[-] Ping timeout (seq=" << pingSeq - 1 << ", no action)\n";
            pingFailCount = 0;
            pingAwait = false;   // 允许重新发送
            lastPing = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    world.Disconnect();

    // 走到这里 = TCP 真断(connection_lost, 主循环 break)。
    // server_kick_logout(服务器明确登出)已在主循环内正常 return 0, 不会到这里。
    // 遵循合理自动重连: 只在 TCP 真断时重连, 先重建 TCP/IP(重新走 auth→world→进世界)。
    std::cout << "\n[+] Session ended (connection lost), will reconnect.\n";
    goto retry_login;
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
