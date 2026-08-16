# WoW Client Simulator

魔兽世界 3.3.5a (WotLK) 独立客户端模拟器，用于模拟真实游戏客户端与服务器（AzerothCore 等）进行交互。

不依赖 AzerothCore 库，不连接数据库，使用 OpenSSL 自行实现 SRP6 认证与 ARC4 加密。

## 功能特性

- ✅ **SRP6 认证**：完整实现 Auth Server 登录流程（CMD_AUTH_LOGON_CHALLENGE / PROOF / REALM_LIST）
- ✅ **World 认证**：实现 CMSG_AUTH_SESSION、加密握手（ARC4-drop1024）
- ✅ **角色管理**：获取角色列表、选择角色、进入世界
- ✅ **保活机制**：自动响应 TimeSync、发送移动心跳、定时 Ping，可长时间稳定在线
- ✅ **Bot 模式**：支持发送 `/bot` 聊天命令与服务器 Bot 系统交互
- ✅ **多模式运行**：登录（login）、角色列表（list）、认证测试（test）

## 环境依赖

- **CMake** ≥ 3.16
- **C++17** 编译器（GCC / Clang / MSVC）
- **OpenSSL** 开发库
- **zlib** 开发库

## 安装与编译

### Ubuntu / Debian

一键部署脚本（会自动安装依赖、克隆代码并编译）：

```bash
bash setup-ubuntu.sh
```

或手动编译：

```bash
# 安装依赖
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev zlib1g-dev

# 编译
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

编译产物：`build/wow_client`

### Windows

```bat
:: 需安装 CMake、Visual Studio 2022 (C++ 工具链)、OpenSSL、zlib
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

## 配置说明

复制 `config.example.ini` 为 `config.ini` 并修改：

```ini
[auth]
; 账号设置（必须与服务器数据库中的用户名一致）
account = your_account
password = your_password

; 服务器设置
host = 127.0.0.1     ; Auth 服务器地址
port = 3724          ; Auth 服务器端口

; 角色设置（可选）
character =          ; 指定角色名，留空则自动选择第一个角色
bot_target =         ; Bot 模式目标玩家名（可选）

; 操作模式: login / list / test
action = login
```

> **注意**：`character` 指定后会登录该角色进入世界；留空则自动选择列表中的第一个角色。

## 运行方法

```bash
cd build

# 1. 使用 config.ini 完整登录并进入游戏
./wow_client

# 2. 指定配置文件
./wow_client --config /path/to/config.ini

# 3. 直接命令行指定账号密码登录
./wow_client login --account MYACC --password mypass --character MyHero --host 127.0.0.1

# 4. 仅获取角色列表
./wow_client list --account MYACC --password mypass

# 5. 仅测试 Auth 认证连接
./wow_client test --account MYACC --password mypass
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `login` / `list` / `test` | 操作模式 |
| `--account` / `-a` | 账号用户名 |
| `--password` / `-p` | 密码 |
| `--character` / `-c` | 角色名（可选） |
| `--host` / `-H` | Auth 服务器地址（默认 `127.0.0.1`） |
| `--port` / `-P` | Auth 服务器端口（默认 `3724`） |
| `--bot-target` / `-t` | Bot 模式目标玩家名（可选） |
| `--config` | 配置文件路径（默认 `config.ini`） |

## 正常运行日志示例

```
[+] Auth login successful!
[*] Realms available: 1
    - 开发测试服 (119.3.216.43:8085)
[+] World server authenticated!
  [MyHero] Lv80 Race:1 Class:2 Map:0 GUID:74
[+] MyHero entered the world!
[07:15:59] Ping OK (seq=0)
[07:16:29] Ping OK (seq=1)
```

## 常见问题排查

### 1. `Auth response error: 14 (AUTH_REJECT)`

认证被服务器拒绝，常见原因：

- 世界服务器（worldserver）未运行或处于关闭/维护状态
- Warden 检查失败（正常客户端登录后账号 OS 字段问题，本模拟器已用 OSX 绕过）
- 客户端 IP 被服务器封禁

**解决**：确认 worldserver 正常运行；检查服务器端日志。

### 2. 进入世界后很快掉线

- 确认客户端持续发送心跳（本模拟器已内置移动心跳 + TimeSync 响应）
- 检查同一账号是否被其他客户端占用（同账号同 Realm 只能一个在线）

### 3. 编译报错缺少 OpenSSL

```bash
sudo apt-get install -y libssl-dev
```

### 4. `config.ini` 未生效

确认配置文件与可执行文件在同一目录，或使用 `--config` 显式指定路径。

## 项目结构

```
client-simulator/
├── CMakeLists.txt        # CMake 构建脚本
├── main.cpp              # 主程序（命令行解析、登录流程）
├── wow_client.h          # 公共头文件（常量、数据结构、SRP6、加密）
├── wow_auth.cpp          # Auth Server 认证实现
├── wow_world.cpp         # World Server 连接与协议实现
├── config.example.ini    # 配置文件示例
├── setup-ubuntu.sh       # Ubuntu 一键部署脚本
└── README.md
```

## 说明

- 仅用于技术学习与测试，请遵守所在服务器的使用条款
- 协议细节参考 AzerothCore 3.3.5a 源码实现