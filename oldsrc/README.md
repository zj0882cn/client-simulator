# 旧版本源代码 (oldsrc)

这是**依赖 AzerothCore 加密模块**的旧版本客户端模拟器代码。

## 依赖
- g++ (C++17)
- OpenSSL 开发库
- zlib 开发库

## 编译

```bash
bash build.sh
```

编译脚本会自动编译 `ac_deps/` 目录下的 AzerothCore 加密模块。

## 目录结构

```
oldsrc/
├── main.cpp              # 主程序
├── AuthSocket.h/cpp      # AuthServer 认证
├── WorldSocket.h/cpp     # WorldServer 连接
├── SRP6Helpers.h         # SRP6 协议辅助
├── BotState.h            # Bot 状态定义
├── build.sh              # 编译脚本
├── README.md
└── ac_deps/              # AzerothCore 加密模块（已提取）
    ├── Define.h
    ├── CompilerDefs.h
    ├── Debugging/Errors.h
    ├── Utilities/Util.h
    └── Cryptography/
        ├── BigNumber.h/cpp
        ├── ARC4.h/cpp
        ├── HMAC.h
        ├── CryptoHash.h
        ├── CryptoConstants.h
        ├── CryptoRandom.h/cpp
        ├── OpenSSLCrypto.h/cpp
        └── Authentication/
            ├── SRP6.h/cpp
            └── AuthDefines.h
```

## 运行

```bash
cd build
./client-simulator config.ini 1
```

## 说明
- 此版本保留原始 AzerothCore 依赖结构
- 推荐使用独立版本（`standalone` 分支），无需编译 AzerothCore 模块
