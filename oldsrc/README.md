# 旧版本源代码 (oldsrc)

这是**依赖 AzerothCore** 的旧版本客户端模拟器代码。

## 编译依赖
- AzerothCore (libcommon.a)
- OpenSSL
- MySQL (用于数据库连接)

## 编译方法
需要在 AzerothCore 环境中编译，或引用 AzerothCore 的头文件和库。

```bash
g++ -std=c++17 main.cpp AuthSocket.cpp WorldSocket.cpp \
    -I/path/to/azerothcore/src/common \
    -L/path/to/azerothcore/build/src/common \
    -lcommon -lssl -lcrypto -lz -lmysqlclient
```

## 说明
此目录保留作为参考，推荐使用独立版本（根目录或 standalone 分支）。
