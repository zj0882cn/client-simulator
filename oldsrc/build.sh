#!/bin/bash
#
# build.sh - 编译旧版客户端（依赖 AzerothCore 加密模块）
#
# 依赖: g++ (C++17), OpenSSL, zlib
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "============================================"
echo "  WoW Client Simulator - 旧版编译"
echo "============================================"
echo ""

echo "[1/4] 检查编译环境..."
if ! command -v g++ &> /dev/null; then
    echo "错误: 未找到 g++ 编译器"
    echo "  Ubuntu/Debian: sudo apt install g++"
    exit 1
fi

if ! echo '#include <openssl/evp.h>' | g++ -x c++ -c - -o /dev/null 2>/dev/null; then
    echo "错误: 未找到 OpenSSL 开发库"
    echo "  Ubuntu/Debian: sudo apt install libssl-dev"
    exit 1
fi

if ! echo '#include <zlib.h>' | g++ -x c++ -c - -o /dev/null 2>/dev/null; then
    echo "错误: 未找到 zlib 开发库"
    echo "  Ubuntu/Debian: sudo apt install zlib1g-dev"
    exit 1
fi

echo "  ✓ 编译环境就绪"
echo ""

echo "[2/4] 准备构建目录..."
mkdir -p "$BUILD_DIR"

CXXFLAGS="-std=c++17 -O2"
INCLUDES="-I$SCRIPT_DIR -I$SCRIPT_DIR/ac_deps"

# 源文件列表（客户端 + AzerothCore 加密模块）
SOURCES=(
    "$SCRIPT_DIR/main.cpp"
    "$SCRIPT_DIR/AuthSocket.cpp"
    "$SCRIPT_DIR/WorldSocket.cpp"
    "$SCRIPT_DIR/ac_deps/Cryptography/BigNumber.cpp"
    "$SCRIPT_DIR/ac_deps/Cryptography/ARC4.cpp"
    "$SCRIPT_DIR/ac_deps/Cryptography/OpenSSLCrypto.cpp"
    "$SCRIPT_DIR/ac_deps/Cryptography/CryptoRandom.cpp"
    "$SCRIPT_DIR/ac_deps/Cryptography/Authentication/SRP6.cpp"
)

echo "[3/4] 编译源文件..."
OBJECTS=""
for src in "${SOURCES[@]}"; do
    if [ ! -f "$src" ]; then
        echo "  ⚠ 文件不存在，跳过: $(basename "$src")"
        continue
    fi
    obj_name=$(basename "$src" .cpp).o
    obj_path="$BUILD_DIR/$obj_name"
    echo "  编译 $(basename "$src")"
    g++ $CXXFLAGS $INCLUDES -c "$src" -o "$obj_path"
    OBJECTS="$OBJECTS $obj_path"
done

echo ""
echo "[4/4] 链接可执行文件..."
g++ $CXXFLAGS $OBJECTS -o "$BUILD_DIR/client-simulator" -lssl -lcrypto -lz -lpthread

echo ""
echo "============================================"
echo "  构建成功!"
echo "============================================"
echo ""
echo "  可执行文件: $BUILD_DIR/client-simulator"
echo "  使用方法:"
echo "    cd $BUILD_DIR"
echo "    ./client-simulator [config_file] [bot_count]"
echo ""
