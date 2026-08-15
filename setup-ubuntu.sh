#!/bin/bash
# WoW Client Simulator - Ubuntu 一键部署脚本
# Usage: bash setup-ubuntu.sh

set -e

echo "=============================================="
echo "  WoW Client Simulator - Ubuntu 部署脚本"
echo "=============================================="
echo ""

# 1. 更新系统包
echo "[1/4] 更新系统包..."
sudo apt-get update -qq

# 2. 安装依赖
echo "[2/4] 安装编译依赖..."
sudo apt-get install -y -qq \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libz-dev \
    zlib1g-dev

echo ""
echo "[3/4] 拉取代码..."

# 3. 克隆或更新代码
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/client-simulator"

if [ -d "$PROJECT_DIR" ]; then
    echo "  仓库已存在，更新中..."
    cd "$PROJECT_DIR"
    git pull
else
    echo "  克隆仓库..."
    git clone https://github.com/zj0882cn/client-simulator.git
    cd "$PROJECT_DIR"
fi

echo ""
echo "[4/4] 编译项目..."

# 4. 编译
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

echo ""
echo "=============================================="
echo "  部署完成！"
echo "=============================================="
echo ""
echo "  可执行文件: $PROJECT_DIR/build/wow_client"
echo ""
echo "  运行方式:"
echo "    cd $PROJECT_DIR/build"
echo "    ./wow_client              # 使用 config.ini"
echo "    ./wow_client -u test -p test -h 127.0.0.1"
echo ""
echo "  创建 config.ini:"
echo "    cat > config.ini << 'EOF'"
echo "    [Client]"
echo "    username = your_account"
echo "    password = your_password"
echo "    host = 127.0.0.1"
echo "    port = 3724"
echo "    EOF"
echo ""

# 创建默认配置文件
cd "$PROJECT_DIR/build"
if [ ! -f "config.ini" ]; then
    cat > config.ini << 'EOF'
[Client]
username = test
password = test
host = 127.0.0.1
port = 3724
EOF
    echo "  已创建默认 config.ini"
fi

echo "  请修改 config.ini 中的账号密码和服务器地址后运行"
echo ""
