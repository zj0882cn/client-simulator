=======================================
  WoW Client Simulator
  魔兽世界客户端模拟器
=======================================

【使用方法】
1. 双击 wow_client.exe 运行（自动读取同目录下的 config.ini）
2. 或在命令行中运行: wow_client.exe [选项]

【配置文件 config.ini】
  在同目录下创建 config.ini，格式如下：
  
  [Client]
  username = your_account
  password = your_password
  host = 127.0.0.1
  port = 3724
  character = MyHero     (可选)
  bot_target = BotTarget (可选)
  action = login         (login / list / test)

  示例 (连接远程服务器):
  
  [Client]
  username = stong
  password = 111111
  host = 119.3.216.43
  port = 3724

【命令行参数】
  -u, --username <name>  账号名
  -p, --password <pass>  密码
  -h, --host <ip>        服务器地址
  -P, --port <port>      认证服务器端口
  -c, --config <file>    指定配置文件路径
  --help                 显示帮助信息

【示例】
  # 使用配置文件 (推荐)
  wow_client.exe

  # 命令行指定参数
  wow_client.exe -u test -p test -h 127.0.0.1

  # 连接远程服务器
  wow_client.exe -u myaccount -p mypassword -h 119.3.216.43

【系统要求】
  - Windows 7/8/10/11 (64-bit)
  - 无需额外安装任何运行时
  - 仅依赖 Windows 系统自带的 DLL 文件

【故障排查】
  1. 确保 config.ini 与 wow_client.exe 在同一目录
  2. 检查配置文件格式是否正确（[Client] 节）
  3. 查看控制台日志可获取详细调试信息

【技术信息】
  - 基于 AzerothCore 协议实现
  - 支持 SRP6 认证协议
  - 支持 ARC4 加密通信
  - 静态编译，单文件部署
