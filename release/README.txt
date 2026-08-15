=======================================
  WoW Client Simulator
  魔兽世界客户端模拟器
=======================================

【使用方法】
1. 双击 wow_client.exe 运行
2. 或在命令行中运行: wow_client.exe [选项]

【命令行参数】
  -u, --username <name>  账号名
  -p, --password <pass>  密码
  -h, --host <ip>        服务器地址 (默认: 127.0.0.1)
  -P, --port <port>      认证服务器端口 (默认: 3724)
  -c, --config <file>    配置文件路径 (默认: config.ini)
  --help                 显示帮助信息

【示例】
  # 使用配置文件
  wow_client.exe

  # 命令行指定参数
  wow_client.exe -u test -p test -h 127.0.0.1

  # 连接远程服务器
  wow_client.exe -u myaccount -p mypassword -h 119.3.216.43

【配置文件 config.ini】
  可在 config.ini 中预设账号、密码、服务器地址等参数。
  程序启动时会自动读取同目录下的 config.ini。

【系统要求】
  - Windows 7/8/10/11 (64-bit)
  - 无需额外安装任何运行时 (VC++ runtime, OpenSSL 等均已内置)
  - 仅依赖 Windows 系统自带的 DLL 文件

【故障排查】
  1. 如果提示连接失败，请检查服务器地址和端口是否正确
  2. 如果提示认证失败，请确认账号密码是否正确
  3. 如果连接 World Server 超时，可能是服务器未启动或网络问题
  4. 查看控制台日志可获取详细调试信息

【技术信息】
  - 基于 AzerothCore 协议实现
  - 支持 SRP6 认证协议
  - 支持 ARC4 加密通信
  - 静态编译，单文件部署
