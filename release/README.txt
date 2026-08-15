WoW Standalone Client Simulator - Windows 版
============================================

使用方法:
1. 编辑 config.ini 配置文件，填入服务器地址、账号和密码
2. 双击 wow_client.exe 运行，或在命令行执行

配置文件说明 (config.ini):
    [auth]
    account = TEST              ; 游戏账号
    password = TEST123          ; 账号密码
    host = 127.0.0.1            ; Auth 服务器地址
    port = 3724                 ; Auth 服务器端口
    character = TestHero        ; 角色名（可选）
    bot_target =                ; Bot 模式目标（可选）
    action = login              ; login=完整登录, list=仅列表, test=仅测试

命令行参数 (可选):
    wow_client.exe                              读取 config.ini
    wow_client.exe login --account XXX --password XXX --character XXX
    wow_client.exe list --account XXX --password XXX
    wow_client.exe test --account XXX --password XXX
    wow_client.exe --config D:\path\to\config.ini  指定配置文件

示例 (用户名 test 密码 test 服务器本机):
    方式1: 修改 config.ini 后双击运行
    方式2: 命令行: wow_client.exe login --account test --password test --host 127.0.0.1

流程:
    1. 客户端连接 AuthServer (3724) 完成 SRP6 认证
    2. 自动获取 Realm 列表
    3. 连接 WorldServer (8085) 进入游戏世界

注意:
- 静态编译版本，单文件即可独立运行，无需任何 DLL 或运行时
- 请确保防火墙允许程序出站访问 3724 / 8085 端口
