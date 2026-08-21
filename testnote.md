# Test Note — 客户端移动位置不更新（CMSG_MOVE_HEARTBEAT 格式）

> 记录 2026-08-22 黑盒测试发现并修复的**移动心跳格式**问题。
> 现象：客户端（tester / wow_client）登录后发送移动心跳，但服务器端角色位置永不更新（`.gps` 坐标不变）。

## 根因

AzerothCore 服务器 `ReadMovementInfo`（`WorldSession.cpp`）按以下顺序解析移动包：

```
packed guid + flags(uint32) + flags2(uint16) + time(uint32) + x,y,z,o(4×float32) + fallTime(uint32)
```

两个必踩的坑：

1. **guid 必须是 packed 格式**（不是原始 8 字节）
   - 服务器 `readPackGUID`：首字节 guidmark（bit i=1 表示第 i 字节存在）+ 按序输出非零字节
   - 例：`guid=17(0x11)` → `[0x01][0x11]`（2 字节）
   - ❌ 旧代码 `writeU64LE` 发原始 8 字节 → 服务器把首字节 `0x01` 当 guidmark，guid 解析错乱 → guid 校验失败 → 位置永不更新

2. **`flags2` 是 uint16（2 字节），不是 uint32**
   - 服务器 `MovementInfo::flags2` 声明为 `uint16`（`Object.h`）
   - ❌ 若客户端发 4 字节 flags2 → 服务器按 `flags(4)+flags2(2)+time(4)` 读，time/pos 整体**偏移 +2 字节** → 读出垃圾坐标 → `IsPositionValid` 拦截 → 位置永不更新
   - 症状特征：服务器 `time` 读出 `0x84D40000`（= flags2 尾 2 字节 + time 头 2 字节拼接）

## 正确 payload（32 字节）

| 字段 | 长度 | 值 |
|---|---|---|
| guidmark | 1 | bitmask，如 `0x01` |
| guid 非零字节 | 1~8 | 如 `0x11` |
| flags | 4 | `MOVEMENTFLAG_NONE=0` |
| flags2 | **2** | `0` |
| time | 4 | 毫秒时间戳 |
| x,y,z,o | 16 | 位置+朝向 |
| fallTime | 4 | `0` |

## 修复（已提交）

- `wow_world.cpp::SendMoveHeartbeat`：
  - guid：`writeU64LE` 原始 8 字节 → **packed 格式**（guidmark + 非零字节）
  - flags2：**新增 `pushU16(0)`**（2 字节，原代码缺失）
- 参考实现：`/workspace/test-tool/client/tt_world.cpp::SendMoveHeartbeat`（同款修复）

## 验证

- socket 层断点：心跳 payload 应为 **32 字节**，坐标字段对齐正确（如 x=-8949.95 出现在字节 12-15）
- handler 层：`MovementHandler.cpp:578`（`mover->UpdatePosition(movementInfo.pos)`）应**命中**（= 位置真正更新）
- 实测：tester `mv` 移动后，服务器端 UPDATE_POS 坐标实时变化（如 -8949.95 → -8902.60 → -8894.71）

## 调试陷阱（备忘）

- gdb 断点打在 `if (!pos.IsPositionValid())`（`MovementHandler.cpp:382`）这一行，**无论条件真假都会命中**——命中 ≠ 位置被拦截。要看 `UpdatePosition`（578 行）是否触发才是真正更新。
- socket 层 payload 正确 ≠ handler 层解析正确——若 handler 读出垃圾值，用「垃圾值 = payload 相邻字段字节拼接」反推偏移量，快速定位字段宽度错位。
