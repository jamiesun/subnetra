# Subnetra 生产部署指南

> 本文是 [`deployment.md`](deployment.md) 的中文版，内容保持同步；如有出入，以英文版为准。

本指南部署一个公网 **Hub** 和两个位于 NAT 后的 **Spoke**，使各 Spoke 私有局域网内的主机能够通过 Hub 中继互相访问。Subnetra 以单一静态二进制发布，无运行时依赖，因此部署主要围绕配置、capabilities 和主机网络。

如果是 MikroTik/RouterOS Container 部署，除本指南外还需阅读
[`routeros-container.md`](routeros-container.md)。RouterOS 模型需要专门的 veth 路由和容器侧转发。

> 拓扑（v1）：单 Hub 的 hub-and-spoke。Hub 在各 Spoke 之间中继；Spoke 不做中继。
> Peer 的**身份**是由报文头 `key_id` 选中的逐 peer PSK（issue #34），而不是源端点：
> Spoke 的 UDP 端点是配置里的**引导（bootstrap）**值，但在收到一个通过认证的数据报后
> 会在运行时重新学习，因此处于 NAT 后/漫游的 Spoke 无需运维介入即可恢复。Hub 仍必须
> 拥有一个稳定、可达、每个 Spoke 都能到达的端点。

如需把 **macOS 主机作为 Spoke** 接入（原生 `utun`），服务化方式见下文 §4（launchd），
端到端真机验收流程见手册
[`macos-spoke-acceptance.md`](macos-spoke-acceptance.md)。Hub 与中继仍为 Linux/RouterOS；
macOS 仅作为 **Spoke** 支持。

## 0. 组件

| 节点     | Mesh id | Overlay IP   | Underlay 端点         | 私有局域网          |
|----------|---------|--------------|-----------------------|--------------------|
| Hub      | 1       | （仅中继）   | `203.0.113.1:18020`   | —                  |
| Spoke A  | 2       | `10.0.0.2/24`| NAT 后                | `192.168.10.0/24`  |
| Spoke B  | 3       | `10.0.0.3/24`| NAT 后                | `192.168.31.0/24`  |

示例配置就在本指南旁边：
[`deploy/hub.json`](../deploy/hub.json)、
[`deploy/spoke-a.json`](../deploy/spoke-a.json)、
[`deploy/spoke-b.json`](../deploy/spoke-b.json)。

## 1. 安装二进制

构建（或下载发布版）并安装静态二进制和控制工具：

```bash
zig build -Doptimize=ReleaseSmall
sudo install -m 0755 zig-out/bin/subnetrad /usr/local/bin/subnetrad
sudo install -m 0755 zig-out/bin/subnetra  /usr/local/bin/subnetra
```

`ldd /usr/local/bin/subnetrad` 应当报告 *not a dynamic executable*。

> **macOS：** 从[发布页](https://github.com/jamiesun/subnetra/releases/latest)下载
> `subnetra-<ver>-macos-<arch>.tar.gz`（或 `zig build`），用 `sudo install -m 0755`
> 把两个二进制装入 `/usr/local/bin`，再清除 Gatekeeper 隔离属性：
> `sudo xattr -d com.apple.quarantine /usr/local/bin/subnetrad /usr/local/bin/subnetra`。
> macOS 二进制为*最小动态链接*（Apple 不提供静态 libc），因此用 `otool -L`（而非 `ldd`）
> 验证——应当只显示 `/usr/lib/libSystem.B.dylib`。

## 2. 下发逐节点配置与密钥

Hub 与每个 Spoke 之间的每条**链路**都有自己**独立的**私有 PSK（共用一把全网 mesh 密钥会被拒绝）。
每条链路生成一把 32 字节密钥：

```bash
openssl rand -hex 32   # 64 个十六进制字符；每条 Hub<->Spoke 链路运行一次
```

- 链路 Hub(1)<->Spoke A(2)：**相同**的值放进 Hub 的 `peers[id=2].psk`
  和 Spoke A 的 `peers[id=1].psk`。
- 链路 Hub(1)<->Spoke B(3)：**不同**的值，放进 Hub 的 `peers[id=3].psk`
  和 Spoke B 的 `peers[id=1].psk`。

跨链路复用同一把 PSK 会被拒绝（`DuplicatePsk`）；缺失或非十六进制的 PSK 会被拒绝（`InvalidPsk`）。
示例配置里包含明显伪造的占位密钥（`aaaa…`、`bbbb…`），**仅用于让 `--check` 通过**——
部署前请逐一替换。

把每个节点的配置安装为 `/etc/subnetra/config.json`：

```bash
sudo mkdir -p /etc/subnetra
sudo install -m 0600 -o root -g root deploy/spoke-a.json /etc/subnetra/config.json
```

> **密钥处理（必须）：** 配置文件携带私有 PSK。它们必须 root 属主、`0600`（不可被所有人读取）。
> `/etc/subnetra` 本身应为 `0700`。切勿把真实配置提交到版本控制。

启动前先校验：

```bash
sudo subnetrad --check --config /etc/subnetra/config.json
# subnetra v… (mtu=1400, udp_ports={ 18020 }, mode=raw_direct, local_id=2, peers=1) [config ok]
```

`--config` 是可选的；不指定时守护进程会从其工作目录读取 `./config.json`（或 `$SUBNETRA_CONFIG`）。
`subnetrad --version` 和 `subnetrad --help` 无需配置即可使用；无法识别的参数会被拒绝而不是被忽略。

## 3. 主机网络

subnetrad 创建 TUN 设备，但只**打印**（绝不应用）主机配置，这样你既保留零依赖保证，又能掌控路由。
为每个节点生成方案：

```bash
sudo subnetrad --print-network-plan           # 假设 1500 字节 underlay
sudo subnetrad --print-network-plan --path-mtu 1420   # 例如位于 PPPoE/另一层 VPN 之后
```

应用打印出来的 `ip` 命令（或粘贴进 systemd unit 的 `ExecStartPost` 钩子）。该方案还会报告该路径的
**安全隧道 MTU**，并在 `local_tun_mtu` 过大时发出警告——修正它可以避免经典的
“小包能通、大包传输卡死”故障。要让 LAN 到 LAN 的 TCP 在更小的路径 MTU 下存活，请应用打印出的
MSS-clamp 规则。

`--print-network-plan` 只是 **假设** 1500 字节承载。要测量两节点间的 **真实** 路径 MTU——包括
ICMP 被过滤、内核 PMTU 发现会静默失败的情形——请用树内的 `mtu-probe` 工具（一端跑响应方、
另一端跑探测方）；它置 Don't-Fragment 位、主动走 UDP 探测，并打印应配置的 `local_tun_mtu`：

```bash
zig build tool:mtu-probe
zig-out/tools/mtu-probe --listen 18020              # 远端节点
zig-out/tools/mtu-probe --probe 203.0.113.9:18020   # 近端节点
```


要实现 LAN 到 LAN 可达，通常还需在每个 Spoke 上开启转发，并把对端 LAN 路由经由 overlay：

```bash
sudo sysctl -w net.ipv4.ip_forward=1
# 在 Spoke A 上，通过隧道到达 Spoke B 的 LAN：
sudo ip route add 192.168.31.0/24 dev snr0
```

> **macOS：** `subnetrad --print-network-plan` 输出的是 `ifconfig`/`route` 方案，而非
> `ip …`。`utun` 名字由**内核分配**（`utunN`），因此请在守护进程启动**之后**、用 `[ready]`
> 横幅里的真实名字替换后再应用方案（见 §4 launchd 与验收手册）。subnetra 在任何平台都不会
> 自行改动路由。

## 4. 以服务方式运行

### Linux — systemd

安装 unit 并启动守护进程：

```bash
sudo install -m 0644 deploy/subnetrad.service /etc/systemd/system/subnetrad.service
sudo systemctl daemon-reload
sudo systemctl enable --now subnetra
```

该 unit 仅申请 `CAP_NET_ADMIN`，授予 `/dev/net/tun`，以 `ExecStartPre` 运行 `subnetrad --check`，
失败时重启，其余均做了沙箱限制（`ProtectSystem=strict`、`NoNewPrivileges`、受限地址族等）。
编辑注释掉的 `ExecStartPost` 行以匹配你的 `--print-network-plan` 输出。

日志进入 journal：

```bash
journalctl -u subnetrad -f
```

### macOS — launchd

在 macOS Spoke 上，用 `launchd` 托管守护进程。由于创建 `utun` 需要 root，它是一个**系统级**
守护进程（`/Library/LaunchDaemons`，以 root 运行），而非每用户的 LaunchAgent。安装
[`deploy/net.subnetra.subnetrad.plist`](../deploy/net.subnetra.subnetrad.plist)（配置按 §2
准备好——`/etc/subnetra/config.json`，root 拥有、`0600`）：

```bash
sudo install -m 0644 deploy/net.subnetra.subnetrad.plist \
    /Library/LaunchDaemons/net.subnetra.subnetrad.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/net.subnetra.subnetrad.plist
sudo launchctl enable  system/net.subnetra.subnetrad
# 较旧的 macOS：sudo launchctl load -w /Library/LaunchDaemons/net.subnetra.subnetrad.plist
```

该任务以 root 运行 `subnetrad --config /etc/subnetra/config.json`，异常退出时重启
（`KeepAlive.SuccessfulExit=false`，带节流——相当于 systemd 的 `Restart=on-failure`），
日志写入 `/var/log/subnetrad.log`。请先用 `subnetrad --check` 校验配置，避免坏配置反复崩溃重启。
从日志的 `[ready]` 横幅读取内核分配的接口名：

```bash
sudo tail -f /var/log/subnetrad.log
# subnetra v… (… mode=raw_direct …) tun=utun4 sock=/var/run/subnetra.sock [ready]
```

**主机网络方案需单独应用。** 与所有平台一样，守护进程只**打印**方案；在 macOS 上 `utunN`
名字由内核分配，因此请在守护进程启动**之后**、用横幅里的真实名字替换后再应用：

```bash
subnetrad --print-network-plan --config /etc/subnetra/config.json   # ifconfig/route 方案
sudo ifconfig utun4 inet 10.0.0.2 10.0.0.2 mtu 1400 up
sudo route add -net 10.0.0.0/24 -interface utun4
```

> `KeepAlive` 重启后可能落在**不同的** `utunN` 上；请重新读取横幅并重新应用方案。subnetra
> 刻意把路由留给你掌控（不自动改动路由），且 macOS 仅作为 **Spoke**。用
> `sudo launchctl kickstart -k system/net.subnetra.subnetrad` 重启、
> `sudo launchctl bootout system/net.subnetra.subnetrad` 停止并卸载。完整的真机验收流程见
> [`macos-spoke-acceptance.md`](macos-spoke-acceptance.md)。

## 5. 安装中继策略（Hub）

> **捷径（推荐）：** [`../deploy/`](../deploy/) 中的示例配置设置了
> `"role": "hub"` / `"role": "spoke"`，因此守护进程会在启动时**从配置推导出整套策略**——
> 你可以跳过本节。参见
> [README → Roles](../README.md#roles-auto-derive-the-policy-from-config-role)。
> 下面的手动步骤适用于 `"role": "manual"` 配置，或当你想在推导出的表上叠加额外规则时。

Hub 以空策略树启动；在运行时通过本地控制套接字安装中继/投递规则（热替换，无需重启）。
在 Linux 上 CLI 默认值已与守护进程一致（`/run/subnetra/subnetra.sock`），无需设置
`SUBNETRA_SOCK`——仅自定义路径时才设置：

```bash
# 把 overlay 流量投递/中继到正确的 spoke：
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 2
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.3/32 --action forward --target 3
sudo subnetra policy show
sudo subnetra save        # 持久化一个可重放的快照
```

在每个 Spoke 上，把目的为本地 overlay 地址的隧道流量投递到本地 TUN（target `0` = 本地）：

```bash
sudo subnetra policy add --src 0.0.0.0/0 --dst 10.0.0.2/32 --action forward --target 0
```

## 6. 查看、排障、升级

```bash
sudo -E subnetra status      # peers、流量计数器，以及逐原因的丢包计数器
```

守护进程不在时 `subnetra status` 以非零退出。上升的丢包计数器直指原因：
`unknown_peer`（报文头 `key_id` 匹配不到任何已配置 peer）、
`auth_or_invalid`（PSK/epoch/wire 不匹配）、
`spoof`（内层源地址在 `allowed_src` 之外）、
`no_route`（无匹配策略）。每当一个已认证 peer 在新的 UDP 端点被观察到时（漫游/NAT 重映射——见 issue #34），
`endpoint_learned` 计数器上升。`keepalive rx`/`tx` 行统计内置 NAT 保活（见 §7）：
`tx` 在发送保活的 spoke 上上升，`rx` 在接收的 hub 上上升。PSK 永远不会被打印。

### 机器可读状态（`--json`）

用于监控、告警与自动化：`subnetra status --json` 把与文本视图相同的数据，输出为一个稳定、带版本号的
JSON 对象（无需抓取/解析自由文本）。同样的不变量成立：**PSK 与派生密钥永不被序列化。**

```bash
subnetra status --json | jq .
```

```jsonc
{
  "schema_version": 1,                 // 仅在 schema 发生破坏性变更时递增
  "version": "0.9.0",
  "mode": "raw_direct",
  "local_id": 1,
  "listen_port": 18020,
  "tun": "snr0",
  "peers": [
    {
      "id": 2,
      "endpoint": "203.0.113.7:51822",
      "name": "bj-office-gw",               // 可选的运维标签（未设置时为 ""）
      "allowed_src": "10.66.0.2/32",
      "last_seen_wall_ns": 1700000095000000000,
      "last_seen_age_seconds": 5,      // 若该 peer 从未认证过则为 null
      "online": true                   // last_seen 在新鲜窗口（~90s）之内
    }
  ],
  "counters": { "tun_rx_packets": 3, "udp_tx_packets": 0, /* …每一个数据面计数器… */ }
}
```

- `peers[].name` 是一个**可选**的人类可读标签（如 `bj-office-gw`、`colo-hub`），
  在 `config.json` 里逐 peer 设置（`peers[].name`）。它**仅是元数据**——绝不参与
  身份/认证/路由（密钥派生、线缆 `key_id`、peer 匹配都仍以数字 `id` 为准）——且限定为
  可打印 ASCII，因此在 `subnetra status` 中回显是安全的。省略时 JSON 为空字符串、
  文本视图仅显示 id（与之前一致）。
- `peers[].online` 在该 peer 最近一次已认证报文落在 ~90s 之内时为 `true`——足以容忍几次漏掉的保活（§7）
  而不抖动。用它（或 `last_seen_age_seconds`）做逐 peer 的健康/心跳告警。
- `counters` 承载文本视图里的**每一个**计数器（流量 + 完整的丢包分类），所以抓取不会漏掉任何字段——
  它就是下面 Prometheus textfile exporter 的数据源。
- 在你的监控里固定 `schema_version`；它仅在破坏性变更（删除/重命名键，或改变类型）时递增。

### Prometheus textfile exporter

要对节点健康做告警，[`deploy/subnetra-textfile-exporter.sh`](../deploy/subnetra-textfile-exporter.sh)
把 `subnetra status --json` 转成 node_exporter **textfile collector** 指标。守护进程内有意**不**内置 HTTP
服务（多一个监听 socket + 攻击面，违背单二进制理念）：脚本只写一个 `.prom` 文件，由你已有的 `node_exporter`
抓取。唯一前置依赖是 `jq`。

```bash
sudo install -m 0755 deploy/subnetra-textfile-exporter.sh /usr/local/bin/
sudo install -m 0644 deploy/subnetra-textfile-exporter.service /etc/systemd/system/
sudo install -m 0644 deploy/subnetra-textfile-exporter.timer   /etc/systemd/system/
# 在 .service 里把 OUTPUT 设为你的 collector 目录，然后：
sudo systemctl enable --now subnetra-textfile-exporter.timer
```

它发出（原子写入，绝不会出现写了一半的文件）：

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `subnetra_up` | gauge | 读到状态为 `1`，守护进程 down/未绑定为 `0`——本身即可告警。 |
| `subnetra_build_info{version,mode,tun,local_id,listen_port}` | gauge | 恒为 `1`；身份信息在标签里。 |
| `subnetra_peer_online{id,allowed_src}` | gauge | 在新鲜窗口内为 `1`，否则 `0`。 |
| `subnetra_peer_last_seen_age_seconds{id,allowed_src}` | gauge | 对从未认证过的 peer 省略。 |
| `subnetra_<counter>_total` | counter | `counters` 里的**每一个**字段（流量 + 丢包），抗漂移。 |

告警规则示例：

```yaml
groups:
  - name: subnetra
    rules:
      - alert: SubnetraDaemonDown
        expr: subnetra_up == 0 or absent(subnetra_up)
        for: 1m
        annotations: { summary: "subnetra 守护进程 down 或状态不可用：{{ $labels.instance }}" }
      - alert: SubnetraPeerOffline
        expr: subnetra_peer_online == 0
        for: 2m
        annotations: { summary: "subnetra peer id={{ $labels.id }} 离线：{{ $labels.instance }}" }
      - alert: SubnetraPeerStale            # 比完全离线更早的预警
        expr: subnetra_peer_last_seen_age_seconds > 120
        for: 1m
        annotations: { summary: "subnetra peer id={{ $labels.id }} 上次出现于 {{ $value }}s 前" }
      - alert: SubnetraAuthDropsClimbing    # PSK/epoch/wire 不匹配（密钥轮换错位，§6；或 wire break）
        expr: rate(subnetra_drop_udp_auth_or_invalid_total[5m]) > 0
        for: 10m
        annotations: { summary: "subnetra auth_or_invalid 丢包在攀升：{{ $labels.instance }}" }
      - alert: SubnetraSpoofDrops           # 内层源地址在某 peer 的 allowed_src 之外
        expr: rate(subnetra_drop_udp_spoof_total[5m]) > 0
        for: 10m
        annotations: { summary: "subnetra spoof 丢包：{{ $labels.instance }}" }
```

### 升级与回滚 runbook

Subnetra 是单个静态二进制，没有持久化的数据面磁盘状态，所以机械步骤就是“换二进制并重启”。
真正的风险是**线缆（wire）兼容性**：跨越一个破坏 wire 的边界做升级，会让已升级的节点无法认证尚未升级的节点；
又因为传输是 **fail-closed**（认证失败的报文被静默丢弃），半升级的 mesh 会**静默分区**——
没有任何报错，只有 `auth_or_invalid` 丢包计数器在攀升。

**线缆兼容性矩阵**

| 边界 | 是否 wire 兼容 | 说明 |
|---|---|---|
| `v0.5.0` ↔ `v0.5.1` | ✅ 是 | 密钥调度（`subnetra-v1-*`）与 20 字节报头完全一致，`wire_version = 1`。可任意顺序升级。 |
| `v0.5.1` ↔ 当前 `main`（含 #96 keepalive） | ✅ 是 | `KEEPALIVE`（`flags` bit 0）是增量特性，**未**提升 `wire_version`；旧节点只是丢弃 keepalive，数据路径不变。 |
| `≤ v0.4.x` ↔ `≥ v0.5.0` | ❌ **否——硬破坏** | v0.5.0 把 HKDF 密钥派生标签从 `btunnel-v1-*` 改名为 `subnetra-v1-*`（项目改名，#82）。派生出的 link/session 密钥不同，因此**每一个**跨版本报文都会认证失败。两端 `version` 字节仍是 `1`，报头检查看不到它——唯一症状就是 `auth_or_invalid` 丢包计数器攀升。 |

> **经验法则：** 在 `v0.5.x` 内（以及向前到当前 `main`）升级是滚动、与顺序无关的。
> **任何跨越 `v0.4.x → v0.5.0` 这条线的跳跃，都是一次协调一致、整个 mesh 一次性切换。**
> 拿不准时，就把版本跳跃当作破坏性的，整个 mesh 一起切。

**1. 预检——在动任何运行中的节点之前。** 用*新*二进制对每个节点的*真实*配置做校验；
这能在你重启任何东西之前，先抓出新版本会拒绝的配置：

```bash
/path/to/new/subnetrad --check --config /etc/subnetra/config.json
# subnetra vX.Y.Z (mtu=…, mode=raw_direct, local_id=…, peers=…) [config ok]
```

**2a. 兼容升级（`v0.5.x` 内 → `main`）。** 一次升一个节点，无需协调。
保留被替换下来的二进制以便回滚（步骤 4）：

```bash
sudo cp -a /usr/local/bin/subnetrad /usr/local/bin/subnetrad.prev
sudo install -m 0755 zig-out/bin/subnetrad /usr/local/bin/subnetrad
sudo systemctl restart subnetrad
```

每升完一个节点，先在**它的某个 peer** 上确认链路已恢复（见下方*验证*），再继续下一个。

**2b. 破坏性升级（跨 `v0.4.x → v0.5.0`）。** 在这里做滚动升级**必然**会分区 mesh，所以要一起切：

- 在每个节点上预置并 `--check` 新二进制（步骤 1）。
- 在一个维护窗口内，把**所有**节点尽量同时重启到新二进制。切换窗口内 mesh 是断的——这是预期且有界的。
- Hub 先还是 spoke 先都无所谓：跨边界什么都不互通，所以要做的是把窗口压到最短，而不是排顺序。

**3. 验证——每一步都绑定一个可观测信号，绝不靠“看起来没问题”。**
在重启的节点以及它至少一个 peer 上：

```bash
sudo -E subnetra status
```

- 每个 peer 的 `last_seen` 在**前进**（是最近的，没冻住）→ 链路在认证并承载流量。
- `udp … auth_or_invalid` 丢包计数器**保持平稳**（没在涨）→ 没有密钥/wire 不匹配。
  升级后 `auth_or_invalid` 攀升，是 **wire 不匹配**的铁证——你在某个节点还跑旧二进制时跨过了破坏边界。
- 真实负载下流量计数器（`tun_tx` / `udp_tx`）在前进。

**4. 回滚。** 把上一版二进制留在磁盘上（步骤 2a 里的 `subnetrad.prev`）。回滚：

```bash
sudo install -m 0755 /usr/local/bin/subnetrad.prev /usr/local/bin/subnetrad
sudo systemctl restart subnetrad
```

如果回滚目标早于你新增的某条策略，重新应用保存的策略快照（`subnetra policy add …`，见 §5）。
回滚的**范围要和你升级的范围一致**：兼容升级就回单个节点，破坏性升级就回**整个 mesh**
（跨 wire 破坏时，单独回退的一个节点和单独升级的一个节点一样是被分区的）。
按步骤 3 同样用 `subnetra status` 验证。

> **时间同步（必须）。** 上述“每次重启一个全新 epoch”的特性依赖于正常的挂钟：session 密钥派生自
> 启动时从 `CLOCK_REALTIME` 采样的 boot epoch，且接收方对 session 做**仅向前**排序
> （更新的 epoch 取代更旧的）。当时钟读数早于 2024-01-01 时守护进程会 fail-closed，
> 但它**无法**检测一个在重启之间**倒退**的时钟。如果某节点以早于其上次启动的挂钟重启
> （例如没有电池供电的 RTC 且 NTP 尚未同步），它新的、更低的 epoch 会被每个 peer 拒绝，
> 直到对端时钟前进越过旧值——链路会静默黑洞，对端的 `auth_or_invalid` 丢包计数器（见上）攀升。
> **缓解：** 运行时间守护进程（`chrony` / `systemd-timesyncd`）；在没有 RTC 的硬件上，
> 让 `subnetrad.service` 排在 `time-sync.target` 之后（`After=time-sync.target` +
> `Wants=time-sync.target`），使时钟在重启之间单调。如果时钟确实发生过倒退，
> **重启受影响链路的两端**以在各自一侧强制刷新 epoch。这是无状态、无握手传输（铁律 #8）
> 一个被接受的、永久的取舍：协议内没有 epoch 交换来修复它，因此修复是运维层面的（保持时钟同步）。

### 密钥轮换 runbook

按计划轮换链路 PSK，或在怀疑泄露后立即轮换。链路密钥只存在于 `config.json` 中，且在**启动时**读取；
没有在线 rekey 命令（控制面只管 policy）。由于认证**fail-closed**，幼稚的轮换——只改一端、碰运气——
会静默丢弃该链路的流量，直到两端达成一致（`auth_or_invalid` 丢包计数器攀升，见 §6）。下面的流程把影响
限制在单条链路、以及两次重启之间的几秒内。

**你在改什么。** PSK 是*按链路*的（§2）：轮换 Hub↔Spoke A 的密钥意味着把**同一个**新值写进 Hub 的
`peers[id=2].psk` **和** Spoke A 的 `peers[id=1].psk`。端点不变——Hub 会从该 spoke 下一个已认证的数据报
重新学习其端点（issue #34），所以没有需要重新接线的东西。**一次只轮换一条链路**，这样任何失误都只会影响
那一个 spoke。

1. **生成一个全新的按链路密钥**（离线，无安全熵源时 fail-closed）：

   ```bash
   zig build tool:keygen && zig-out/tools/keygen   # 64 位十六进制；或：openssl rand -hex 32
   ```

2. **记录当前密钥**以便回滚（在覆盖前把旧 `psk` 值复制到安全的地方）。

3. **在两端都暂存新密钥——先不要重启。** 把 Hub 的 `peers[id=2].psk` 和 Spoke A 的 `peers[id=1].psk`
   改成新值，并各自离线校验；在这里抓到的笔误代价为零：

   ```bash
   sudo subnetrad --check --config /etc/subnetra/config.json   # 在 Hub 和 Spoke A 上各跑一次
   ```

4. **背靠背切换。** 尽量同时重启两端（写成脚本／开两个 SSH 会话）；被轮换的链路只在两次重启之间的
   时间差里中断：

   ```bash
   sudo systemctl restart subnetrad     # 在 Spoke A 上
   sudo systemctl restart subnetrad     # 在 Hub 上
   ```

   重启 Hub 会重新读取**每一个** peer，所以其他 spoke 的链路会在它们的下一个报文上重新认证
   （无状态、亚秒级——它们的密钥没变）。只有被轮换的链路会出现真正的间隙。

5. **验证**：在 Hub 上用 `subnetra status`（或 `--json`，§6）：被轮换 peer 的 `last_seen` 在推进
   （`last_seen_age_seconds` 很小 / `online: true`），且 `udp: auth_or_invalid` **停止攀升**。再用一次
   跨链路的 overlay ping 确认。如果 `auth_or_invalid` 仍在攀升且 `last_seen` 陈旧，说明两端不一致——
   重新检查新 `psk` 在两端是否逐字节相同。

6. **回滚：** 在**两端**配置里恢复保存的旧密钥并**同时重启两端**（同样的背靠背切换）。由于改动是运维
   驱动的静态配置，回滚与第 4 步对称。

> **红线（铁律 #8）。** 轮换始终由运维通过静态配置 + 协调重启驱动；subnetra **永远不会**长出协议内的
> 密钥交换或握手来在线协商密钥。第 4 步里短暂的按链路窗口，是无状态、无握手传输被接受的代价。真正
> make-before-break（零窗口）的轮换需要一个可选的第二个按 peer 密钥*槽*——守护进程在重叠窗口内同时接受
> 出站-旧 与 入站-新 密钥，使两端独立轮换。该增强作为 issue #107 的可选路径被跟踪，**不属于**当前机制。

## 7. 防火墙 / NAT 要求

- **Hub** 必须接受来自互联网、到全部已配置 `listen_ports` 的入站 UDP。默认值是显式端口集
  `18020, 18023, 18026`（不是范围），避开 WireGuard 知名端口指纹；单个端口被封锁或限速也
  不会让节点离线。
- 每个 **Spoke** 只需要对 Hub 的 `ip:port` 有**出站** UDP 可达性；无需任何入站端口转发（由 spoke 发起）。
  因此 Spoke 只需 **一个** 监听端口（按角色而定的默认值只绑定 `[18020]`）；多个 `listen_ports` 是 Hub 一侧的特性。
- 如果某个 spoke 的 NAT 映射发生变化，Hub 会从它下一个已认证数据报中重新学习该 spoke 的新端点
  （issue #34），因此回包会自动跟随。保持 **Hub** 端点稳定；始终由 spoke 发起。

### NAT 保活（内置）

**空闲** spoke 的 NAT / 有状态防火墙映射最终会超时（UDP 常见 ~30 秒），此后 Hub 将无法再
触达该 spoke，直到它再次发包——对空闲 spoke 的入站中继会静默黑洞。为避免这一点，`role=spoke`
节点运行**内置保活**（issue #96）：每隔 `keepalive_secs`，spoke 向其 Hub 发送一个微小的已认证
数据报，保持 NAT 针孔打开，并让 Hub 学到的端点（issue #34）保持新鲜。

- 对 `role=spoke` **默认开启**（默认 `keepalive_secs = 20`，低于典型 NAT 超时）。
  `role=hub`/`role=manual` 默认 `0`（关闭）。
- 显式设置 `keepalive_secs` 可调整间隔，或设为 `0` 关闭（例如不在 NAT 后、或始终有主机流量的 spoke）：

  ```json
  { "role": "spoke", "local_id": 2, "keepalive_secs": 20, "peers": [ … ] }
  ```

- 它零分配、不引入线程或外部进程：每个间隔一个约 36 字节的数据报，由 reactor 自身的 poll 超时驱动。
  在 spoke 上用 `subnetra status` 确认（`keepalive tx` 计数器上升），在 Hub 上确认（`keepalive rx` 上升）。
  它**取代**了早期部署中仅为保持针孔打开而使用的外部 pinger/`netwatch` 旁路。

### Hub 使用动态 IP（DDNS）

端点配置是数字 `IP:port`，且 endpoint learning 是**单向**的——Hub 能学到漫游的 spoke，
但 spoke 无法发现一个换了地址的 Hub（它要发出第一个包必须先有正确的目的地址）。因此守护进程
**不**解析主机名、也不在运行时重解析：一个守护进程内的实时 DNS 客户端会把解析器/线程/状态
拉进刻意保持极简、零依赖、单线程的数据面（铁律 #1/#3）。

常规答案是给 Hub 一个**稳定的公网 IP**（一台小 VPS）。如果你必须让 Hub 跑在**动态**地址后面，
就在每个 spoke 上用一个极小的 DDNS 监视脚本从运维层解决——无需任何守护进程改动。重启是
**无状态且廉价的**（每个生命周期都派生一个全新的 session epoch），所以"重新指向"只是改配置 + 重启：

```bash
# /usr/local/bin/subnetrad-ddns.sh —— 在每个 spoke 上用 systemd timer 每约 60s 运行一次
new=$(getent hosts hub.example.com | awk '{print $1}')
cur=$(grep -oE '[0-9.]+:[0-9]+' /etc/subnetra/config.json | head -1 | cut -d: -f1)
[ -n "$new" ] && [ "$new" != "$cur" ] && {
  sed -i "s/$cur/$new/" /etc/subnetra/config.json
  systemctl restart subnetrad        # 无状态重启：派生一个全新 epoch
}
```

只在启动时解析一次主机名**并不是** DDNS——它会漏掉启动之后的任何地址变化，而这正是本监视脚本
处理的情况。

## 8. 高可用 / 故障切换

v1 是**单 hub** 的 hub-and-spoke（见 `PROTOCOL.md`）：hub 一旦失效，mesh 就被切断。
本能的修法——在守护进程内做自动健康探测并切换路径——是**被设计禁止**的（铁律 #8；数据面是无状态、
无握手、**单路径**的——见 §9，“永远不做自动切换的 path manager”）。因此高可用要靠**冗余 hub 加一个在
守护进程之外做出的故障切换决策**来实现，而不是新增守护进程状态机。守护进程保持单路径；由主机／网络／运维
来决定一个 spoke 使用哪个存活的 hub。

**模式 A —— 共享 hub VIP（网络驱动的切换）。** 在**一个**虚拟地址后面跑两个 hub 实例——共享 LAN 上的
VRRP/`keepalived` VIP，或跨两个站点的 anycast 前缀。每个 spoke 拨向那个唯一稳定的 `endpoint`；主机／网络
在故障时把地址迁移到存活的 hub，spoke 下一个数据报就会落到它上面，**无需 spoke 改配置**（端点从未变过）。
两个 hub 对 spoke 必须**不可区分**：相同的 `local_id`、**相同的**按 spoke PSK、相同的 relay policy（§5）。

> **Epoch 注意事项（必读）。** 接收方按 boot epoch 对 session 做**仅向前**排序（§6，“时间同步”）。切换时
> 存活的 hub 呈现的 epoch **不能低于** spoke 上次接受的值，否则 spoke 会拒绝它，直到自己存的 epoch 被越过
> （链路静默黑洞，`auth_or_invalid` 攀升）。用 NTP/`chrony` 约束两个 hub；最安全的形态是**主/备，且备机在
> 接管时（重）启动**，使其以全新、最高的 epoch 启动。如果你需要对称/双活的切换又不想要这种耦合，用模式 B。

**模式 B —— 静态多 hub、独立身份（无 epoch 耦合）。** 跑两个完全独立的 hub，各有**自己的** `local_id` 和
**自己的**按 spoke PSK。每个 spoke 把**两个** hub 都列为 peer：

```jsonc
// spoke 配置 —— 两个 hub peer；overlay 的一个活跃下一跳，一个备用
"peers": [
  { "id": 1,  "endpoint": "hub-a.example:18020", "allowed_src": "10.66.0.0/24", "psk": "…A…" },
  { "id": 11, "endpoint": "hub-b.example:18020", "allowed_src": "10.66.0.0/24", "psk": "…B…" }
]
```

由于每个 hub 是**不同的 session**（不同 `key_id`），不存在 epoch 混淆。单路径数据面**不会**在两个重叠的
下一跳之间自动选择，所以切换是一个**外部**决策：两条隧道上的 OS 路由 metric、按 hub 切分 overlay 前缀，
或一个把流量重新指向备机的运维/脚本。（`config-gen` 可以生成各 spoke 的 peer 条目；每条链路的 PSK 仍须按
§2 唯一。）

**只观察的健康检查（驱动切换的依据）。** 用 `subnetra status` / `subnetra status --json`（§6）读取每个 hub
的存活状态——每个 peer 的 `last_seen` / `last_seen_age_seconds` / `online`，以及保持平稳的 `auth_or_invalid`
——把它喂给你选定的外部机制：`keepalived` 健康检查脚本、anycast 路由健康检查，或一个重新指向主机路由的
cron。读取是**非修改性**的；守护进程**自身不做**任何切换决策。

**非目标（明确）。** subnetra **不会**新增守护进程内的健康探测 / 存活驱动的路径切换 / 报文分striping 状态机。
数据面有意保持单路径、无握手（铁律 #8；§9）；故障切换策略应放在拥有完整网络上下文的地方（主机、路由器或
anycast fabric），而不是放进一个无分配的报文泵里。改变这一点是 v2 / **修订铁律的 RFC**，不是一个 feature
PR——也有意不放进 backlog。

## 9. 运营商跨区整形（Cross-ISP / cross-region traffic shaping）

在长距离、跨运营商或跨地域的链路上，抖动和丢包的主要成因**不是**隧道“被识别”，而是 underlay：
运营商互联拥塞、最后一公里排队、单流速率上限、突发 UDP。Subnetra 刻意是一个
**无状态、无握手、零分配的数据面**（铁律 #2、#3、#8）：它**不**提供隧道内调度器、
自适应速率控制器或自动切换的选路管理器，而且永远不会。下面所有整形都在
**操作系统层用 `tc`** 和标准内核工具完成——**无守护进程改动，无协议改动**。
内核在明文 `snr0` 设备上本来就能看到真实的内层五元组，让它去做它擅长的事。

> 这里的一切都是**可选的主机调优**。先测量（第 6 节，`subnetra status` 丢包计数器以及你的监控所采集的计数器），
> 一次只改一项，并保留回滚手段。不要不加判断地全部开启。

**1. 自己把出口限速，别让运营商替你粗暴限。** 一条以线速喷 UDP 的隧道，看起来恰恰就是运营商 QoS
要惩罚的东西。把你自己的出口整形到链路*稳定*吞吐的约 60–80%（实测它；别信销售数字）。
对一条稳定在约 80 Mbit/s 的链路，从 50–60 Mbit/s 起步：

```bash
# 在物理上行口平滑突发并钉死一个精确速率。
sudo tc qdisc replace dev eth0 root tbf rate 60mbit burst 512k latency 80ms
```

**2. 按 flow 做公平队列，让批量流量无法饿死交互流量。** 把它应用在**内层**设备（`snr0`）上，
那里内核能看到每一条真实 flow（DNS、SSH、RDP、一次 HTTP API 调用、一次备份）——
而不是应用在外层 UDP socket 上，那里一切都坍缩成一条 flow：

```bash
sudo tc qdisc replace dev snr0 root fq_codel target 5ms interval 100ms limit 2000
```

如果是在家庭/分支网关上自己做出口整形，CAKE 是一个很好的单 qdisc 替代
（它集成了整形 + AQM + 公平队列）：

```bash
sudo tc qdisc replace dev eth0 root cake bandwidth 60mbit
```

这件事——在明文设备上做内核公平队列——才是逐 flow 优先级的正确归宿。它取代任何“隧道内 QoS 调度器”：
操作系统本来就理解这些 flow，因此 Subnetra 绝不能在数据面里重造 `tc`。

**3. MTU 要保守，并 clamp MSS。** 叠加的 PPPoE / 云 VPC / 网桥跳数，加上 Subnetra 自身的
外层 IP/UDP + AEAD 开销，会缩小可用 MTU。不要从 1500 起步。使用守护进程自己的方案（第 3 节）——
它会打印该路径的安全隧道 MTU**以及** MSS-clamp 规则：

```bash
sudo subnetrad --print-network-plan --path-mtu 1280   # 稳定后再往上加
```

如果小包能通但大包传输卡死，几乎总是这个原因。

**4. 别指望公网路径尊重你的 DSCP。** 你可以在自己的局域网内标记交互流量，但运营商经常把奇怪的
DSCP 标记清零、忽略，或错误地引入异常路径。在公网出口归一化（清零）DSCP，
把优先级留在上面的本机队列里解决：

```bash
sudo iptables -t mangle -A POSTROUTING -o eth0 -j DSCP --set-dscp 0
```

**5. 多路径——如果你确实需要——保持静态且无状态。** 优先选择**同运营商**的 Hub 选址和分地域 Hub，
而不是让一个全国中心 Hub 去硬扛一条饱和的骨干——但要把这表达为**静态的逐链路/逐 spoke 配置和路由**，
由运维（或 `subnetra`）决定，**而不是**守护进程内的协议内健康探测或自动切换状态机（铁律 #8）。
如果你把一条链路扇出到多个端点，按**内层五元组**做哈希，让同一条 TCP 连接始终走同一条路径；
绝不要把一条连接的包跨多条路径分散乱序发送——乱序会把 TCP 拥塞控制打傻。

**6. 可靠性（KCP/FEC）是 v2 的静态配置选项——不是默认。** FEC 冗余能掩盖轻微丢包，
但在一条本就拥塞或被 QoS 的链路上，它会增加流量、甚至让情况更糟。它只由静态逐链路配置选择
（铁律 #8 / `AGENT.md` 中的“v1 vs v2”），绝不协商，绝不默认开启。

**判断该拧哪个旋钮（先读计数器）：**

- RTT 平稳但吞吐上不去 → 限速或单流瓶颈（第 1/5 项）。
- 负载下 RTT p95 飙升 → 排队/拥塞（第 2 项）。
- 大包丢、小包通 → MTU（第 3 项）。
- 同运营商好、跨运营商坏 → 是**路径**问题，不是协议——把 Hub 挪近（第 5 项），别往代码里改。
- 晚上坏、白天好 → 是拥塞时段，不是代码突然回归。

### 主机与网卡调优（socket 缓冲、CPU 与 IRQ 亲和）

上面的整形讲的是**出方向**；这一节讲的是**入方向缓冲与 CPU**，目的是让一个繁忙的节点——尤其是 **Hub**
——不要在单线程 reactor 来得及排空之前就丢包。和路由、`tc` 一样，这些全是**主机侧、由运维施加**的：守护进程
只打印它的方案、从不修改主机状态（§3，“print, don't apply”），也从不自动 `sysctl`。

**Socket 接收缓冲——*静默*丢包。** 在突发下，过小的 UDP**接收**缓冲会让内核在 reactor 读取之前就丢掉数据报。
这种丢包**在 `subnetra status`（§6）里看不到**：它是内核 socket 缓冲溢出，不是守护进程的丢弃，所以丢包计数器
一个都不动。要去内核侧找：

```bash
ss -u -m                       # 每个 socket 的 rmem/wmem 用量与上限
nstat -az | grep -i 'Udp.*Errors'   # RcvbufErrors / InErrors = 内核 UDP 丢包
netstat -su | grep -i 'receive buffer errors'
```

同时抬高上限**和**默认值。subnetra 使用内核**默认**缓冲（它不会 `setsockopt` 自己的大小——与路由相同的
“不偷偷覆盖主机”原则），所以真正决定它 socket 大小的是 `*_default`，而 `*_max` 是上限：

```bash
sudo tee /etc/sysctl.d/30-subnetra.conf >/dev/null <<'EOF'
net.core.rmem_max     = 8388608
net.core.wmem_max     = 8388608
net.core.rmem_default = 4194304
net.core.wmem_default = 2097152
EOF
sudo sysctl --system
```

从几 MB 起步，确认在你真实的突发下 `RcvbufErrors` 计数器停止增长即可；过度加大只会增加时延。

**把 reactor 钉在一个安静的核上。** 数据面按铁律 #3 是单线程的。让它远离正在跑网卡 softirq / 其他负载的核，
以免它在排空途中被抢占：

```ini
# /etc/systemd/system/subnetrad.service.d/cpu.conf  ->  [Service]
CPUAffinity=2
```

（或运行时 `taskset -cp 2 "$(pidof subnetrad)"`。）

**把网卡中断从那个核上挪开。** 启用网卡的多队列/RSS，并把它的 IRQ 与 RPS/XPS softirq 工作分散到*其他*核上，
使接收处理不与 reactor 抢它被钉住的那个核：

```bash
# RPS：让若干个核共担某个 rx 队列的 softirq（掩码排除 reactor 所在核）。
echo fb | sudo tee /sys/class/net/eth0/queues/rx-0/rps_cpus
# IRQ 亲和：把每个网卡 rx 队列的 IRQ 钉到 reactor 之外的核
# （参见你驱动的 set_irq_affinity 工具；如果 irqbalance 跟你对着干就关掉它）。
```

**单核 Hub 注意事项（按此规格选型）。** Hub 做**中继**：每转发一个包都要做一次入向解密**和**一次出向重新加密，
全在那一个 reactor 线程上（`reactor.zig`）。所以 Hub 会比 spoke 先吃满**单个 CPU 核**，也是最先撞到每秒包数
（PPS）天花板的地方。据此选型：单核主频比核数更重要；当一个 Hub 核吃满时，要**横向**扩展（更多 Hub——§9 第 5 项
的按区域部署，或 §8 的冗余 Hub 模式），而**不是纵向**加线程（守护进程按铁律是单线程的，不会长出线程池）。在选型前，
用 §10 的基准工具（*单机可复现基线*，issue #97）测出你的真实天花板。

## 10. 对生产部署做基准测试（Benchmarking a live deployment）

第 9 节讲的是*调优*，这一节讲的是*测量*——从已部署的 overlay 上取得真实的 RTT 与
吞吐/pps 数字，并定位丢包。这里是对真实 mesh 的**现场测量**（真实 NAT/WAN、hub 中继、
跨操作系统的 spoke）；单机可复现的 CI 基线（issue #97）见本节末尾的*单机可复现基线*。用
`iperf3`（**主机**工具——绝不链接进守护进程，铁律 #1）和 `ping`，然后读守护进程自己的计数器。

> **被部署的守护进程保持原样。** `subnetrad` 始终以 `-O ReleaseSmall` 发布（铁律 #6）。
> 你测量的是已部署的二进制，**不要**为了端到端测试把它重编为 `ReleaseFast`。
> （`ReleaseFast` 构建只用于离线的密码学/转发微基准——`tools/crypto-bench`，以及 #101 的
> `forward-bench`。）

### 快速开始

`deploy/bench-overlay.sh` 驱动整套矩阵，且是只读的：

```bash
# 在目标端（例如 hub）——绑定到 overlay IP 起服务端，使只有隧道流量能到达它：
deploy/bench-overlay.sh serve 10.66.0.1

# 在对端（一个 spoke）——对目标跑 ping + iperf3 客户端矩阵：
deploy/bench-overlay.sh 10.66.0.1 -u -t 30
#   -u  额外跑 UDP 吞吐 + 64 字节小包 pps
#   -d <direct-ip>  额外跑一次直连（underlay）以计算隧道开销 %
```

### 或者手动逐项运行

```bash
# RTT / 抖动 / 丢包
ping -c 50 10.66.0.1

# 批量吞吐（先在 hub 上起服务端：iperf3 -s -B 10.66.0.1）
iperf3 -c 10.66.0.1 -t 30            # 单条 TCP 流
iperf3 -c 10.66.0.1 -t 30 -P 4       # 并行——把 hub 的单核上限压出来
iperf3 -c 10.66.0.1 -t 30 -R         # 反向（hub -> spoke 方向）

# 包速率 + 丢包
iperf3 -c 10.66.0.1 -u -b 0 -t 30        # UDP 无上限：抖动 + 丢包%
iperf3 -c 10.66.0.1 -u -b 0 -l 64 -t 30  # 64 字节包：小包 pps
```

**隧道开销。** 对 overlay IP 和对端的直连（underlay/公网）IP 各跑一次同样的单流测试；
吞吐之比就是隧道税（外层 IP/UDP + AEAD + 单线程 reactor）。`bench-overlay.sh -d <direct-ip>`
会替你算出来。

### 用守护进程的计数器定位丢包

`iperf3` 告诉你*丢了*包；`subnetra status`（第 6 节）告诉你丢在*哪里*。在一次运行前后各
快照一次，读增量（`bench-overlay.sh` 在 Linux 上会自动做）：

| 计数器（位于 `drops:`） | 增量非零意味着 |
|---|---|
| `udp spoof` | 内层源 IP 不在该 peer 的 `allowed_src` 内——前缀配错了 |
| `udp no_route` / `tun no_route` | 目的地没有策略条目——中继策略缺失/不全（第 5 节） |
| `udp unknown_peer` | 数据报的 `key_id` 匹配不到任何已配置 peer |
| `udp auth_or_invalid` | AEAD/重放/格式校验失败——密钥不匹配或被篡改 |
| `*_send_err` | 内核拒绝了发送——本节点的本地路由/MTU/缓冲问题 |
| `relay packets`（位于 `traffic:`） | 正在发生 hub 转发（在 hub 上属预期） |

一次干净的运行：traffic 计数器在涨，而 `drop_*` 计数器保持不动。如果 `iperf3` 报告丢包，
但**两端**的每个 `drop_*` 都不动，那丢包在 **underlay**（第 9 节），不在 subnetra。

> **macOS spoke：** `subnetra status` 按设计返回 `Unsupported`（控制客户端仅 Linux）。
> spoke 自身健康用 `deploy/mac-spoke-status.sh`；逐 peer 的 relay/drop/last_seen 计数器到
> **hub** 上查（`ssh <hub> 'sudo subnetra status'`）。

### 结合 MTU 解读结果

overlay MTU 为 **1452**（raw_direct）；内层负载不得超过它。经典特征——小包正常、大块传输卡死——
是 MTU/MSS 问题，不是吞吐问题（第 9 节第 3 项；另见 #98）。在你相信一个偏低的批量数字之前，
先用 `subnetrad --print-network-plan` 打印安全隧道 MTU 与 MSS-clamp 规则。

### 单机可复现基线（issue #97）

上面的现场测量告诉你*你的* mesh 今天能跑多少，但它无法告诉你某次**代码改动**是否动了数据面。
为此你需要一个单机、可复现的数字。`test/integration/bench.sh` 会把守护进程以
`-Doptimize=ReleaseFast` 构建（仅用于测量——发布的二进制始终是 ReleaseSmall），在本地网络
命名空间里搭起 3 节点的 hub-and-spoke 星型拓扑，用内置的 `udp-blast` 生成器打满 overlay，
再从每个守护进程**自己**的计数器（`subnetra status`）读出达成的包速率/吞吐：

```bash
# Linux，root（需要 netns + /dev/net/tun）。在仓库根目录：
sudo test/integration/bench.sh
SUBNETRA_BENCH_SECS=10 sudo --preserve-env=SUBNETRA_BENCH_SECS test/integration/bench.sh
```

它测两种模式，并为每种打印 pps、内层有效吞吐（按 snr0 MTU 的 Gbps）以及 **hub 的单核 CPU%**：

| 模式 | 压的是什么 |
|---|---|
| `spoke -> hub` | hub 终结流量——每包一次 AEAD `open` |
| `spoke -> hub -> spoke`（中继） | hub **中继**——每包 `recvfrom`+`sendto` **加** `open`+`seal`；它会最先吃满一个核，所以这是头条天花板，也是 issue #100 的 `recvmmsg`/`sendmmsg` 批处理的目标 |

记录的基线在 `test/integration/bench-baseline.env`；每次运行都会打印与它的差值。它是**信息性**的
——共享 CI runner 会有波动，所以回归会被呈现，但绝不强制（没有性能门禁，正如 #100 把基线称为
"先作信息参考"）。同一基准也通过 **Benchmark** 工作流在 CI 跑（`.github/workflows/bench.yml`，
`workflow_dispatch` 或推送 `bench/**` 分支），把表格发到 job summary，便于一次性能 PR 附上可复现的数字。

> **这里为什么用内置生成器而不是 `iperf3`？** issue #97 明确允许一个小巧的内置 blaster；一个零依赖、
> 确定性的 `udp-blast`（经 `zig build tool:udp-blast` 构建，绝不随守护进程发布）让基线无需安装主机
> 工具即可复现。`iperf3` 仍是上面现场测量里更丰富的**主机**工具。两者都遵守铁律 #1——都绝不会被
> 链接进守护进程。
