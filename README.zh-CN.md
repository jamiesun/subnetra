# Subnetra

**把你的服务器、站点和设备连接成一张私有的加密网络——只需一个随处可跑的小巧二进制文件，从云主机到 MikroTik 路由器都能部署。**

[![CI](https://github.com/jamiesun/subnetra/actions/workflows/ci.yml/badge.svg)](https://github.com/jamiesun/subnetra/actions/workflows/ci.yml)
[![Release](https://github.com/jamiesun/subnetra/actions/workflows/release.yml/badge.svg)](https://github.com/jamiesun/subnetra/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/jamiesun/subnetra?sort=semver)](https://github.com/jamiesun/subnetra/releases/latest)
[![License: MIT](https://img.shields.io/github/license/jamiesun/subnetra)](LICENSE)
![Binary size](https://img.shields.io/badge/binary-%E2%89%A4512KB-44cc11)
[![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64%20%7C%20armv7%20%7C%20armv5%20%7C%20macOS-2b90d9)](https://github.com/jamiesun/subnetra/releases/latest)

[English](README.md) · **简体中文**

<p align="center">
  <img src="subnetra.png" alt="Subnetra —— 私有三层组网：各 Spoke 把加密流量打到 Hub，由 Hub 按策略路由在彼此之间中继" width="100%">
</p>

## Subnetra 是什么？

Subnetra 把分散在不同地点的机器——分支办公室、数据中心、移动办公的笔记本、家庭实验室、容器、路由器——
连接成**一张扁平的私有子网**。

它采用**星型拓扑（Hub-and-Spoke）**：一个可达的 **Hub** 在各个 **Spoke** 之间中继流量，
于是任意节点都能用一个固定的虚拟 IP 访问其他任意节点——**哪怕大多数节点都藏在 NAT 后面**。
每个数据包都在普通的 UDP 隧道里**全程加密**传输，而整套东西就是**一个自包含的二进制文件**——
无需额外安装任何东西，没有内核模块，也没有一堆守护进程。

## 你能用它做什么

- 🏢 **打通分支办公室与数据中心**——在一张私有 overlay 上做站点到站点（site-to-site）的整段子网路由。
- 💻 **给移动办公的笔记本一个固定私有 IP**——它会随你在 Wi-Fi、4G/5G、家庭网络之间漫游而保持不变。
- 🧪 **访问家庭实验室 / IoT / 容器里的服务**——就像它们和你在同一个局域网里一样。
- 🛰 **从 NAT 后面对外发布一整段局域网**——例如让 MikroTik 路由器把 `192.168.88.0/24` 暴露给整张网。
- 📦 **在塞不下重型 VPN 的地方运行**——资源受限的容器、BusyBox、小型 ARM 设备、边缘路由器。

## ✨ 核心亮点

- **随处可跑，一个文件即装**——单个静态二进制（Linux 下**小于 512KB**），**零外部依赖**。
  可直接丢进云主机、容器、BusyBox、树莓派以及 **MikroTik RouterOS**。支持
  `amd64` / `arm64` / `armv7` / `armv5`，外加一个原生 **macOS** Spoke。
- **默认加密，链路上低特征**——每个包都用 ChaCha20-Poly1305 加密，**每条链路独立密钥**，
  带**防重放**。没有任何特征字（magic bytes），未通过认证的包会被**静默丢弃**——在端口扫描器
  看来，这个隧道就像没有任何东西在监听。**报头混淆默认开启**（`obfuscate`，需全 mesh 一致）：
  20 字节封装报头按包做 XOR 掩码，使整个数据报看起来像随机字节，NAT 保活节奏也被去周期化——
  *被动*观察者拿不到协议指纹。设 `"obfuscate": false` 可改发可读的明文报头（例如抓包调试），
  此时被动观察者即可对协议做指纹识别。混淆隐藏的是协议指纹，而非包长或时序。
  见 [`docs/PROTOCOL.md` §3.4](docs/PROTOCOL.md)。
- **一张带策略路由的扁平私有子网**——给每个节点分配一个 overlay IP，按整段子网做站点到站点路由，
  并由 Hub 做 **Spoke 到 Spoke** 的中继，让 NAT 后的节点也能互相访问。
- **天生穿透 NAT**——Spoke 通过**内置保活（keepalive）**维持自己的 NAT 映射，
  Hub 则会在 Spoke 漫游到新地址时**自动重新学习**它的端点——无需外部 ping 脚本，无需手动重连。
- **路由可热改**——运行时注入或更新转发规则，**零中断**：不重启、不丢包。
- **为运维而生**——同时提供人类可读**和** JSON 两种状态输出、按原因细分的丢包计数器
  （告诉你流量*为什么*没通）、每个对端的健康/`online` 标志，以及用于告警的 **Prometheus** 导出器。
- **简单的声明式配置**——把一个节点声明成 `hub` 或 `spoke`，转发表会自动推导出来。
  还能给对端起名字，让 `status` 里显示的是 `bj-office-gw`，而不是 `id=2`。

## 🚀 快速上手

最快的方式是用容器镜像（Hub 通常是一台公网云主机）：

```bash
# 1. 创建配置——一个 Hub，一个或多个 Spoke。
cp config.example.json config.json
#    给每条对端链路设置一把唯一的 64 位十六进制密钥：openssl rand -hex 32

# 2. 运行（隧道需要 TUN 设备 + NET_ADMIN）。
docker run -d --name subnetra \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    -v "$PWD/config.json":/etc/subnetra/config.json:ro \
    ghcr.io/jamiesun/subnetra:latest

# 3. 查看状态。
docker exec subnetra subnetra status
```

更喜欢裸二进制？从[**最新发布**](https://github.com/jamiesun/subnetra/releases/latest)
下载对应架构的静态构建，放一个 `config.json` 在旁边，运行 `./subnetrad` 即可。
完整的「一个 Hub + 两个 Spoke」生产部署演练见
[**部署指南**](docs/deployment.md)。

## ⚙️ 配置速览

设置一个 `role`，Subnetra 就会为你推导路由表。一个对外暴露自己 overlay IP、
其余流量都走 Hub 的家庭/办公 **Spoke**，只需要：

```json
{
  "role": "spoke",
  "virtual_subnet": "10.0.0.0/24",
  "local_id": 2,
  "obfuscate": true,
  "local_tun_ip": "10.0.0.2/24",
  "local_routes": ["10.0.0.2/32"],
  "peers": [
    { "id": 1, "name": "cloud-hub", "endpoint": "203.0.113.1:18020", "allowed_src": "10.0.0.0/24", "psk": "…64 位十六进制…" }
  ]
}
```

与之配对的 **Hub** 只需列出它的各个 Spoke——每个对端都会变成通往该节点的一条路由：

```json
{
  "role": "hub",
  "virtual_subnet": "10.0.0.0/24",
  "local_id": 1,
  "obfuscate": true,
  "peers": [
    { "id": 2, "name": "bj-office-gw", "endpoint": "203.0.113.2:18020", "allowed_src": "10.0.0.2/32", "psk": "…64 位十六进制…" },
    { "id": 3, "name": "alice-laptop", "endpoint": "203.0.113.3:18020", "allowed_src": "10.0.0.3/32", "psk": "…64 位十六进制…" }
  ]
}
```

> **注意：** Hub 刻意不设 `local_tun_ip`——推导出的表只转发给 Spoke，因此 Hub 是纯中继、
> 在叠加网络上*不可达*。仅当你需要访问 Hub 自身时，才给它配置 `local_tun_ip` **并** 追加一条
> 本地投递规则。

每条对端链路都使用**各自**的私有预共享密钥（用 `openssl rand -hex 32` 生成）；
多条链路共用一把密钥会被拒绝。Spoke 会自动开启 NAT 保活。
所有字段详见 [`config.example.json`](config.example.json) 和
[部署指南](docs/deployment.md)，可用 `subnetrad --check` 离线校验配置。

## 📡 运维与可观测

`subnetra status` 把那些「设计上静默丢弃」的包变成可计数的信号，
让你能判断流量*为什么*通或不通：

```text
subnetra v0.5.1 [running]
mode=raw_direct local_id=1 udp_port=18020 tun=snr0 peers=2
peers:
  id=2 name=bj-office-gw endpoint=203.0.113.2:18020 allowed_src=10.0.0.2/32
  id=3 name=alice-laptop endpoint=203.0.113.3:18020 allowed_src=10.0.0.3/32
traffic: tun_rx / udp_tx / udp_rx / tun_tx / relay / keepalive …
drops:   unknown_peer / auth_or_invalid / spoof / no_route …
```

- `subnetra status --json` 把同样的数据输出为一个稳定、带版本号的 JSON 对象——
  其中包含每个对端的 `last_seen_age_seconds` 和 `online` 标志——便于监控与自动化
  （永远不会序列化任何密钥）。
- 一个开箱即用的 **Prometheus** [textfile 导出器](deploy/subnetra-textfile-exporter.sh)
  能把它变成可抓取的指标与告警。

完整的状态字段、丢包分类和告警示例见[部署指南 §6–§7](docs/deployment.md)。

## 🔌 安装方式

| 目标 | 方法 |
|---|---|
| **容器**（amd64 / arm64 / armv7 / armv5） | `docker pull ghcr.io/jamiesun/subnetra:latest`——内置 `HEALTHCHECK`，编排系统能直接报告 `healthy`/`unhealthy`。 |
| **静态二进制** | 从 [Releases](https://github.com/jamiesun/subnetra/releases/latest) 下载 `subnetra-<version>-<arch>.tar.gz`——无任何运行时依赖。 |
| **离线 / 内网隔离** | 加载每个 release 附带的、可 `docker load` 的镜像 tar 包；用 `SHA256SUMS.txt` 校验。 |
| **macOS Spoke** | `subnetra-<version>-macos-arm64.tar.gz`（Apple Silicon）/ `…-amd64`（Intel）——已通过 runbook 验收，见 [`docs/macos-spoke-acceptance.md`](docs/macos-spoke-acceptance.md)。 |
| **MikroTik RouterOS** | [`deploy/routeros/`](deploy/routeros/) 提供脚本化的容器启停——见 [`docs/routeros-container.md`](docs/routeros-container.md)。 |
| **systemd / launchd** | [`deploy/`](deploy/) 下有可直接改用的 unit 文件和 hub/spoke 配置。 |

## 📚 文档与资源

- 📘 [**部署指南**](docs/deployment.md)——「一个 Hub + 两个 Spoke」生产演练：密钥管理、主机网络、升级、HA/故障切换、密钥轮换、监控。
- 📐 [**线路协议规范**](docs/PROTOCOL.md)——规范化的 v1 链路协议（用于互操作与审阅）。
- 🎛 [**控制面协议**](docs/CONTROL-PROTOCOL.md)——管理/监控运行中守护进程的本地 UDS API，任意语言可直接对接（无需 FFI）。
- 🍏 [**macOS Spoke runbook**](docs/macos-spoke-acceptance.md) · 🛰 [**RouterOS 容器指南**](docs/routeros-container.md)
- 🏗 [**设计与架构**](docs/subnetra-develop.md)——产品需求与系统设计。
- 📦 [**发布页**](https://github.com/jamiesun/subnetra/releases/latest) · 🐳 [**容器镜像**](https://github.com/jamiesun/subnetra/pkgs/container/subnetra) · ⚙️ [**示例配置**](config.example.json)

## 🛠 从源码构建

只需要 [Zig](https://ziglang.org/) 0.16.0 工具链——别无他求。

```bash
zig build                                   # 本机构建
zig build -Dtarget=aarch64-linux-musl       # 静态交叉编译（也支持 x86_64 / arm-*）
zig build test                              # 运行测试套件
```

产物输出在 `zig-out/bin/`（`subnetrad` 守护进程 + `subnetra` 控制工具）。
Linux 开发容器与集成/基准测试脚本位于 [`.devcontainer/`](.devcontainer/) 和
[`test/integration/`](test/integration/)；发布流程是修改
[`build.zig.zon`](build.zig.zon) 里的 `.version` 并推送对应的 `vX.Y.Z` 标签。

## 📄 许可证

[MIT](LICENSE) © 2026 jettwang

---

> 🔁 本文档的英文版位于 [`README.md`](README.md)。
> **两者必须保持同步：修改其中之一时，请在同一次改动里更新另一个。**
