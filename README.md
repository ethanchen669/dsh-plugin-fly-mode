# @dsh-fly/dsh-plugin-fly-mode

把 **Fly 安全模式**（agent preset `fly`）作为一个**可安装的 bundle 层**发出去：任何 profile
装上它之后就能服务 `fly` preset，于是跨 profile 共用的会话库里那些带 `fly` 标签的会话不再是
"看得见、拿不到"（宿主会抛 `agent-preset/not-found: Unknown agent preset: fly`）。

## 它是什么 / 不是什么

- **是**：**两个 preset** 的声明（`- insert:`）：
  - **Fly 安全模式** `preset-fly`（行表来自 `dsh-fly` 的 `presets/fly/agent.cordis.yml`，45 行）；
  - **Fly 标准模式** `preset-fly-standard`（行表 = **上游 `standard` 的行表** + 一行 smart，33 行）——
    由生成器从**引擎自己的组合结果**里取上游行表（不手抄），所以引擎升级后行表跟着走、漂了 `--check` 会红。
  其中
  **8 个 Fly 工具**（binary / reverse / pwn / diag / recon / blackbox / artifact / guard）的源码**内联在包内
  `tools/`**，行表用**本包子路径**引用它们 —— 装这个包**不会**在 npm 上再拉这 8 个包；
  **`fly-smart` 单独一个 plugin**：它是本包 `dependencies` 里**唯一**一项，行表保持裸名，
  由 npm 装进 profile 的 `node_modules`（它变化最快，且与工作台面板是一个整体，不适合内联）。
- **不是**：不带 `dsh.client`（模式是 agent 平面，没有浏览器半边）；不带 Fly 工作台
  （console / diagnostics / netops / plugins / smart-panel 是各自独立的包）；**不带**
  `dsh-plugin-fly-shell`（那会在别人的 UI 上再画一层 Fly 外壳）。
- **不写 registry 的 `default:`**：默认模式归上游 `standard`。装上它 ≠ 默认变 fly（或 fly-standard）——
  只是「设置 → Agent 预设」里多出来的一个可选模式。
- **不含三模型路由**：`brainRoute` / `handRoute` / `reviewRoute` 是**用户机器**上的状态
  （`~/.dsh-fly/smart-routes.json`，面板写），本机那份值还是内网 provider。未被配置时工具会
  大声报错并指路（行配置 `<field>Route` 优先，其次才是工作台抽屉）。

## `cordis.patch.yml` 是生成的，别手改

```bash
# 在 dsh-fly 仓库里：
node scripts/build-fly-mode-bundle.mjs --out ../dsh-plugins/dsh-plugin-fly-mode/cordis.patch.yml
node scripts/build-fly-mode-bundle.mjs --out ../dsh-plugins/dsh-plugin-fly-mode/cordis.patch.yml --check
```

同源：它跑的是 `dsh-fly` 仓库里 `scripts/lib/fly-profile.mjs` 的 `seedAgentPreset()` —— dev 装配
（`pnpm setup:profile`）写进 `~/.dsh/profiles/fly/cordis.patch.yml` 的是**同一个函数**的输出。
`--check` 用于门禁（漂移即红）。

## 发布（0.1.3 起走 tag → OIDC，自动带 provenance）

- **以后每次发版**：升 `version` → 提交 → 打**注释 tag** → 推 tag；`.github/workflows/release.yml`
  会自动 `npm publish --access public --provenance` —— **不需要 token、不需要 2FA、不需要人工批准**。
  前提是包的「Settings → Trusted Publisher」按下面配好（**一次即可**）：

  ```
  Publisher            GitHub Actions
  Organization or user ethanchen669
  Repository           dsh-plugin-fly-mode
  Workflow filename    release.yml        ← 只写文件名，不是 workflow 里的 name:
  Allowed actions      ☑ Allow npm publish  ← 不勾只会"暂存"，npm publish 会"成功"但什么都不发
  ```

  重推同一个 tag **不会**重跑 workflow ⇒ 要重跑就换一个新 tag。
- **首次发布（≤0.1.2）走的是另一条路**：包在 npm 上还不存在 ⇒ 没有 Trusted Publisher 页面可填，
  只能 `npm stage publish --access public` 再在网页上批准（`stage` 不需要 2FA）。
  0.1.0 / 0.1.1 已废弃，**0.1.2 是最后一个用 stage 发出去的版本**。
- **验收三件**（必须**换缓存键**再读：registry 的 packument 会被 CDN 缓存，反复查同一把钥匙只会读到第一次的结果）：
  ① `dist-tags.latest == 新版本`；② **`dist.attestations` 存在**（= provenance 成了）；
  ③ `readme` 是**发布那一刻**的快照（改了 README 要等下一次发版才上 npm 页面）。
- 发布前两条硬要求：`repository.url` 与跑 workflow 的仓库**逐字一致**（`--provenance` 会校验，写错**直接拒发**）；
  发布目标钉在 `publishConfig.registry = https://registry.npmjs.org/` —— 本机默认 registry 是**内网镜像**。

## 安装

```bash
# CLI 路径（web 等 profile）；cwd 必须是 DSH_HOME
cd ~/.dsh
dsh plugin --profile=web add @dsh-fly/dsh-plugin-fly-mode@0.1.3 --registry=https://registry.npmjs.org/
```

- 装完**必须重启那个进程**：引擎把层与服务缓存在**进程内**，刷新页面不够。
- **官方桌面版**归 app 独占（`dsh plugin` 会拒：`profile "desktop" is managed exclusively by the
  Electron application`）⇒ 在 `~/.dsh/profiles/desktop/` 里 `pnpm add …@0.1.3 --registry=…`，
  并且要把包名加进 `package.json` 的 **`dsh.profile.bundles`** —— 那一条才让它成为一层
  （只写 `dependencies` 是不会生效的）。

## Linux（Ubuntu）支持

2026-10-27 在 **Ubuntu 24.04 / Linux 6.8（x86_64）** 上逐工具实测并补齐。macOS 仍是主发布
平台；Linux 侧优先用系统自带的数据源，**拿不到数据时大声报「没有数据」**，绝不把缺命令读成
「链路正常 / 没有邻居 / 文件不存在」。

| 工具 | Linux 数据源 / 行为 |
| --- | --- |
| `diag_host` / `diag_procs` | `uname` / `ps aux`（原本就可移植） |
| `diag_net` | `ss -ltnp`（缺 `ss` 退 `netstat -ltnp`）；只列 TCP LISTEN，unix socket 不再冒充 listener |
| `diag_net_rtt` | iputils `ping`：`-W 2`（秒）单包超时、`-w <deadline>` 整轮截止；网关默认从 `ip route` 取 |
| `diag_net_watch` | 同一套 ping 参数；链路采样改为 `iw dev <if> link`；status 的 mtime 用 GNU `stat -c %Y`（BSD `-f %m` 兜底） |
| `diag_wifi_link` | `iw dev` + `iw dev <if> link` + `/proc/net/wireless`（底噪）+ `iw reg get`（国家码）；没有无线接口 ⇒ `available:false` |
| `diag_wifi_channels` | `iw phy <phy> info`（监管允许信道）+ `iw dev <if> scan dump`（只读缓存）；`iw` 读不到时退 `nmcli … wifi list --rescan no`（nmcli 不报带宽 ⇒ `widthMhz:null`，不当成 20） |
| `diag_net_throughput` | `curl`；默认目标按平台选（Linux x64 / macOS arm64） |
| `recon_ports` | `nmap` 缺失时用系统 `nc`：Linux `nc -z -w 1`，**不再传 macOS 的 `-G`**；`nc` 也没有 ⇒ 报错，不返回「全部 no-response」 |
| `recon_http_fingerprint` | `curl`（原本就可移植） |
| `bin_*` / `pwn_*` / `rev_disasm` / `rev_imports` / `rev_gadget_scan` | ELF 走 `readelf` / `objdump` / 内置解析器；Mach-O 的 `lipo`/`otool` 分支在 Linux 上自然不触发 |
| `rev_ghidra` | `analyzeHeadless` 查找顺序：`GHIDRA_HOME` → `PATH` → `~/tools/ghidra_*` / `/opt/ghidra*` / `/usr/share/ghidra*`；JDK 从 `JAVA_HOME` → `~/tools/jdk-*/bin/java` → `command -v java` 反解，**最低版本读 `<GHIDRA_HOME>/Ghidra/application.properties` 的 `application.java.min`**（12.3 DEV = 25），低于它在 doctor 里报红 |
| `bx_*`（blackbox） | 工作区取 `workingDirectory` 服务 / `exec.agent.session.header.cwd`；文件大小用 GNU `stat -c%s`；监听用 `ss -ltnp`（`lsof` 兜底）；CA 用 `openssl verify -CAfile <系统 bundle>` + `update-ca-certificates` 指引；系统代理用 GNOME `gsettings`；mitmdump 自动发现 `~/tools/mitmproxy-venv/bin/mitmdump`（或 `FLY_MITM_BIN` / PATH），缺装时给 Ubuntu 的 venv / pipx 指引 |
| `artifact_*` | 原本就有 GNU `stat` / `wc -c` / `sha256sum` 兜底 |

安装依赖（按需）：

```bash
sudo apt install -y iw netcat-openbsd openssl python3-venv   # Wi-Fi / recon / CA / mitmproxy
# Ghidra：解压后设 GHIDRA_HOME，或放到 /opt/ghidra*；JDK 版本以 Ghidra 的
# Ghidra/application.properties（application.java.min）为准（12.3 DEV 要 25）
```

### 本机持久安装（2026-10-28）

这台 Ubuntu 上已经按下面布局装好，**不需要再设 `FLY_MITM_BIN` / `GHIDRA_HOME` /
`JAVA_HOME`**：

| 位置 | 内容 |
| --- | --- |
| `~/tools/jdk-25` | Temurin JDK 25.0.5（Ghidra 12.3 的最低版本） |
| `~/tools/ghidra_12.3_DEV` | 从源码构建的 Ghidra headless 发行版（461MB，含 `support/analyzeHeadless` 与原生 decompile） |
| `~/tools/mitmproxy-venv` | 从源码安装的 mitmproxy `13.0.0.dev`（Python 3.14） |
| `~/.local/bin/mitmdump` | → `~/tools/mitmproxy-venv/bin/mitmdump`（已在 PATH 上） |
| `~/.local/bin/ghidra-analyze` | 直接调 `analyzeHeadless` 的包装（自动带 JDK 25） |

工具侧自动发现：blackbox 先看 `~/tools/mitmproxy-venv/bin/mitmdump`，`rev_ghidra` 先看
`~/tools/ghidra_*` 与 `~/tools/jdk-*`；都支持用环境变量覆盖。

已知边界（如实写出来，不当成"支持"）：

- **无线**：本次测试机没有 Wi-Fi 硬件，`iw`/`nmcli` 解析器用夹具做了回归（20 条 Linux
  可移植性检查），**没有在真实射频上跑过**；上表两个无线工具在无接口时返回 `available:false`。
- **ICMP**：`diag_net_rtt` / `diag_net_watch` 需要 `CAP_NET_RAW`（Ubuntu 的 `ping` 通常带
  `cap_net_raw`）；在禁 raw socket 的沙箱里会明确报错。本次沙箱即如此，参数构造用假 `ping`
  验证过。
- **mitmproxy**：用 clone 的 `13.0.0.dev` 建 venv 后实测：`bx_proxy start/status/stop`、
  HTTP 与 HTTPS 各 200、`bx_doctor` ①–⑤ 全过、`bx_flows` 读真实 dump（2 条 flow，flow
  format 21 与读取器一致）。仍未验证：真实客户端（微信小程序等）的 pinning 与"只读启动时
  系统代理"行为。
- **Ghidra**：从 clone 构建 `12.3 DEV`（JDK 25）后实测：doctor（JDK 25 + 原生
  `os/linux_x86_64/decompile` 都在）、`functions`、`decompile`、`decompile-many`、`strings`、`xrefs`、`trace`
  均跑通；`decompile` 指定不存在函数时的报错文案也已修正。构建 Ghidra 12.3 **必须 JDK 25**
  （`application.java.min=25`），只装 JDK 11/21 会被 doctor 明确拦下。仍未验证：反编译质量、
  超大二进制的耗时。
- **GNOME 系统代理**：只影响读 `gsettings` 的应用；CLI 多数认 `http_proxy`/`https_proxy`，
  工具输出里会同时给出宿主环境变量。
- 授权门不变：`recon_*` 仍需 `FLY_ALLOW_RECON=1`，`bx_proxy`/`bx_sysproxy` 的写动作仍需
  `FLY_ALLOW_INTERCEPT=1`；Linux 实现没有绕过任何一道门。

门禁：`node scripts/verify.mjs` 现在包含 20 条 Linux 可移植性检查（纯函数、无新依赖），
与原有包形状检查一起跑。

## 仓库状态（2026-10-11）

- 形状定稿：一条 `- insert:` 声明 + 包内 `tools/`（8 个工具内联，行表用本包子路径引用）+
  `dsh-plugin-fly-smart` 作为**唯一** npm 依赖。声明由 `dsh-fly` 仓的
  `scripts/build-fly-mode-bundle.mjs` 生成，门禁用 `--check` 断漂移（含多出来的文件）。
- `.github/workflows/{ci,release}.yml` **已适配本仓**（纯声明包：不装依赖、直接跑
  `node scripts/verify.mjs`），CI 已在公开仓实测全绿，含 `fetch-depth: 0` 的**全历史署名硬门**。
- 身份已按规范设好（仓级 `user.email = ethanchen669@users.noreply.github.com`）。
