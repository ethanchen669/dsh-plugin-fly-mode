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

## 仓库状态（2026-10-11）

- 形状定稿：一条 `- insert:` 声明 + 包内 `tools/`（8 个工具内联，行表用本包子路径引用）+
  `dsh-plugin-fly-smart` 作为**唯一** npm 依赖。声明由 `dsh-fly` 仓的
  `scripts/build-fly-mode-bundle.mjs` 生成，门禁用 `--check` 断漂移（含多出来的文件）。
- `.github/workflows/{ci,release}.yml` **已适配本仓**（纯声明包：不装依赖、直接跑
  `node scripts/verify.mjs`），CI 已在公开仓实测全绿，含 `fetch-depth: 0` 的**全历史署名硬门**。
- 身份已按规范设好（仓级 `user.email = ethanchen669@users.noreply.github.com`）。
