# @dsh-fly/dsh-plugin-fly-mode

把 **Fly 安全模式**（agent preset `fly`）作为一个**可安装的 bundle 层**发出去：任何 profile
装上它之后就能服务 `fly` preset，于是跨 profile 共用的会话库里那些带 `fly` 标签的会话不再是
"看得见、拿不到"（宿主会抛 `agent-preset/not-found: Unknown agent preset: fly`）。

## 它是什么 / 不是什么

- **是**：一条 `- insert:` 声明（`id: preset-fly`，行表来自 `presets/fly/agent.cordis.yml`）。其中
  **7 个 Fly 工具**（binary / reverse / pwn / diag / recon / blackbox / guard）的源码**内联在包内
  `tools/`**，行表用**本包子路径**引用它们 —— 装这个包**不会**在 npm 上再拉这 7 个包；
  **`fly-smart` 单独一个 plugin**：它是本包 `dependencies` 里**唯一**一项，行表保持裸名，
  由 npm 装进 profile 的 `node_modules`（它变化最快，且与工作台面板是一个整体，不适合内联）。
- **不是**：不带 `dsh.client`（模式是 agent 平面，没有浏览器半边）；不带 Fly 工作台
  （console / diagnostics / netops / plugins / smart-panel 是各自独立的包）；**不带**
  `dsh-plugin-fly-shell`（那会在别人的 UI 上再画一层 Fly 外壳）。
- **不写 registry 的 `default:`**：默认模式归上游 `standard`。装上它 ≠ 默认变 fly —— fly
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

## 发布前要做的两件

1. 8 个工具包目前都是 `private: true`（未发布）⇒ 先去掉它们的 `private` 并按同样方式发布，
   否则本包的 `dependencies` 解析不到；本包自己的 `private: true` 也在那时拿掉。
   **`private: true` 不是发布闸门**（实测：`npm publish --dry-run` 一路走到鉴权才停，鉴权前
   没有任何拦截）—— 它只是"别误装"的占位。真正的闸门是 `publishConfig` 里钉死的
   `registry: https://registry.npmjs.org/`：本机默认 registry 是**内网镜像**（`npm config get
   registry` = `pkgs.d.xiaomi.net/…/mi-npm/`），不钉的话 `npm publish` 会发到内网镜像去。
   手敲发布也请带 `--registry=https://registry.npmjs.org/`。
2. `repository.url` 必须与跑发布 workflow 的仓库一致（npm `--provenance` 会校验；写错的失败
   形状是"直接拒发"，见 `dsh-fly/AGENTS.md` 坑表）。

## 仓库状态（2026-10-11）

- 本仓刚落地：`cordis.patch.yml`（生成）、`package.json`、本 README。
- `.github/workflows/{ci,release}.yml` 是从 `@dsh-fly/dsh-plugin-fly-skins` 仓**抄来的模板，
  尚未适配**（里面的包名/路径/构建步骤还是皮肤那套）—— 适配是发布前的一步，别直接推它去跑。
- 身份已按规范设好（仓级 `user.email = ethanchen669@users.noreply.github.com`）。
