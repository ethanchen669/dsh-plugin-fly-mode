# @dsh-fly/dsh-plugin-fly-mode

把 **Fly 安全模式**（agent preset `fly`）作为一个**可安装的 bundle 层**发出去：任何 profile
装上它之后就能服务 `fly` preset，于是跨 profile 共用的会话库里那些带 `fly` 标签的会话不再是
"看得见、拿不到"（宿主会抛 `agent-preset/not-found: Unknown agent preset: fly`）。

## 它是什么 / 不是什么

- **是**：一条 `- insert:` 声明（`id: preset-fly`，行表来自 `presets/fly/agent.cordis.yml`）
  \+ 8 个 Fly 工具包作为 `dependencies`（profile 用 hoisted 布局 ⇒ 行表里的裸包名解析得到）。
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
2. `repository.url` 必须与跑发布 workflow 的仓库一致（npm `--provenance` 会校验；写错的失败
   形状是"直接拒发"，见 `dsh-fly/AGENTS.md` 坑表）。

## 仓库状态（2026-10-11）

- 本仓刚落地：`cordis.patch.yml`（生成）、`package.json`、本 README。
- `.github/workflows/{ci,release}.yml` 是从 `@dsh-fly/dsh-plugin-fly-skins` 仓**抄来的模板，
  尚未适配**（里面的包名/路径/构建步骤还是皮肤那套）—— 适配是发布前的一步，别直接推它去跑。
- 身份已按规范设好（仓级 `user.email = ethanchen669@users.noreply.github.com`）。
