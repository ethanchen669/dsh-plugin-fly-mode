/**
 * fly-guard — DSH Fly 的「持久化写」授权门。
 *
 * 官方 `plugin_manager`（`@deepseek-ai/dsh-plugin-manager/tools`）是**唯一**能把包写进
 * 这份部署的工具：`set_plugin` / `set_bundle` 改的是 `cordis.patch.yml`（profile 层的
 * 覆盖项），`install_bundle` / `remove_bundle` 装/摘的是**会在宿主进程里跑起来**的代码。
 * 这些改动跨会话存活、且绕过我们的装配脚本（`scripts/lib/fly-profile.mjs`）。
 *
 * 它自己的门只有「会话沙箱模式 + 逐次审批」这一层。而**创造模式**就是要一个能改自己的
 * DSH，实测会话里那两项是 `never` + `danger-full-access` —— 也就是**没有门**（本仓库
 * `packages/dsh-plugin-fly-plugins` 的面板一装上去就能看到这一层有多薄）。
 *
 * 所以 Fly 给「写自己」补一道自己的门，判据放在**宿主环境变量**上：
 *
 *   未设 `FLY_ALLOW_PROFILE_WRITE=1` → 只读动作放行，写入动作一律 deny（默认全拒）；
 *   设了                              → 写入动作也放行（人显式授权）。
 *
 * 为什么是宿主 env 而不是行配置：行配置写在 patch 层里，而 agent 手里**正是**那个能改
 * patch 层的工具 —— 用受它管的门去管它自己，不是门。env 只有人（终端 / Electron 主进程）
 * 能设；会话里的 bash 子进程设不了宿主进程的 env。
 *
 * fail-closed：`plugin_manager` 上出现本文件不认识的 `action`（上游加了新动作），或读不到
 * `action`（形状变了），**一律 deny**。上游 `lib/types/tools.js` 里的 `enum` 是那份词表的
 * 真值来源，`scripts/tests/fly-guard.spec.mjs` 直接对着钉住的闭包逐条比 —— 上游加动作而
 * 这里没跟上，门禁红（不是静默开门）。
 *
 * `action` 读的是 `exec.arguments.action`：引擎交给 `tools/pre-execute` 的 execution 由
 * `@deepseek-ai/dsh-tools` 的 `createExecution()` 造出来，字段是 `arguments`，**没有 `args`**。
 * 黑盒那包曾按 `exec.args?.action` 写、门禁也按 `args` 喂，于是"改动动作被 deny"假绿了
 * 整整一版，真机上 5 个动作根本没进门（见 AGENTS.md 坑表）。
 */
export const name = 'fly-guard'

/**
 * `inject: ['tools']`：这道门挂在**工具面**上（`tools/pre-execute` 是工具执行的
 * waterfall），必须在有工具注册表的那个 scope 里挂载。它自己不注册任何工具，
 * 也不碰 `shell` —— 因此不需要 `shell` / `skills` 那两项。
 */
export const inject = ['tools']

/** 上游 `plugin_manager` 的只读动作：任何情况下放行。 */
export const READ_ONLY_ACTIONS = ['list_plugins', 'list_bundles', 'list_version_exemptions']

/** 上游 `plugin_manager` 的写入动作：须 `FLY_ALLOW_PROFILE_WRITE=1`。 */
export const WRITE_ACTIONS = ['set_plugin', 'set_bundle', 'install_bundle', 'remove_bundle', 'set_version_exemption']

/** 本门只管这一个工具；其余任何工具原样透传。 */
export const GATED_TOOL = 'plugin_manager'

/** 放行写入的宿主环境变量（人也只能用它的名字，见上面"为什么是宿主 env"）。 */
export const ALLOW_ENV = 'FLY_ALLOW_PROFILE_WRITE'

/**
 * 从引擎真正交下来的 execution 里读出 `action`。
 *
 * 读不到（没有 `arguments`、`action` 不是非空字符串）返回 `undefined` —— 由调用方
 * **按受控处理**，不是放行。
 *
 * @param exec - `tools/pre-execute` 的 execution 对象。
 * @returns 动作名，或 undefined（读不到）。
 */
function actionOf(exec) {
  const action = exec?.arguments?.action
  return typeof action === 'string' && action.trim() !== '' ? action : undefined
}

/**
 * 拒绝文案。它要能被人直接读懂"为什么拒、怎么放行"，因为 agent 会把原文转给用户。
 *
 * @param action - 被拒的动作名，或 undefined（读不到）。
 * @returns 一段给人看的拒绝理由。
 */
function denialReason(action) {
  const what = action === undefined
    ? '一个读不出名字的动作（可能是上游换了形状，或加了本门还不认识的新动作）'
    : `\`${action}\``
  return `Fly 的安全门拒绝了 plugin_manager 的 ${what}：任何写入都会**持久**留在 profile 里`
    + '（patch 层的覆盖项 / bundles / 会在宿主进程里执行的代码），跨会话存活，并且绕过装配脚本。'
    + `只读动作（${READ_ONLY_ACTIONS.join(' / ')}）不受限。`
    + `确实要写，就请用户在他自己的终端给宿主进程设 ${ALLOW_ENV}=1 后重启 —— `
    + '这个变量故意不放在会话里，agent 自己设不了它。'
}

/**
 * 挂上这道门。
 *
 * 判定顺序就是权限顺序：先看是不是受管工具（不是 ⇒ `next()`，本门对别的工具零影响），
 * 再看是不是声明的只读动作（是 ⇒ 放行），再看人的显式授权（`=1` ⇒ 放行），
 * 剩下的**全拒** —— 未知动作、空动作、读不到 `action`，一个都不漏。
 *
 * @param ctx - Cordis 插件上下文（`inject: ['tools']`）。
 */
export function apply(ctx) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec?.name !== GATED_TOOL) return next()
    const action = actionOf(exec)
    if (action !== undefined && READ_ONLY_ACTIONS.includes(action)) return next()
    if (process.env[ALLOW_ENV] === '1') return next()
    return { kind: 'deny', reason: denialReason(action) }
  })
}
