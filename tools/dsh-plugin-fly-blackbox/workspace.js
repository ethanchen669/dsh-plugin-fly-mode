/**
 * fly-blackbox 的**会话工作区解析**（纯逻辑：不碰 shell、不读文件、不碰时钟）。
 *
 * 为什么单独一个文件：这条解析里有两个"看起来成功、其实没有答案"的坑，而它们都只能靠
 * 假 ctx / 假 exec 的纯函数断言钉住（`tests/workspace.spec.mjs`）。
 *
 *  1. **`workingDirectory.get(session)` 永远不返回空**。引擎的实现是
 *     `sessionProjections.stateOf(session, 'workingDirectory') ?? defaultDirectory`，
 *     而 `defaultDirectory` 的构造是 `config.defaultDirectory ?? process.cwd()`。
 *     也就是说"这个会话根本没有记录工作目录"时，它照样返回一个**字符串**——那个字符串
 *     可能是宿主的 cwd。把它当成会话工作区，状态文件与 dump 会落到别处，而且**没有任何提示**：
 *     正是 AGENTS.md 坑表里"禁 `process.cwd()` 兜底"那条的形状。治法：先问
 *     `sessionProjections.stateOf()`（无投影时给 `undefined`，这才是"没有答案"），
 *     再退到 `header.cwd`；服务给的值**等于 defaultDirectory** 时不采纳。
 *  2. **`exec.workspace` 在某些引擎版本上不存在**（2026-10 在 Ubuntu 0.1.18 上实测：
 *     五个 bx_* 工具全部报"取不到工作区"），而 `exec.agent.session.header.cwd` 一直有。
 *     所以 header 排在老形状前面。
 *
 * 一切都取不到时**大声报错**，并给出显式指定的办法（`FLY_BLACKBOX_WORKSPACE`）——
 * 绝不静默拿宿主 cwd 顶替。
 */

/** 非空字符串才算一个目录；空白串不是。 */
function usable(value) {
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

/**
 * 问一个服务方法：服务缺席 / 方法缺席 / 抛错都返回 `null`。
 *
 * 只表示"这条问不出答案"，不是吞结论 —— 调用方必须继续往下找，找不到就抛。
 */
function ask(ctx, service, method, ...args) {
  const owner = ctx?.get?.(service)
  if (owner === undefined || owner === null || typeof owner[method] !== 'function') return null
  try {
    return owner[method](...args)
  } catch {
    return null
  }
}

/**
 * 当前会话的工作区根目录。
 *
 * @param exec - 工具执行的 execution 对象（`exec.agent.session` / `header.cwd` / 老形状）。
 * @param ctx - 插件上下文（用来机会式取 `sessionProjections` / `workingDirectory` 服务）。
 * @param env - 环境变量（默认 `process.env`；测试注入用）。
 * @returns 绝对目录字符串。
 * @throws 什么都取不到时抛出，文案点名 `FLY_BLACKBOX_WORKSPACE`。
 */
export function sessionWorkspace({ exec, ctx, env = process.env } = {}) {
  const explicit = usable(env?.FLY_BLACKBOX_WORKSPACE)
  if (explicit !== null) return explicit

  const session = exec?.agent?.session
  if (session !== undefined && session !== null) {
    // ① 会话投影才是"当前"目录（用户 `cd` 过也准）；没有投影时 stateOf 给 undefined。
    const projected = usable(ask(ctx, 'sessionProjections', 'stateOf', session, 'workingDirectory'))
    if (projected !== null) return projected

    // ② 服务兜底 —— 但它的 `get()` 在"没有投影"时会返回 defaultDirectory（可能是宿主 cwd），
    //    那不是这个会话的工作区，必须跳过、让 header.cwd 接住。
    const directory = usable(ask(ctx, 'workingDirectory', 'get', session))
    const fallback = ctx?.get?.('workingDirectory')?.defaultDirectory
    if (directory !== null && directory !== fallback) return directory
  }

  // ③ header.cwd 是引擎一直有的字段（会话创建目录）；④ 老形状保留兼容。
  for (const candidate of [
    exec?.agent?.session?.header?.cwd,
    exec?.session?.header?.cwd,
    exec?.workspace,
    exec?.cwd,
    exec?.session?.workspace,
    exec?.agent?.session?.workspace,
  ]) {
    const value = usable(candidate)
    if (value !== null) return value
  }

  throw new Error(
    '取不到当前会话的工作区（会话投影、workingDirectory 服务、exec.agent.session.header.cwd、'
    + 'exec.workspace / exec.cwd / exec.session.workspace 都是空），'
    + '拒绝用宿主 cwd 顶替：状态文件与 dump 路径会跟着错。'
    + '无头或验证场景请显式设 FLY_BLACKBOX_WORKSPACE=<绝对路径>。',
  )
}
