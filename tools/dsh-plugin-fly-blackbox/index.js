/**
 * fly-blackbox — 客户端黑盒排查能力（skill + 工具）。
 *
 * 这个包把一次真实事件（某小程序"性别字段死锁"导致账号无法报名）里沉淀出的客户端
 * 黑盒排查能力收进 Fly 安全模式，分两层交付：
 *
 *  · **知识层**：一个 bundled skill（`assets/client-blackbox/`），按需加载。agent 读到的是
 *    心智模型（三源一闸 S1/S2/S3/G）、六条判据 T1–T6、五阶段带 Gate 流程与可复用脚本模板。
 *    知识本身不产生副作用，所以不受授权闸门管。
 *  · **执行层**：十个工具，走宿主 `shell` 接缝（最近三件 `bx_cdp_targets` / `bx_cdp_scripts` /
 *    `bx_cdp_coverage` 是**进程内通道**：CDP 调试端口上的 target 清单、已解析脚本清单、精确覆盖率 ——
 *    线缆层看不见"进程里显示了什么、哪段 JS 改的它"，它们补这一半；只连回环、整件在授权门后）。它只管**可观测性与判定**（起代理、判管道、
 *    读抓包、比对前后），改写路径（请求/响应注入）必须显式授权。
 *
 * 三条纪律写死在实现里，因为每一条都对应一次实测事故：
 *
 *  1. **一律经 `ctx.shell`**：`ShellExecutor` 只有 `resolve()` + `execute()`（0.1.7-rc.2 与
 *     0.2.0-rc.2 都是），绝不 `child_process`；`node:fs` 只用于两处：读自带 skill 资产、
 *     读写工作区内的自身状态文件。**用户数据（dump / 规则文件）必须走接缝**，这样沙箱拒绝
 *     会以 `SandboxError` 报出来，而不是一个裸 EACCES。
 *  2. **`truncated` 即失败**：`result.stdout.truncated` / `spillPath` 出现就报错。对 base64
 *     读 dump 尤其致命 —— 截断的 base64 会解出半个 dump，然后给出"抓到的就这些"的假结论。
 *  3. **永不提权**：`runCmd` 在执行前拒绝 `sudo` 与 `osascript … administrator privileges`。
 *     理由不是审美：提权调用在沙箱里弹不出框也没有超时，而 `execute` 要 `await result()`，
 *     真会话里那会**无超时地挂住**。需要人跑的命令只作为**文本**输出，不经过接缝。
 *
 * 缺依赖的口径是**大声**：macOS 没有 readelf/nmap 时仓库内补（见 fly-binary/recon），
 * 但 TLS 拦截**没有纯仓内替代**（只转发 CONNECT 的代理看得到域名、看不到 body，而这类
 * 缺陷恰恰在 body 里），所以这里既不假装能抓、也不静默降级：`bx_proxy status` 会报出
 * 点名解释器的两行安装命令，`bx_doctor` 把"无抓包能力"当一等状态。
 *
 * 静态禁项（`scripts/verify-blackbox.mjs` 剥离注释后扫描）：无 `shell.run(` / `shell.start(` /
 * `child_process`；`inject` 恰好是 `['tools','shell','skills']`。
 */
import { createHash } from 'node:crypto'
// `node:fs` 的**两个允许用途**（design §3.1）：① 下面三行读自带 skill 资产；
// ② `writeState`/`clearState` 读写工作区内的自身状态文件。用户数据（dump、规则文件）
// 一律走 `shell` 接缝，这样沙箱拒绝会以 SandboxError 报出来。
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
// gzip 只用 Node 自带的 `zlib`：`.har.gz` 的识别**按 magic 判**，不新增依赖、也不靠扩展名。
import { gunzipSync } from 'node:zlib'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { BUNDLED_SKILL_RANK } from '@deepseek-ai/dsh-skill'

import {
  caInstallLines,
  caTrustNote,
  caVerifyArgv,
  GNOME_PROXY_KEYS,
  gnomeProxyOffCommands,
  gnomeProxyOnCommands,
  gnomeProxyRestoreCommand,
  listenerLinesForPort,
  listenerListArgv,
  listenerPidOfLine,
  mitmInstallLines,
  parseGsettingsValue,
  parseStatSize,
  quitHint,
  statSizeArgv,
} from './platform.js'

export const name = 'fly-blackbox'
/** 少一个 = 整棵 preset 被拒：provider 在 `apply()` 里注册，注不到 `skills` 就抛。 */
export const inject = ['tools', 'shell', 'skills']

/** 本包实现的 flow 文件格式版本（见 §B1 的版本闸）。 */
const FLOW_FORMAT_VERSION = 21

/** `assets/client-blackbox` 的绝对路径（打包版走真实路径，不是 SEA）。 */
const ASSET_ROOT = fileURLToPath(new URL('./assets/client-blackbox/', import.meta.url))
/** 自带资产：一个都不能少，缺任一 `apply()` 就抛（宁可整棵 preset 被拒，也不要静默少一个 skill）。 */
const ASSETS = [
  'SKILL.md',
  'reference/playbook.md',
  'reference/checklist.md',
  'reference/case-ttw.md',
  'reference/rules.schema.md',
  'code/mitm_addon_template.py',
  'code/rules.example.json',
]

// ─────────────────────────────────────────────────────────────────────────────
// §B1 tnetstring 读取器（纯函数，门禁直接 import）
//
// mitmproxy 的 dump 是"长度前缀 + 载荷 + 类型标记"的 tnetsing 串接：
//   `<len>:<payload><marker>`；marker：`;`=str、`,`=bytes、`#`=int、`^`=float、
//   `!`=bool、`~`=null、`]`=list、`}`=dict。
//
// 与上游 `mitmproxy/io/tnetstring.py`（12.2.3）逐条对齐的三点，每一点都踩过或差点踩：
//   · dict 的**键**也走 `;`（str），不是 bytes —— 所以 `version` 在线上是 `7:version;`，
//     值 `21` 是 int（`2:21#`，长度前缀 2）。**长度前缀随位数变**，改版本号不能只替换数字。
//   · `~` 空值（`0:~`）是**常态**（`websocket: null`），不是"首条占位" —— 必须当普通值。
//   · str 严格 UTF-8 解码：坏字节**抛错**，绝不产生 U+FFFD（否则"非 UTF-8 判据"被打穿）。
// ─────────────────────────────────────────────────────────────────────────────

/** Python `int(...)` 接受的十进制字面量（拒绝 `+5` / ` 5` / `1_0` 之外的宽松形态）。 */
const INT_LITERAL = /^[+-]?\d+$/u
/** Python `float(...)` 接受的形态；`1.` / `.5` / `1e3` 都算，空的 `#` 不算。 */
const FLOAT_LITERAL = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/u

/** 大写十六进制，用于坏字节回显（`hex` 字段与 `non-utf8 header` 的载荷）。 */
export function hexOf(buffer, limit = 64) {
  return buffer.subarray(0, limit).toString('hex').toUpperCase()
}

/**
 * 把一个字节串按**严格** UTF-8 解码。
 * @returns 解码文本，或 `null`（有坏字节时）。
 */
export function strictUtf8(buffer) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer)
  } catch {
    return null
  }
}

/**
 * 从 `cursor` 处读一个 tnetstring 值的长度前缀，返回 `{ length, payloadAt }`。
 *
 * 长度前缀超过 12 位数字视为"荒谬的长度前缀"（上游同款保护）。**抛出的错误带
 * `code:'TRUNCATED'`**：只有"读着读着到头了"才算截断，调用方据此区分尾部半条记录
 * 与中间损坏 —— 靠匹配错误文本区分是脆的。
 */
function readLength(bytes, from, what) {
  let at = from
  while (at < bytes.length && bytes[at] >= 0x30 && bytes[at] <= 0x39) {
    at += 1
    if (at - from > 12) throw new Error(`tnetstring: absurdly large length prefix at byte ${from} (${what})`)
  }
  if (at >= bytes.length || bytes[at] !== 0x3a) {
    const error = new Error(`tnetstring: missing or invalid length prefix at byte ${from} (${what})`)
    error.code = 'TRUNCATED'
    throw error
  }
  return { length: Number(bytes.toString('latin1', from, at)), payloadAt: at + 1 }
}

/**
 * 解析 `bytes` 中 `at` 处的一个值。
 * @returns `{ value, next }`，`next` 是下一个值的起点。
 */
function parseValue(bytes, at, path) {
  const { length, payloadAt } = readLength(bytes, at, path)
  if (payloadAt + length > bytes.length) {
    const error = new Error(`tnetstring: value at byte ${at} claims ${length} payload bytes but only ${bytes.length - payloadAt} remain (${path})`)
    error.code = 'TRUNCATED'
    throw error
  }
  const payload = bytes.subarray(payloadAt, payloadAt + length)
  const markerAt = payloadAt + length
  if (markerAt >= bytes.length) {
    const error = new Error(`tnetstring: value at byte ${at} has no type tag — the dump ends inside a record (${path})`)
    error.code = 'TRUNCATED'
    throw error
  }
  const marker = String.fromCharCode(bytes[markerAt])
  const next = markerAt + 1
  const where = `${path} @byte ${at}`

  if (marker === ';') {
    const text = strictUtf8(payload)
    if (text === null) throw new Error(`tnetstring: ${where} is not valid UTF-8: hex ${hexOf(payload)}`)
    return { value: text, next }
  }
  if (marker === ',') return { value: Buffer.from(payload), next }
  if (marker === '#') {
    const literal = payload.toString('latin1')
    if (!INT_LITERAL.test(literal)) throw new Error(`tnetstring: ${where} has an invalid integer literal ${JSON.stringify(literal)}`)
    return { value: Number.parseInt(literal, 10), next }
  }
  if (marker === '^') {
    const literal = payload.toString('latin1')
    if (!FLOAT_LITERAL.test(literal)) throw new Error(`tnetstring: ${where} has an invalid float literal ${JSON.stringify(literal)}`)
    return { value: Number.parseFloat(literal), next }
  }
  if (marker === '!') {
    if (length === 4 && payload.toString('latin1') === 'true') return { value: true, next }
    if (length === 5 && payload.toString('latin1') === 'false') return { value: false, next }
    throw new Error(`tnetstring: ${where} has an invalid boolean literal ${JSON.stringify(payload.toString('latin1'))}`)
  }
  if (marker === '~') {
    if (length !== 0) throw new Error(`tnetstring: ${where} has an invalid null literal (${length} bytes of payload)`)
    return { value: null, next }
  }
  if (marker === ']') {
    const items = []
    let inner = payloadAt
    let index = 0
    while (inner < markerAt) {
      const item = parseValue(bytes, inner, `${path}[${index}]`)
      items.push(item.value)
      inner = item.next
      index += 1
    }
    if (inner !== markerAt) throw new Error(`tnetstring: ${where} list payload does not end on its marker`)
    return { value: items, next }
  }
  if (marker === '}') {
    const object = {}
    let inner = payloadAt
    while (inner < markerAt) {
      const key = parseValue(bytes, inner, `${path}.<key>`)
      const item = parseValue(bytes, key.next, `${path}.${String(key.value)}`)
      object[key.value] = item.value
      inner = item.next
    }
    if (inner !== markerAt) throw new Error(`tnetstring: ${where} dict payload does not end on its marker`)
    return { value: object, next }
  }
  throw new Error(`tnetstring: ${where} has an unknown type tag ${JSON.stringify(marker)}`)
}

/**
 * 读一个 dump 里的**全部** flow（一条记录一个 tnetstring）。
 *
 * 结束条件是"读指针 == 文件长度"；**尾部**半条记录 → 明说读到第 N 字节截断、可能有 1 条
 * 未完成；**中间**损坏（长度前缀/类型标记不对，且后面还剩下完整字节）→ 抛错。
 *
 * 两类失败的判据不是错误文本而是**剩余字节**：记录从 `cursor` 起解不动、且失败点已经吃到
 * 文件末尾 → 截断；失败点后面还有整条记录的字节 → 中间损坏。
 *
 * @param buffer - 整个 dump 的字节。
 * @returns `{ flows, cursor, fileLength, truncated, note }`。
 */
export function readFlows(buffer) {
  const flows = []
  let cursor = 0
  let truncated = false
  let note = ''
  while (cursor < buffer.length) {
    const at = cursor
    let parsed
    try {
      parsed = parseValue(buffer, cursor, 'flow')
    } catch (error) {
      const remainder = buffer.length - cursor
      const truncatedShape = error.code === 'TRUNCATED'
      if (truncatedShape) {
        truncated = true
        note = `读到第 ${cursor} 字节截断，可能有 1 条未完成（从该处起只剩 ${remainder} 字节）`
        break
      }
      throw new Error(`${error.message}（在第 ${flows.length + 1} 条记录、字节 ${at} 处；后面还有 ${remainder} 字节，属中间损坏而不是尾部截断）`)
    }
    if (Array.isArray(parsed.value) || Buffer.isBuffer(parsed.value) || parsed.value === null || typeof parsed.value !== 'object') {
      throw new Error(`tnetstring: byte ${at} holds a ${parsed.value === null ? 'null' : typeof parsed.value}, not a flow dict — wrong file?`)
    }
    flows.push(parsed.value)
    cursor = parsed.next
  }
  // 末条记录必须**正好**吃到文件末尾：尾部截断可能落在"长度前缀声明得太大"上（parse 会抛
  // TRUNCATED），也可能**恰好落在剩余字节里**（parse 成功但记录少了一截）。后一种会在光标处
  // 留下半条尾巴，所以用它当判据 —— 不靠"解析器有没有抛错"。
  if (cursor !== buffer.length) {
    truncated = true
    note = `读到第 ${cursor} 字节截断，可能有 1 条未完成（从该处起只剩 ${buffer.length - cursor} 字节）；已读到的 ${flows.length} 条是完整的。`
  }
  return { flows, cursor, fileLength: buffer.length, truncated, note }
}

/**
 * 版本闸：**接受 ≤ 本包实现的版本，拒绝更高**。
 *
 * 上游不是"必须等于"：`mitmproxy/io/compat.py:512-525` 的 `migrate_flow` 只在
 * `flow_version > version.FLOW_FORMAT_VERSION` 时抛 `cannot read files with flow format
 * version {v}, please update mitmproxy`，低于它的一律走 `converters` 升级。纯 JS 读取器
 * 没有那套 converter，但"旧结构"恰恰是**同一个结构**（本读取器只依赖字段名，不依赖
 * 版本特性），所以口径照上游：高了拒绝，低了照读。
 *
 * **注意：它是导出给调用侧的，`readFlows()` 自己不调用它**（读取器只管字节 → 结构）。
 * 所以"读取器有版本闸"这句话要读成"**读 dump 的那条工具路径有**"：工具路径在 `readFlows()`
 * 之后逐条过这里；单跑 `readFlows()` 喂一个 99 版的 dump 会照读不误（门禁第 13 条把两侧
 * 都钉住：工具路径必须拒、手工配对也必须断）。
 *
 * @param flow - 一个已解析的 flow dict。
 * @param context - 出错文案要回显的东西（文件路径、mitmdump 版本）。
 */
export function assertReadableVersion(flow, context = {}) {
  const raw = flow?.version
  const dumpVersion = typeof raw === 'number' ? raw : undefined
  if (dumpVersion !== undefined && dumpVersion <= FLOW_FORMAT_VERSION) return dumpVersion
  const where = context.path === undefined ? '' : `${context.path}: `
  const hint = context.mitmdumpVersion === undefined ? '' : `\n本机 mitmdump --version：${context.mitmdumpVersion}`
  throw new Error(
    `${where}这个 dump 的 flow 格式版本是 ${dumpVersion === undefined ? `不可解析的 ${JSON.stringify(raw)}` : dumpVersion}，`
    + `本包实现的版本是 ${FLOW_FORMAT_VERSION}；版本更高的 dump 结构可能已经变了，拒绝按旧结构硬解。`
    + `\n修法：用与 dump 同版本的 mitmproxy 重新导出，或升级 fly-blackbox 的读取器。${hint}`,
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// §B4 接缝纪律
// ─────────────────────────────────────────────────────────────────────────────

function shq(value) {
  return `'${String(value).replace(/'/gu, "'\\''")}'`
}

/** 执行前拒绝提权：`sudo` 出现在命令里，或 `osascript` + `administrator privileges`。 */
function assertNotPrivileged(command) {
  if (/(^|[\s;&|(])sudo\b/u.test(command) || (/osascript/u.test(command) && /administrator privileges/u.test(command))) {
    throw new Error(
      `拒绝执行提权命令（本包永不提权）：${command}\n`
      + '理由：提权调用弹不出授权框且没有超时，而 execute 要 await result()，真会话里会无超时挂住。'
      + '需要人跑的提权命令由 bx_ca command 输出成文本，用户自己复制到终端执行。',
    )
  }
}

/**
 * 跑一条命令 —— **每一条执行路径的唯一入口**。
 *
 * 与 `fly-recon` 的 `runCmd` 同形，但多两条：① 执行前拒提权（§B1 的纪律三）；
 * ② **读截断信息**：`stdout.truncated === true` 或出现 `spillPath` 一律当失败。
 * 既有五个安全插件的 `runCmd` 不读 `truncated`（当前输出都远低于上限所以没触发，
 * 见 docs/capability-iterations.md 的"已知缺口"）—— 新包不许继承这条。
 *
 * **`result` 是方法，不是属性**：`ShellExecution.result()`（类型见 `dsh-shell` 的
 * `types.d.ts`）。写成 `await handle.result` 会 await 到**函数本身**（不是 thenable ⇒
 * 原样返回），随后 `result.stdout.text` 抛 `TypeError: Cannot read properties of
 * undefined (reading 'text')` —— 每一个工具调用都炸，而"只提供 result 属性"的桩看不见
 * 这一点（本仓既有五个插件的 `runCmd` 正是这个写法；门禁桩现在按真接缝的形状发布
 * `result()`，所以这类"桩和真接缝不同形"的假绿会在这一层被抓住）。
 */
/**
 * 路径参数规范化：以 `-` 开头的路径加 `./` 前缀（2026-10-13）。
 *
 * 为什么不插 `--`：实测本机（macOS，发布目标平台）**objdump（-h/-d/-T）/ base64 -i / otool -hv 都不支持
 * `--`**，插进去直接失败；而 `file -b --version` 会打印 `file-5.41`、`nm -u --version` 会打印
 * `llvm-nm, …`，两者都 **exit 0** ⇒ 工具会把版本串当**数据**返回。加 `./` 之后它就是一个普通相对路径：
 * 不存在就正常报错，存在就是那个文件。
 */
function safePath(value) {
  const text = String(value ?? '')
  return text.startsWith('-') ? './' + text : text
}

async function runCmd(shell, argv, exec, opts = {}) {
  const command = typeof argv === 'string' ? argv : argv.map(shq).join(' ')
  assertNotPrivileged(command)
  const handle = await shell.execute(shell.resolve({
    command,
    ...opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {},
    ...opts.stdoutMaxBytes !== undefined ? { stdoutMaxBytes: opts.stdoutMaxBytes } : {},
    ...opts.onExpiry !== undefined ? { onExpiry: opts.onExpiry } : {},
    signal: exec.signal,
  }))
  const result = await handle.result()
  if (result.aborted) {
    const error = new Error('tool call aborted')
    error.name = 'AbortError'
    throw error
  }
  if (result.sandbox?.denied) {
    const error = new Error(`[sandbox: file access denied under ${result.sandbox.mode} mode]`)
    error.name = 'SandboxError'
    throw error
  }
  if (result.stdout?.truncated === true || result.stdout?.spillPath !== undefined) {
    const spill = result.stdout?.spillPath === undefined ? '' : `（溢写到 ${result.stdout.spillPath}）`
    throw new Error(
      `命令输出被截断${spill}，拒绝把不完整的输出当结果：${command}\n`
      + `stdoutMaxBytes=${opts.stdoutMaxBytes ?? '(默认)'}；请调大 stdoutMaxBytes 或先用过滤器把输入缩小。`,
    )
  }
  return { stdout: result.stdout.text, stderr: result.stderr.text, exitCode: result.exitCode, command }
}

/**
 * 起一个**常驻**进程（代理）—— 与 `runCmd` 的唯一区别是**不 await `result`**。
 *
 * 依据是 `dsh-shell` 的 `ShellExecutor` 契约原文（0.1.7-rc.2 / 0.2.0-rc.2 一致）：
 * "execute resolves with the process handle after preparation. 'Foreground' is a
 * property of what the caller awaits, not of the spawn — a caller that awaits
 * `ShellExecution.result` ran the command in the foreground; one that keeps the
 * handle ran it in the background." 而 `handle.result()` 直到**进程退出**才 settle。
 *
 * 代理是常驻进程 ⇒ 只要 await 了 `result`，`bx_proxy start` 就会一直挂到 mitmdump
 * 退出为止 —— 真会话里的症状是"工具不返回"（不是报错、也没有超时：`onExpiry:'none'`
 * 不挂 deadline）。所以这里刻意只 await 到"进程已起来"，就绪判定交给调用方有界的
 * `lsof` 轮询。
 *
 * 实测证据（真 `dsh-bash-local` 0.2.0-rc.2 + `dsh-subprocess-local`，`sleep 30` +
 * `onExpiry:'none'`）：`execute()` 2ms 返回句柄，`handle.result()` 2 秒内不 settle。
 *
 * 接缝桩**故意让长跑 spec 的 `result` 永不 settle**（门禁第 8 条），于是"有没有 await
 * result"这件事变成可判的：一旦有人改回 `await runCmd(...)`，第 8 条就会红（挂住）。
 */
async function startCmd(shell, argv, exec, opts = {}) {
  const command = typeof argv === 'string' ? argv : argv.map(shq).join(' ')
  assertNotPrivileged(command)
  const handle = await shell.execute(shell.resolve({
    command,
    ...opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {},
    ...opts.stdoutMaxBytes !== undefined ? { stdoutMaxBytes: opts.stdoutMaxBytes } : {},
    ...opts.onExpiry !== undefined ? { onExpiry: opts.onExpiry } : {},
    // 环境变量是**唯一**能在 addon 的 `load()` 之前就生效的通道（见 `start` 里的注释）。
    ...opts.env !== undefined ? { env: opts.env } : {},
    signal: exec.signal,
  }))
  /** 现在为止能读到的输出（早退时的诊断用；`readOutput` 是接缝上的增量读）。 */
  const peek = () => {
    const read = handle.readOutput?.()
    return typeof read?.delta === 'string' ? read.delta : ''
  }
  return { handle, command, peek }
}

/** 失败的命令绝不返回空串（空输出会被读成"工具说没有"）。 */
function requireOk(run, what) {
  if (run.exitCode === 0) return run.stdout
  const detail = run.stderr.trim().split('\n').map(line => line.trim()).filter(Boolean).slice(0, 3).join(' | ')
  const missing = run.exitCode === 127 || /command not found/iu.test(run.stderr) ? ' — the command is not installed on this host' : ''
  const error = new Error(`${what} failed (exit ${run.exitCode})${missing}: ${run.command}${detail === '' ? '' : `\n${detail}`}`)
  error.name = 'CommandError'
  throw error
}

/** 退出码 127 / "command not found"：这个可选工具本机没有。 */
function missingTool(run) {
  return run.exitCode === 127 || /command not found/iu.test(run.stderr)
}

// ─────────────────────────────────────────────────────────────────────────────
// 工作区、状态文件与规则文件
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 这个会话的工作区根。
 *
 * 取不到就**大声报错**：`process.cwd()` 是宿主的 cwd，拿它顶替会把状态文件与 dump 路径
 * 写到别处（AGENTS.md 坑表"禁 `process.cwd()` 兜底"）。`FLY_BLACKBOX_WORKSPACE` 只给
 * 无头/测试用。
 *
 * 取法按引擎版本演进（2026-10 在 Ubuntu 0.1.18 上实测：`exec.workspace` 根本不存在，
 * 五个 bx_* 工具全部报"取不到工作区"）：
 *   ① `workingDirectory` 服务（有就优先，它记录的是**当前** cwd，`cd` 过也准）；
 *   ② `exec.agent.session.header.cwd`（Session 的创建目录，引擎一直有）；
 *   ③ 老形状 `exec.workspace` / `exec.cwd` / `exec.session.workspace`（保留兼容）。
 */
function workspaceRoot(exec, ctx) {
  const explicit = process.env.FLY_BLACKBOX_WORKSPACE
  if (typeof explicit === 'string' && explicit.trim() !== '') return explicit
  const session = exec?.agent?.session
  const directories = ctx?.get?.('workingDirectory')
  if (session !== undefined && directories !== undefined && typeof directories.get === 'function') {
    try {
      const cwd = directories.get(session)
      if (typeof cwd === 'string' && cwd.trim() !== '') return cwd
    } catch {
      // 服务在场但读不出这个 session：继续走下面的字段，不在这里吞掉结论。
    }
  }
  for (const candidate of [
    exec?.agent?.session?.header?.cwd,
    exec?.session?.header?.cwd,
    exec?.workspace,
    exec?.cwd,
    exec?.session?.workspace,
    exec?.agent?.session?.workspace,
  ]) {
    if (typeof candidate === 'string' && candidate.trim() !== '') return candidate
  }
  throw new Error(
    '取不到当前会话的工作区（workingDirectory 服务、exec.agent.session.header.cwd、'
    + 'exec.workspace / exec.cwd / exec.session.workspace 都是空），'
    + '拒绝用宿主 cwd 顶替：状态文件与 dump 路径会跟着错。'
    + '无头或验证场景请显式设 FLY_BLACKBOX_WORKSPACE=<绝对路径>。',
  )
}

/**
 * 读一行文本，走接缝。用于**用户数据**（dump、规则文件）—— 这样沙箱拒绝会以
 * `SandboxError` 报出。允许 fs 的两处例外（自带资产 / 自身状态文件）见 §3.1。
 */
// ── CDP（进程内通道）───────────────────────────────────────────────────────
//
// 为什么加在 blackbox 而不是新开一个包（裁决 2026-10-15）：线缆层（mitm 抓包）看得见
// "谁跟谁说了什么"，看不见"进程里到底显示了什么、哪段 JS 改的它"；Electron / Chromium 内核
// 宿主这两层都开着，所以 CDP 是同一个使命的另一条通道。
//
// 两条结构性纪律：
//   · **只走回环**：URL 由端口拼出来，参数表里**没有 host** ⇒ 结构上不可能指向别的主机；
//   · **端口只认参数**：状态文件里的 `port` 是 mitm **代理**端口，拿它当调试端口是类别错误。

/** 一次列多少条 target（超出的报 omitted，不静默丢）。 */
const CDP_TARGETS_SHOWN = 50

/** CDP 调试端口：只认显式参数。 */
function requireCdpPort(value) {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const error = new Error(
      `CDP 端口必须是 1..65535 的整数（收到 ${JSON.stringify(value)}）。`
      + '这一项**只认参数**：.fly-blackbox 状态里的 port 是 mitm 代理端口，不是调试端口。',
    )
    error.name = 'ArgumentError'
    throw error
  }
  return port
}

/** 只走回环：URL 由端口拼出来（没有 host 参数，所以不可能指向别处）。 */
function cdpListUrl(port) {
  return `http://127.0.0.1:${port}/json/list`
}

/** 怎么起一个带调试端口的 Chromium（按平台给可复制的命令）。 */
function chromeCdpHint(port) {
  return process.platform === 'darwin'
    ? `open -a "Google Chrome" --args --remote-debugging-port=${port} --user-data-dir=/tmp/cdp-${port}`
    : `google-chrome --remote-debugging-port=${port} --user-data-dir=/tmp/cdp-${port}   # 或 chromium / chromium-browser`
}

/** 连不上时的**大声**文案：是什么 + 为什么只可能是这几种 + 下一步（怎么起目标）。 */
function cdpUnreachableError(port, run) {
  const detail = (run.stderr ?? '').trim().split('\n').filter(Boolean)[0] ?? ''
  const error = new Error([
    `连不上 CDP 调试端口 127.0.0.1:${port}：${detail === '' ? `curl 退出码 ${run.exitCode}` : detail}`,
    '—— 这一项**只连回环**，所以只剩三种可能：那个进程没在监听这个端口 / 端口号给错了 / 目标没带调试开关起来。',
    '怎么起一个带调试端口的目标（端口号自己换一个没人用的）：',
    `  · Chromium 内核浏览器：${chromeCdpHint(port)}`,
    `  · Electron 应用：<App 可执行文件> --remote-debugging-port=${port}`,
    '顺带一句：调试端口开着就等于把那个界面完全交出去（能读 DOM、也能改它），用完关掉那个实例。',
  ].join('\n'))
  error.name = 'CommandError'
  return error
}

/** `/json/list` 的返回体：不是 JSON / 不是数组，都要说清"是那端口不对，不是没有 target"。 */
function parseCdpTargets(text, port) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    throw new Error(
      `127.0.0.1:${port}/json/list 返回的不是 JSON —— 这**不是**"没有 target"，`
      + `是那个端口上不是调试接口（${error.message}）。返回体头 120 字：${JSON.stringify(text.slice(0, 120))}`,
    )
  }
  if (!Array.isArray(parsed)) {
    throw new Error(
      `127.0.0.1:${port}/json/list 的返回不是数组（CDP 的约定是数组）—— 实际是 ${typeof parsed}：`
      + '这**不是**"没有 target"，是那个端口上不是调试接口。',
    )
  }
  return parsed.filter(item => item !== null && typeof item === 'object' && !Array.isArray(item))
}

/** 取一次 target 清单（走接缝的 curl，所以有审计、沙箱拒绝会照常浮出）。 */
async function fetchCdpTargets(shell, exec, port) {
  const run = await runCmd(shell, ['curl', '-sS', '-m', '8', cdpListUrl(port)], exec, { timeoutMs: 15_000 })
  if (run.exitCode !== 0) return { ok: false, run }
  return { ok: true, targets: parseCdpTargets(run.stdout, port) }
}

/** 从清单里挑一个**可附加**的 target：给了 id 就按 id，否则优先第一个 page。 */
function pickCdpTarget(targets, wanted, port) {
  const attachable = targets.filter(item => typeof item.webSocketDebuggerUrl === 'string' && item.webSocketDebuggerUrl !== '')
  const wantedId = wanted === undefined || wanted === null ? '' : String(wanted).trim()
  if (wantedId !== '') {
    const found = attachable.find(item => item.id === wantedId)
    if (found === undefined) {
      throw new Error(`127.0.0.1:${port} 上没有 id=${wantedId} 的可附加 target（可附加的有：${attachable.map(item => `${item.id}(${item.type})`).join(', ') || '无'}）`)
    }
    return found
  }
  const page = attachable.find(item => item.type === 'page')
  if (page !== undefined) return page
  if (attachable.length > 0) return attachable[0]
  throw new Error(`127.0.0.1:${port} 上没有可附加的 target（清单里 ${targets.length} 条，但都没有 webSocketDebuggerUrl）—— 这不等于"这个进程没有页面"，只是没有可附加的调试目标。`)
}

/** 采样窗口：夹在合理区间里（给 0 或负值等于"什么都不收"，那就不是测量了）。 */
function clampWindow(value, fallback, lo, hi) {
  if (value === undefined || value === null) return fallback
  const window = Number(value)
  if (!Number.isFinite(window)) return fallback
  return Math.min(hi, Math.max(lo, Math.round(window)))
}

/**
 * 把一组 offset 区间**求并集**：V8 的函数区间会嵌套，直接相加会重复计数。
 * （这是 bx_cdp_coverage 的口径；尺子反过来也专抓"直接相加"那种错。）
 */
function mergeRanges(ranges) {
  const sorted = ranges.slice().sort((a, b) => a.startOffset - b.startOffset)
  const merged = []
  for (const range of sorted) {
    const last = merged.at(-1)
    if (last !== undefined && range.startOffset <= last.endOffset) {
      last.endOffset = Math.max(last.endOffset, range.endOffset)
      continue
    }
    merged.push({ startOffset: range.startOffset, endOffset: range.endOffset })
  }
  return merged
}

/** `Profiler.takePreciseCoverage` 的返回 → 逐脚本"跑过多少"（区间求并集后统计）。 */
function summarizeCoverage(scripts) {
  const rows = []
  let usedTotal = 0
  let sizeTotal = 0
  for (const script of scripts) {
    const functions = Array.isArray(script.functions) ? script.functions : []
    const rangesOf = entry => (Array.isArray(entry.ranges) ? entry.ranges : [])
    const executed = functions.flatMap(entry => rangesOf(entry)
      .filter(range => (range.count ?? 0) > 0)
      .map(range => ({ startOffset: range.startOffset, endOffset: range.endOffset })))
    const ends = functions.flatMap(entry => rangesOf(entry).map(range => range.endOffset))
    const size = ends.length === 0 ? 0 : Math.max(...ends)
    const used = mergeRanges(executed).reduce((sum, range) => sum + (range.endOffset - range.startOffset), 0)
    usedTotal += used
    sizeTotal += size
    rows.push({
      scriptId: script.scriptId,
      url: typeof script.url === 'string' && script.url !== '' ? script.url : '(inline/eval)',
      functions: functions.length,
      executedFunctions: functions.filter(entry => rangesOf(entry).some(range => (range.count ?? 0) > 0)).length,
      usedBytes: used,
      sizeBytes: size,
    })
  }
  return { rows, usedTotal, sizeTotal }
}

/** 取 target → 挑 target → 连上去跑一段会话；连不上就给两条信号合起来的判词。 */
async function cdpAttach(transport, shell, exec, { port, target, commands, finish, windowMs }) {
  const fetched = await fetchCdpTargets(shell, exec, port)
  if (!fetched.ok) throw cdpUnreachableError(port, fetched.run)
  const picked = pickCdpTarget(fetched.targets, target, port)
  try {
    const session = await transport.session(picked.webSocketDebuggerUrl, { commands, finish, windowMs })
    return { session, picked }
  } catch (error) {
    throw new Error(await cdpUnreachableDetail(shell, exec, port, error, { httpKnownOk: true }))
  }
}

/** 真传输：Node 全局 WebSocket（22+，零依赖）。 */
function realCdpTransport() {
  return {
    /**
     * 连上去 → 发 commands → 收 windowMs 事件 → 发 finish → 等它们的响应 → 关掉。
     *
     * 实测的三种失败**在客户端长得一模一样**（error.message 为空、close code 1006、没有 reason），
     * 所以这里只如实记下 closeCode/reason，**不猜**是哪一种失败 —— 分辨交给调用方（它会另跑一次
     * /json/list 探针）。
     */
    session(wsUrl, { commands = [], finish = [], windowMs = 1200, finishTimeoutMs = 3000 } = {}) {
      return new Promise((resolve, reject) => {
        let ws
        try {
          ws = new WebSocket(wsUrl)
        } catch (error) {
          reject(error)
          return
        }
        const events = []
        const results = {}
        const wanted = new Map()
        let opened = false
        let settled = false
        let windowTimer
        let finishTimer
        const settle = (payload, error) => {
          if (settled) return
          settled = true
          clearTimeout(windowTimer)
          clearTimeout(finishTimer)
          try { ws.close() } catch { /* 关不掉就算了，下面已经把结果交出去了 */ }
          if (error !== undefined) reject(error)
          else resolve(payload)
        }
        const send = (spec, id) => {
          wanted.set(id, spec.key ?? spec.method)
          ws.send(JSON.stringify({ id, method: spec.method, ...spec.params === undefined ? {} : { params: spec.params } }))
        }
        ws.onopen = () => {
          opened = true
          let id = 0
          for (const spec of commands) { id += 1; send(spec, id) }
          windowTimer = setTimeout(() => {
            let pending = 0
            for (const spec of finish) { id += 1; pending += 1; send(spec, id) }
            if (pending === 0) { settle({ events, results, closedEarly: false, closeCode: null, closeReason: '' }); return }
            finishTimer = setTimeout(() => settle({ events, results, closedEarly: false, closeCode: null, closeReason: '' }), finishTimeoutMs)
          }, windowMs)
        }
        ws.onmessage = (message) => {
          let parsed
          try {
            parsed = JSON.parse(String(message.data))
          } catch {
            return // 不认识的帧就当没看见（不假装解析过）
          }
          if (typeof parsed.method === 'string') {
            events.push(parsed)
            return
          }
          if (typeof parsed.id === 'number' && wanted.has(parsed.id)) {
            results[wanted.get(parsed.id)] = parsed.error === undefined ? { result: parsed.result } : { error: parsed.error }
            if (finishTimer !== undefined && [...wanted.values()].every(key => Object.hasOwn(results, key))) {
              settle({ events, results, closedEarly: false, closeCode: null, closeReason: '' })
            }
          }
        }
        ws.onerror = () => {
          // 实测：message 是空串 ⇒ 这里什么都不记，别编原因（closeCode 由 onclose 给）
        }
        ws.onclose = (event) => {
          const closeCode = event.code
          const closeReason = event.reason ?? ''
          if (opened) {
            settle({ events, results, closedEarly: true, closeCode, closeReason })
            return
          }
          const error = new Error(`WebSocket 没连上 ${wsUrl}（close code ${closeCode}${closeReason === '' ? '' : ` · ${closeReason}`}）`)
          error.name = 'CdpOpenError'
          error.closeCode = closeCode
          error.closeReason = closeReason
          settle(undefined, error)
        }
      })
    },
  }
}

/**
 * 连不上时把两种信号合起来判：WebSocket 侧（只有 closeCode）＋ /json/list 探针（HTTP 侧通不通）。
 * **不猜**是哪一种 —— 实测三种失败在客户端同形（见 realCdpTransport 的注释）。
 */
async function cdpUnreachableDetail(shell, exec, port, error, { httpKnownOk = false } = {}) {
  // 注意别拿"假的探针结果"当哨兵：一开始这里用 `{ exitCode: 1 }` 表示"HTTP 侧已知是活的"，
  // 于是它和自己的失败分支**同形**，被读成"两条路都不通"（测试当场抓到）。现在用**独立布尔**。
  const probe = httpKnownOk
    ? undefined
    : await runCmd(shell, ['curl', '-sS', '-m', '8', cdpListUrl(port)], exec, { timeoutMs: 15_000 })
  const httpOk = httpKnownOk || probe.exitCode === 0
  const wsShape = `WebSocket 侧：close code ${error?.closeCode ?? '(无)'}${(error?.closeReason ?? '') === '' ? '、reason 空' : `、reason ${error.closeReason}`}`
  if (!httpOk) {
    const detail = (probe.stderr ?? '').trim().split('\n').filter(Boolean)[0] ?? ''
    return [
      `连不上 CDP 调试端口 127.0.0.1:${port} —— HTTP 探针（/json/list）也失败：${detail === '' ? `curl 退出码 ${probe.exitCode}` : detail}`,
      `${wsShape}。两条路都不通 ⇒ 最可能是那个进程没在监听这个端口。`,
      '怎么起一个带调试端口的目标（端口号自己换一个没人用的）：',
      `  · Chromium 内核浏览器：${chromeCdpHint(port)}`,
      `  · Electron 应用：<App 可执行文件> --remote-debugging-port=${port}`,
    ].join('\n')
  }
  return [
    `127.0.0.1:${port} 的 HTTP 侧是**活的**（/json/list 正常返回），但 WebSocket 握手没成 —— ${wsShape}`,
    '（实测：Node 自带的 WebSocket 把"没人听""握手被拒""握上就断"报成**同一个形状** —— error.message 为空、close 1006；'
      + '所以这里不猜是哪一种，只给两条分辨路。）',
    '常见原因：Chrome 会拒绝 Host 头不是 localhost/IP 的握手；那个调试端口已被另一个工具占着（同一时间只允许一个客户端）；目标刚退出。',
    '另外：如果你要的是"看页面里有什么、跑了哪些代码"，用同样在这个包里的 bx_cdp_targets 先看一眼清单是否还在。',
  ].join('\n')
}



async function readTextFileVia(shell, exec, path, what, opts = {}) {
  const run = await runCmd(shell, ['base64', '-i', path], exec, { stdoutMaxBytes: 64 * 1024 * 1024 })
  if (missingTool(run)) throw new Error(`${what} 读不到：${path} —— 本机没有 base64（不应发生）`)
  if (run.exitCode !== 0) throw new Error(`${what} 读不到：${path} —— ${run.stderr.trim().split('\n').at(-1) ?? `exit ${run.exitCode}`}`)
  // `allowEmpty`：规则文件走它 —— 空文件要由 `validateRules` 给出**说得通**的理由
  // （"空文件曾经静默回退成默认注入"），而不是在这里丢一句干巴巴的"读出来是空的"。
  return decodeBase64(run.stdout, what, path, opts)
}

/** macOS/Linux 的 `base64` 默认会在 stdout 里插换行（`-b` 更狠），解码前一律剔除空白。 */
export function decodeBase64(text, what, path, opts = {}) {
  const compact = text.replace(/\s+/gu, '')
  if (compact === '' && opts.allowEmpty !== true) throw new Error(`${what} 读出来是空的：${path}`)
  return Buffer.from(compact, 'base64')
}

/**
 * 文件字节数：平台各自的 stat 形状（GNU `-c%s` / BSD `-f%z`）。
 *
 * 旧实现写死 `stat -f%z`，Ubuntu 上它直接 exit 1（`-f` 是"显示文件系统"），于是
 * `bx_har` 把每一份**存在**的 HAR 都报成"不存在或读不到"。
 */
async function statSizeVia(shell, exec, path, what) {
  const run = await runCmd(shell, statSizeArgv(process.platform, path), exec, { timeoutMs: 15_000 })
  const size = run.exitCode === 0 ? parseStatSize(run.stdout) : null
  if (size === null) {
    throw new Error(
      `${what} 不存在或读不到：${path} —— ${run.stderr.trim().split('\n').at(-1) ?? `exit ${run.exitCode}`}`,
    )
  }
  return size
}

/**
 * 读一份 HAR（`bx_har` 的入口）：**先 stat 再走接缝读**，与 `bx_flows` 同一条路、同一个量级上限。
 *
 * 顺序不能反：先 stat 才能在读之前就拒掉"重到解不动"的文件（真的读进来才发现超限，那一次
 * base64 已经付过了）；而读本身必须经 `readTextFileVia`，否则沙箱拒绝会变成一个裸 EACCES，
 * 而不是 §B4 里那条 `SandboxError`。
 */
async function readHarFile(shell, exec, path, what) {
  const size = await statSizeVia(shell, exec, path, what)
  if (size > HAR_MAX_BYTES) {
    throw new Error(
      `${what} 有 ${(size / 1024 / 1024).toFixed(1)}MB，超过 ${HAR_MAX_BYTES / 1024 / 1024}MB 上限，拒绝读（读它要走 base64，重了解不动）。\n`
      + '修法：导出时只勾目标域名（DevTools 的 filter / mitmproxy 过滤后再存），'
      + '或先用 bx_flows grep 定位目标域名，只抓那一段。',
    )
  }
  return readHarDocument(await readTextFileVia(shell, exec, path, what), path)
}

/** 状态文件在**工作区内**（唯一允许的自身状态写入面）。 */
function statePath(root) {
  return join(root, '.fly-blackbox', 'proxy.json')
}

function readState(root) {
  try {
    return JSON.parse(readFileSync(statePath(root), 'utf8'))
  } catch {
    return undefined
  }
}

function writeState(root, state) {
  const path = statePath(root)
  // `node:fs` 的第二个允许用途：自身状态文件（工作区内）。同步写，因为 `start` 必须在
  // 返回前把 PID 落盘，否则紧随其后的 status 会读到上一个实例。
  mkdirSync(join(root, '.fly-blackbox'), { recursive: true })
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
  return path
}

function clearState(root) {
  rmSync(statePath(root), { force: true })
}

/** 规则文件：固定 `<workspace>/.fly-blackbox/rules.json`，`bx_proxy start` 只读并校验。 */
function rulesPath(root, override) {
  return typeof override === 'string' && override.trim() !== '' ? override : join(root, '.fly-blackbox', 'rules.json')
}

/**
 * 校验规则文件。
 *
 * **空文件 / 缺键 = 非法**：原会话的 `set_inject.sh off` 写了一个空文件，addon 静默回退到
 * 默认注入继续改包 —— 这是整个复盘里最贵的一个坑。所以"关掉注入"必须是**显式**字段
 * （`{"enabled": false}`），缺键不算关。
 */
function validateRules(text, path) {
  if (text.trim() === '') return { ok: false, reason: `规则文件是空的：${path} —— 空文件曾经静默回退成"默认注入"，所以这里一律当非法。要关掉注入请显式写 {"enabled": false}` }
  let rules
  try {
    rules = JSON.parse(text)
  } catch (error) {
    return { ok: false, reason: `规则文件不是合法 JSON：${path} —— ${error.message}` }
  }
  if (typeof rules !== 'object' || rules === null || Array.isArray(rules)) {
    return { ok: false, reason: `规则文件的顶层必须是对象：${path}` }
  }
  if (rules.enabled === false) return { ok: true, rules, summary: 'enabled=false（只记录，不注入）' }
  if (rules.enabled !== true && rules.enabled !== undefined) {
    return { ok: false, reason: `规则文件的 enabled 必须是布尔：${path}` }
  }
  for (const key of ['watch', 'patch_request', 'patch_response']) {
    if (rules[key] !== undefined && typeof rules[key] !== 'object') {
      return { ok: false, reason: `规则文件的 ${key} 必须是对象/数组：${path}` }
    }
  }
  for (const key of ['patch_request', 'patch_response']) {
    if (rules[key] === undefined) continue
    if (!Array.isArray(rules[key])) return { ok: false, reason: `规则文件的 ${key} 必须是数组：${path}` }
    for (const [index, rule] of rules[key].entries()) {
      if (typeof rule !== 'object' || rule === null) return { ok: false, reason: `${key}[${index}] 必须是对象：${path}` }
      if (typeof rule.path !== 'string' || rule.path === '') return { ok: false, reason: `${key}[${index}] 缺少 path（正则字符串）：${path}` }
      if (rule.mode !== undefined && !['set_if_empty', 'force', 'only_missing'].includes(rule.mode)) {
        return { ok: false, reason: `${key}[${index}].mode 只能是 set_if_empty / force / only_missing：${path}` }
      }
      if (rule.set === undefined || typeof rule.set !== 'object' || rule.set === null) {
        return { ok: false, reason: `${key}[${index}] 缺少 set 对象：${path}` }
      }
    }
  }
  return { ok: true, rules, summary: `enabled=${rules.enabled === true ? 'true' : '(未声明)'}, patch_request ${rules.patch_request?.length ?? 0} 条, patch_response ${rules.patch_response?.length ?? 0} 条` }
}

// ─────────────────────────────────────────────────────────────────────────────
// mitmproxy 定位与安装指引
// ─────────────────────────────────────────────────────────────────────────────

/** `FLY_MITM_BIN` 指向 mitmdump；缺省走 PATH。 */
function mitmBin() {
  const configured = process.env.FLY_MITM_BIN
  if (typeof configured === 'string' && configured.trim() !== '') return configured
  // 持久安装（本机 ~/tools）优先于 PATH：不依赖 agent 会话继承了哪个 PATH。
  for (const candidate of [
    join(os.homedir(), 'tools', 'mitmproxy-venv', 'bin', 'mitmdump'),
    join(os.homedir(), 'tools', 'mitmproxy', '.venv', 'bin', 'mitmdump'),
  ]) {
    if (existsSync(candidate)) return candidate
  }
  return 'mitmdump'
}

/** 缺 mitmdump 时的**大声**报错文案：按平台给可复制的安装命令。 */
function missingMitmdumpMessage(detail) {
  return [
    `本机没有可用的 mitmdump${detail === '' ? '' : `（${detail}）`} —— 这台机器上**没有抓包能力**，不是"追查失败"。`,
    '',
    ...mitmInstallLines(process.platform),
    '',
    '装完用 `bx_proxy start` 会回显 `mitmdump --version`。',
  ].join('\n')
}

/** 查 mitmdump 版本；缺了就抛装配指引。 */
async function mitmdumpVersion(shell, exec) {
  const bin = mitmBin()
  const run = await runCmd(shell, [bin, '--version'], exec, { timeoutMs: 20_000 })
  if (run.exitCode !== 0) throw new Error(missingMitmdumpMessage(missingTool(run) ? `${bin}: command not found` : run.stderr.trim().split('\n')[0] ?? `exit ${run.exitCode}`))
  return run.stdout.trim().split('\n').map(line => line.trim()).filter(Boolean).join('\n')
}

/**
 * 复用的端口查询：谁在 LISTEN 这个端口。
 *
 * Linux 用 `ss -ltnp`（本机实测 `lsof` 在受限环境里对所有端口 exit 1，旧实现因此
 * 永远认为"没有监听者"）；macOS 继续用 lsof。
 */
async function listenersOn(shell, exec, port) {
  const run = await runCmd(shell, listenerListArgv(process.platform), exec, { timeoutMs: 20_000 })
  if (run.exitCode !== 0) return []
  return listenerLinesForPort(process.platform, run.stdout, port)
}

/** 端口上第一个监听进程的 PID（用于 bx_proxy start 写状态文件）。 */
async function listenerPidOn(shell, exec, port) {
  const lines = await listenersOn(shell, exec, port)
  for (const line of lines) {
    const pid = listenerPidOfLine(process.platform, line)
    if (pid !== null) return pid
  }
  // `ss` 在受限内核/沙箱里可能不给 pid= 字段（只列 socket）。Linux 上再问一次 lsof：
  // 它看得到自己进程的 fd，够拿到刚起的 mitmdump。
  if (process.platform !== 'darwin') {
    const lsof = await runCmd(shell, ['lsof', '-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], exec, { timeoutMs: 20_000 })
    const pid = lsof.exitCode === 0 ? Number.parseInt(lsof.stdout.trim().split('\n').filter(Boolean)[0] ?? '', 10) : NaN
    if (Number.isInteger(pid) && pid > 0) return pid
  }
  return null
}

/** 读一个 gsettings 键；读不到返回 null（不把 "gsettings 缺席" 读成 "值就是空"）。 */
async function readGsettings(shell, exec, qualifiedKey) {
  const separator = qualifiedKey.indexOf(' ')
  const schema = qualifiedKey.slice(0, separator)
  const key = qualifiedKey.slice(separator + 1)
  const run = await runCmd(shell, ['gsettings', 'get', schema, key], exec, { timeoutMs: 15_000 })
  return run.exitCode === 0 ? parseGsettingsValue(run.stdout) : null
}

/**
 * GNOME 系统代理的只读状态。
 *
 * 只覆盖读 `gsettings` 的桌面；KDE 等不读这些键，所以 `backend` 必须回给调用方
 * （不能把 GNOME 的值冒充成"系统代理"）。
 */
async function gnomeProxyStatus(shell, exec) {
  const probe = await runCmd(shell, ['sh', '-c', 'command -v gsettings'], exec, { timeoutMs: 10_000 })
  if (probe.exitCode !== 0 || probe.stdout.trim() === '') {
    return { available: false, backend: 'gsettings', reason: 'gsettings 不在本机（不是 GNOME 桌面，或没装 glib-2.0-bin）' }
  }
  const mode = await readGsettings(shell, exec, GNOME_PROXY_KEYS.mode)
  return {
    available: true,
    backend: 'gsettings (GNOME)',
    mode,
    httpHost: await readGsettings(shell, exec, GNOME_PROXY_KEYS.httpHost),
    httpPort: await readGsettings(shell, exec, GNOME_PROXY_KEYS.httpPort),
    httpsHost: await readGsettings(shell, exec, GNOME_PROXY_KEYS.httpsHost),
    httpsPort: await readGsettings(shell, exec, GNOME_PROXY_KEYS.httpsPort),
  }
}

/** 状态 + 现实的一致性：`kill -0`（进程）与 `lsof`（端口）必须一致。 */
async function proxyStatusLines(shell, exec, root) {
  const state = readState(root)
  const port = state?.port ?? Number(process.env.FLY_PROXY_PORT ?? 8080)
  if (state === undefined) return { state, port, alive: false, listeners: [], stale: false }
  const alive = (await runCmd(shell, ['kill', '-0', String(state.pid)], exec, { timeoutMs: 15_000 })).exitCode === 0
  const listeners = await listenersOn(shell, exec, state.port)
  const holding = listeners.some(line => new RegExp(`\\b${state.pid}\\b`, 'u').test(line))
  return { state, port: state.port ?? port, alive, listeners, stale: alive !== holding || (!alive && listeners.length > 0) }
}

function describeState(state) {
  if (state === undefined) return '没有状态文件（`bx_proxy start` 未在这个工作区起过实例）'
  return `PID ${state.pid} · port ${state.port} · confdir ${state.confdir} · dump ${state.dump} · 规则 ${state.rules} · 起于 ${state.startedAt}`
}

// ─────────────────────────────────────────────────────────────────────────────
// §B2 `bx_flows` / `bx_diff` 的数据整形
// ─────────────────────────────────────────────────────────────────────────────

/** flow 里的"头部字节字段"（bytes）：打印前显式解码，坏字节**报出来**，不当正文。 */
const HEADER_BYTES = {
  request: ['method', 'path', 'scheme', 'authority', 'http_version'],
  response: ['reason', 'http_version'],
}

function decodeHeader(buffer, where) {
  const text = strictUtf8(buffer)
  if (text === null) return { text: `non-utf8 header, hex ${hexOf(buffer)}`, bad: where }
  return { text, bad: undefined }
}

/**
 * body 的三种形态：`text` / `binary` / `none`。
 *
 * `binary` **不带 `text`**（一条非 UTF-8 的图片/字体会被 JSON 化成
 * `{"type":"Buffer",…}`，那是给人看的垃圾而非数据），带 `bytes` + `sha256` + 前 64 字节 `hex`。
 */
export function shapeBody(buffer) {
  if (buffer === undefined || buffer === null) return { kind: 'none', bytes: 0 }
  if (buffer.length === 0) return { kind: 'none', bytes: 0 }
  const text = strictUtf8(buffer)
  if (text !== null) return { kind: 'text', text, bytes: buffer.length }
  return {
    kind: 'binary',
    bytes: buffer.length,
    sha256: createHash('sha256').update(buffer).digest('hex'),
    hex: hexOf(buffer),
  }
}

function headerPairs(list, bad) {
  if (!Array.isArray(list)) return []
  return list.map((pair, index) => {
    if (!Array.isArray(pair) || pair.length < 2) return ['<malformed>', `<entry ${index} is not a [name, value] pair>`]
    const name = Buffer.isBuffer(pair[0]) ? decodeHeader(pair[0], `header name ${index}`) : { text: String(pair[0]) }
    const value = Buffer.isBuffer(pair[1]) ? decodeHeader(pair[1], `header value ${index}`) : { text: String(pair[1]) }
    if (name.bad !== undefined) bad.push(`${name.bad}: ${name.text}`)
    if (value.bad !== undefined) bad.push(`${value.bad}: ${value.text}`)
    return [name.text, value.text]
  })
}

/** 把一条 flow 整形成 `bx_flows show --json` 的形状（也是 `bx_diff` 的输入契约）。 */
export function summarizeFlow(flow, index) {
  const bad = []
  const request = flow.request ?? {}
  const response = flow.response ?? {}
  const requestHeaders = headerPairs(request.headers, bad)
  const responseHeaders = headerPairs(response.headers, bad)
  const fields = {}
  for (const key of HEADER_BYTES.request) {
    const raw = request[key]
    if (Buffer.isBuffer(raw)) {
      const decoded = decodeHeader(raw, `request.${key}`)
      fields[`request.${key}`] = decoded.text
      if (decoded.bad !== undefined) bad.push(`${decoded.bad}: ${decoded.text}`)
    } else if (raw !== undefined) {
      fields[`request.${key}`] = String(raw)
    }
  }
  for (const key of HEADER_BYTES.response) {
    const raw = response[key]
    if (Buffer.isBuffer(raw)) {
      const decoded = decodeHeader(raw, `response.${key}`)
      fields[`response.${key}`] = decoded.text
      if (decoded.bad !== undefined) bad.push(`${decoded.bad}: ${decoded.text}`)
    } else if (raw !== undefined) {
      fields[`response.${key}`] = String(raw)
    }
  }
  const status = response.status_code
  const text = key => {
    const value = request[key] ?? response[key]
    return Buffer.isBuffer(value) ? (strictUtf8(value) ?? `<non-utf8 ${key}>`) : value === undefined ? undefined : String(value)
  }
  return {
    index,
    version: typeof flow.version === 'number' ? flow.version : flow.version,
    type: flow.type ?? '(no type)',
    // `host` 在 dump 里也是 `,`(bytes)：**必须走 `text()` 解码**，不能把 Buffer 直接漏进
    // 摘要 —— 漏了 `JSON.stringify` 就会吐出一坨 `{"type":"Buffer","data":[...]}`。
    // 门禁第 12 条盯的就是这个（它真的红在这一行）。
    host: text('host') ?? text('authority') ?? '(no host)',
    method: text('method') ?? '(no method)',
    path: text('path') ?? '(no path)',
    scheme: text('scheme') ?? '',
    status: typeof status === 'number' ? status : String(response.reason ?? '(no response)'),
    websocket: flow.websocket === null || flow.websocket === undefined ? null : '(present)',
    error: flow.error === null || flow.error === undefined ? null : String(flow.error),
    requestHeaders,
    responseHeaders,
    requestBody: shapeBody(Buffer.isBuffer(request.content) ? request.content : undefined),
    responseBody: shapeBody(Buffer.isBuffer(response.content) ? response.content : undefined),
    badHeaders: bad,
  }
}

/** `bx_flows list` 的一行。 */
function listLine(flow) {
  const method = flow.method.padEnd(6)
  const status = String(flow.status).padEnd(6)
  const size = flow.requestBody.bytes + flow.responseBody.bytes
  return `${String(flow.index).padStart(4)}  ${method} ${status} ${flow.host}${flow.path}  (${size} bytes)`
}

/** `show` 的人读形态（也把坏 header 明说）。 */
function showText(flow) {
  const lines = [
    `# flow ${flow.index} · type=${flow.type} · version=${flow.version}`,
    `${flow.method} ${flow.scheme}://${flow.host}${flow.path}  →  ${flow.status}`,
    '',
    '── request headers ──',
    ...flow.requestHeaders.map(([key, value]) => `${key}: ${value}`),
    '',
    `── request body (${flow.requestBody.kind}, ${flow.requestBody.bytes} bytes) ──`,
    flow.requestBody.text ?? `(binary, sha256 ${flow.requestBody.sha256}, hex ${flow.requestBody.hex})`,
    '',
    '── response headers ──',
    ...flow.responseHeaders.map(([key, value]) => `${key}: ${value}`),
    '',
    `── response body (${flow.responseBody.kind}, ${flow.responseBody.bytes} bytes) ──`,
    flow.responseBody.text ?? `(binary, sha256 ${flow.responseBody.sha256}, hex ${flow.responseBody.hex})`,
  ]
  if (flow.badHeaders.length > 0) lines.push('', `⚠ ${flow.badHeaders.join('\n⚠ ')}`)
  return lines.join('\n')
}

/** 所有 body 文本里搜关键词（T2"文案搜响应体"那一招）。 */
function grepText(flow, pattern) {
  const haystack = [
    flow.requestBody.text ?? '',
    flow.responseBody.text ?? '',
    ...flow.requestHeaders.map(([key, value]) => `${key}: ${value}`),
    ...flow.responseHeaders.map(([key, value]) => `${key}: ${value}`),
  ].join('\n')
  return new RegExp(pattern, 'iu').test(haystack)
}

// ─────────────────────────────────────────────────────────────────────────────
// `bx_diff`：把"缺失 / 假值 / 类型变化"变成机器不变量
// ─────────────────────────────────────────────────────────────────────────────

const EMPTY_VALUES = new Set([null, '', 0, false])

function isEmptyValue(value) {
  if (value === undefined) return true
  if (value === null) return true
  if (typeof value === 'string') return value === ''
  if (typeof value === 'number') return value === 0
  if (typeof value === 'boolean') return value === false
  if (Array.isArray(value)) return value.length === 0
  if (typeof value === 'object') return Object.keys(value).length === 0
  return false
}

/**
 * 字段级 diff。三种标注**永不混淆**：
 *   · `缺失` —— 键在新侧不存在（这是"字段被白名单丢掉"的形状）
 *   · `空值` —— 键存在但当下的值是 `null`/`""`/`0`/`false`（这是"假值陷阱"的形状）
 *   · `类型变化` —— `0` vs `"0"` 这种（这是"编码不一致"的形状）
 *
 * @param a - 旧 JSON 值。
 * @param b - 新 JSON 值。
 * @param path - 当前字段路径（顶层调用传 `''`）。
 * @returns 每一行一个字段的差异描述。
 */
export function diffJson(a, b, path = '') {
  // 三种"没值"必须分清，混在一起就会把 T5 的假值陷阱报错：
  //   `undefined` → 键**不存在**（缺失）· `null` → 键在但值是**空值**
  // `null` 也不要走下面的 `typeof` 分支：`typeof null === 'object'` 会把它误报成类型变化。
  const missing = value => value === undefined
  if (missing(a) && missing(b)) return []
  if (missing(a)) return [`${path}: 缺失 → ${JSON.stringify(b)}`]
  if (missing(b)) return [`${path}: ${JSON.stringify(a)} → 缺失`]
  if (a === null || b === null) {
    if (a === null && b === null) return []
    return a === null ? [`${path}: 空值 → ${JSON.stringify(b)}`] : [`${path}: ${JSON.stringify(a)} → 空值`]
  }
  if (typeof a === 'number' && typeof b === 'string') return [`${path}: 类型变化（数字 ${JSON.stringify(a)} → 字符串 ${JSON.stringify(b)}）`]
  if (typeof a === 'string' && typeof b === 'number') return [`${path}: 类型变化（字符串 ${JSON.stringify(a)} → 数字 ${JSON.stringify(b)}）`]
  if (typeof a !== typeof b) return [`${path}: 类型变化（${typeof a} ${JSON.stringify(a)} → ${typeof b} ${JSON.stringify(b)}）`]

  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return [`${path}: 类型变化（数组 ↔ 非数组）`]
    const lines = []
    const length = Math.max(a.length, b.length)
    for (let index = 0; index < length; index += 1) {
      if (index >= b.length) lines.push(`${path}[${index}]: ${JSON.stringify(a[index])} → 缺失（新侧没有这个下标）`)
      else if (index >= a.length) lines.push(`${path}[${index}]: 缺失 → ${JSON.stringify(b[index])}`)
      else lines.push(...diffJson(a[index], b[index], `${path}[${index}]`))
    }
    return lines
  }
  if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
    const lines = []
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const child = path === '' ? key : `${path}.${key}`
      if (!(key in b)) lines.push(`${child}: ${JSON.stringify(a[key])} → 缺失`)
      else if (!(key in a)) lines.push(`${child}: 缺失 → ${JSON.stringify(b[key])}`)
      else lines.push(...diffJson(a[key], b[key], child))
    }
    return lines
  }
  if (a === b) return []
  if (isEmptyValue(a)) return [`${path}: 空值 → ${JSON.stringify(b)}`]
  if (isEmptyValue(b)) return [`${path}: ${JSON.stringify(a)} → 空值`]
  return [`${path}: ${JSON.stringify(a)} → ${JSON.stringify(b)}`]
}

// ─────────────────────────────────────────────────────────────────────────────
// §B7 `bx_har`：HAR 的归一化、摘要与两次捕获对比
//
// 两条纪律，各对应一类事故：
//
//  1. **白名单式脱敏**（不是"输出前擦一遍"）：归一化只**挑**要用的字段，headers / cookies /
//     postData / content 从源头就不复制。HAR 里最常出现的凭据正好在这些地方（`Cookie` /
//     `Authorization` / `Set-Cookie` / 请求体里的令牌），而擦除式脱敏只要漏一个字段，就是
//     一整份令牌落进模型上下文。URL 的 query 与 fragment 同理：**不入键、不输出**。
//  2. **截断显式**：任何受 `top` 限界的列表都给 `bounds`（shown / total / omitted），顶层另有
//     `truncated` 布尔 —— 省略绝不藏起来（把"只列了 20 条"读成"一共 20 条"会直接得出错误
//     的量级结论，这正是 `bx_flows` 那条 truncated 纪律的同族）。
//
// 数字口径（同时写进结果的 `limitations`）：`bytes` = `response.content.size`（缺失时
// `response.bodySize`；都没有则 `null`，绝不用 0 假装知道）；`timeMs` = `entry.time`。
// 文件读取走 §B4 的接缝（`base64 -i`，与 `bx_flows` / `bx_diff` 同一条路）。
// ─────────────────────────────────────────────────────────────────────────────

/** `top` 缺省；任何列表超过它就一定在 `bounds.<list>.omitted` 里报出来。 */
const HAR_DEFAULT_TOP = 20
const HAR_GROUPINGS = ['host', 'status', 'mime']
/** 与 `bx_flows` 同一个量级上限：读文件要走 base64（4/3 膨胀），再大就不是"读一份摘要"的重量了。 */
const HAR_MAX_BYTES = 32 * 1024 * 1024
/** 对比用的**大小档位**边界：打点/时间戳会让字节数永远不相等，档位才是"变了没有"的判据。 */
const HAR_SIZE_BUCKETS = [[1024, '<1KB'], [10 * 1024, '1-10KB'], [100 * 1024, '10-100KB'], [1024 * 1024, '100KB-1MB']]
const HAR_SIZE_BUCKET_TEXT = '0-1KB / 1-10KB / 10-100KB / 100KB-1MB / >=1MB'

/** 字节 → 档位。`null`/负数/非数 → `unknown`（缺数据不等于"小"）。 */
export function harSizeBucket(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) return 'unknown'
  for (const [bound, label] of HAR_SIZE_BUCKETS) if (bytes < bound) return label
  return '>=1MB'
}

/** HAR 的 `request.url` → `{ host, path }`（**query 与 fragment 一律丢掉**：它们常带令牌）。 */
export function splitHarUrl(raw) {
  const text = typeof raw === 'string' ? raw : ''
  try {
    const url = new URL(text)
    return {
      host: url.host === '' ? '(no host)' : url.host,
      path: url.pathname === '' ? '/' : url.pathname,
      hadQuery: url.search !== '' || url.hash !== '',
    }
  } catch {
    // 相对 URL / 不是 URL：退回正则取可读的那一段，**绝不整串透传**（整串里就带着 query）。
    const match = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)([^?#]*)/iu.exec(text)
    if (match === null) {
      const bare = text.split(/[?#]/u)[0]
      return { host: '(no host)', path: bare === '' ? '(no path)' : bare, hadQuery: /[?#]/u.test(text) }
    }
    return { host: match[1], path: match[2] === '' ? '/' : match[2], hadQuery: /[?#]/u.test(text) }
  }
}

/** `mimeType` 归一：去掉 `; charset=…` 这类参数、转小写（分组要用它当键）。 */
function harMime(response) {
  const raw = response?.content?.mimeType
  if (typeof raw !== 'string') return '(no mime)'
  const base = raw.split(';')[0].trim().toLowerCase()
  return base === '' ? '(no mime)' : base
}

/** `bytes` 的口径：`response.content.size` → `response.bodySize` → `null`（不猜）。 */
function harBytes(response) {
  for (const value of [response?.content?.size, response?.bodySize]) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value
  }
  return null
}

function harTimeMs(entry) {
  const value = entry?.time
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

function harStatus(response) {
  return typeof response?.status === 'number' && Number.isFinite(response.status) ? response.status : null
}

/**
 * 一条 HAR entry → 归一化行。
 *
 * **只有这里列出的字段会出现在输出里**（白名单制）：headers / cookies / postData / body
 * 连"被漏出去"的机会都没有 —— 这也是"最强的脱敏"唯一的落地方式：不复制，而不是复制后再擦。
 */
export function normalizeHarEntry(entry, index) {
  const request = entry?.request ?? {}
  const response = entry?.response ?? {}
  const { host, path, hadQuery } = splitHarUrl(request.url)
  const status = harStatus(response)
  const errored = entry?._error !== undefined && entry?._error !== null
  const method = typeof request.method === 'string' && request.method !== '' ? request.method.toUpperCase() : '(no method)'
  return {
    index,
    method,
    host,
    path,
    hadQuery,
    status,
    timeMs: harTimeMs(entry),
    bytes: harBytes(response),
    mime: harMime(response),
    // status 0 = 请求根本没拿到响应（浏览器取消 / 连接失败），它同样是"错误条目"。
    failed: status === 0 || errored,
    key: `${method} ${host}${path}`,
  }
}

/** 状态码计数：键按数值序（`0` → `200` → `404`），`(no status)` 这类非数值键排在最后。 */
function harCounts(counts) {
  const keys = [...counts.keys()].sort((left, right) => {
    const a = Number(left)
    const b = Number(right)
    if (Number.isFinite(a) && Number.isFinite(b)) return a - b
    return left.localeCompare(right)
  })
  return Object.fromEntries(keys.map(key => [key, counts.get(key)]))
}

/** 4xx/5xx，外加 status 0（没拿到响应）。 */
export function isHarError(row) {
  return row.failed === true || (row.status !== null && row.status >= 400)
}

/** 展示一行时的形状（**不含** headers / body / query）。 */
function harRow(row) {
  return { method: row.method, host: row.host, path: row.path, status: row.status, timeMs: row.timeMs, bytes: row.bytes, mime: row.mime }
}

/**
 * 文件字节 → `{ file, har, entries }`。
 *
 * gzip **按 magic 判**（`1f 8b`）而不是扩展名：反过来（信扩展名）会让一份没压缩的 `.har.gz`
 * 走进解压分支、报一个看不懂的错；BOM 在 `JSON.parse` 前剔除（有些导出器会带）。
 */
export function readHarDocument(buffer, path) {
  const gzip = buffer.length > 1 && buffer[0] === 0x1f && buffer[1] === 0x8b
  let payload = buffer
  if (gzip) {
    try {
      payload = gunzipSync(buffer)
    } catch (error) {
      throw new Error(`${path} 带 gzip magic（1f 8b）却解压失败：${error.message} —— 文件可能被截断，或根本不是 gzip。`)
    }
  }
  let parsed
  try {
    parsed = JSON.parse(payload.toString('utf8').replace(/^\uFEFF/u, ''))
  } catch (error) {
    // Q6（2026-10-13）：失败文案要对读它的模型可行动 —— what + why + **what to try next**，
    // 且不臆断具体原因（写错的「为什么」比没有更糟）。
    throw new Error(`${path} 不是合法 JSON${gzip ? '（已按 gzip magic 解压）' : ''}：${error.message}`
      + ' —— 修法：确认这是 HAR 导出（浏览器 DevTools 的 Save all as HAR，或 mitmproxy 的硬拷贝转 HAR）；' 
      + '只做普通 JSON 校验的话，先看它是不是别的格式。')
  }
  const entries = parsed?.log?.entries
  if (!Array.isArray(entries)) {
    throw new Error(`${path} 不像 HAR：log.entries 不是数组（HAR 1.2 的条目都在 log.entries 下）。`
      + ' —— 修法：重新导出一份 HAR，或确认导出的是 HAR 而不是本仓自己的 mitmproxy dump' 
      + '（`.mitm` 那种用 bx_flows 读）。')
  }
  const creator = parsed.log.creator
  return {
    file: {
      path,
      bytes: buffer.length,
      ...(gzip ? { uncompressedBytes: payload.length } : {}),
      gzip,
      sha256: createHash('sha256').update(buffer).digest('hex'),
    },
    har: {
      version: typeof parsed.log.version === 'string' ? parsed.log.version : null,
      creator: typeof creator?.name === 'string'
        ? { name: creator.name, version: typeof creator.version === 'string' ? creator.version : null }
        : null,
    },
    entries: entries.map((entry, index) => normalizeHarEntry(entry, index)),
  }
}

/**
 * 摘要：分组聚合（条数 / 字节 / 状态码分布）+ 最慢 N + 错误条目。
 *
 * 返回的是**未截断**的全量列表 —— 截断由调用方按 `top` 做，并且必须把省略了几个报出来。
 * 排序一律是**确定**的（条数 → 字节 → 键名 / 耗时 → 键名）：同一份 HAR 两次跑出不同的
 * "最热分组"，对比就没有意义了。
 */
export function summarizeHarEntries(entries, groupBy = 'host') {
  const grouped = new Map()
  for (const row of entries) {
    const key = groupBy === 'status'
      ? (row.status === null ? '(no status)' : String(row.status))
      : groupBy === 'mime' ? row.mime : row.host
    const group = grouped.get(key) ?? { key, entries: 0, bytes: 0, bytesUnknown: 0, statuses: new Map() }
    group.entries += 1
    if (row.bytes === null) group.bytesUnknown += 1
    else group.bytes += row.bytes
    const status = row.status === null ? '(no status)' : String(row.status)
    group.statuses.set(status, (group.statuses.get(status) ?? 0) + 1)
    grouped.set(key, group)
  }
  const groups = [...grouped.values()]
    .map(group => ({
      key: group.key,
      entries: group.entries,
      bytes: group.bytes,
      bytesUnknown: group.bytesUnknown,
      statuses: harCounts(group.statuses),
    }))
    .sort((left, right) => right.entries - left.entries || right.bytes - left.bytes || left.key.localeCompare(right.key))
  const slowest = entries
    .filter(row => row.timeMs !== null)
    .sort((left, right) => right.timeMs - left.timeMs || left.key.localeCompare(right.key))
  const errors = entries
    .filter(isHarError)
    .sort((left, right) => (right.status ?? -1) - (left.status ?? -1) || (right.timeMs ?? -1) - (left.timeMs ?? -1) || left.key.localeCompare(right.key))
  return { groups, slowest, errors, withoutTime: entries.length - slowest.length }
}

/** 同一个键下的多条请求折叠成一份可比对的小结。 */
function harAggregate(rows) {
  const statuses = new Map()
  let bytes = 0
  let bytesUnknown = 0
  let maxTimeMs = null
  for (const row of rows) {
    const status = row.status === null ? '(no status)' : String(row.status)
    statuses.set(status, (statuses.get(status) ?? 0) + 1)
    if (row.bytes === null) bytesUnknown += 1
    else bytes += row.bytes
    if (row.timeMs !== null) maxTimeMs = maxTimeMs === null ? row.timeMs : Math.max(maxTimeMs, row.timeMs)
  }
  return {
    entries: rows.length,
    statuses: harCounts(statuses),
    bytes,
    bytesUnknown,
    // 字节一个都没读到时不编档位：`unknown` 才是诚实的答案。
    bucket: harSizeBucket(bytesUnknown === rows.length ? null : bytes),
    maxTimeMs,
  }
}

function harIndex(entries) {
  const index = new Map()
  for (const row of entries) {
    const rows = index.get(row.key) ?? []
    rows.push(row)
    index.set(row.key, rows)
  }
  return index
}

const harCompareRow = rows => ({
  key: rows[0].key,
  method: rows[0].method,
  host: rows[0].host,
  path: rows[0].path,
  ...harAggregate(rows),
})

/**
 * 两次捕获的对比，键是 `method + host + path`。
 *
 * `changed` 只认两件事：**状态码分布**变了，或大小**档位**变了（逐字节比会天天报差异，
 * 档位才是"变了没有"的判据）。同一个键出现多次时按该键的全部条目折叠后再比 —— 否则
 * "第一次 200、重试 500"这种最常见的形状会被压成一条而看不出来。
 */
export function compareHarEntries(baseEntries, otherEntries) {
  const base = harIndex(baseEntries)
  const other = harIndex(otherEntries)
  const added = []
  const removed = []
  const changed = []
  let unchanged = 0
  for (const [key, rows] of other) {
    if (!base.has(key)) added.push(harCompareRow(rows))
  }
  for (const [key, rows] of base) {
    if (!other.has(key)) {
      removed.push(harCompareRow(rows))
      continue
    }
    const before = harAggregate(rows)
    const after = harAggregate(other.get(key))
    const why = []
    if (JSON.stringify(before.statuses) !== JSON.stringify(after.statuses)) why.push('status')
    if (before.bucket !== after.bucket) why.push('size')
    if (why.length === 0) {
      unchanged += 1
      continue
    }
    changed.push({ key, method: rows[0].method, host: rows[0].host, path: rows[0].path, why, before, after })
  }
  const byKey = (left, right) => left.key.localeCompare(right.key)
  return {
    added: added.sort(byKey),
    removed: removed.sort(byKey),
    changed: changed.sort(byKey),
    unchanged,
    counts: { added: added.length, removed: removed.length, changed: changed.length, unchanged },
  }
}

/** 按 `top` 切一刀，并把"切掉了几个"一起返回（省略绝不藏起来）。 */
function harBound(rows, top) {
  const shown = rows.slice(0, top)
  return { rows: shown, bounds: { shown: shown.length, total: rows.length, omitted: rows.length - shown.length } }
}

/**
 * 这份摘要**看不见什么** —— 照 §5 的最小证据形状，逐条写给模型（也写给以后改这个工具的人：
 * 每加一个数字字段，都要在这里回答"它的口径是什么、缺数据时是什么样"）。
 */
function harLimitations({ withQuery, withoutTime, compare, truncated, top }) {
  const lines = [
    '离线读文件：不发起任何网络请求、不改本机状态。',
    '未分析 headers 与 body：输出里不含任何请求/响应头、Cookie、postData 或 body 内容（白名单式脱敏，不是输出前擦除）。',
    `URL 的 query 与 fragment 不入键、不输出（本次 ${withQuery} 条 URL 带 query/fragment，已剔除）。`,
    'bytes 取 response.content.size（缺失时 response.bodySize），只算响应体；缺失记 null 并计入 bytesUnknown，不当 0。',
    `耗时取 HAR 里记录的 entry.time（毫秒），不是本次重测；${withoutTime} 条没有该字段，不参与最慢排名。`,
    'errors = 4xx/5xx，外加 status 0（请求没拿到响应，例如被取消或连接失败）。',
  ]
  if (compare) lines.push(`对比键是 method + host + path，大小档位按同一键的响应体合计分桶（${HAR_SIZE_BUCKET_TEXT}）。`)
  if (truncated) lines.push(`输出被 top=${top} 截断：看每一段的 bounds（shown/total/omitted），这不是全量。`)
  return lines
}

// ─────────────────────────────────────────────────────────────────────────────
// §B6 授权闸门
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 授权表：**登记的是"哪些动作永远可用"，其余一律受控**（fail-closed）。
 *
 * 之前这张表是反过来的（登记"哪些动作受控"，没登记的动作放行），于是加一个新动作
 * —— 或由调用方送一个空动作 —— 就等于**悄悄开了个口子**。三条默认值现在都是"关"：
 *  1. 工具不在表里 ⇒ 受控（新加一个 `bx_*` 忘了登记，是门关着，不是门开着）；
 *  2. 动作不在该工具的 `readOnly` 里 ⇒ 受控（含空动作与拼错的动作）；
 *  3. 只有显式写明 `actionless: true` 的工具（没有 action 参数、且只读）才不受这道门管。
 *
 * `readOnly` 里的动作必须来自各工具 `parameters.action` 真正声明的词表，多写一个不存在的
 * 动作等于给一个不存在的入口开门（门禁第 6 条按词表逐项两向断）。
 */
const GATE_TABLE = {
  // 起 / 停 / 重启本地拦截代理：只有 status 是只读。
  bx_proxy: { readOnly: ['status'] },
  // 开关 macOS 系统代理：只有 status 是只读。
  bx_sysproxy: { readOnly: ['status'] },
  // 主动探测（发 HTTP/HTTPS/openssl 请求出去）：整件受控，没有只读动作。
  bx_doctor: { readOnly: [] },
  // 只读：看 CA 信任态、打印给人复制的那条 sudo 命令、security verify-cert 校验。
  bx_ca: { readOnly: ['status', 'command', 'verify'] },
  // 只读：离线读 mitmproxy dump。
  bx_flows: { readOnly: ['hosts', 'list', 'show', 'grep'] },
  // 只读：离线读 HAR（摘要 / 两份对比），没有 action 参数。
  bx_har: { actionless: true },
  // 没有 action 参数，只读两份 JSON。
  bx_diff: { actionless: true },
  // 进程内通道：**整件受控**（照 bx_doctor 的先例）—— 附加调试接口会读走那个进程的实时状态，
  // 后续的 Debugger/Profiler 还会在目标里打开仪表，属于"主动探测"那一档。
  bx_cdp_targets: { readOnly: [] },
  bx_cdp_scripts: { readOnly: [] },
  bx_cdp_coverage: { readOnly: [] },
}

function gateReason(tool, action) {
  const known = Object.hasOwn(GATE_TABLE, tool)
  return `fly-blackbox: \`${tool}\` 的 \`${action ?? ''}\` 会改变本机状态（起代理 / 主动探测 / 动系统代理），`
    + '属于**改动路径**，必须显式授权：设 FLY_ALLOW_INTERCEPT=1 再调用。'
    + '只读路径（bx_proxy status、bx_sysproxy status、bx_ca *、bx_flows *、bx_har、bx_diff）不受这道门管。'
    + (known ? '' : `（\`${tool}\` 没有在授权表 GATE_TABLE 里登记，按 fail-closed 处理：登记它之前一律受控。）`)
}

/**
 * 读这次调用的 `action`。
 *
 * **字段名是接缝的一部分**：引擎交给 `tools/pre-execute` 的 execution 由
 * `@deepseek-ai/dsh-tools` 的 `createExecution()` 造出来，那个对象只有
 * `token / callId / rootCallId / name / signal / agent? / parent? / schema? / arguments / …`
 * —— **没有 `args`**。本文件曾读 `exec.args?.action`，于是 action 恒为 `undefined`，
 * `bx_proxy start|stop|restart` 与 `bx_sysproxy on|off` 在未设 FLY_ALLOW_INTERCEPT 时
 * **根本不进这道门**：门存在、门禁绿、门不关。`scripts/verify-blackbox.mjs` 第 6 条现在
 * 按引擎真形状（`arguments`）喂这个 guard，并另有一条静态断言禁止这里再出现 `exec.args`。
 */
function actionOf(exec) {
  const action = exec.arguments?.action
  return typeof action === 'string' ? action : undefined
}

function isGated(tool, action) {
  const row = GATE_TABLE[tool]
  if (row === undefined) return true
  if (row.actionless === true) return false
  return !row.readOnly.includes(action ?? '')
}

// ─────────────────────────────────────────────────────────────────────────────
// skill provider（照 dsh-skill-office 的形状）
// ─────────────────────────────────────────────────────────────────────────────

function skillDescription(raw, path) {
  const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u.exec(raw)
  if (frontmatter?.[1] === undefined) throw new Error(`fly-blackbox: ${path} has no YAML frontmatter`)
  // 只取 description（frontmatter 只有 name/description 两个键，见 SKILL.md）。
  const description = /^description:\s*(.+)$/mu.exec(frontmatter[1])?.[1]?.trim()
  if (description === undefined || description === '') throw new Error(`fly-blackbox: ${path} has no description`)
  return { description, content: raw.slice(frontmatter[0].length).trim() }
}

function blackboxSkillProvider() {
  const locator = join(ASSET_ROOT, 'SKILL.md')
  const { description } = skillDescription(readFileSync(locator, 'utf8'), locator)
  const candidate = {
    name: 'client-blackbox',
    description,
    invocation: { modelInvocable: true, userInvocable: true },
    provider: 'fly-blackbox',
    source: 'bundled',
    rank: BUNDLED_SKILL_RANK,
    resourceBase: { kind: 'directory', path: ASSET_ROOT },
    locator,
  }
  return {
    name: 'fly-blackbox',
    list: () => Promise.resolve([candidate]),
    async get(requested, options) {
      const { rank: _rank, locator: file, ...summary } = requested
      const raw = readFileSync(file, { encoding: 'utf8', signal: options?.signal })
      return { ...summary, content: skillDescription(raw, file).content }
    },
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// tools
// ─────────────────────────────────────────────────────────────────────────────

/** 每个工具的统一输出形状（字符串 + 渲染成一行文本）。 */
const stringOutput = { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] }

export function apply(ctx) {
  const shell = ctx.shell

  // **先 stat 再注册**：缺任一资产就抛，宁可整棵 preset 被拒（日志可见），也不要静默少一个 skill。
  for (const relative of ASSETS) {
    const path = join(ASSET_ROOT, relative)
    try {
      if (!statSync(path).isFile()) throw new Error('not a file')
    } catch {
      throw new Error(`fly-blackbox: 自带资产缺失 ${relative}（期望在 ${path}）—— files 里少一行就会这样，整棵 preset 拒绝挂载。`)
    }
  }
  ctx.skills.registerProvider(() => blackboxSkillProvider())

  // ── §B6 授权 guard ────────────────────────────────────────────────────────
  //
  // `actionOf()` 读的是 `exec.arguments`（引擎真形状），不是 `exec.args`。这里**不许**再
  // 出现 `exec.args`：读错字段会让整个 guard 恒不触达，而门禁仍然全绿（见 actionOf 的注释）。
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name?.startsWith('bx_')) {
      const action = actionOf(exec)
      if (isGated(exec.name, action) && process.env.FLY_ALLOW_INTERCEPT !== '1') {
        return { kind: 'deny', reason: gateReason(exec.name, action) }
      }
    }
    return next()
  })

  // ── bx_proxy ─────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_proxy',
    description: 'Start/stop/inspect the local mitmproxy interception proxy (status is read-only; start/stop/restart need FLY_ALLOW_INTERCEPT=1).',
    parameters: {
      action: { type: 'string', required: true, description: 'start | stop | status | restart' },
      port: { type: 'number', description: 'listen port, default FLY_PROXY_PORT or 8080' },
      rules: { type: 'string', description: 'rules.json path, default <workspace>/.fly-blackbox/rules.json' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const root = workspaceRoot(exec, ctx)
      const action = String(args.action ?? '')
      const port = args.port ?? Number(process.env.FLY_PROXY_PORT ?? 8080)
      const state = readState(root)

      if (action === 'status') {
        const status = await proxyStatusLines(shell, exec, root)
        const lines = [`state: ${describeState(status.state)}`]
        const version = await runCmd(shell, [mitmBin(), '--version'], exec, { timeoutMs: 20_000 })
        if (version.exitCode !== 0) {
          lines.push('mitmdump: 缺席', '', missingMitmdumpMessage(missingTool(version) ? `${mitmBin()}: command not found` : version.stderr.trim().split('\n')[0] ?? `exit ${version.exitCode}`))
          return lines.join('\n')
        }
        lines.push(`mitmdump: ${version.stdout.trim().split('\n')[0]}`)
        if (status.state === undefined) return lines.join('\n')
        lines.push(`process alive (kill -0): ${status.alive ? 'yes' : 'no'}`)
        lines.push(`port ${status.port} listeners: ${status.listeners.length === 0 ? '(none)' : status.listeners.join(' | ')}`)
        if (status.stale) {
          lines.push('', '⚠ 状态**陈旧**：进程存活与端口占用不一致 —— 不自动杀，请核对后清理状态文件：')
          lines.push(`  rm -f ${statePath(root)}`)
        }
        return lines.join('\n')
      }

      if (action === 'stop') {
        if (state === undefined) return `没有状态文件，无需停止（${statePath(root)}）`
        const kill = await runCmd(shell, ['kill', String(state.pid)], exec, { timeoutMs: 15_000 })
        const deadline = Date.now() + 5_000
        let listeners = await listenersOn(shell, exec, state.port)
        while (listeners.length > 0 && Date.now() < deadline) {
          await new Promise(resolve => setTimeout(resolve, 250))
          listeners = await listenersOn(shell, exec, state.port)
        }
        if (listeners.length > 0) {
          return `PID ${state.pid} 已发信号（exit ${kill.exitCode}），但端口 ${state.port} 5 秒内未释放，状态文件保留：\n${listeners.join('\n')}`
        }
        clearState(root)
        return `已停止 PID ${state.pid}，端口 ${state.port} 已释放，状态文件已删除。`
      }

      if (action !== 'start' && action !== 'restart') {
        return `unparsable action ${JSON.stringify(action)} — 只能是 start / stop / status / restart`
      }

      if (action === 'restart' && state !== undefined) {
        const stop = await runCmd(shell, ['kill', String(state.pid)], exec, { timeoutMs: 15_000 })
        const deadline = Date.now() + 5_000
        let listeners = await listenersOn(shell, exec, state.port)
        while (listeners.length > 0 && Date.now() < deadline) {
          await new Promise(resolve => setTimeout(resolve, 250))
          listeners = await listenersOn(shell, exec, state.port)
        }
        if (listeners.length > 0) {
          throw new Error(`restart 拒绝继续：PID ${state.pid} 收到信号（exit ${stop.exitCode}）后端口 ${state.port} 5 秒内未释放，先人工确认占用者`)
        }
        clearState(root)
      }

      if (action === 'start' && state !== undefined) {
        const status = await proxyStatusLines(shell, exec, root)
        if (status.alive) {
          throw new Error(`这个工作区已经有一个实例在跑：${describeState(state)}\n要重启请用 action=restart，或先 action=stop。`)
        }
      }

      const version = await mitmdumpVersion(shell, exec)
      const rules = rulesPath(root, args.rules)
      const rulesText = await readTextFileVia(shell, exec, rules, '规则文件', { allowEmpty: true })
      const verdict = validateRules(rulesText.toString('utf8'), rules)
      if (!verdict.ok) throw new Error(`${verdict.reason}\n规则文件由 agent/用户用文件工具写（schema 见 skill 资产 reference/rules.schema.md）；bx_proxy start 只读并校验。`)

      const listeners = await listenersOn(shell, exec, port)
      if (listeners.length > 0) {
        throw new Error(`端口 ${port} 已被占用，拒绝启动（不是我们自己的实例）：\n${listeners.join('\n')}`)
      }

      const confdir = join(root, '.fly-blackbox', 'mitmproxy')
      const dump = join(root, '.fly-blackbox', 'flows.mitm')
      const addon = join(ASSET_ROOT, 'code', 'mitm_addon_template.py')
      // `onExpiry:'none'` **必须显式传**：`dsh-bash-local` 的 resolve() 缺省是
      // `onExpiry: request.onExpiry ?? "kill"`、`timeoutMs` 缺省 120000 —— 不 await result()
      // 只让调用立即返回，进程仍会在 120 秒被引擎杀掉。timeoutMs 一并显式传，免得读代码的人
      // 以为默认值无所谓。
      // 用 `startCmd`（**不 await result**）：代理是常驻进程，await result 会挂到它退出。
      //
      // 规则路径与授权开关**只走环境变量，不走 `--set`**。实测（真 mitmdump 12.2.3）：
      // `--set` 的值要等 addon 的 `load()` **之后**才写进 `ctx.options`（`load()` 里读
      // 到的是空串、`running()` 里才是给定值），而本 addon 的纪律是"规则文件缺失/非法
      // = 在 `load()` 里拒绝启动"。所以 `--set fly_rules=…` 曾经**静默无效**：addon
      // 退回默认的 `rules.json`、当场抛 `RuleError`、mitmdump 退出 1 —— 整条"起代理"
      // 的路都走不通，而只验证命令形状的接缝桩看不见这一点（真 mitmdump 的端到端才看见）。
      // 环境变量在 addon 的 import 期就读得到，所以只有它能撑住 `load()` 里的校验。
      mkdirSync(join(root, '.fly-blackbox'), { recursive: true })
      const started = await startCmd(shell, [
        mitmBin(),
        '-s', addon,
        '-w', dump,
        '--set', `confdir=${confdir}`,
        '-p', String(port),
      ], exec, {
        onExpiry: 'none',
        timeoutMs: 600_000,
        env: {
          MITM_RULES: rules,
          MITM_CAPTURE: join(root, '.fly-blackbox', 'capture'),
          FLY_ALLOW_INTERCEPT: process.env.FLY_ALLOW_INTERCEPT === '1' ? '1' : '0',
          // 不让 Python 把 __pycache__ 写进**包资产目录**（addon 就在 assets 里）：
          // 实测 Ubuntu 上第一次 start 会在包内生成 .pyc，污染发布字节。
          PYTHONDONTWRITEBYTECODE: '1',
        },
      })
      if (started.handle.status === 'completed' && started.handle.exitCode === 0 && started.peek().trim() === '') {
        throw new Error(`mitmdump 退出码 0 且没有任何输出，拒绝写状态文件`)
      }

      // 等就绪：最多 20 × 0.25s（原会话"3 次端口自旋 + 4 次重启"要的就是这个原语）。
      let ready = false
      for (let attempt = 0; attempt < 20 && !ready; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 250))
        ready = (await listenersOn(shell, exec, port)).length > 0
      }

      const pid = await listenerPidOn(shell, exec, port)
      if (pid === null) {
        const early = started.peek().trim().slice(-2000)
        const state = started.handle.status === 'running' ? '还在跑但没等到 LISTEN' : `${started.handle.status}（exit ${String(started.handle.exitCode)}）`
        throw new Error(`mitmdump ${state}，${port} 上没有可识别的 LISTEN 进程，拒绝写状态文件。${early === '' ? '' : `\n${early}`}`)
      }
      const written = writeState(root, {
        pid,
        port,
        confdir,
        dump,
        rules,
        mitmdumpVersion: version.split('\n')[0],
        startedAt: new Date().toISOString(),
      })

      return [
        `已启动：PID ${pid} · port ${port} · 就绪=${ready ? 'yes' : 'no（20×0.25s 内没看到 LISTEN）'}`,
        `confdir: ${confdir}`,
        `dump:    ${dump}`,
        `rules:   ${rules}（${verdict.summary}）`,
        `mitmdump --version: ${version.replace(/\n/gu, ' | ')}`,
        `状态文件: ${written}`,
        '',
        '下一步：`bx_doctor` 判管道（第②段会核对 HTTPS 签发者是不是 confdir 里的 mitm CA）。',
      ].join('\n')
    },
  }))

  // ── bx_doctor ────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_doctor',
    description: 'Judge the interception pipeline in five legs (HTTP, HTTPS issuer == confdir mitm CA, client traffic, conflicting proxies, system proxy). Needs FLY_ALLOW_INTERCEPT=1.',
    parameters: {
      host: { type: 'string', description: 'target host to probe, default example.com' },
      port: { type: 'number', description: 'proxy port, default 8080' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const root = workspaceRoot(exec, ctx)
      const state = readState(root)
      const port = args.port ?? state?.port ?? Number(process.env.FLY_PROXY_PORT ?? 8080)
      const host = args.host ?? 'example.com'
      const confdir = state?.confdir ?? join(root, '.fly-blackbox', 'mitmproxy')
      const lines = [`bx_doctor · proxy 127.0.0.1:${port} · 目标 ${host}`]
      let failed = 0
      const fail = (text, next) => {
        failed += 1
        lines.push(`FAIL ${text}`)
        if (next !== undefined) lines.push(`     next: ${next}`)
      }

      const version = await runCmd(shell, [mitmBin(), '--version'], exec, { timeoutMs: 20_000 })
      if (version.exitCode !== 0) {
        lines.push('mitmdump: 缺席 —— **本机没有抓包能力**（一等状态，不是"我没查出来"）')
        lines.push(missingMitmdumpMessage(missingTool(version) ? `${mitmBin()}: command not found` : version.stderr.trim().split('\n')[0] ?? `exit ${version.exitCode}`))
        lines.push('')
        lines.push('（没有 mitmproxy 时 TLS 拦截没有纯仓内替代：只转发 CONNECT 的代理看得到域名、看不到 body，而这类缺陷恰恰在 body 里。要么装上它，要么以后做原生代理——不做"半个代理"。）')
        return lines.join('\n')
      }
      lines.push(`mitmdump: ${version.stdout.trim().split('\n')[0]}`)
      lines.push('')

      // ① HTTP 过代理
      const http = await runCmd(shell, ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-x', `http://127.0.0.1:${port}`, `http://${host}/`], exec, { timeoutMs: 30_000 })
      if (http.exitCode === 0 && http.stdout.trim() === '200') lines.push(`ok   ① HTTP 过代理：200`)
      else fail(`① HTTP 过代理：${http.stdout.trim() || 'no answer'}（curl exit ${http.exitCode}）`, '代理没起来？先 `bx_proxy status`，再看 `bx_proxy start` 的回显。')

      // ② HTTPS 的签发者必须是 confdir 里的 mitm CA —— 只看 200 会被"别的代理/直连"骗过去
      const caPem = join(confdir, 'mitmproxy-ca-cert.pem')
      const https = await runCmd(shell, ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-x', `http://127.0.0.1:${port}`, '--cacert', caPem, `https://${host}/`], exec, { timeoutMs: 30_000 })
      const issuer = await runCmd(shell, ['openssl', 's_client', '-connect', `${host}:443`, '-proxy', `127.0.0.1:${port}`, '-servername', host, '-showcerts'], exec, { timeoutMs: 30_000 })
      const issuerText = issuer.exitCode === 0 ? issuer.stdout : ''
      const caText = await runCmd(shell, ['openssl', 'x509', '-in', caPem, '-noout', '-subject', '-fingerprint', '-sha256'], exec, { timeoutMs: 30_000 })
      const caSubject = caText.exitCode === 0 ? (caText.stdout.match(/subject=.*/u)?.[0] ?? '').trim() : ''
      const seenIssuer = /issuer=.*/u.exec(issuerText)?.[0]?.trim() ?? ''
      if (https.exitCode === 0 && https.stdout.trim() === '200' && caSubject !== '' && /mitmproxy/iu.test(issuerText)) {
        lines.push(`ok   ② HTTPS 过代理且证书链里是 mitm CA（curl ${https.stdout.trim()}；${seenIssuer === '' ? caSubject : seenIssuer}）`)
      } else {
        fail(
          `② HTTPS 的第②条校验没过：curl=${https.stdout.trim() || 'no answer'} · confdir CA=${caSubject === '' ? `读不到 ${caPem}` : caSubject} · 链里看到的 issuer=${seenIssuer === '' ? '(没拿到)' : seenIssuer}`,
          `只看 200 不算过：要确认签发者**就是** ${confdir} 里的 mitm CA。CA 不存在 → 先 'bx_ca status'；证书链里没有 mitmproxy → 目标有 pinning 或用别的代理。`,
        )
      }

      // ③ 目标客户端是否出现（dump 里的 [NEW HOST] 计数来自 addon 的 all.log；用 dump 的 host 集合代替）
      const dump = state?.dump ?? join(root, '.fly-blackbox', 'flows.mitm')
      const dumpRun = await runCmd(shell, statSizeArgv(process.platform, dump), exec, { timeoutMs: 15_000 })
      const dumpSize = dumpRun.exitCode === 0 ? parseStatSize(dumpRun.stdout) : null
      if (dumpSize === null) {
        lines.push('info ③ 还没有 dump 文件 —— 目标客户端一次都没走过这条代理。')
        lines.push(`     注意：${quitHint(process.platform)}`)
      } else {
        const hosts = await runCmd(shell, ['strings', dump], exec, { timeoutMs: 20_000, stdoutMaxBytes: 8 * 1024 * 1024 })
        const unique = new Set((hosts.stdout.match(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/giu) ?? []).map(hit => hit.toLowerCase()))
        lines.push(`ok   ③ dump 里出现过 ${unique.size} 个域名样本（dump ${dumpSize} 字节）`)
        if (unique.size === 0) lines.push('     ⚠ 一个域名都没解析出来：可能只抓到握手，或客户端根本没走代理。')
      }

      // ④ 冲突代理（Clash / Surge / mihomo 常驻 7890/7897/8888）+ 占用我们端口者
      const conflicts = []
      for (const candidate of [7890, 7897, 8888]) {
        for (const line of await listenersOn(shell, exec, candidate)) conflicts.push(`${candidate}: ${line}`)
      }
      for (const line of await listenersOn(shell, exec, port)) conflicts.push(`${port}: ${line}`)
      if (conflicts.length === 0) lines.push('ok   ④ 7890/7897/8888 与我们的端口都没有别的 LISTEN 者')
      else {
        lines.push(`info ④ 本机在跑的代理进程：`)
        for (const line of conflicts) lines.push(`     ${line}`)
        lines.push('     它们可能抢流量。确认系统代理指向我们之后，再看 ③ 有没有目标客户端的域名。')
      }

      // ⑤ 系统代理：真实状态是「mode/Enabled」，不是「Server 有值」。
      if (process.platform === 'darwin') {
        const scutil = await runCmd(shell, ['scutil', '--proxy'], exec, { timeoutMs: 20_000 })
        if (scutil.exitCode !== 0) {
          lines.push('info ⑤ 读不到系统代理（scutil 失败）')
        } else {
          const httpEnabled = /HTTPEnable\s*:\s*(\d)/u.exec(scutil.stdout)?.[1]
          const httpsEnabled = /HTTPSEnable\s*:\s*(\d)/u.exec(scutil.stdout)?.[1]
          const server = /HTTPSProxy\s*:\s*(\S+)/u.exec(scutil.stdout)?.[1] ?? '(none)'
          const enabled = httpEnabled === '1' || httpsEnabled === '1'
          if (enabled) lines.push(`ok   ⑤ 系统代理 Enabled（HTTP=${httpEnabled}, HTTPS=${httpsEnabled}, Server=${server}）`)
          else lines.push(`FAIL ⑤ 系统代理没开：Enabled 字段是 HTTP=${httpEnabled ?? '?'}/HTTPS=${httpsEnabled ?? '?'}（注意 Server 字段可能是残留的 ${server}，**它不代表生效**）`)
          if (!enabled) lines.push(`     next: \`bx_sysproxy on\` 之后 ${quitHint(process.platform)}`)
        }
      } else if (process.platform === 'linux') {
        const proxy = await gnomeProxyStatus(shell, exec)
        if (!proxy.available) {
          lines.push(`info ⑤ 读不到系统代理（${proxy.reason}）`)
        } else {
          const httpPointsHere = proxy.httpHost === '127.0.0.1' && Number(proxy.httpPort) === port
          const httpsPointsHere = proxy.httpsHost === '127.0.0.1' && Number(proxy.httpsPort) === port
          const enabled = proxy.mode === 'manual' && httpPointsHere && httpsPointsHere
          if (enabled) {
            lines.push(`ok   ⑤ GNOME 系统代理指向本机（mode=${proxy.mode}, http=${proxy.httpHost}:${proxy.httpPort}, https=${proxy.httpsHost}:${proxy.httpsPort}）`)
          } else {
            fail(
              `⑤ GNOME 系统代理没指向本机：mode=${proxy.mode ?? '?'} · http=${proxy.httpHost ?? '?'}:${proxy.httpPort ?? '?'} · https=${proxy.httpsHost ?? '?'}:${proxy.httpsPort ?? '?'}`,
              `用 \`bx_sysproxy on\` 指到 127.0.0.1:${port}；${quitHint(process.platform)}`
              + ' CLI/Electron 不一定读 GNOME 设置：必要时再给那个进程设 http_proxy/https_proxy。',
            )
          }
        }
      } else {
        lines.push(`info ⑤ 这个平台（${process.platform}）没有实现系统代理检查`)
      }

      const rules = state?.rules ?? join(root, '.fly-blackbox', 'rules.json')
      const rulesRun = await runCmd(shell, ['base64', '-i', rules], exec, { timeoutMs: 20_000 })
      if (rulesRun.exitCode !== 0) lines.push(`info 规则文件：none（${rules}）`)
      else {
        const verdict = validateRules(decodeBase64(rulesRun.stdout, '规则文件', rules, { allowEmpty: true }).toString('utf8'), rules)
        lines.push(verdict.ok ? `ok   规则文件：valid（${verdict.summary}）` : `FAIL 规则文件：invalid —— ${verdict.reason}`)
        if (!verdict.ok) failed += 1
      }

      lines.push('')
      lines.push(failed === 0 ? '判决：管道自检通过（这不等于"已经验证过真实拦截成功"——它证明的是管道通）。' : `判决：${failed} 条没过。`)
      return lines.join('\n')
    },
  }))

  // ── bx_sysproxy ──────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_sysproxy',
    description: 'Inspect/point the system proxy at the local interception proxy (macOS: networksetup/scutil; Linux: GNOME gsettings). on/off need FLY_ALLOW_INTERCEPT=1; always prints the one command that restores it.',
    parameters: {
      action: { type: 'string', required: true, description: 'status | on | off' },
      port: { type: 'number', description: 'proxy port, default FLY_PROXY_PORT or 8080' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const action = String(args.action ?? '')
      const state = readState(workspaceRoot(exec, ctx))
      const port = args.port ?? state?.port ?? Number(process.env.FLY_PROXY_PORT ?? 8080)

      if (process.platform === 'linux') {
        const proxy = await gnomeProxyStatus(shell, exec)
        if (!proxy.available) {
          throw new Error(
            `Linux 系统代理：${proxy.reason}。\n`
            + '本包只实现了 GNOME（gsettings）系统代理；KDE 等桌面请改桌面设置，或给目标进程设 http_proxy/https_proxy。',
          )
        }
        const restore = gnomeProxyRestoreCommand()
        const envLine = ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']
          .filter(name => typeof process.env[name] === 'string' && process.env[name].trim() !== '')
          .map(name => `${name}=${process.env[name]}`)
        if (action === 'status') {
          return [
            `系统代理后端：${proxy.backend}`,
            `mode=${proxy.mode ?? '(读不到)'} · http=${proxy.httpHost ?? '?'}:${proxy.httpPort ?? '?'} · https=${proxy.httpsHost ?? '?'}:${proxy.httpsPort ?? '?'}`,
            envLine.length === 0 ? '宿主环境变量：没有 http_proxy/https_proxy（CLI 不一定读 GNOME 设置）' : `宿主环境变量：${envLine.join(' · ')}`,
            `还原命令（一条）：${restore}`,
          ].join('\n')
        }
        if (action !== 'on' && action !== 'off') return `unparsable action ${JSON.stringify(action)} — 只能是 status / on / off`
        const commands = action === 'on' ? gnomeProxyOnCommands(port) : gnomeProxyOffCommands()
        for (const argv of commands) requireOk(await runCmd(shell, argv, exec, { timeoutMs: 30_000 }), argv.join(' '))
        const after = await gnomeProxyStatus(shell, exec)
        return [
          action === 'on'
            ? `已把 GNOME 系统代理指向 127.0.0.1:${port}（http + https）`
            : '已关掉 GNOME 系统代理（mode=none）',
          `随手核对：mode=${after.mode ?? '(读不到)'} · http=${after.httpHost ?? '?'}:${after.httpPort ?? '?'} · https=${after.httpsHost ?? '?'}:${after.httpsPort ?? '?'}`,
          `还原命令（一条，随时可复制）：${restore}`,
          action === 'on' ? `下一步：${quitHint('linux')}然后 bx_doctor。` : '',
          '',
          '注意：GNOME 设置只影响读它的应用（GNOME 组件 / 部分 Chromium）；终端与很多 CLI 认 http_proxy/https_proxy，不认 gsettings。',
        ].filter(Boolean).join('\n')
      }
      if (process.platform !== 'darwin') {
        throw new Error(`bx_sysproxy 只实现了 macOS（networksetup/scutil）与 Linux（GNOME gsettings）—— 当前平台 ${process.platform}。`)
      }

      const route = await runCmd(shell, ['sh', '-c', "route -n get default 2>/dev/null | awk '/interface:/{print $2}'"], exec, { timeoutMs: 20_000 })
      const iface = route.stdout.trim()
      const order = await runCmd(shell, ['sh', '-c', "networksetup -listnetworkserviceorder 2>/dev/null"], exec, { timeoutMs: 20_000 })
      let service = ''
      if (iface !== '') {
        // `(Hardware Port: Wi-Fi, Device: en0)` 是 networksetup 的成对形状；按 Device 命中。
        const block = new RegExp(`\\(\\d+\\)\\s+([^\\n]*)\\n\\(Hardware Port: ([^,]+), Device: ${iface.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}\\)`, 'u').exec(order.stdout)
        service = block?.[1]?.trim() ?? ''
      }
      if (service === '') {
        throw new Error(
          `解析不出默认路由的网络服务名（默认接口 ${iface === '' ? '(route 没给出)' : iface}）—— 绝不拿空名去发 networksetup 命令。`
          + '\n请人工执行 `networksetup -listnetworkserviceorder` 确认服务名，再用 `bx_sysproxy` 之外的方式设置，或回报本机的服务名形状。',
        )
      }
      const restore = `networksetup -setwebproxystate ${shq(service)} off && networksetup -setsecurewebproxystate ${shq(service)} off`

      if (action === 'status') {
        const current = await runCmd(shell, ['scutil', '--proxy'], exec, { timeoutMs: 20_000 })
        const httpEnabled = /HTTPEnable\s*:\s*(\d)/u.exec(current.stdout)?.[1] ?? '?'
        const httpsEnabled = /HTTPSEnable\s*:\s*(\d)/u.exec(current.stdout)?.[1] ?? '?'
        return [
          `默认路由服务：${service}（接口 ${iface}）`,
          `系统代理（真实状态看 Enabled）：HTTPEnable=${httpEnabled} · HTTPSEnable=${httpsEnabled}`,
          `还原命令（一条）：${restore}`,
        ].join('\n')
      }
      if (action !== 'on' && action !== 'off') return `unparsable action ${JSON.stringify(action)} — 只能是 status / on / off`

      const commands = action === 'on'
        ? [
            `networksetup -setwebproxy ${shq(service)} 127.0.0.1 ${port}`,
            `networksetup -setsecurewebproxy ${shq(service)} 127.0.0.1 ${port}`,
          ]
        : [
            `networksetup -setwebproxystate ${shq(service)} off`,
            `networksetup -setsecurewebproxystate ${shq(service)} off`,
          ]
      for (const command of commands) requireOk(await runCmd(shell, ['sh', '-c', command], exec, { timeoutMs: 30_000 }), command)
      const after = await runCmd(shell, ['scutil', '--proxy'], exec, { timeoutMs: 20_000 })
      const line = action === 'on'
        ? `已把系统代理指向 127.0.0.1:${port}（服务 ${service}）`
        : `已关掉系统代理（服务 ${service}）`
      return [
        line,
        `随手核对的 Enabled 字段：${/HTTPEnable\s*:\s*\d/u.exec(after.stdout)?.[0] ?? '(读不到)'} · ${/HTTPSEnable\s*:\s*\d/u.exec(after.stdout)?.[0] ?? '(读不到)'}`,
        `还原命令（一条，随时可复制）：${restore}`,
        action === 'on' ? `下一步：${quitHint('darwin')}然后 bx_doctor。` : '',
      ].filter(Boolean).join('\n')
    },
  }))

  // ── bx_ca ────────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_ca',
    description: 'Inspect the mitm CA trust state and print (never run) the command a human must execute; verify afterwards with security verify-cert (macOS) or openssl verify (Linux). Never escalates privileges.',
    parameters: {
      action: { type: 'string', required: true, description: 'status | command | verify' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const root = workspaceRoot(exec, ctx)
      const state = readState(root)
      const confdir = state?.confdir ?? join(root, '.fly-blackbox', 'mitmproxy')
      const caPem = join(confdir, 'mitmproxy-ca-cert.pem')
      const action = String(args.action ?? '')
      const platform = process.platform

      const fingerprint = await runCmd(shell, ['openssl', 'x509', '-in', caPem, '-noout', '-sha256', '-fingerprint'], exec, { timeoutMs: 20_000 })
      if (fingerprint.exitCode !== 0) {
        if (fingerprint.exitCode === 127 || /not found/iu.test(fingerprint.stderr)) {
          return [
            '读不到 mitm CA 的指纹：本机没有 openssl（Ubuntu：sudo apt install openssl）。',
            `CA 路径（文件本身可能已在）：${caPem}`,
            '装好 openssl 后重试；也可以手跑 `openssl x509 -in <CA> -noout -fingerprint -sha256` 核对。',
          ].join('\n')
        }
        return [
          `读不到 mitm CA：${caPem}`,
          'CA 由 mitmdump 首次启动时生成 —— 先 `bx_proxy start`（它会回显 confdir 绝对路径），再回来。',
        ].join('\n')
      }
      const fp = fingerprint.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean).join(' | ')
      // 校验命令按平台分派：macOS 用 security，Linux 用 `openssl verify -CAfile <系统 bundle>`。
      const verifyArgv = caVerifyArgv(platform, caPem)
      const verifyText = verifyArgv.join(' ')
      const trust = await runCmd(shell, verifyArgv, exec, { timeoutMs: 30_000 })
      const trusted = trust.exitCode === 0
      const trustLine = trusted
        ? `可信：${verifyText} 退出 0`
        : `不可信：${verifyText} 退出 ${trust.exitCode} —— ${trust.stderr.trim().split('\n').slice(-2).join(' | ')}`
          + (trust.exitCode === 127 ? '（openssl 不在本机：sudo apt install openssl）' : '')

      if (action === 'status') {
        return [
          `CA: ${caPem}`,
          `指纹: ${fp}`,
          trustLine,
          caTrustNote(platform),
          trusted ? '' : '\n要人跑的那条命令用 `bx_ca command` 取（本包**永不提权**，所以不经接缝执行）。',
        ].filter(Boolean).join('\n')
      }

      if (action === 'command') {
        // 带 `sudo` 的命令是**给人复制的文本**，不经过接缝。理由见文件头纪律三。
        if (platform === 'darwin') {
          return [
            '# 下面这条命令要你自己在终端跑（本包永不提权：沙箱里提权调用弹不出框、也没有超时，真会话会挂住）',
            `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${caPem}`,
            '',
            `# 只用当前用户（不需要 sudo，但只对当前用户生效）：`,
            `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ${caPem}`,
            '',
            `# 跑完用 bx_ca verify 取事后证据（security verify-cert 的退出码 + 指纹）。`,
            `# 还原：sudo security delete-certificate -c "mitmproxy" /Library/Keychains/System.keychain`,
          ].join('\n')
        }
        if (platform === 'linux') {
          return [
            '# 下面的命令要你自己在终端跑（本包永不提权：沙箱里提权调用弹不出框、也没有超时，真会话会挂住）',
            ...caInstallLines(caPem),
          ].join('\n')
        }
        throw new Error(`bx_ca 只实现了 macOS 与 Linux 的信任安装指引 —— 当前平台 ${platform}。`)
      }

      if (action === 'verify') {
        return [
          `证据：${verifyText} → ${trusted ? '退出 0（可信）' : `退出 ${trust.exitCode}（仍不可信）`}`,
          `指纹（应与上面的命令装的是同一张）：${fp}`,
          trust.stderr.trim() === '' ? '' : `stderr: ${trust.stderr.trim().split('\n').slice(-2).join(' | ')}`,
          '',
          caTrustNote(platform),
          `提示：装完 CA 后目标客户端要**重启**才会读新的信任设置（小程序宿主尤其如此）。`,
        ].filter(Boolean).join('\n')
      }
      return `unparsable action ${JSON.stringify(action)} — 只能是 status / command / verify`
    },
  }))

  // ── bx_flows ─────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_flows',
    description: 'Read a mitmproxy dump offline (hosts | list | show | grep).',
    parameters: {
      action: { type: 'string', required: true, description: 'hosts | list | show | grep' },
      path: { type: 'string', description: 'dump path, default <workspace>/.fly-blackbox/flows.mitm' },
      pattern: { type: 'string', description: 'grep pattern (regex, case-insensitive)' },
      index: { type: 'number', description: 'flow index for show, default 0' },
      limit: { type: 'number', description: 'max rows for list/grep, default 50' },
      json: { type: 'boolean', description: 'machine JSON output (list/show)' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const root = workspaceRoot(exec, ctx)
      const state = readState(root)
      const action = String(args.action ?? '')
      const dump = safePath(args.path ?? state?.dump ?? join(root, '.fly-blackbox', 'flows.mitm'))

      const size = await statSizeVia(shell, exec, dump, 'dump')
      if (size > 32 * 1024 * 1024) {
        throw new Error(
          `dump 有 ${(size / 1024 / 1024).toFixed(1)}MB，超过 32MB 上限，拒绝读（读它要走 base64，重了解不动）。\n`
          + `修法：先用 mitmdump 过滤一遍再存，例如\n`
          + `  mitmdump -nr ${dump} -w ${dump.replace(/\.mitm$/u, '')}-filtered.mitm "${'~u example.com'}"\n`
          + `或直接用 bx_flows 的 grep 定位目标域名后，只导出那段。`,
        )
      }
      const buffer = await readTextFileVia(shell, exec, dump, 'dump')
      const version = await runCmd(shell, [mitmBin(), '--version'], exec, { timeoutMs: 20_000 })
      const mitmdumpVersion = version.exitCode === 0 ? version.stdout.trim().split('\n')[0] : undefined
      const read = readFlows(buffer)
      for (const flow of read.flows) assertReadableVersion(flow, { path: dump, mitmdumpVersion })
      const flows = read.flows.map((flow, index) => summarizeFlow(flow, index))
      const limit = args.limit ?? 50
      const note = read.truncated ? `⚠ ${read.note}；下面的结果是**已完整读到的部分**，不是全量。` : ''

      if (action === 'hosts') {
        const counts = new Map()
        for (const flow of flows) counts.set(flow.host, (counts.get(flow.host) ?? 0) + 1)
        const rows = [...counts].sort((left, right) => right[1] - left[1])
        const body = args.json === true
          ? JSON.stringify({ hosts: rows.map(([host, count]) => ({ host, count })), total: flows.length }, null, 2)
          : [`${rows.length} 个域名 / ${flows.length} 条 flow`, ...rows.map(([host, count]) => `${String(count).padStart(5)}  ${host}`)].join('\n')
        return [note, body].filter(Boolean).join('\n')
      }
      if (action === 'list') {
        const shown = flows.slice(0, limit)
        const body = args.json === true
          ? JSON.stringify({ total: flows.length, shown: shown.length, flows: shown.map(flow => ({ index: flow.index, method: flow.method, status: flow.status, host: flow.host, path: flow.path, bytes: flow.requestBody.bytes + flow.responseBody.bytes })) }, null, 2)
          : shown.map(flow => listLine(flow)).join('\n')
        const rest = flows.length - shown.length
        return [note, body, rest > 0 ? `还有 ${rest} 条未显示（limit=${limit}）` : ''].filter(Boolean).join('\n')
      }
      if (action === 'show') {
        const index = args.index ?? 0
        const flow = flows[index]
        if (flow === undefined) throw new Error(`没有第 ${index} 条 flow（这个 dump 有 ${flows.length} 条）`)
        return [note, args.json === true ? JSON.stringify(flow, null, 2) : showText(flow)].filter(Boolean).join('\n')
      }
      if (action === 'grep') {
        const pattern = args.pattern
        if (typeof pattern !== 'string' || pattern === '') throw new Error('grep 需要 pattern（正则，大小写不敏感）')
        let matcher
        try {
          matcher = new RegExp(pattern, 'iu')
        } catch (error) {
          throw new Error(`grep 的 pattern 不是合法正则：${error.message}`)
        }
        const hits = flows.filter(flow => grepText(flow, matcher.source))
        const shown = hits.slice(0, limit)
        return [
          note,
          `${hits.length} 条命中 ${JSON.stringify(pattern)}`,
          ...shown.map(flow => showText(flow)),
          hits.length - shown.length > 0 ? `还有 ${hits.length - shown.length} 条未显示（limit=${limit}）` : '',
        ].filter(Boolean).join('\n')
      }
      return `unparsable action ${JSON.stringify(action)} — 只能是 hosts / list / show / grep`
    },
  }))

  // ── bx_har ───────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_har',
    description: 'Summarize a HAR capture offline (entry counts, groups, slowest entries, 4xx/5xx); optionally diff two captures by method+host+path. Never includes headers or bodies.',
    parameters: {
      path: { type: 'string', required: true, description: 'HAR file path (.har or .har.gz; gzip is detected by its magic bytes)' },
      compareWith: { type: 'string', description: 'second HAR file; adds an added/removed/changed diff against path' },
      groupBy: { type: 'string', description: 'host | status | mime, default host' },
      top: { type: 'number', description: 'max rows per list, default 20; anything omitted is counted under bounds' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const path = safePath(typeof args.path === 'string' ? args.path.trim() : '')
      if (path === '') throw new Error('bx_har 需要 path（.har 或 .har.gz 的路径）')
      const groupBy = args.groupBy ?? 'host'
      if (!HAR_GROUPINGS.includes(groupBy)) {
        throw new Error(`bx_har 的 groupBy 只能是 ${HAR_GROUPINGS.join(' / ')}：给了 ${JSON.stringify(args.groupBy)}`)
      }
      const top = args.top === undefined ? HAR_DEFAULT_TOP : args.top
      if (typeof top !== 'number' || !Number.isInteger(top) || top < 1) {
        throw new Error(`bx_har 的 top 必须是 ≥1 的整数：给了 ${JSON.stringify(args.top)}`)
      }

      const base = await readHarFile(shell, exec, path, 'HAR')
      const summary = summarizeHarEntries(base.entries, groupBy)
      const groups = harBound(summary.groups, top)
      const slowest = harBound(summary.slowest, top)
      const errors = harBound(summary.errors, top)

      const result = {
        file: base.file,
        har: base.har,
        total: base.entries.length,
        groupBy,
        groups: groups.rows,
        slowest: slowest.rows.map(harRow),
        errors: errors.rows.map(row => ({ ...harRow(row), failed: row.failed })),
        top,
        bounds: {
          groups: groups.bounds,
          slowest: slowest.bounds,
          errors: errors.bounds,
        },
      }

      const comparePath = typeof args.compareWith === 'string' ? args.compareWith.trim() : ''
      if (comparePath !== '') {
        const other = await readHarFile(shell, exec, comparePath, '对比 HAR')
        const compared = compareHarEntries(base.entries, other.entries)
        const added = harBound(compared.added, top)
        const removed = harBound(compared.removed, top)
        const changed = harBound(compared.changed, top)
        result.compare = {
          base: base.file,
          other: other.file,
          total: { base: base.entries.length, other: other.entries.length },
          counts: compared.counts,
          added: added.rows,
          removed: removed.rows,
          changed: changed.rows,
          bounds: { added: added.bounds, removed: removed.bounds, changed: changed.bounds },
        }
      }

      const omitted = [
        ...Object.values(result.bounds),
        ...(result.compare === undefined ? [] : Object.values(result.compare.bounds)),
      ].reduce((total, bound) => total + bound.omitted, 0)
      result.truncated = omitted > 0
      result.limitations = harLimitations({
        withQuery: base.entries.filter(row => row.hadQuery).length,
        withoutTime: summary.withoutTime,
        compare: result.compare !== undefined,
        truncated: result.truncated,
        top,
      })
      return JSON.stringify(result, null, 2)
    },
  }))

  // ── bx_diff ──────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_diff',
    description: 'Field-level JSON diff for before/after change audits: distinguishes 缺失 vs 假值 vs 类型变化.',
    parameters: {
      a: { type: 'string', required: true, description: 'old JSON file path' },
      b: { type: 'string', required: true, description: 'new JSON file path' },
      fields: { type: 'string', description: 'comma list of top-level fields to compare (default: all)' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const readJson = async (path, what) => {
        const text = (await readTextFileVia(shell, exec, path, what)).toString('utf8')
        try {
          return JSON.parse(text)
        } catch (error) {
          throw new Error(`${what} 不是合法 JSON：${path} —— ${error.message}`)
        }
      }
      const a = await readJson(args.a, 'a')
      const b = await readJson(args.b, 'b')
      if (typeof a !== 'object' || a === null || Array.isArray(a)) throw new Error(`a 必须是 JSON 对象：${args.a}`)
      if (typeof b !== 'object' || b === null || Array.isArray(b)) throw new Error(`b 必须是 JSON 对象：${args.b}`)
      const only = typeof args.fields === 'string' && args.fields.trim() !== '' ? args.fields.split(',').map(field => field.trim()).filter(Boolean) : null
      const lines = []
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
        if (only !== null && !only.includes(key)) continue
        if (!(key in b)) lines.push(`${key}: ${JSON.stringify(a[key])} → 缺失`)
        else if (!(key in a)) lines.push(`${key}: 缺失 → ${JSON.stringify(b[key])}`)
        else lines.push(...diffJson(a[key], b[key], key))
      }
      if (lines.length === 0) return '无差异（两份 JSON 在这些字段上逐值相同）'
      return [`${lines.length} 处差异：`, ...lines.map(line => `  ${line}`)].join('\n')
    },
  }))
  // 传输是可注入的（`ctx.flyCdpTransport`）—— 桩就钉在这里：真接缝是 Node 全局 WebSocket，
  // 而实测它把"没人听 / 握手被拒 / 握上就断"报成**同一个形状**，所以桩必须复刻那个形状。
  const cdpTransport = () => (typeof ctx.flyCdpTransport?.session === 'function' ? ctx.flyCdpTransport : realCdpTransport())

  // ── bx_cdp_targets（进程内通道第一件）───────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_cdp_targets',
    description: 'List debuggable targets (pages/workers/iframes) in a Chromium/Electron process started with --remote-debugging-port, via GET 127.0.0.1:<port>/json/list. Loopback only; needs FLY_ALLOW_INTERCEPT=1.',
    parameters: {
      port: { type: 'number', required: true, description: 'CDP debug port on 127.0.0.1, e.g. 9222' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const port = requireCdpPort(args.port)
      const run = await runCmd(shell, ['curl', '-sS', '-m', '8', cdpListUrl(port)], exec, { timeoutMs: 15_000 })
      if (run.exitCode !== 0) throw cdpUnreachableError(port, run)
      const targets = parseCdpTargets(run.stdout, port)
      const shown = targets.slice(0, CDP_TARGETS_SHOWN)
      return JSON.stringify({
        tool: 'bx_cdp_targets',
        target: `127.0.0.1:${port}`,
        operation: `GET ${cdpListUrl(port)}（只走回环；端口只认参数）`,
        observed: {
          count: targets.length,
          shown: shown.length,
          omitted: targets.length - shown.length,
          targets: shown.map(item => ({
            id: item.id,
            type: item.type,
            title: item.title,
            url: item.url,
            attachable: typeof item.webSocketDebuggerUrl === 'string' && item.webSocketDebuggerUrl !== '',
          })),
        },
        confidence: 'observed',
        limitations: [
          '这是**某一刻**的清单：target 会随页面开关、进程进退而变（attach 之后还会变）',
          '只列**开了调试端口的那一个进程** —— 本机别的 Electron / 浏览器没开端口就完全看不见，'
            + '这**不是**"本机没有这类应用"',
          '只走回环（参数表里没有 host），所以它**不能**用来连远端设备 —— 那是另一件事',
          '`webSocketDebuggerUrl`（真正的控制通道）**故意不打印**，只给 attachable 真假；'
            + '拿到它就能完全接管那个页面，需要附加上去的动作在后续工具里、同样在这道门后面',
          '`/json/list` 的字段随 Chromium 版本变（本工具只挑 id/type/title/url 四列 + attachable），'
            + '少一列就是少一列，不当作失败',
        ],
      }, null, 2)
    },
  }))
  // ── bx_cdp_scripts（进程内通道第二件）───────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_cdp_scripts',
    description: 'Attach to a CDP target on a loopback debug port and inventory its parsed scripts (Debugger.enable + Debugger.scriptParsed over a short window). Replays already-parsed scripts; source text is NOT returned. Needs FLY_ALLOW_INTERCEPT=1.',
    parameters: {
      port: { type: 'number', required: true, description: 'CDP debug port on 127.0.0.1, e.g. 9222' },
      target: { type: 'string', description: 'target id from bx_cdp_targets; omit = first page target' },
      windowMs: { type: 'number', description: 'how long to collect scriptParsed (default 1200, clamped 200..5000)' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const port = requireCdpPort(args.port)
      const windowMs = clampWindow(args.windowMs, 1200, 200, 5000)
      const { session, picked } = await cdpAttach(cdpTransport(), shell, exec, {
        port, target: args.target, windowMs, commands: [{ method: 'Debugger.enable' }],
      })
      const enable = session.results['Debugger.enable']
      if (enable?.error !== undefined) {
        throw new Error(`Debugger.enable 被目标拒绝（${enable.error.code ?? '?'} ${enable.error.message ?? ''}）—— 这个 target 不允许附加调试域，换一个 target 或换一个实例。`)
      }
      const scripts = session.events.filter(event => event.method === 'Debugger.scriptParsed').map(event => event.params ?? {})
      const shown = scripts.slice(0, CDP_TARGETS_SHOWN)
      return JSON.stringify({
        tool: 'bx_cdp_scripts',
        target: `127.0.0.1:${port} · ${picked.id}(${picked.type})`,
        operation: `WebSocket 附加 → Debugger.enable → 收 ${windowMs}ms 的 Debugger.scriptParsed`,
        observed: {
          count: scripts.length,
          shown: shown.length,
          omitted: scripts.length - shown.length,
          closedEarly: session.closedEarly,
          closeCode: session.closeCode,
          scripts: shown.map(item => ({
            scriptId: item.scriptId,
            url: typeof item.url === 'string' && item.url !== '' ? item.url : '(inline/eval)',
            length: item.length,
            isModule: item.isModule,
            sourceMap: typeof item.sourceMapURL === 'string' && item.sourceMapURL !== '',
            hasSourceURL: item.hasSourceURL,
          })),
        },
        confidence: 'observed',
        limitations: [
          '这是**已经解析过**的脚本清单：`Debugger.enable` 会**回放**已解析的（实测挂上去立刻收到 7 条），'
            + '它不是"将要解析什么"的预测',
          '看不见**还没解析的懒加载代码**（窗口内没加载就不出现）、**已被 GC 的脚本**、以及**别的 target**'
            + '（worker / iframe 在清单里是独立条目，要各自附加）',
          '`url` 显示 `(inline/eval)` = 那段脚本没有 URL（内联或 eval）；`length` 是**源文本字符数**，不是字节数',
          '**不返回源码**（要源码得再发 `Debugger.getScriptSource`，那是另一件事、另一个工具）',
          `只收了一个窗口（${windowMs}ms），窗口一结束就**断开连接** —— CDP 的域随连接走，断开即释放，目标上不留仪表`,
          session.closedEarly
            ? `⚠️ 连接在窗口内断了（close code ${session.closeCode}）：上面这份是**窗口内收到的部分**，不是完整清单`
            : '窗口内连接保持正常（没有提前断开）',
        ],
      }, null, 2)
    },
  }))

  // ── bx_cdp_coverage（进程内通道第三件）───────────────────────
  ctx.tools.register(defineTool({
    name: 'bx_cdp_coverage',
    description: 'Attach to a CDP target on a loopback debug port, measure precise JS coverage (Profiler.startPreciseCoverage + takePreciseCoverage) over a short window, and report executed-byte ratios per script. Fails loudly when the snapshot cannot be taken. Needs FLY_ALLOW_INTERCEPT=1.',
    parameters: {
      port: { type: 'number', required: true, description: 'CDP debug port on 127.0.0.1, e.g. 9222' },
      target: { type: 'string', description: 'target id from bx_cdp_targets; omit = first page target' },
      windowMs: { type: 'number', description: 'sampling window before the snapshot (default 1500, clamped 300..10000)' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const port = requireCdpPort(args.port)
      const windowMs = clampWindow(args.windowMs, 1500, 300, 10000)
      const { session, picked } = await cdpAttach(cdpTransport(), shell, exec, {
        port,
        target: args.target,
        windowMs,
        commands: [
          { method: 'Profiler.enable' },
          { method: 'Profiler.startPreciseCoverage', params: { callCount: true, detailed: false }, key: 'start' },
        ],
        finish: [{ method: 'Profiler.takePreciseCoverage', key: 'take' }],
      })
      const took = session.results.take
      if (took === undefined) {
        throw new Error(session.closedEarly
          ? `采样窗口里连接断了（close code ${session.closeCode}）—— **拿不到快照**，所以不给"部分覆盖率"：半份快照会让人把"没跑过"读成"跑过了"。`
          : '发了 Profiler.takePreciseCoverage 但没等到响应 —— 目标可能卡住了（这一次没有覆盖率可报）。')
      }
      if (took.error !== undefined) {
        throw new Error(`Profiler.takePreciseCoverage 被目标拒绝（${took.error.code ?? '?'} ${took.error.message ?? ''}）—— 目标可能不允许精确覆盖率采样。`)
      }
      const started = session.results.start
      if (started?.error !== undefined) {
        throw new Error(`Profiler.startPreciseCoverage 被目标拒绝（${started.error.code ?? '?'} ${started.error.message ?? ''}）—— 这一步没成功，后面的数就不是覆盖率。`)
      }
      const summary = summarizeCoverage(Array.isArray(took.result?.result) ? took.result.result : [])
      const ranked = summary.rows.slice().sort((a, b) => b.sizeBytes - a.sizeBytes)
      const shown = ranked.slice(0, CDP_TARGETS_SHOWN)
      const percent = summary.sizeTotal === 0 ? null : Math.round(1000 * summary.usedTotal / summary.sizeTotal) / 10
      return JSON.stringify({
        tool: 'bx_cdp_coverage',
        target: `127.0.0.1:${port} · ${picked.id}(${picked.type})`,
        operation: `WebSocket 附加 → Profiler.enable + startPreciseCoverage → 采 ${windowMs}ms → takePreciseCoverage`,
        observed: {
          windowMs,
          scripts: summary.rows.length,
          shown: shown.length,
          omitted: ranked.length - shown.length,
          executedBytes: summary.usedTotal,
          totalBytes: summary.sizeTotal,
          executedPercent: percent,
          rows: shown.map(row => ({
            url: row.url,
            functions: row.functions,
            executedFunctions: row.executedFunctions,
            executedBytes: row.usedBytes,
            sizeBytes: row.sizeBytes,
          })),
        },
        confidence: 'observed',
        limitations: [
          `只反映**这个 ${windowMs}ms 窗口内**跑过的代码 —— 再采一次会变；它不是"静态可达性"，`
            + '更不能读成"这段代码永远不会跑"',
          '**没加载的脚本根本不出现**（覆盖率只报看得见的脚本）—— 清单里没有 ≠ 这个应用没有那段代码',
          '`detailed: false` ⇒ **函数粒度**（不是块粒度 / 不是逐语句）',
          '区间**求了并集**再相加（V8 的函数区间会嵌套，直接相加会重复计数）—— 这是本工具的口径',
          '采样期间目标带着 V8 的仪表跑，会略微变慢；窗口一结束就**断开连接**（域随连接走，断开即释放）',
          '`执行比例` 是**字节口径**（已执行区间 / 脚本最大偏移），不是函数比例',
        ],
      }, null, 2)
    },
  }))
}
