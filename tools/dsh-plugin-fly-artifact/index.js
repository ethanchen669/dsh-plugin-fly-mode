import { defineTool } from '@deepseek-ai/dsh-tools'

/**
 * fly-artifact — 打包产物的**静态重建**（规划 §3.2，P1 能力线第一条）。
 *
 * 两个工具，两层：
 *
 *  1. `artifact_asar_inventory`（清单层）：只读 asar 头（8 字节 pickle 前缀 + header JSON），
 *     给 header 布局、条目数与大小、`package.json` 的入口（`main`）、关键成员（`*.node` /
 *     `package.json` / main 指向的那个文件）与整档 sha256。**不解包、不执行、不落盘**。
 *  2. `artifact_js_boundaries`（边界层）：对一棵解包后的 JS 树**或** asar 里的 `.js` 成员做
 *     **字面量**扫描，抽 fetch / XHR / WebSocket / URL 字面量与 Electron IPC 通道名，
 *     每条带 **file:line**，去重后有界（`top`），并**显式报覆盖率**（扫了几个、跳过几个、为什么）。
 *
 * 三条纪律：
 *
 *  · **读文件一律走 `ctx.shell` 接缝**：`od` 取字节区间、`stat`/`base64` 取整份小文件、
 *    `shasum` 取摘要 —— 沙箱拒绝会以 `SandboxError` 报出，而不是一个裸 EACCES。本包
 *    **不 import `node:fs`**（门禁有一条静态钉子盯着这件事）。为什么必须按**区间**读：
 *    真实 Electron 应用的 app.asar 是 150MB 量级（本机 DSH Fly 自己那份 158,976,491 字节，
 *    光 header JSON 就 4,418,662 字节）—— 整份 base64 回来的那一天就是"重到解不动"。
 *  · **不做数据流**：这是字面量扫描，不是 AST。字符串拼接、变量别名、压缩后的名字一律看不见；
 *    每一条这样的盲区都写在结果的 `limitations` 里，绝不留成"看起来扫全了"。
 *  · **省略绝不藏起来**：任何受 `top` 限界的列表都给 `bounds`（shown / total / omitted），
 *    顶层 `truncated` 汇总；覆盖率里"跳过的文件"逐条点名（含原因），不静默丢。
 *
 * ASAR 布局（本机**实测解码**，不是回忆 —— 见 `scripts/verify-artifact-tools.mjs` 的
 * "真实 Electron 应用的 app.asar" 那条断言）：
 *
 *     偏移 0   u32  恒为 4：第一个 pickle 的长度字段
 *     偏移 4   u32  headerBlockBytes —— 下面整块 pickle 的字节数（= 4 + payloadBytes）
 *     偏移 8   u32  payloadBytes = 4 + jsonBytes + 补到 4 字节对齐的 0..3 字节
 *     偏移 12  u32  jsonBytes（header JSON 的字节数）
 *     偏移 16  …    header JSON
 *     内容基址 = 8 + headerBlockBytes（成员条目里的 `offset` 相对它）
 *
 * `@electron/asar` 的读法是"读 8 字节 → 取 u32 → 再从偏移 8 读整块"，与上表同一件事。
 * 本包不引 `@electron/asar`（新增依赖要用户点头，而这张表已经把需要的全说了），按表自己读。
 *
 * 两个入口都在 P1 的"结论要能回指源码位置"那条要求下：清单的每条成员给**相对路径**，
 * 边界的每条命中给 **file:line**。
 *
 * **起因**（为什么这个包存在）：`morluto/rea` 那边有 APK/JADX、固件/Binwalk、.NET、**JS/ASAR 与 HAR**
 * 这些"看得懂打包产物"的能力，而 fly 这边此前只有原生二进制三件套 —— 一个 Electron 应用的
 * 150MB `app.asar` 摆在面前，只能靠 `bin_strings` 碰运气。安全模式的定位是客户端黑盒排查，
 * 所以这一面必须在拆仓之前补上（规划 §3.2）：先把"清单 + 字面量边界"两层做出来，
 * 再谈 AST 与 CDP（P2）。**不抄代码，只在设计上对齐**（分层、覆盖率、bounds 三件）。
 */

export const name = 'fly-artifact'
export const inject = ['tools', 'shell']

function shq(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`
}

/**
 * Run one confined command through the host `shell` seam.
 *
 * `ShellExecutor` exposes exactly `resolve()` and `execute()` (verified against
 * 0.1.7-rc.2 and 0.2.0-rc.2): `execute()` returns a process handle whose `result`
 * projection carries the run result. An earlier revision of this file awaited a
 * nonexistent `shell.run()`, so every shell-backed tool threw
 * `TypeError: shell.run is not a function` on every call, in every engine
 * version. `scripts/verify-security-tools.mjs` now fails loudly if a call site
 * names a seam method the executor does not have.
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
  const result = await (await shell.execute(shell.resolve({
    command: argv.map(shq).join(' '),
    ...opts.timeoutMs !== void 0 ? { timeoutMs: opts.timeoutMs } : {},
    ...opts.stdoutMaxBytes !== void 0 ? { stdoutMaxBytes: opts.stdoutMaxBytes } : {},
    signal: exec.signal,
  }))).result()
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
  return { stdout: result.stdout.text, stderr: result.stderr.text, exitCode: result.exitCode, command: argv.join(' ') }
}

/**
 * A failed command must never come back as an empty success.
 *
 * Exit 127 (and the shell's "command not found") gets its own wording, because
 * macOS ships no ELF toolchain: `readelf`, `checksec`, `ROPgadget` and `nmap`
 * are simply absent. The old code turned that into "no output", which read
 * exactly like "nothing found".
 */
function requireOk(run, what) {
  if (run.exitCode === 0) return run.stdout
  const detail = run.stderr.trim().split('\n').map(line => line.trim()).filter(Boolean).slice(0, 3).join(' | ')
  const missing = run.exitCode === 127 || /command not found/iu.test(run.stderr) ? ' — the command is not installed on this host' : ''
  const error = new Error(`${what} failed (exit ${run.exitCode})${missing}: ${run.command}${detail === '' ? '' : `\n${detail}`}`)
  error.name = 'CommandError'
  throw error
}

// ── 常量 ────────────────────────────────────────────────────────────────────

/** 任何受 `top` 限界的列表的缺省上限。 */
const DEFAULT_TOP = 50
/** header JSON 超过它就拒读：实测最大的真实档头是 4,418,662 字节（本机 DSH Fly 自己那份），8MB 已是它的两倍。 */
const ASAR_MAX_HEADER_BYTES = 8 * 1024 * 1024
/** 条目数硬闸：畸形档不许把整条工具拖死。 */
const ASAR_MAX_ENTRIES = 500_000
/** 视为"源码"的扩展名。 */
const JS_EXTENSIONS = ['.js', '.mjs', '.cjs', '.jsx']
/** 单文件超过它**整份跳过**（读半份再假装扫过，等于把省略藏起来）。 */
const JS_MAX_FILE_BYTES = 256 * 1024
/** 本次调用读进内存的总预算。 */
const JS_MAX_TOTAL_BYTES = 4 * 1024 * 1024
/** 文件数上限。 */
const JS_MAX_FILES = 2000
/** 每条命中最多带几个位置（`occurrences` 仍是真值）。 */
const MAX_SITES_PER_ROW = 5

/** 工具输出形状：结构化 JSON 文本（与 `bx_har` 同一形状，模型与人都能读）。 */
const stringOutput = { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] }

// ── 接缝读取：区间 / 整份 / 摘要 ─────────────────────────────────────────────

/** 错误文案里的最后一行 stderr（没有就 undefined）。 */
function lastLine(text) {
  const line = String(text ?? '').trim().split('\n').at(-1)?.trim() ?? ''
  return line === '' ? undefined : line
}

/**
 * 读一段字节（经接缝，`od`）—— 与 `fly-binary` 的 `elfReadRange` 同一条路、同一个理由：
 * 读**区间**而不是整份，才不会为了看一个 4KB 成员把 150MB 拖进来。
 *
 * `od` 拒绝从 EOF 起跳（"cannot skip past end of input"，exit 1）—— 那是**短读**，不是失败：
 * 被截断的档要给"这里没有内容"，而不是把整条工具打挂。解码长度由调用方按真值再核一次。
 *
 * **配额不是拍脑袋的**：`od -tx1` 每字节吐 3 个字符，而 `-An` 只是把地址列涂白、宽度还在
 * —— 实测 4,418,662 字节 → 20,436,359 字符（4.63 字符/字节）。第一版按 4 倍给，于是真实档的
 * 头被 stdoutMaxBytes 悄悄截掉 13%，报出去的却是"档被截断了"（一个假结论，A/B 之外自己踩到）。
 */
async function readRange(shell, exec, path, offset, length) {
  const budget = Math.max(65536, Math.min(64 * 1024 * 1024, length * 6 + 65536))
  const run = await runCmd(
    shell,
    ['od', '-An', '-v', '-tx1', '-j', String(offset), '-N', String(length), path],
    exec,
    { stdoutMaxBytes: budget },
  )
  if (run.exitCode !== 0 && !/cannot skip|past end of input/iu.test(run.stderr)) requireOk(run, `od -j ${offset} -N ${length}`)
  const hex = run.stdout.replace(/\s+/gu, '')
  const bytes = Buffer.from(hex.slice(0, hex.length - (hex.length % 2)), 'hex')
  if (bytes.length < length && run.stdout.length >= budget) {
    throw new Error(`${path} 的 ${offset}..${offset + length} 读不动：od 的输出撞上 ${budget} 字节的读取配额（本工具的上限，不是档的问题）`)
  }
  return bytes
}

/**
 * 文件字节数：`stat -f%z`（BSD/macOS，与 `bx_har` 同一条路），非 BSD 上退回 `wc -c`（GNU）。
 *
 * **先量再读**：读之前就知道"这个太大"，才不会为了拒掉一个 200MB 的档先把那一次读取付掉。
 */
async function fileSize(shell, exec, path, what) {
  const stat = await runCmd(shell, ['stat', '-f%z', path], exec, { timeoutMs: 15_000 })
  if (stat.exitCode === 0) {
    const last = stat.stdout.trim().split('\n').at(-1)?.trim() ?? ''
    if (/^\d+$/u.test(last)) return Number(last)
  }
  const wc = await runCmd(shell, ['wc', '-c', path], exec, { timeoutMs: 15_000 })
  const first = wc.stdout.trim().split(/\s+/u)[0] ?? ''
  if (wc.exitCode !== 0 || !/^\d+$/u.test(first)) {
    throw new Error(
      `${what} 不存在或读不到：${path} —— stat 说 ${JSON.stringify(lastLine(stat.stderr) ?? `exit ${stat.exitCode}`)}，`
      + `wc 说 ${JSON.stringify(lastLine(wc.stderr) ?? `exit ${wc.exitCode}`)}`,
    )
  }
  return Number(first)
}

/** 整档 sha256（经接缝调本机 `shasum -a 256`；GNU coreutils 的 `sha256sum` 作后备）。 */
async function fileSha256(shell, exec, path, what) {
  const attempts = [['shasum', '-a', '256', path], ['sha256sum', path]]
  const reasons = []
  for (const argv of attempts) {
    const run = await runCmd(shell, argv, exec, { timeoutMs: 300_000 })
    const hex = run.stdout.trim().split(/\s+/u)[0] ?? ''
    if (run.exitCode === 0 && /^[0-9a-f]{64}$/u.test(hex)) return { sha256: hex, method: argv.join(' ') }
    reasons.push(`${argv[0]}: ${lastLine(run.stderr) ?? `exit ${run.exitCode}`}`)
  }
  throw new Error(`${what} 的 sha256 算不出来：${path} —— ${reasons.join('；')}`)
}

/**
 * 整份读一个**小**文件（经接缝 `base64 -i`）—— 与 `bx_har` 的读取同一条路。
 * 超过 `maxBytes` 就不读，返回 `tooLarge`（由调用方点名记进覆盖率）。
 */
async function readSmallFile(shell, exec, path, what, maxBytes) {
  const size = await fileSize(shell, exec, path, what)
  if (size > maxBytes) return { tooLarge: true, size }
  const run = await runCmd(shell, ['base64', '-i', path], exec, { stdoutMaxBytes: maxBytes * 2 + 65536 })
  if (run.exitCode !== 0) throw new Error(`${what} 读不到：${path} —— ${lastLine(run.stderr) ?? `exit ${run.exitCode}`}`)
  // macOS/Linux 的 `base64` 默认在 stdout 里插换行，解码前一律剔除空白。
  const compact = run.stdout.replace(/\s+/gu, '')
  return { tooLarge: false, size, bytes: Buffer.from(compact, 'base64') }
}

// ── ASAR 读取与清单 ─────────────────────────────────────────────────────────

/**
 * 读 asar 头。**先核 pickle 不变量再信里面的数字**：畸形档（比如把别的文件改名叫 `.asar`）
 * 必须在这一步被拒，而不是拿着 `jsonBytes = 0x7fffffff` 去 od 一个天大的区间。
 */
async function readAsar(shell, exec, path) {
  const bytes = await fileSize(shell, exec, path, 'ASAR')
  if (bytes < 16) throw new Error(`${path} 只有 ${bytes} 字节，装不下 asar 的 16 字节 pickle 头 —— 这不是一个 ASAR`)
  const head = await readRange(shell, exec, path, 0, 16)
  if (head.length < 16) throw new Error(`${path} 的头只读到 ${head.length}/16 字节 —— 档被截断了`)
  const sizeField = head.readUInt32LE(0)
  const headerBlockBytes = head.readUInt32LE(4)
  const payloadBytes = head.readUInt32LE(8)
  const jsonBytes = head.readUInt32LE(12)
  const paddingBytes = payloadBytes - 4 - jsonBytes
  const problems = []
  if (sizeField !== 4) problems.push(`第一个长度字段是 ${sizeField}（asar/pickle 恒为 4）`)
  if (jsonBytes <= 0) problems.push(`header JSON 长度是 ${jsonBytes}`)
  else if (jsonBytes > ASAR_MAX_HEADER_BYTES) {
    problems.push(`header JSON ${(jsonBytes / 1048576).toFixed(1)}MB 超过 ${ASAR_MAX_HEADER_BYTES / 1048576}MB 上限`)
  }
  if (paddingBytes < 0 || paddingBytes > 3) problems.push(`payload(${payloadBytes}) − 4 − json(${jsonBytes}) = ${paddingBytes}，不在 0..3 的对齐填充范围里`)
  if (headerBlockBytes !== 4 + payloadBytes) problems.push(`headerBlock(${headerBlockBytes}) ≠ 4 + payload(${payloadBytes})`)
  if (problems.length > 0) {
    throw new Error(
      `${path} 不像一个 ASAR：${problems.join('；')}。\n`
      + '修法：确认路径指的是 Electron 打包出来的 `.asar`（未打包的应用目录请直接给那个目录，'
      + '`artifact_js_boundaries` 会按解包后的 JS 树扫）。',
    )
  }
  const jsonBuf = await readRange(shell, exec, path, 16, jsonBytes)
  if (jsonBuf.length !== jsonBytes) throw new Error(`${path} 的 header JSON 只读到 ${jsonBuf.length}/${jsonBytes} 字节 —— 档被截断了`)
  let header
  try {
    header = JSON.parse(jsonBuf.toString('utf8'))
  } catch (error) {
    throw new Error(`${path} 的 header JSON 解析失败：${error.message}（头 80 字节：${JSON.stringify(jsonBuf.toString('utf8', 0, 80))}）`)
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header) || header.files === undefined || header.files === null) {
    throw new Error(`${path} 的 header 里没有 \`files\` 映射 —— 这不是 asar 的根节点`)
  }
  return {
    bytes,
    header,
    contentBase: 8 + headerBlockBytes,
    format: {
      kind: 'asar',
      sizeField,
      headerBlockBytes,
      payloadBytes,
      jsonBytes,
      paddingBytes,
      contentBase: 8 + headerBlockBytes,
      headerKeys: Object.keys(header).sort(),
    },
  }
}

/**
 * 把 header 的嵌套 `files` 树摊平成条目表。
 *
 * 条目的 `offset` **可能是字符串**（实测：本机 DSH Fly 自己那份 app.asar 里 `"offset":"154557515"`，
 * 而 `size` 是数字）—— 两处都必须按数字再用，不然 `base + offset` 会变成字符串拼接（一个
 * 静默读到别处的错值）。`unpacked: true` 的成员**没有 offset**：它的内容在
 * `<档名>.asar.unpacked/` 里，头里只有声明大小。
 */
function asarMembers(header) {
  const files = []
  const directories = []
  const walk = (node, prefix, depth) => {
    if (depth > 64) return
    for (const [name, entry] of Object.entries(node.files ?? {})) {
      const memberPath = `${prefix}${name}`
      if (entry !== null && typeof entry === 'object' && entry.files !== undefined) {
        directories.push(memberPath)
        walk(entry, `${memberPath}/`, depth + 1)
        continue
      }
      if (files.length >= ASAR_MAX_ENTRIES) throw new Error(`asar 条目超过 ${ASAR_MAX_ENTRIES} 条，拒绝继续摊平（档畸形或超出本工具的设计面）`)
      const size = Number(entry?.size ?? 0)
      files.push({
        path: memberPath,
        size: Number.isFinite(size) ? size : 0,
        offset: entry?.offset === undefined || entry?.offset === null ? null : Number(entry.offset),
        unpacked: entry?.unpacked === true,
        executable: entry?.executable === true,
        integrity: typeof entry?.integrity?.hash === 'string' ? entry.integrity.hash : null,
      })
    }
  }
  walk(header, '', 0)
  files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
  directories.sort()
  return { files, directories }
}

/** 按 `top` 切一刀，把"切掉了几个"一起返回（省略绝不藏起来）。 */
function bound(rows, top) {
  const shown = rows.slice(0, top)
  return { rows: shown, bounds: { shown: shown.length, total: rows.length, omitted: rows.length - shown.length } }
}

function readTop(value, tool) {
  const top = value === undefined ? DEFAULT_TOP : value
  if (typeof top !== 'number' || !Number.isInteger(top) || top < 1) {
    throw new Error(`${tool} 的 top 必须是 ≥1 的整数：给了 ${JSON.stringify(value)}`)
  }
  return top
}

/** 扩展名（小写，含点）。 */
function extensionOf(path) {
  const base = path.slice(path.lastIndexOf('/') + 1)
  const dot = base.lastIndexOf('.')
  return dot <= 0 ? '' : base.slice(dot).toLowerCase()
}

/** `main` 的写法归一：`./out/main.js` 与 `/out/main.js` 都指向 `out/main.js`。 */
function normalizeMemberPath(path) {
  let out = String(path).trim()
  while (out.startsWith('./')) out = out.slice(2)
  while (out.startsWith('/')) out = out.slice(1)
  return out
}

/**
 * 这份清单**看不见什么** —— 照 §5 的最小证据形状，逐条写给模型（也写给以后改这个工具的人）。
 */
function asarLimitations({ file, format, members, entry, top, truncated, sharedOffsetEntries }) {
  const lines = [
    '只读 asar 头（pickle 前缀 + header JSON），不解包、不执行、不落盘：成员**内容**没有被读过，'
    + '条目里的 integrity 哈希是**原样报出**的声明值，本工具不重算。',
    `sha256 是**整个档**的（经接缝调本机 ${file.sha256Method}），不是任何一个成员的内容摘要。`,
    '成员大小取自 header 的声明（`size`），没有和盘上的实际内容核过；'
    + '`unpacked: true` 的成员内容在 `<档名>.asar.unpacked/` 里，本工具不读那个目录。',
    `成员大小合计（declaredTotal）**可以大于档体积**：asar 允许多条目录项共享同一段内容`
    + `（本次 ${sharedOffsetEntries} 条目录项的 (offset,size) 与别的条目完全相同），`
    + '另外本工具把 unpacked 成员的声明大小也计入了 declaredTotal，而它们不在档里。',
    `关键成员按**名字与扩展名**分类（*.node / package.json / main 指向的那一个），不看内容：`
    + `本次 ${members.files} 个文件条目里 *.node ${members.nativeAddons} 个、package.json ${members.packageJson} 个。`,
    entry.found
      ? `入口取自根 package.json 的 main（${JSON.stringify(entry.main)}），并在成员表里找到了它。`
      : `**入口未知**：${entry.error ?? (entry.main === null ? '根的 package.json 里没有 main 字段' : `main=${JSON.stringify(entry.main)} 在成员表里找不到`)}`
        + ' —— 这是"没读到"，不是"没有入口"。',
    `没有任何签名 / 公证（codesign / notarization）检查：这不是一个"档可不可信"的结论。`,
    `header 的解析只覆盖上面那张 pickle 布局（本次 paddingBytes=${format.paddingBytes}；`
    + '实测真实档里 0 与 2 两种填充都出现过）。',
  ]
  if (truncated) lines.push(`输出被 top=${top} 截断：看每一段的 bounds（shown/total/omitted），这不是全量。`)
  return lines
}

// ── JS 字面量扫描 ───────────────────────────────────────────────────────────

/**
 * 一行里的**字符串字面量**与"把字符串和注释挖空、其余字符位置不变"的掩码。
 *
 * 为什么不是"先剔注释再正则"：`https://…` 里的 `//` 与行注释同形，先剔注释会把一半的
 * URL 从中间切掉（本工具第一版就是这么错的形状）。所以反过来：**先切字符串**，
 * 注释只在字符串之外被认出来。
 *
 * 模板串只取 `${}` **之前**的静态前缀（`dynamic: true` 标出来）：`${}` 里是代码，
 * 拼出来的那一段是数据流问题，超出本工具的口径。
 */
function lexLine(line, state) {
  const tokens = []
  let masked = ''
  let i = 0
  while (i < line.length) {
    if (state.block) {
      const end = line.indexOf('*/', i)
      if (end === -1) {
        masked += ' '.repeat(line.length - i)
        i = line.length
        continue
      }
      masked += ' '.repeat(end + 2 - i)
      i = end + 2
      state.block = false
      continue
    }
    const ch = line[i]
    if (ch === '/' && line[i + 1] === '*') {
      state.block = true
      masked += '  '
      i += 2
      continue
    }
    if (ch === '/' && line[i + 1] === '/') {
      masked += ' '.repeat(line.length - i)
      i = line.length
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch
      let j = i + 1
      let raw = ''
      while (j < line.length) {
        const c = line[j]
        if (c === '\\') {
          raw += line.slice(j, j + 2)
          j += 2
          continue
        }
        if (c === quote) {
          j += 1
          break
        }
        raw += c
        j += 1
      }
      const dynamic = quote === '`' && raw.includes('${')
      const value = (dynamic ? raw.slice(0, raw.indexOf('${')) : raw).replace(/\\(["'`\\/])/gu, '$1')
      tokens.push({ value, raw, quote, start: i, end: j, dynamic })
      masked += ' '.repeat(j - i)
      i = j
      continue
    }
    masked += ch
    i += 1
  }
  return { tokens, masked }
}

/**
 * 已知的调用面。`arg` 是"第几个字符串字面量是它的目标"（从 0 开始），
 * `arg: null` 表示这只是一处**位置证据**（例如 `new XMLHttpRequest` 本身没有字面量）。
 *
 * 这是一张**白名单**：不在表里的写法看不见（`got('x')` 这种自定义包装、压缩后的 `a.b("x")`），
 * 这一条写在 `limitations` 里，不许当成"没有别的边界"。
 */
const CALL_PATTERNS = [
  { kind: 'fetch', re: /(?:^|[^\w$.])(?:window\s*\.\s*)?fetch\s*\(/gu, arg: 0 },
  { kind: 'websocket', re: /new\s+WebSocket\s*\(/gu, arg: 0 },
  { kind: 'eventsource', re: /new\s+EventSource\s*\(/gu, arg: 0 },
  { kind: 'beacon', re: /navigator\s*\.\s*sendBeacon\s*\(/gu, arg: 0 },
  // `.open(method, url)` 是 XHR 的经典形状，但别的 API 也叫 open —— 所以这一条**只认
  // 第二个参数是显式 URL** 的写法（`requireUrl`）。代价是相对路径的 XHR 看不见，
  // 那一条写在 limitations 里，不藏。
  { kind: 'xhr-open', re: /\.\s*open\s*\(/gu, arg: 1, requireUrl: true },
  { kind: 'xhr', re: /new\s+XMLHttpRequest\s*\(/gu, arg: null, marker: 'new XMLHttpRequest' },
  { kind: 'ipc-main', re: /\bipcMain\s*\.\s*(?:handle|handleOnce|on|once|emit)\s*\(/gu, arg: 0 },
  { kind: 'ipc-renderer', re: /\bipcRenderer\s*\.\s*(?:invoke|send|sendSync|sendTo|on|once|postMessage)\s*\(/gu, arg: 0 },
  { kind: 'ipc-webcontents', re: /\bwebContents\s*\.\s*(?:send|invoke)\s*\(/gu, arg: 0 },
  { kind: 'context-bridge', re: /\bcontextBridge\s*\.\s*exposeInMainWorld\s*\(/gu, arg: 0 },
]

/**
 * 调用的第 `wanted` 个字面量参数：从 `from` 往后找字符串记号，中间**只允许**
 * 括号 / 逗号 / 空白 / 花括号方括号 —— 别的东西一出现就说明那不是同一个调用
 * （这一条挡掉"同一行里前一个调用的字符串被算到后一个调用头上"）。
 */
function argumentToken(masked, tokens, from, wanted) {
  let cursor = from
  let seen = 0
  for (const token of tokens) {
    if (token.start < from) continue
    if (!/^[\s(),{}[\]]*$/u.test(masked.slice(cursor, token.start))) return null
    if (seen === wanted) return token
    seen += 1
    cursor = token.end
  }
  return null
}

/**
 * 一个字符串字面量里的 URL（**去掉 query 与 fragment**：打包产物里的 query 常常带
 * token / 签名，与 `bx_har` 同一条隐私口径 —— 那一段根本不复制进输出）。
 * 只认**显式 scheme** 的写法（`https://`、`wss://`、`file://`…）：协议相对地址
 * （`//host/x`）与相对路径会作为普通字面量走 `fetch` 之类的 kind，不在这里猜。
 */
function urlOf(value) {
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^\s/?#]*)([^\s?#]*)/u.exec(value.trim())
  if (match === null) return null
  const scheme = match[1].toLowerCase()
  const host = match[2]
  const path = match[3]
  const rest = value.trim().slice(match[0].length)
  return {
    scheme,
    host,
    path,
    canonical: `${scheme}://${host}${path}`,
    hadQuery: rest.startsWith('?') || rest.startsWith('#'),
  }
}

/** 扫一份文本，把命中交给 `collect`。空行直接跳过（省一次词法）。 */
function scanText(text, file, collect) {
  const state = { block: false }
  const lines = text.split('\n')
  for (const [index, rawLine] of lines.entries()) {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine
    if (line.trim() === '') continue
    const { tokens, masked } = lexLine(line, state)
    const lineNumber = index + 1
    const used = new Set()
    for (const pattern of CALL_PATTERNS) {
      for (const match of masked.matchAll(pattern.re)) {
        if (pattern.arg === null) {
          collect(pattern.kind, { value: pattern.marker, dynamic: false }, file, lineNumber)
          continue
        }
        const token = argumentToken(masked, tokens, match.index + match[0].length, pattern.arg)
        if (token === null) continue
        if (pattern.requireUrl === true && urlOf(token.value) === null) continue
        used.add(tokens.indexOf(token))
        collect(pattern.kind, token, file, lineNumber)
      }
    }
    for (const [i, token] of tokens.entries()) {
      if (used.has(i)) continue
      if (urlOf(token.value) === null) continue
      collect('url-literal', token, file, lineNumber)
    }
  }
}

/**
 * 命中表：**去重键 = kind + 整条字面量**（不是 host、不是 path 前缀）。
 *
 * 为什么写死这一条：把键退化成 host 之后，"同一个域名的两个不同路径"会被折叠成一条，
 * `occurrences` 反而变大 —— 一份看着更"干净"的端点数，掩盖了真实边界数（A/B 变异 A 就是这个形状）。
 */
function createHitTable() {
  const rows = new Map()
  const byFile = new Map()
  let sites = 0
  let dynamicHits = 0
  let queryStripped = 0
  return {
    collect(kind, token, file, line) {
      const url = urlOf(token.value)
      if (url !== null && url.hadQuery) queryStripped += 1
      const key = `${kind}\u0000${token.value}`
      let row = rows.get(key)
      if (row === undefined) {
        row = { kind, value: url === null ? token.value : url.canonical, occurrences: 0, dynamic: false, sites: [] }
        rows.set(key, row)
      }
      row.occurrences += 1
      sites += 1
      if (token.dynamic) {
        row.dynamic = true
        dynamicHits += 1
      }
      if (!row.sites.some(site => site.file === file && site.line === line) && row.sites.length < MAX_SITES_PER_ROW) {
        row.sites.push({ file, line })
      }
      byFile.set(file, (byFile.get(file) ?? 0) + 1)
    },
    result() {
      const all = [...rows.values()].sort((left, right) => (left.kind === right.kind
        ? (left.value < right.value ? -1 : left.value > right.value ? 1 : 0)
        : (left.kind < right.kind ? -1 : 1)))
      return {
        rows: all,
        endpoints: all.filter(row => row.kind !== 'ipc-main' && row.kind !== 'ipc-renderer' && row.kind !== 'ipc-webcontents' && row.kind !== 'context-bridge'),
        channels: all.filter(row => row.kind === 'ipc-main' || row.kind === 'ipc-renderer' || row.kind === 'ipc-webcontents' || row.kind === 'context-bridge'),
        filesWithHits: [...byFile.entries()].map(([file, hits]) => ({ file, hits })).sort((left, right) => (left.hits === right.hits ? (left.file < right.file ? -1 : 1) : right.hits - left.hits)),
        sites,
        dynamicHits,
        queryStripped,
      }
    },
  }
}

/**
 * 这份边界扫描**看不见什么** —— 每条都要能对上实现里的一行，不许写成套话。
 */
function jsLimitations({ mode, coverage, scope, top, truncated, hits, filesWithHits }) {
  const lines = [
    '**字面量扫描，不是 AST**：不做数据流、不追变量拼接、不解析 `require`/`import` 的别名。'
    + '`const base = "https://x"; fetch(base + "/a")`、`const { invoke } = ipcRenderer; invoke("ch")`、'
    + '压缩后的 `a.b("ch")` —— 这些一律看不见。',
    '命令执行一律经 host 的 `shell` 接缝（读文件、列目录都是）；本工具**不执行**被扫的代码、'
    + '不发任何网络请求、不改本机状态。',
    `识别的调用面是一张白名单（${CALL_PATTERNS.map(pattern => pattern.kind).join(' / ')}）：`
    + '表外的写法（自定义包装、动态属性名）看不见，所以"没看到 fetch"不等于"没有外联"；'
    + '其中 `xhr-open` 只认 `.open(method, <显式 URL>)` 的形状 —— 相对路径的 XHR 看不见。',
    `模板字符串只取 \`\${}\` 之前的静态前缀（本次 ${hits.dynamicHits} 处命中带 \`\${}\`），`
    + '拼接出来的那一段是数据流问题，本工具不猜。',
    'URL 一律**去掉 query 与 fragment** 再输出（打包产物里的 query 常带 token / 签名）；'
    + `本次有 ${hits.queryStripped} 处命中带 query 或 fragment，那一段没有被复制进输出。`,
    `只有字符串字面量会被看：正则字面量里的 URL、注释里的 URL、运行时拼出来的 URL 都不算`
    + '（注释里的样例 URL 被**故意**排除：它们是文档，不是边界）。',
    `本次扫了 ${coverage.scanned} 个文件（${coverage.bytes.scanned} 字节），`
    + `跳过 ${coverage.skipped.total} 个（${
      Object.entries(coverage.skipped.reasons).filter(([, count]) => count > 0).map(([reason, count]) => `${reason} ${count}`).join(' / ') || '无'
    }）—— 跳过的文件在 coverage.skipped.files 里逐条点名。`,
    coverage.skipped.reasons.tooLarge > 0 || coverage.skipped.reasons.budget > 0
      ? '**跳过的文件是被整份跳过的**（不读半份再算扫过）：单文件上限与总预算见 coverage.limits；'
        + '要提高覆盖就把它们切开、或分几次调用（例如按目录分批）。'
      : '没有文件因为大小或预算被跳过。',
    scope === 'app'
      ? `默认 scope=app：路径里含 \`node_modules/\` 的文件不进扫描（本次 ${coverage.skipped.reasons.nodeModules} 个，`
        + '这是**策略性排除**、不逐条列文件，但数字一定报出来），所以"依赖里的外联"不在本次结果里；'
        + '要连依赖一起扫请显式给 scope=all。'
      : 'scope=all：依赖（node_modules）也在扫描面里，第三方库的外联会与本体代码混在一起。',
    mode === 'tree' && coverage.bytes.candidate === null
      ? '树模式下 bytes.candidate 是 null：候选文件的字节数要逐个 stat 才知道，本工具不为报一个总数去多跑 N 条命令（bytes.scanned 是真值）。'
      : '',
    mode === 'asar'
      ? '扫描对象是 asar 里的**打包**成员（`unpacked: true` 的成员内容在 `.asar.unpacked/` 里，本次没有读）。'
      : '扫描对象是盘上的解包 JS 树。',
    `每条命中最多带 ${MAX_SITES_PER_ROW} 个位置（sites），\`occurrences\` 是真实命中次数。`,
    filesWithHits.length === 0 ? '本次没有任何命中 —— 这是"在扫到的这些文件里没有"，不是"这个产物没有边界"。' : '',
  ]
  if (truncated) lines.push(`输出被 top=${top} 截断：看每一段的 bounds（shown/total/omitted），这不是全量。`)
  return lines.filter(line => line !== '')
}

// ── 工具面 ──────────────────────────────────────────────────────────────────

export function apply(ctx) {
  const shell = ctx.shell

  // ── artifact_asar_inventory ───────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'artifact_asar_inventory',
    description: 'Inventory an ASAR archive (Electron app bundle): header layout, entry counts and sizes, the package.json main entry, key members (*.node, package.json, the main target) and a whole-archive sha256. Reads the header only — nothing is extracted or executed.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path to the .asar file' },
      top: { type: 'number', description: 'max rows per list, default 50; anything omitted is counted under bounds' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const path = safePath(typeof args.path === 'string' ? args.path.trim() : '')
      if (path === '') throw new Error('artifact_asar_inventory 需要 path（.asar 的路径）')
      const top = readTop(args.top, 'artifact_asar_inventory')

      const archive = await readAsar(shell, exec, path)
      const digest = await fileSha256(shell, exec, path, 'ASAR')
      const { files, directories } = asarMembers(archive.header)

      const rootPackageJson = files.find(member => member.path === 'package.json')
      let declaredName = null
      let declaredVersion = null
      let declaredMain = null
      let rootPackageJsonError = null
      if (rootPackageJson === undefined) {
        rootPackageJsonError = '根目录没有 package.json 成员'
      } else if (rootPackageJson.unpacked || rootPackageJson.offset === null) {
        rootPackageJsonError = '根的 package.json 是 unpacked 成员，内容不在档里（本工具不读 .asar.unpacked/）'
      } else {
        const size = Math.min(rootPackageJson.size, JS_MAX_FILE_BYTES)
        if (rootPackageJson.size > JS_MAX_FILE_BYTES) {
          rootPackageJsonError = `根的 package.json 有 ${rootPackageJson.size} 字节，超过 ${JS_MAX_FILE_BYTES} 字节的读取上限`
        } else {
          const bytes = await readRange(shell, exec, path, archive.contentBase + rootPackageJson.offset, size)
          try {
            const parsed = JSON.parse(bytes.toString('utf8'))
            declaredName = typeof parsed.name === 'string' ? parsed.name : null
            declaredVersion = typeof parsed.version === 'string' ? parsed.version : null
            declaredMain = typeof parsed.main === 'string' ? parsed.main : null
          } catch (error) {
            rootPackageJsonError = `根的 package.json 解析失败：${error.message}`
          }
        }
      }

      const mainPath = declaredMain === null ? null : normalizeMemberPath(declaredMain)
      const mainMember = mainPath === null ? undefined : files.find(member => member.path === mainPath)

      const nativeAddons = files.filter(member => extensionOf(member.path) === '.node')
      const nativeLibs = files.filter(member => ['.dylib', '.so', '.dll'].includes(extensionOf(member.path)))
      const packageJson = files.filter(member => member.path.endsWith('package.json'))

      const packed = files.filter(member => !member.unpacked && member.offset !== null)
      const unpacked = files.filter(member => member.unpacked || member.offset === null)
      const offsets = new Map()
      for (const member of packed) {
        const key = `${member.offset}:${member.size}`
        offsets.set(key, (offsets.get(key) ?? 0) + 1)
      }
      const sharedEntries = [...offsets.values()].filter(count => count > 1).reduce((total, count) => total + count, 0)
      const maxEnd = packed.reduce((end, member) => Math.max(end, member.offset + member.size), 0)
      const declaredTotal = files.reduce((total, member) => total + member.size, 0)

      const membersBounds = bound(files, top)
      const nativeAddonsBounds = bound(nativeAddons, top)
      const nativeLibsBounds = bound(nativeLibs, top)
      const packageJsonBounds = bound(packageJson, top)
      const mainBounds = bound(mainMember === undefined ? [] : [mainMember], top)

      const result = {
        tool: 'artifact_asar_inventory',
        target: path,
        operation: 'read an ASAR header and inventory its members (no extraction, no execution)',
        file: { path, bytes: archive.bytes, sha256: digest.sha256, sha256Method: digest.method },
        format: archive.format,
        entry: {
          name: declaredName,
          version: declaredVersion,
          main: declaredMain,
          path: mainPath,
          found: mainMember !== undefined,
          member: mainMember === undefined ? null : { path: mainMember.path, size: mainMember.size, offset: mainMember.offset },
          error: rootPackageJsonError,
        },
        members: {
          files: files.length,
          directories: directories.length,
          unpacked: unpacked.length,
          nativeAddons: nativeAddons.length,
          packageJson: packageJson.length,
          shown: membersBounds.rows.map(member => ({
            path: member.path,
            size: member.size,
            offset: member.offset,
            ...(member.unpacked ? { unpacked: true } : {}),
            ...(member.executable ? { executable: true } : {}),
          })),
        },
        keyMembers: {
          nativeAddons: nativeAddonsBounds.rows.map(member => member.path),
          nativeLibs: nativeLibsBounds.rows.map(member => member.path),
          packageJson: packageJsonBounds.rows.map(member => member.path),
          main: mainBounds.rows.map(member => member.path),
        },
        bytes: {
          file: archive.bytes,
          declaredTotal,
          packed: packed.reduce((total, member) => total + member.size, 0),
          unpacked: unpacked.reduce((total, member) => total + member.size, 0),
          contentBase: archive.contentBase,
          contentEnd: archive.contentBase + maxEnd,
          unaccounted: archive.bytes - (archive.contentBase + maxEnd),
          sharedOffsetEntries: sharedEntries,
        },
        top,
        bounds: {
          members: membersBounds.bounds,
          nativeAddons: nativeAddonsBounds.bounds,
          nativeLibs: nativeLibsBounds.bounds,
          packageJson: packageJsonBounds.bounds,
          main: mainBounds.bounds,
        },
        confidence: 'observed',
      }
      result.truncated = Object.values(result.bounds).some(entryBounds => entryBounds.omitted > 0)
      result.limitations = asarLimitations({
        file: result.file,
        format: archive.format,
        members: result.members,
        entry: result.entry,
        top,
        truncated: result.truncated,
        sharedOffsetEntries: sharedEntries,
      })
      return JSON.stringify(result, null, 2)
    },
  }))

  // ── artifact_js_boundaries ────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'artifact_js_boundaries',
    description: 'Scan a JS tree or the JS members of an asar for literal network endpoints (fetch, XHR, WebSocket, URL literals) and Electron IPC channel names, each with file:line; reports how many files were scanned and which were skipped, and why. Literal-level only — no data flow.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path to an .asar file OR to an unpacked JS directory' },
      top: { type: 'number', description: 'max rows per list, default 50; anything omitted is counted under bounds' },
      scope: { type: 'string', description: 'app (default: skip node_modules/) | all' },
    },
    output: stringOutput,
    async execute(args, exec) {
      const path = safePath(typeof args.path === 'string' ? args.path.trim() : '')
      if (path === '') throw new Error('artifact_js_boundaries 需要 path（.asar 的路径，或解包后的 JS 目录）')
      const top = readTop(args.top, 'artifact_js_boundaries')
      const scope = args.scope === undefined ? 'app' : args.scope
      if (scope !== 'app' && scope !== 'all') throw new Error(`artifact_js_boundaries 的 scope 只能是 app / all：给了 ${JSON.stringify(args.scope)}`)

      const probe = await runCmd(shell, ['find', path, '-maxdepth', '0', '-type', 'd'], exec, { timeoutMs: 15_000 })
      if (probe.exitCode !== 0) {
        throw new Error(`${path} 不存在或读不到：${lastLine(probe.stderr) ?? `exit ${probe.exitCode}`}`)
      }
      const isDirectory = probe.stdout.trim() !== ''

      let mode
      let archive = null
      let memberIndex = new Map()
      let list = []
      let nonJs = 0
      let unpackedJs = 0
      let candidateBytes = null
      if (isDirectory) {
        mode = 'tree'
        const listing = await runCmd(shell, ['find', path, '-type', 'f'], exec, { timeoutMs: 120_000, stdoutMaxBytes: 16 * 1024 * 1024 })
        if (listing.exitCode !== 0) requireOk(listing, `find ${path} -type f`)
        list = listing.stdout.split('\n').map(line => line.trim()).filter(line => line !== '').sort()
        const candidates = list.filter(file => JS_EXTENSIONS.includes(extensionOf(file)))
        nonJs = list.length - candidates.length
        list = candidates
      } else {
        mode = 'asar'
        try {
          archive = await readAsar(shell, exec, path)
        } catch (error) {
          throw new Error(`${path} 既不是一个目录，也不像一个 ASAR：${error.message}`)
        }
        const { files } = asarMembers(archive.header)
        memberIndex = new Map(files.map(member => [member.path, member]))
        const js = files.filter(member => JS_EXTENSIONS.includes(extensionOf(member.path)))
        nonJs = files.length - js.length
        const scanable = js.filter(member => !member.unpacked && member.offset !== null)
        unpackedJs = js.length - scanable.length
        list = scanable.map(member => member.path).sort()
      }

      const dependency = file => file.includes('/node_modules/') || file.startsWith('node_modules/')
      const inScope = scope === 'all' ? list : list.filter(file => !dependency(file))
      if (mode === 'asar') candidateBytes = inScope.reduce((total, file) => total + (memberIndex.get(file)?.size ?? 0), 0)
      const skipped = { tooLarge: [], budget: [], unreadable: [], nodeModules: scope === 'all' ? [] : list.filter(dependency) }
      const hits = createHitTable()
      let scanned = 0
      let scannedBytes = 0
      const rootPrefix = path.endsWith('/') ? path : `${path}/`
      // 命中与"跳过的文件"用**同一套标签**：asar 模式是成员相对路径，树模式是相对根目录的路径。
      // 两种标签混着用会让"这条命中出自哪个文件"和"跳过了哪个文件"对不上号。
      const labelOf = file => (mode === 'asar' ? file : (file.startsWith(rootPrefix) ? file.slice(rootPrefix.length) : file))

      for (const file of inScope) {
        if (scanned >= JS_MAX_FILES) {
          skipped.budget.push({ file: labelOf(file), reason: 'fileCountLimit', bytes: null, detail: `超过文件数上限 ${JS_MAX_FILES}` })
          continue
        }
        let bytes
        if (mode === 'asar') {
          const member = memberIndex.get(file)
          if (member.size > JS_MAX_FILE_BYTES) {
            skipped.tooLarge.push({ file: labelOf(file), reason: 'tooLarge', bytes: member.size })
            continue
          }
          if (scannedBytes + member.size > JS_MAX_TOTAL_BYTES) {
            skipped.budget.push({ file: labelOf(file), reason: 'totalBudget', bytes: member.size, detail: `已读 ${scannedBytes} 字节，再加它超过总预算 ${JS_MAX_TOTAL_BYTES}` })
            continue
          }
          const read = await readRange(shell, exec, path, archive.contentBase + member.offset, member.size)
          bytes = read
        } else {
          let read
          try {
            read = await readSmallFile(shell, exec, file, 'JS 文件', JS_MAX_FILE_BYTES)
          } catch (error) {
            skipped.unreadable.push({ file: labelOf(file), reason: 'unreadable', bytes: null, detail: `${error.name}: ${error.message}`.slice(0, 200) })
            continue
          }
          if (read.tooLarge) {
            skipped.tooLarge.push({ file: labelOf(file), reason: 'tooLarge', bytes: read.size })
            continue
          }
          if (scannedBytes + read.bytes.length > JS_MAX_TOTAL_BYTES) {
            skipped.budget.push({ file: labelOf(file), reason: 'totalBudget', bytes: read.size, detail: `已读 ${scannedBytes} 字节，再加它超过总预算 ${JS_MAX_TOTAL_BYTES}` })
            continue
          }
          bytes = read.bytes
        }
        scanned += 1
        scannedBytes += bytes.length
        scanText(bytes.toString('utf8'), labelOf(file), hits.collect)
      }

      const collected = hits.result()
      const endpoints = bound(collected.endpoints, top)
      const channels = bound(collected.channels, top)
      const filesWithHits = bound(collected.filesWithHits, top)
      const skippedFiles = bound([...skipped.tooLarge, ...skipped.budget, ...skipped.unreadable], top)
      const reasons = {
        tooLarge: skipped.tooLarge.length,
        budget: skipped.budget.length,
        unreadable: skipped.unreadable.length,
        nodeModules: skipped.nodeModules.length,
      }
      const skippedTotal = reasons.tooLarge + reasons.budget + reasons.unreadable + reasons.nodeModules
      const coverage = {
        mode,
        scope,
        candidates: list.length,
        inScope: inScope.length,
        scanned,
        nonJsFiles: nonJs,
        ...(mode === 'asar' ? { unpackedJsSkipped: unpackedJs } : {}),
        bytes: { scanned: scannedBytes, candidate: candidateBytes },
        skipped: { total: skippedTotal, reasons, files: skippedFiles.rows },
        limits: { maxFileBytes: JS_MAX_FILE_BYTES, maxTotalBytes: JS_MAX_TOTAL_BYTES, maxFiles: JS_MAX_FILES },
        filesWithHits: filesWithHits.rows,
        summary: `扫了 ${scanned} 个 JS 文件（${scannedBytes} 字节），跳过 ${skippedTotal} 个（${
          Object.entries(reasons).filter(([, count]) => count > 0).map(([reason, count]) => `${reason} ${count}`).join(' / ') || '无'
        }）；候选 ${list.length} 个${nonJs > 0 ? `，另有 ${nonJs} 个非 JS 文件不在扫描面` : ''}`,
        complete: skippedTotal === 0 && scanned === inScope.length,
      }

      const result = {
        tool: 'artifact_js_boundaries',
        target: path,
        operation: 'scan a JS tree (or the JS members of an ASAR) for literal network endpoints and Electron IPC channels',
        mode,
        asar: archive === null ? null : archive.format,
        coverage,
        endpoints: endpoints.rows,
        channels: channels.rows,
        hits: { total: collected.sites, rows: collected.rows.length, endpoints: collected.endpoints.length, channels: collected.channels.length },
        top,
        bounds: {
          endpoints: endpoints.bounds,
          channels: channels.bounds,
          skippedFiles: skippedFiles.bounds,
          filesWithHits: filesWithHits.bounds,
        },
        confidence: 'observed',
      }
      result.truncated = Object.values(result.bounds).some(entryBounds => entryBounds.omitted > 0)
      result.limitations = jsLimitations({
        mode,
        coverage,
        scope,
        top,
        truncated: result.truncated,
        hits: collected,
        filesWithHits: collected.filesWithHits,
      })
      return JSON.stringify(result, null, 2)
    },
  }))
}
