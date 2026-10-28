import os from 'node:os'
import { join } from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'

import {
  blockOf,
  collapseNeighbors,
  filterListenerLines,
  parseIwDev,
  parseIwLink,
  parseIwPhyChannels,
  parseIwReg,
  parseIwScanNeighbors,
  parseLinkSample,
  parseNmcliNeighbors,
  parsePingStats,
  parseProcNetWireless,
  parseSpeedSample,
  parseWifiReport,
  pingArgv as pingArgvForPlatform,
  portableMtimeCommand,
  summarizeChannels,
} from './wifi.js'

/** fly-diag — local host diagnostics for the Diagnostics view / agent. */
export const name = 'fly-diag'
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
 *
 * **失败面的口径是"大声"**（Q5）：这一包全是**活读数**，"没量到"绝不能读成"没有" ——
 *   · 缺 `ps` / `lsof` / `netstat` / `ping` 时各自走已登记的路径：能换方法的换（`lsof` 不通换
 *     `netstat`，并在结果里说清"netstat 的表更粗、没有进程名/PID"），换不了就 `requireOk` 抛错；
 *   · "成功却没输出"是一等状态：`diag_procs` 会明说"ps 成功却没有任何输出 ⇒ 这张表是被读空的"；
 *   · `diag_net_watch` 读到**半个样本**就跳过并**报出跳过数**（静默丢数据比丢数据更糟），
 *     停止是**异步**的（写完信号文件就返回），这些都在各支的 `limitations` 里。
 */
/**
 * 路径参数规范化：以 `-` 开头的路径加 `./` 前缀（2026-10-14）。
 *
 * 与六个安全包里的同名助手同源（§5.4.1/§5.4.3）：不插 `--`（本机 objdump/base64/otool 不支持），
 * 而是把它变成一个普通相对路径。这里用于 `diag_net_watch` 的 `dir` —— 同一族的**无伤**版本
 * （裸 `-o/tmp/x` 进 `mkdir` 只会响亮报错），本笔是**一致性收尾**，不是安全修复。
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
 * A probe the sandbox blocks (`ps` under a restrictive policy) or a command the
 * host lacks must surface as an error, never as an empty table — the sibling
 * `dsh-plugin-fly-diagnostics` workbench already asserts the same rule.
 */
function requireOk(run, what) {
  if (run.exitCode === 0) return run.stdout
  // 沙箱拒绝的形状是**结果正文里的标记**（`[sandbox: file access denied under <mode> mode]`，
  // 抄自 @deepseek-ai/dsh-sandbox/index.js:65）—— 它落在 stdout 上；只读 stderr 就会把它丢掉，
  // 于是模型读到的是「命令失败」，而不是「你没有被授权」。所以标记必须原样带进错误文案。
  const sandboxMark = /^\[sandbox: .*\]$/mu.exec(run.stdout)
  const detail = [sandboxMark?.[0], ...run.stderr.trim().split('\n').map(line => line.trim()).filter(Boolean)].slice(0, 3).join(' | ')
  const notInstalled = run.exitCode === 127 || /command not found/iu.test(run.stderr)
  const missing = notInstalled ? ' — the command is not installed on this host' : ''
  // 失败文案要对**读它的模型**可行动（Q6）：不是裸 stderr，但也不许臆断原因 ——
  // 只给「这条 exit 属于哪一类」与「下一步可以试什么」，具体判断仍留给读的人。
  const next = notInstalled
    ? 'next: this host lacks that command — look for a built-in fallback in this package, or read the file another way'
    : 'next: check the path, and that the file is what this tool expects (bin_file shows what it is); the line above is the command own reason'
  const error = new Error(`${what} failed (exit ${run.exitCode})${missing}: ${run.command}${detail === '' ? '' : `\n${detail}\n${next}`}`)
  error.name = 'CommandError'
  throw error
}

// ── 网络 / 无线排障面 ────────────────────────────────────────────────────────
//
// 这一组把「到底是哪一层慢」变成可测量的量：链路层（信道/带宽/协商速率/MCS）、
// 空口与局域网层（网关 RTT 与抖动）、外网层（WAN RTT）。判据是**抖动与结构性变化**，
// 不是任何一次测速的绝对值 —— 一次 611 Mbps 不能证明「间歇性变慢」消失了，只有
// 记录仪里那段时间的链路和 RTT 才能。全部解析走 `wifi.js` 的纯函数（夹具门在
// `scripts/tests/wifi-report.spec.mjs`），这个文件只负责采集与编排。

/** `system_profiler SPAirPortDataType`：darwin-only，是本机链路唯一的只读来源。 */
const AIRPORT_ARGV = ['system_profiler', 'SPAirPortDataType']

/**
 * 默认吞吐目标：国内 CDN 上一个稳定的大文件，可用 `url` 覆盖。
 *
 * 「默认跑满」是用户的裁决（一次调用就看清上限），代价是每次调用都在真实链路上
 * 产生流量 —— 所以结果里必定回传 `totalBytes`，让 agent 和人都知道这次花了多少。
 * 门禁不碰外网：它把 `url` 指向自己起的 127.0.0.1 服务。
 */
const DEFAULT_SPEED_URL = process.platform === 'darwin'
  ? 'https://registry.npmmirror.com/-/binary/node/v20.11.0/node-v20.11.0-darwin-arm64.tar.gz'
  : 'https://registry.npmmirror.com/-/binary/node/v20.11.0/node-v20.11.0-linux-x64.tar.gz'

/** 只允许这两种 scheme 进 curl。`file:` 会把本地文件读了回显进工具结果。 */
const ALLOWED_SCHEMES = ['http:', 'https:']

/** 记录仪默认落点。绝不写 `~/.dsh`（用户配置区）。 */
const WATCH_DIR = join(os.homedir(), '.dsh-fly', 'netdiag')

/**
 * 校验 agent 给的 URL 之后再交给 curl。
 *
 * `runCmd` 对每个 argv 元素做 shell 引号，元字符逃不出去；但 `curl file:///etc/passwd`
 * 是一个**完全合法**的参数，会把本地文件读出来回显。挡住它的是 scheme 白名单 ——
 * 分类不了的 URL 一律拒绝，不猜。
 */
function requireHttpUrl(value, fallback) {
  const text = String(value ?? '').trim()
  let parsed
  try {
    parsed = new URL(text === '' ? fallback : text)
  } catch {
    const error = new Error(`不是合法的 URL：${text}`)
    error.name = 'ArgumentError'
    throw error
  }
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    const error = new Error(`拒绝 ${parsed.protocol} 目标：只允许 http/https（file: 会读本地文件）`)
    error.name = 'ArgumentError'
    throw error
  }
  return parsed.href
}

/**
 * 校验主机目标。
 *
 * 要挡的不是 shell 元字符（`runCmd` 已经引号了），而是**开头的 `-`**：`-f` 会被
 * `ping` 当成 flood 参数，一个 agent 传进来的字符串就成了压测指令。所以只接受主机名
 * 或 IP 的字符集，且首字符必须是字母数字。
 */
function requireHost(value, fallback) {
  const text = String(value ?? '').trim()
  const host = text === '' ? fallback : text
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u.test(host)) {
    // 理由要写**实际**的原因：这条只可能因为"含空格 / shell 元字符 / 开头是 -"被拒，
    // 而只提 "-" 的文案会让输入 `192.168.1.1; foo` 的人看不懂自己错在哪。
    const error = new Error(
      `拒绝目标 ${JSON.stringify(host)}：只接受主机名或 IP 字面量 ——`
      + ' 不许有空格或 shell 元字符（; | & $ ` 引号 括号），也不许以 "-" 开头（会被当成命令参数，如 ping -f 是 flood）。',
    )
    error.name = 'ArgumentError'
    throw error
  }
  return host
}

/** 夹取整数参数。 */
function clampInteger(value, fallback, min, max) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(parsed)))
}

/**
 * `ping -q` 一条。参数按平台分派：macOS 的 `-W` 是毫秒、`-t` 是整轮秒数；
 * Linux 的 `-W` 是秒、`-w` 是整轮秒数，`-t` 是 TTL（详见 wifi.js 的 `pingArgv`）。
 */
function pingArgv(host, count) {
  return pingArgvForPlatform(process.platform, host, count)
}

/** 读本机默认网关；取不到返回空串（调用方才回退到 192.168.1.1）。 */
async function defaultGateway(shell, exec) {
  const command = process.platform === 'darwin'
    ? "route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'"
    : "ip route show default 2>/dev/null | awk '/default via/{print $3; exit}'"
  const run = await runCmd(shell, ['sh', '-c', command], exec, { timeoutMs: 15_000 })
  return run.exitCode === 0 ? run.stdout.trim().split('\n')[0].trim() : ''
}

/** 把 ping 统计拼成一行。无回应时明说「无回应」，绝不写成 0ms。 */
function pingLine(label, stats) {
  if (stats.avgMs === null) {
    return `${label}: 全程无回应（发出 ${stats.transmitted ?? '?'}，收到 ${stats.received ?? 0}，丢包 ${stats.lossPercent ?? '?'}%）`
  }
  return `${label}: avg ${stats.avgMs}ms  max ${stats.maxMs}ms  抖动 ${stats.stddevMs}ms  丢包 ${stats.lossPercent}%`
}

/** 把 epoch 秒渲染成本地时刻。 */
function stampOf(epoch) {
  return new Date(epoch * 1000).toLocaleString('sv-SE')
}

/** 记录仪的三个路径。 */
function watchPaths(dir) {
  const base = String(dir ?? '').trim() === '' ? WATCH_DIR : String(dir).trim()
  return { dir: base, log: join(base, 'samples.log'), stop: join(base, 'stop'), pid: join(base, 'sampler.pid') }
}

/**
 * 切分记录仪的样本日志。
 *
 * 存的是**原始输出**而不是解析后的数字：`report` 因此用同一套纯函数解析（不存在一份
 * shell 侧、一份 JS 侧的重复解析），而且现场证据原样留着可以复核。
 */
function parseSampleLog(text) {
  const samples = []
  const marks = []
  let current = null
  let section = null
  for (const line of String(text ?? '').split('\n')) {
    const sample = /^@@SAMPLE (\d+)\s*$/u.exec(line)
    if (sample !== null) {
      current = { epoch: Number(sample[1]), complete: false, link: [], gw: [], wan: [] }
      samples.push(current)
      section = null
      continue
    }
    const mark = /^@@MARK (\d+)\s*(.*)$/u.exec(line)
    if (mark !== null) {
      marks.push({ epoch: Number(mark[1]), message: mark[2] })
      continue
    }
    if (line === '@@LINK') { section = 'link'; continue }
    if (line === '@@GW') { section = 'gw'; continue }
    if (line === '@@WAN') { section = 'wan'; continue }
    if (line === '@@END') {
      if (current !== null) current.complete = true
      section = null
      continue
    }
    if (current === null || section === null) continue
    current[section].push(line)
  }
  return { samples, marks }
}

/** 只统计有真实测量的值：`null` 不能当 0 混进均值。 */
function numericSummary(values) {
  const known = values.filter(value => typeof value === 'number' && Number.isFinite(value)).sort((a, b) => a - b)
  if (known.length === 0) return { count: 0, min: null, median: null, max: null }
  return {
    count: known.length,
    min: known[0],
    median: known[Math.floor(known.length / 2)],
    max: known[known.length - 1],
  }
}

/** 把样本日志解析成对齐后的一张表。 */
function readWatch(logText) {
  const { samples, marks } = parseSampleLog(logText)
  // 只有走到 `@@END` 的样本才算一个样本。
  //
  // 记录仪是**边跑边写**的，所以文件末尾任何时刻都可能有一个只写了一半的样本（`mark`
  // 也是往同一个文件追加一行，能落在样本中间）。半个样本不是证据：把它当数据用，
  // 「ping 还没写完」会被渲染成「无回应」—— 一个凭空的故障结论。丢掉，并且**说出丢了多少**，
  // 否则就成了静默的丢数据。
  const complete = samples.filter(sample => sample.complete)
  const rows = complete.map(sample => ({
    epoch: sample.epoch,
    link: parseLinkSample(sample.link.join('\n')),
    gw: parsePingStats(sample.gw.join('\n')),
    wan: parsePingStats(sample.wan.join('\n')),
  }))
  return { rows, marks, skipped: samples.length - complete.length }
}

/**
 * 一次采样的 shell 片段，原样追加到日志。
 *
 * 长驻记录仪与一次性采样共用它 —— 两条路写出的格式必须逐字节同形，否则 `report`
 * 只能解析其中一种。
 */
function sampleSnippet(paths, { count, gateway, wan, indent = '', withLink = true }) {
  const body = [`${indent}{`, `${indent}  echo "@@SAMPLE $(date +%s)"`]
  if (withLink) {
    const linkCommand = process.platform === 'darwin'
      ? `${shq(AIRPORT_ARGV[0])} ${shq(AIRPORT_ARGV[1])} 2>/dev/null | sed -n '/Current Network Information:/,/Other Local Wi-Fi Networks:/p'`
      : process.platform === 'linux'
        // `iw dev` 列出接口，逐个 `iw dev <if> link`；一条命令同时覆盖多网卡。
        ? `for i in $(iw dev 2>/dev/null | awk '/^[[:space:]]*Interface /{print $2}'); do iw dev "$i" link 2>/dev/null; done`
        : 'true'
    body.push(
      `${indent}  echo "@@LINK"`,
      `${indent}  ${linkCommand}`,
    )
  }
  body.push(
    `${indent}  echo "@@GW"`,
    `${indent}  ${pingArgv(gateway, count).map(shq).join(' ')}`,
    `${indent}  echo "@@WAN"`,
    `${indent}  ${pingArgv(wan, count).map(shq).join(' ')}`,
    `${indent}  echo "@@END"`,
    `${indent}} >> ${shq(paths.log)}`,
  )
  return body.join('\n')
}

/**
 * 记录仪的长驻脚本。
 *
 * 整段跑在**一个**长驻 `sh` 里（不是每次采样起一个进程），并且走 `ctx.shell` 接缝 ——
 * 这五个安全插件被门禁钉着不许绕过接缝直接开子进程，而包资产要动 `files` 与打包断言，
 * 一条一次性 shell 循环把两者都避开。链路采样每 `linkEvery` 次取一次：`system_profiler`
 * 要 1–2 秒，每次采样都跑它会在「几天」这个尺度上白烧 CPU。
 */
function samplerScript(paths, { interval, count, gateway, wan, linkEvery }) {
  return [
    `mkdir -p ${shq(paths.dir)}`,
    `rm -f ${shq(paths.stop)}`,
    `echo $$ > ${shq(paths.pid)}`,
    'i=0',
    `while [ ! -f ${shq(paths.stop)} ]; do`,
    '  i=$((i+1))',
    `  if [ $((i % ${linkEvery})) -eq 1 ]; then`,
    sampleSnippet(paths, { count, gateway, wan, indent: '  ' }),
    '  else',
    sampleSnippet(paths, { count, gateway, wan, indent: '  ', withLink: false }),
    '  fi',
    `  sleep ${interval}`,
    'done',
  ].join('\n')
}

/**
 * Linux 的当前链路：`iw dev <if> link` + `iw reg get` + `/proc/net/wireless` 底噪。
 *
 * 没有 `iw`（Ubuntu 需要 `sudo apt install iw`）或没有无线接口时返回 `available:false`
 * 并给出**可行动的**原因；绝不把「量不到」说成「链路正常」。
 */
async function collectLinkLinux(shell, signal) {
  const dev = await runCmd(shell, ['iw', 'dev'], { signal }, { timeoutMs: 15_000 })
  if (dev.exitCode !== 0) {
    return {
      available: false,
      platform: 'linux',
      backend: 'iw',
      error: `iw dev 失败（exit ${dev.exitCode}）：${dev.stderr.trim().split('\n')[0] ?? 'iw 不在本机'} —— Ubuntu 上先装 iw（sudo apt install iw）。`,
    }
  }
  const interfaces = parseIwDev(dev.stdout)
  if (interfaces.length === 0) {
    return {
      available: false,
      platform: 'linux',
      backend: 'iw',
      interfaces: [],
      error: 'iw dev 没有列出任何无线接口：本机没有 Wi-Fi 硬件/驱动，或全部被 rfkill 关掉。这不是「链路正常」，是没有数据。',
    }
  }
  const iface = interfaces[0].name
  const link = await runCmd(shell, ['iw', 'dev', iface, 'link'], { signal }, { timeoutMs: 15_000 })
  if (link.exitCode !== 0) {
    return {
      available: false,
      platform: 'linux',
      backend: 'iw',
      interface: iface,
      error: `iw dev ${iface} link 失败（exit ${link.exitCode}）：${link.stderr.trim().split('\n')[0] ?? ''}`,
    }
  }
  const wireless = await runCmd(shell, ['cat', '/proc/net/wireless'], { signal }, { timeoutMs: 15_000 })
  const noiseDbm = wireless.exitCode === 0 ? parseProcNetWireless(wireless.stdout, iface) : null
  const parsed = parseIwLink(link.stdout, { noiseDbm })
  if (parsed === null) {
    return {
      available: false,
      platform: 'linux',
      backend: 'iw',
      interface: iface,
      error: `接口 ${iface} 存在，但当前没有关联（iw dev ${iface} link 没有 Connected to）。这是「没连上」，不是「链路正常」。`,
    }
  }
  const reg = await runCmd(shell, ['iw', 'reg', 'get'], { signal }, { timeoutMs: 15_000 })
  return {
    available: true,
    platform: 'linux',
    backend: 'iw',
    source: `iw dev ${iface} link`,
    interface: iface,
    countryCode: reg.exitCode === 0 ? parseIwReg(reg.stdout) : null,
    phy: parsed.phy,
    channel: parsed.channel,
    band: parsed.band,
    widthMhz: parsed.widthMhz,
    rssiDbm: parsed.rssiDbm,
    noiseDbm: parsed.noiseDbm,
    snrDb: parsed.snrDb,
    transmitRateMbps: parsed.transmitRateMbps,
    mcs: parsed.mcs,
    ssid: parsed.ssid,
    bssid: parsed.bssid,
    note: 'transmitRateMbps 来自 iw 的 tx bitrate（上行）；noiseDbm 来自 /proc/net/wireless，驱动不报时为 null；rssiDbm / snrDb 为 null 表示没有测量结果，不是 0。',
  }
}

/** 采集本机链路。失败或没有 Wi-Fi 时返回 `available:false`，从不抛异常给面板。 */
async function collectLink(shell, signal) {
  if (process.platform === 'linux') return collectLinkLinux(shell, signal)
  if (process.platform !== 'darwin') {
    return {
      available: false,
      platform: process.platform,
      error: `本包只实现了 macOS 与 Linux 的 Wi-Fi 链路读取（当前平台 ${process.platform}）：没有数据，不是链路正常。`,
    }
  }
  const run = await runCmd(shell, AIRPORT_ARGV, { signal }, { timeoutMs: 30000, stdoutMaxBytes: 4194304 })
  if (run.exitCode !== 0) {
    return { available: false, error: `system_profiler 失败（exit ${run.exitCode}）：${run.stderr.trim().split('\n')[0] ?? ''}` }
  }
  const report = parseWifiReport(run.stdout)
  const iface = report.interfaces.find(candidate => candidate.current !== null) ?? null
  if (iface === null) {
    return {
      available: false,
      interfaces: report.interfaces.map(candidate => candidate.name),
      error: '系统报告里没有「当前网络」：本机没有关联的 Wi-Fi。这不是「链路正常」，是没有数据。',
    }
  }
  const link = iface.current
  return {
    available: true,
    interface: iface.name,
    countryCode: iface.countryCode,
    phy: link.phy,
    channel: link.channel,
    band: link.band,
    widthMhz: link.widthMhz,
    rssiDbm: link.rssiDbm,
    noiseDbm: link.noiseDbm,
    snrDb: link.snrDb,
    transmitRateMbps: link.transmitRateMbps,
    mcs: link.mcs,
    note: 'transmitRateMbps 是上行（本机发给 AP）；macOS 不提供下行速率。rssiDbm / noiseDbm / snrDb 为 null 表示没有测量结果，不是 0。',
  }
}

/**
 * Linux 的信道占用：`iw phy <phy> info` 给监管允许的信道，
 * `iw dev <if> scan dump`（有缓存时）或 `nmcli … wifi list --rescan no` 给邻居。
 *
 * 两条路都只读**已有**缓存，不触发扫描。nmcli 不报带宽 ⇒ `widthMhz:null`，
 * 输出里必须说清「未知带宽」而不是当成 20MHz。
 */
async function collectChannelsLinux(shell, { rounds = 3, signal } = {}) {
  const dev = await runCmd(shell, ['iw', 'dev'], { signal }, { timeoutMs: 15_000 })
  if (dev.exitCode !== 0) {
    return { available: false, platform: 'linux', error: `iw dev 失败（exit ${dev.exitCode}）：${dev.stderr.trim().split('\n')[0] ?? 'iw 不在本机'} —— 先装 iw（sudo apt install iw）。` }
  }
  const interfaces = parseIwDev(dev.stdout)
  if (interfaces.length === 0) {
    return { available: false, platform: 'linux', interfaces: [], error: 'iw dev 没有列出任何无线接口：本机没有 Wi-Fi 硬件/驱动，或全部被 rfkill 关掉。这不是「没有邻居」，是没有数据。' }
  }
  const iface = interfaces[0]
  const phyRun = iface.phy === null
    ? { exitCode: 1, stdout: '' }
    : await runCmd(shell, ['iw', 'phy', iface.phy, 'info'], { signal }, { timeoutMs: 20_000, stdoutMaxBytes: 4194304 })
  const listRun = phyRun.exitCode === 0
    ? phyRun
    : await runCmd(shell, ['iw', 'list'], { signal }, { timeoutMs: 20_000, stdoutMaxBytes: 4194304 })
  const supportedChannels = listRun.exitCode === 0 ? parseIwPhyChannels(listRun.stdout) : []

  // 邻居：先读 iw 的扫描缓存（带宽信息最全），读不到再退回 nmcli。
  let source = null
  let neighbors = []
  const scan = await runCmd(shell, ['iw', 'dev', iface.name, 'scan', 'dump'], { signal }, { timeoutMs: 30_000, stdoutMaxBytes: 8388608 })
  if (scan.exitCode === 0 && /^BSS\s/mu.test(scan.stdout)) {
    source = 'iw scan dump'
    neighbors = parseIwScanNeighbors(scan.stdout)
  } else {
    for (let round = 0; round < Math.max(1, rounds); round += 1) {
      const nmcli = await runCmd(
        shell,
        ['nmcli', '-t', '-f', 'CHAN,FREQ,SIGNAL', 'dev', 'wifi', 'list', '--rescan', 'no'],
        { signal },
        { timeoutMs: 30_000, stdoutMaxBytes: 4194304 },
      )
      if (nmcli.exitCode !== 0) {
        return {
          available: false,
          platform: 'linux',
          interface: iface.name,
          error: `iw scan dump 与 nmcli 都读不到邻居（iw exit ${scan.exitCode}；nmcli exit ${nmcli.exitCode}）。`
            + '这不是「没有邻居」：检查是否装了 iw / NetworkManager，或先用 `iw dev ' + iface.name + ' scan dump` 手工确认权限。',
        }
      }
      source = 'nmcli'
      neighbors.push(...parseNmcliNeighbors(nmcli.stdout))
    }
  }

  const current = source === 'iw scan dump'
    ? parseIwLink((await runCmd(shell, ['iw', 'dev', iface.name, 'link'], { signal }, { timeoutMs: 15_000 })).stdout)
    : null
  const report = {
    interfaces: [{
      name: iface.name,
      status: null,
      countryCode: null,
      phyModes: [],
      supportedChannels,
      current,
      neighbors,
    }],
  }
  const plan = summarizeChannels(report)
  const collapsed = collapseNeighbors(neighbors)
  const widthKnown = source === 'iw scan dump'
  return {
    available: true,
    platform: 'linux',
    backend: source,
    rounds,
    interfaceName: plan.interfaceName,
    permittedChannels: plan.permittedChannels,
    permittedKnown: supportedChannels.some(entry => entry.band === '5GHz'),
    widthKnown,
    blocks: plan.blocks.map(block => ({
      span: block.span,
      primary: block.primary,
      dfs: block.dfs,
      permitted: block.permitted,
      occupied: block.occupied,
      occupants: block.occupants.map(entry => ({
        channel: entry.channel,
        widthMhz: entry.widthMhz,
        bestRssiDbm: entry.bestRssiDbm,
        samples: entry.samples,
      })),
    })),
    width160: plan.width160,
    collapsedNeighbors: collapsed.length,
    note: source === 'nmcli'
      ? 'Linux（nmcli 回退）：只读 NetworkManager 的现有扫描列表；nmcli 不报带宽 ⇒ widthMhz 为 null（未知，不是 20）。监管允许信道读不到时 permittedKnown=false，permitted 字段不能当结论。'
      : 'Linux（iw scan dump）：只读系统已有的扫描缓存；不触发扫描、不发探测请求。占用按主信道折叠，同信道多 AP 会折成一行（占用数偏保守）。',
  }
}

/** 采集信道占用与可用性。只读系统已缓存的扫描结果，不触发扫描、不发探测请求。 */
async function collectChannels(shell, { rounds = 3, signal } = {}) {
  if (process.platform === 'linux') return collectChannelsLinux(shell, { rounds, signal })
  if (process.platform !== 'darwin') {
    return {
      available: false,
      platform: process.platform,
      error: `本包只实现了 macOS 与 Linux 的信道读取（当前平台 ${process.platform}）：没有数据，不是「没有邻居」。`,
    }
  }
  const neighbors = []
  let report = { interfaces: [] }
  for (let round = 0; round < rounds; round += 1) {
    const run = await runCmd(shell, AIRPORT_ARGV, { signal }, { timeoutMs: 30000, stdoutMaxBytes: 4194304 })
    if (run.exitCode !== 0) {
      return { available: false, error: `system_profiler 失败（exit ${run.exitCode}）：${run.stderr.trim().split('\n')[0] ?? ''}` }
    }
    report = parseWifiReport(run.stdout)
    neighbors.push(...report.interfaces.flatMap(candidate => candidate.neighbors))
  }
  // 并集落回第一个接口再交给 summarizeChannels —— 它就是读这个形状的。
  const merged = {
    interfaces: report.interfaces.map((candidate, index) => (index === 0 ? { ...candidate, neighbors } : candidate)),
  }
  const plan = summarizeChannels(merged)
  const collapsed = collapseNeighbors(neighbors)
  return {
    available: collapsed.length > 0 || plan.permittedChannels.length > 0,
    rounds,
    interfaceName: plan.interfaceName,
    permittedChannels: plan.permittedChannels,
    blocks: plan.blocks.map(block => ({
      span: block.span,
      primary: block.primary,
      dfs: block.dfs,
      permitted: block.permitted,
      occupied: block.occupied,
      occupants: block.occupants.map(entry => ({
        channel: entry.channel,
        widthMhz: entry.widthMhz,
        bestRssiDbm: entry.bestRssiDbm,
        samples: entry.samples,
      })),
    })),
    width160: plan.width160,
    collapsedNeighbors: collapsed.length,
    note: '只读系统缓存的扫描结果。BSSID/SSID 被 macOS 抹名，所以「同信道同带宽的多个 AP」会被折成一行，占用数偏保守。bestRssiDbm 为 null 表示没有测量结果，不是 0。',
  }
}

export function apply(ctx) {
  const shell = ctx.shell

  ctx.tools.register(defineTool({
    name: 'diag_host',
    description: 'Collect host identity and load metrics.',
    parameters: {},
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(_args, exec) {
      exec.signal.throwIfAborted()
      const mem = os.totalmem()
      const hostSnapshot = {
          hostname: os.hostname(),
          platform: os.platform(),
          release: os.release(),
          arch: os.arch(),
          cpus: os.cpus().length,
          cpuModel: os.cpus()[0]?.model,
          totalMemGB: +(mem / 1024 ** 3).toFixed(2),
          freeMemGB: +(os.freemem() / 1024 ** 3).toFixed(2),
          loadavg: os.loadavg().map((n) => +n.toFixed(2)),
          uptimeHours: +(os.uptime() / 3600).toFixed(2),
      }
      return JSON.stringify({
        tool: 'diag_host',
        target: 'this host',
        operation: 'read local host identity, CPU and memory counters (read-only, no probing)',
        observed: hostSnapshot,
        confidence: 'observed',
        limitations: [
          '只看得到本机：没有对端/邻居的信息（对端要用 recon_* 或 diag_net_rtt 单独量）',
          '负载与内存是瞬时读数：不说明趋势，也不说明是不是刚刚才变（趋势要用 diag_net_watch 那类记录仪）',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_procs',
    description: 'List top processes by CPU (ps).',
    parameters: {
      limit: { type: 'number', description: 'Max rows (default 15)' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      // 证据形状（规划 §5.1）：两支都产出信封。
      const envelope = (observed, limitations) => JSON.stringify({
        tool: 'diag_procs',
        target: 'this host',
        operation: 'take one ps aux snapshot and return the top rows by %CPU',
        observed,
        confidence: 'observed',
        limitations,
      }, null, 2)
      const limit = Math.max(1, Math.min(50, Number(args.limit) || 15))
      const stdout = requireOk(await runCmd(shell, ['ps', 'aux'], exec, { stdoutMaxBytes: 1048576 }), 'ps aux')
      const lines = stdout.split('\n').filter(Boolean)
      const [header, ...rest] = lines
      if (header === undefined) {
        return envelope({ method: 'ps', rows: 0, dump: 'ps aux produced no output (the command succeeded, which is suspicious)' }, [
          'ps 成功却没有任何输出 ⇒ 这张表是被读空的：**不能**读成「本机没有进程」',
        ])
      }
      const body = rest
        .sort((a, b) => {
          const pa = parseFloat(a.split(/\s+/)[2] || '0')
          const pb = parseFloat(b.split(/\s+/)[2] || '0')
          return pb - pa
        })
        .slice(0, limit)
      return envelope({ method: 'ps', limit, rows: body.length, dump: [header, ...body].join('\n') }, [
        'ps aux 的表格原样返回，本工具只做两件事：按第 3 列（%CPU）降序、取前 limit 行',
        '这是**一次快照**：不说明进程的历史、持续时间或趋势（要趋势得自己隔一段时间再取一次）',
      ])
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_net',
    description: 'Snapshot listening sockets.',
    parameters: {},
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(_args, exec) {
      // 证据形状（规划 §5.1）：三支都产出信封。每条方法（ss / lsof / netstat）与
      // "成功但 0 条"都要说清 —— 「没量到」不能读成「没有」。
      const envelope = (observed, limitations) => JSON.stringify({
        tool: 'diag_net',
        target: 'this host',
        operation: 'snapshot TCP listening sockets (read-only, no probing)',
        observed,
        confidence: 'observed',
        limitations,
      }, null, 2)
      const report = (method, lines, limitations) => envelope({
        method,
        total: lines.length,
        dump: lines.slice(0, 80).join('\n'),
        truncated: lines.length > 80,
      }, limitations)

      if (process.platform === 'linux') {
        // Linux 优先 `ss -ltnp`：`netstat -an` 会把 unix socket 也写成 LISTENING，
        // 旧过滤只看 LISTEN 会把 80 行全给 unix socket（TCP 监听一条都露不出来）。
        const ss = await runCmd(shell, ['ss', '-ltnp'], exec, { timeoutMs: 20_000 })
        if (ss.exitCode === 0) {
          return report('ss -ltnp', filterListenerLines('linux', ss.stdout), [
            'ss 的输出原样返回（截断到 80 行；truncated=true 表示后面还有）。进程名/PID 只有内核允许时才出现，看不到 ≠ 没有',
            '这是**一次快照**：不说明套接字的历史，也不说明谁在连它',
          ])
        }
        const netstat = await runCmd(shell, ['netstat', '-ltnp'], exec, { timeoutMs: 20_000 })
        if (netstat.exitCode === 0) {
          return report('netstat -ltnp', filterListenerLines('linux', netstat.stdout), [
            'ss 不在本机，这份读数是 netstat -ltnp（只含 TCP）；netstat 的表更粗，进程名/PID 可能缺',
            '这是**一次快照**：不说明套接字的历史，也不说明谁在连它',
          ])
        }
        // 两条都跑不动：大声报错，不返回空表。
        requireOk(netstat, 'netstat -ltnp')
      }

      const lsof = await runCmd(shell, ['lsof', '-nP', '-iTCP', '-sTCP:LISTEN'], exec)
      if (lsof.exitCode === 0) {
        return report('lsof', lsof.stdout.split('\n').map(line => line.trim()).filter(Boolean), [
          'lsof 的输出原样返回（截断到 80 行；truncated=true 表示后面还有没给出来的内容）',
          '这是**一次快照**：不说明套接字的历史，也不说明谁在连它',
        ])
      }
      const netstat = await runCmd(shell, ['netstat', '-an'], exec, { timeoutMs: 20_000 })
      if (netstat.exitCode === 0) {
        return report('netstat -an', filterListenerLines(process.platform, netstat.stdout), [
          'lsof 没跑通，这份读数是 netstat -an 里含 LISTEN 的 TCP 行（unix socket 已被排除）',
          'netstat 的表格比 lsof 粗：没有进程名/PID，只说「有东西在这个地址上听」',
        ])
      }
      requireOk(netstat, 'netstat -an')
    },
  }))

  // ── 无线 / 网络排障工具 ────────────────────────────────────────────────────

  ctx.tools.register(defineTool({
    name: 'diag_wifi_link',
    description: '本机 Wi-Fi 链路快照：PHY 模式、主信道、带宽、RSSI/底噪/SNR、协商速率、MCS。macOS 读 system_profiler；Linux 读 iw dev link + /proc/net/wireless，不发任何包。',
    parameters: {},
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(_args, exec) {
      // 证据形状（规划 §5.1）：信封 JSON —— 原有读数整体进 observed，另加 confidence / limitations。
      // 这个工具量的是**当前链路快照**（活的），所以 limitations 必须说清"这是一次采样、不是历史"。
      exec.signal.throwIfAborted()
      const snapshot = await collectLink(shell, exec.signal)
      return JSON.stringify({
        tool: 'diag_wifi_link',
        target: 'the Wi-Fi interface of this host',
        operation: 'read one passive snapshot of the local Wi-Fi link (no probe requests, no packets)',
        observed: snapshot,
        confidence: 'observed',
        limitations: [
          '一次采样：只说"这一刻"的取值，不说明它稳不稳（要历史用 diag_net_watch 记）',
          '被动读系统数据源（macOS system_profiler / Linux iw 与 /proc）：不主动发探测、不连接任何东西，因此看不到对端或邻居的行为',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_wifi_channels',
    description: '5GHz 信道占用图与可用性：邻居按（频段/带宽/主信道）折叠，并算出哪些 80MHz 块被允许、160MHz 是否可能。macOS 读 system_profiler；Linux 读 iw scan dump / nmcli 的只读扫描缓存，不发探测请求。',
    parameters: {
      rounds: { type: 'number', description: '读缓存的轮数（默认 3，上限 8）。缓存要几轮才收敛，一轮会漏报。' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args, exec) {
      // 证据形状（规划 §5.1）：信封 JSON。这个工具读的是**扫描缓存**（活数据），
      // limitations 必须说清"缓存要几轮才收敛、一轮会漏报"这件事 —— 否则容易把漏读当没有。
      exec.signal.throwIfAborted()
      const snapshot = await collectChannels(shell, { rounds: clampInteger(args.rounds, 3, 1, 8), signal: exec.signal })
      return JSON.stringify({
        tool: 'diag_wifi_channels',
        target: 'the 5GHz channel occupancy seen from this host',
        operation: 'read the system scan cache and fold neighbours into 80MHz-block availability',
        observed: snapshot,
        confidence: 'observed',
        limitations: [
          '读的是系统扫描缓存：macOS 的 system_profiler 要几轮才收敛（默认读 3 轮）；Linux 的 iw scan dump 只读一次缓存，nmcli 回退按 rounds 读',
          '只读缓存，不发探测请求、不连接任何东西 —— 因此看不到两次采样之间的变化',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_net_rtt',
    description: '同时测局域网网关与外网的 RTT/丢包/抖动 —— 把「空口被抢」和「路由器/运营商排队」分开的第一刀。会发 ICMP 包。',
    parameters: {
      gateway: { type: 'string', description: '网关地址（默认取本机默认网关；取不到才用 192.168.1.1）' },
      wan: { type: 'string', description: '外网目标（默认 223.5.5.5，阿里公共 DNS）' },
      count: { type: 'number', description: '每个目标发几个包（默认 20，上限 60）' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args, exec) {
      const detectedGateway = args.gateway === undefined || String(args.gateway).trim() === ''
        ? await defaultGateway(shell, exec)
        : ''
      const gateway = requireHost(args.gateway, detectedGateway === '' ? '192.168.1.1' : detectedGateway)
      const wanTarget = requireHost(args.wan, '223.5.5.5')
      const count = clampInteger(args.count, 20, 4, 60)

      exec.signal.throwIfAborted()
      const gwRun = await runCmd(shell, pingArgv(gateway, count), exec, { timeoutMs: 90000, stdoutMaxBytes: 262144 })
      exec.signal.throwIfAborted()
      const wanRun = await runCmd(shell, pingArgv(wanTarget, count), exec, { timeoutMs: 90000, stdoutMaxBytes: 262144 })

      const gw = parsePingStats(gwRun.stdout)
      const wan = parsePingStats(wanRun.stdout)
      // 100% 丢包时 ping 退出码非 0，但那是**有意义的结果**（网关没回应），不是调用失败。
      // 只有连统计行都解析不出来，才说明这条数据不可信 —— 那时必须大声报错。
      if (gw.transmitted === null || wan.transmitted === null) {
        const error = new Error(
          'ping 输出解析不出统计行，这条数据不可信：'
          + `\n${gwRun.command} → exit ${gwRun.exitCode}`
          + `\n${wanRun.command} → exit ${wanRun.exitCode}`,
        )
        error.name = 'CommandError'
        throw error
      }
      const delta = gw.avgMs === null || wan.avgMs === null ? null : wan.avgMs - gw.avgMs
      const verdict = gw.avgMs === null
        ? '网关全程无回应：先确认网关地址、以及本机是否真的在这个网段 —— 这一层没数据，下面什么都推不出来。'
        : wan.avgMs === null
          ? '网关通、外网不通：问题在光猫/路由器上联或运营商侧，不在无线空口。'
          : delta > 30
            ? `外网比网关多 ${delta.toFixed(1)}ms：这段差值来自光猫/路由器的排队与路径，跟 Wi-Fi 空口无关。`
            : `外网与网关只差 ${delta.toFixed(1)}ms，路径干净。此时若仍感到卡，更可能在空口 —— 用 diag_wifi_link 看协商速率与抖动。`
      const snapshot = {
        gateway: { target: gateway, ...gw, line: pingLine(`网关 ${gateway}`, gw) },
        wan: { target: wanTarget, ...wan, line: pingLine(`外网 ${wanTarget}`, wan) },
        deltaMs: delta,
        verdict,
        jitterNote: gw.stddevMs !== null && gw.stddevMs > 2
          ? `网关抖动 ${gw.stddevMs}ms 偏大：空口在被抢，看 diag_wifi_channels 里有没有同频邻居。`
          : null,
      }
      // 证据形状（规划 §5.1）：信封 JSON —— 一次 RTT 采样（网关 + 外网）。
      // limitations 必须说清"这几个数字各自是什么、以及它们看不见什么"。
      return JSON.stringify({
        tool: 'diag_net_rtt',
        target: gateway + ' (gateway) + ' + wanTarget + ' (wan)',
        operation: 'send ICMP echoes to both targets and report min/avg/max, loss and jitter',
        observed: snapshot,
        confidence: 'observed',
        limitations: [
          '回环 / 网关 / 外网是三个不同的东西：别把回环的 0.1ms 当成\u201c网好\u201d',
          'ICMP 会被中间设备限速或直接丢弃 ⇒ 丢包不等于链路断（要用 TCP 层再证一次）',
          '一次采样的 min/avg/max 不说明抖动趋势 —— 要趋势得用 diag_net_watch 那类记录仪',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_net_throughput',
    description: '聚合吞吐测试。默认按「跑满」配置（8 流 × 10 秒），会在目标链路上产生真实流量；结果回传本次实际消耗的字节数。',
    parameters: {
      url: { type: 'string', description: '下载目标（默认一个国内 CDN 大文件，可覆盖）' },
      streams: { type: 'number', description: '并行流数（默认 8，上限 16）' },
      seconds: { type: 'number', description: '每流时长预算秒（默认 10，上限 30）' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args, exec) {
      const url = requireHttpUrl(args.url, DEFAULT_SPEED_URL)
      const streams = clampInteger(args.streams, 8, 1, 16)
      const seconds = clampInteger(args.seconds, 10, 2, 30)
      // -w 同时给出速率与字节数：字节数是「这次花了你多少流量」的凭据。只报速率、
      // 不报消耗，等于让调用者无法为这次测量负责。
      const one = `curl -sL -o /dev/null -w '%{speed_download} %{size_download}\\n' --max-time ${seconds} ${shq(url)}`
      const script = `i=0\nwhile [ "$i" -lt ${streams} ]; do ${one} & i=$((i+1)); done\nwait`
      exec.signal.throwIfAborted()
      const run = await runCmd(shell, ['sh', '-c', script], exec, { timeoutMs: (seconds + 30) * 1000, stdoutMaxBytes: 1048576 })
      const samples = run.stdout.trim().split('\n').filter(Boolean).map((line) => {
        const [speed, size] = line.trim().split(/\s+/)
        return { bps: parseSpeedSample(speed), bytes: Number(size) || 0 }
      })
      const measured = samples.filter(sample => sample.bps !== null)
      if (measured.length === 0) {
        // 一条流都没测到速率 = 目标不可达/被拒，绝不能报成「0 Mbps 测到了」。
        const error = new Error(
          `没有一条流测到速率（${streams} 流 / ${seconds} 秒，exit ${run.exitCode}）：目标可能不可达或被拒。`
          + `\n命令：${run.command}`
          + `\n输出：${run.stdout.trim().slice(0, 400) === '' ? '(空)' : run.stdout.trim().slice(0, 400)}`
          + (run.stderr.trim() === '' ? '' : `\n错误：${run.stderr.trim().slice(0, 400)}`),
        )
        error.name = 'CommandError'
        throw error
      }
      const aggregateBps = measured.reduce((sum, sample) => sum + sample.bps, 0)
      const totalBytes = samples.reduce((sum, sample) => sum + sample.bytes, 0)
      const snapshot = {
        url,
        streams,
        seconds,
        measuredStreams: measured.length,
        aggregateMbps: Number(((aggregateBps * 8) / 1048576).toFixed(1)),
        perStreamMbps: measured.map(sample => Number(((sample.bps * 8) / 1048576).toFixed(1))),
        totalBytes,
        totalMiB: Number((totalBytes / 1048576).toFixed(1)),
        note: '默认按「跑满」配置（8 流 × 10 秒）；totalBytes 是本次实际消耗的流量。测出来的是「无线链路 + 外网」合起来的上限，不是链路理论值。',
      }
      // 证据形状（规划 §5.1）：信封 JSON。这个工具是七个里**唯一会产生真实流量**的，
      // 所以 limitations 要讲清"这次花了你多少流量"与"速率读数看不见什么"。
      return JSON.stringify({
        tool: 'diag_net_throughput',
        target: url,
        operation: 'run ' + streams + ' parallel curl streams for up to ' + seconds + 's each and report throughput',
        observed: snapshot,
        confidence: 'observed',
        limitations: [
          '这是一次**真实流量**测量：observed.totalBytes 就是本次消耗的字节数（默认档位是 8 流 × 10 秒）',
          '读的是链路**容量**：不说明时延、丢包或抖动 —— 那些用 diag_net_rtt / diag_net_watch 量',
          '聚合速率受对端与服务端共同限制：它只证明"这条路径此刻能跑到多少"，不区分是谁的限制',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'diag_net_watch',
    description: '长时间记录仪：定期把「链路 + 网关 RTT + 外网 RTT」原样追加到日志，供事后对齐「什么时候卡的」。间歇性故障只能这样证明，单次测速证明不了。',
    parameters: {
      action: { type: 'string', description: 'start | stop | sample | mark | report | status（默认 status）' },
      dir: { type: 'string', description: '日志目录（默认 ~/.dsh-fly/netdiag）' },
      message: { type: 'string', description: 'mark 时的备注，例如「电视卡了」' },
      interval: { type: 'number', description: '采样间隔秒（默认 10，下限 3，上限 600）' },
      count: { type: 'number', description: '每次采样每个目标发几个包（默认 8，上限 30）' },
      gateway: { type: 'string', description: '网关地址（默认取本机默认网关；取不到才用 192.168.1.1）' },
      wan: { type: 'string', description: '外网目标（默认 223.5.5.5）' },
      samples: { type: 'number', description: 'report 最多回看多少个样本（默认 300，上限 5000）' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute(args, exec) {
      // undefined 必须保持 undefined（否则默认目录就没了）：只规范化"给了且以 - 开头"的那种。
      const paths = watchPaths(args.dir === undefined ? undefined : safePath(args.dir))
      const action = String(args.action ?? 'status').trim() === '' ? 'status' : String(args.action).trim()
      const detectedGateway = args.gateway === undefined || String(args.gateway).trim() === ''
        ? await defaultGateway(shell, exec)
        : ''
      const gateway = requireHost(args.gateway, detectedGateway === '' ? '192.168.1.1' : detectedGateway)
      const wan = requireHost(args.wan, '223.5.5.5')
      const count = clampInteger(args.count, 8, 4, 30)
      // 证据形状（规划 §5.1）：逐支迁移 —— 本轮只把 status 支包上（没有消费方读它的裸文本）。
      const envelope = (observed, limitations) => JSON.stringify({
        tool: 'diag_net_watch',
        target: paths.dir,
        operation: 'long-running link/RTT recorder: ' + action,
        observed,
        confidence: 'observed',
        limitations,
      }, null, 2)

      if (action === 'start') {
        const interval = clampInteger(args.interval, 10, 3, 600)
        const linkEvery = Math.max(1, clampInteger(Math.round(60 / interval), 3, 1, 60))
        const script = samplerScript(paths, { interval, count, gateway, wan, linkEvery })
        // 长驻进程必须显式 onExpiry:'none'：resolve() 缺省是 onExpiry:'kill' + 120s，
        // 记录仪会在两分钟后被杀，症状是「跑一会儿就没了」。这里的 result() 永不 settle，
        // 所以只 await 到「进程起来了」——正是黑盒包踩过的那条。
        await shell.execute(shell.resolve({
          command: script,
          onExpiry: 'none',
          timeoutMs: 7 * 24 * 3600 * 1000,
          signal: exec.signal,
        }))
        return envelope({ method: 'start', log: paths.log, interval, linkEvery, count, gateway, wan, dump: [
          `记录仪已启动`,
          `日志：${paths.log}`,
          `间隔 ${interval}s；每 ${linkEvery} 次采样取一次链路；每次每目标 ${count} 个包`,
          `网关 ${gateway} / 外网 ${wan}`,
          '',
          `卡住时立刻打标记：diag_net_watch action=mark message="电视卡了"`,
          `停止：diag_net_watch action=stop`,
          `回看：diag_net_watch action=report`,
        ].join('\n') }, [
          '这是**后台**记录仪：本工具返回的时候采样循环才刚开始 ⇒ 日志会一直长，随时用 action=report 回看', 
          'observed 里带着它的节奏（间隔 / 每 N 次取链路 / 每目标包数）—— 以后看报告时能对上它是按什么节奏记的', 
        ])
      }

      if (action === 'stop') {
        const run = await runCmd(
          shell,
          ['sh', '-c', `mkdir -p ${shq(paths.dir)} && touch ${shq(paths.stop)}`],
          exec,
          { timeoutMs: 20000 },
        )
        requireOk(run, '写停止文件')
        return envelope({ method: 'stop', stopFile: paths.stop, dump: `停止信号已写入 ${paths.stop}\n采样循环会在当前这一轮 sleep 结束后退出，最多等一个采样间隔。用 action=status 确认。` }, [
          '这是**异步**停止：写完信号文件就返回了，采样循环要等当前这一轮 sleep 结束才退出',
          '要确认它真的停了，用 action=status 看最后写入时间，或再 action=report 比样本数',
        ])
      }

      if (action === 'sample') {
        const run = await runCmd(
          shell,
          ['sh', '-c', `mkdir -p ${shq(paths.dir)}\n${sampleSnippet(paths, { count, gateway, wan })}`],
          exec,
          { timeoutMs: 30000 },
        )
        requireOk(run, '采样')
        return envelope({ method: 'sample', log: paths.log, dump: `已采样并追加到 ${paths.log}\n用 action=report 看，或 action=mark 标一下刚才发生了什么。` }, [
          '这一次采样写进了日志；它的**内容**要看 action=report（这里只报"写成功了"）',
          '样本是往日志尾部**追加**的：这个动作不会覆盖历史，也不会改变记录仪是否在跑',
        ])
      }

      if (action === 'mark') {
        const message = String(args.message ?? '').trim()
        if (message === '') {
          const error = new Error('mark 需要 message，例如 action=mark message="电视卡了"')
          error.name = 'ArgumentError'
          throw error
        }
        const run = await runCmd(
          shell,
          ['sh', '-c', `mkdir -p ${shq(paths.dir)} && printf '@@MARK %s %s\\n' "$(date +%s)" ${shq(message)} >> ${shq(paths.log)}`],
          exec,
          { timeoutMs: 20000 },
        )
        requireOk(run, '写标记')
        return envelope({ method: 'mark', log: paths.log, dump: `已标记「${message}」@ ${stampOf(Math.floor(Date.now() / 1000))}\n日志：${paths.log}` }, [
          '标记是你打的**锚点**，它本身不是测量 —— report 会把它对齐到最近的样本（误差 ≤ 一个采样间隔）',
          '标记只往日志里追加一行，不改变采样节奏，也不影响记录仪是否在跑',
        ])
      }

      if (action === 'report') {
        const limit = clampInteger(args.samples, 300, 1, 5000)
        const run = await runCmd(
          shell,
          ['sh', '-c', `test -f ${shq(paths.log)} && tail -n ${limit * 20} ${shq(paths.log)}`],
          exec,
          { timeoutMs: 30000, stdoutMaxBytes: 8388608 },
        )
        if (run.stdout.trim() === '') {
          return envelope({ method: 'report', samples: 0, dump: '', log: paths.log }, [
            '日志不存在或为空 ⇒ 这是「还没有样本」，不是「网络没问题」',
            `先 action=start 起记录仪，或 action=sample 取一个（看的是 ${paths.log}）`,
          ])
        }
        const { rows, marks, skipped } = readWatch(run.stdout)
        if (rows.length === 0) {
          return envelope({
            method: 'report',
            samples: 0,
            skipped,
            log: paths.log,
            dump: skipped > 0
              ? `日志里有 ${skipped} 个样本还没写完（记录仪正在写），暂时没有完整的样本可看。稍后再试。`
              : `日志里没解析出完整样本（${paths.log}）：文件可能刚被截断。`,
          }, [
            '一个完整样本都没有 ⇒ 这份报告里**没有任何测量**，不是「这一段时间网络正常」',
            skipped > 0
              ? '只有半截样本 —— 读到一半的记录会得出凭空的故障结论，所以它不算证据'
              : '文件可能刚被截断，也可能记录仪根本没在跑 —— 这两种要分开查',
          ])
        }
        const first = rows[0]
        const last = rows[rows.length - 1]
        const lines = [
          `记录仪 ${paths.dir}`,
          `样本 ${rows.length} 个，标记 ${marks.length} 个，跨度 ${stampOf(first.epoch)} → ${stampOf(last.epoch)}`
            + (skipped > 0 ? `（另有 ${skipped} 个未写完已跳过）` : ''),
          '',
          '时刻                  信道/带宽  协商   SNR   网关avg/抖动      外网avg/抖动      网关丢包',
        ]
        for (const row of rows) {
          const link = row.link
          const channel = link.channel === null ? '—' : `${link.channel}/${link.widthMhz ?? '?'}`
          lines.push([
            stampOf(row.epoch).padEnd(21),
            channel.padEnd(10),
            (link.transmitRateMbps === null ? '—' : String(link.transmitRateMbps)).padStart(5),
            (link.snrDb === null ? '—' : String(link.snrDb)).padStart(5),
            (row.gw.avgMs === null ? '无回应' : `${row.gw.avgMs}/${row.gw.stddevMs}`).padEnd(16),
            (row.wan.avgMs === null ? '无回应' : `${row.wan.avgMs}/${row.wan.stddevMs}`).padEnd(16),
            row.gw.lossPercent === null ? '—' : `${row.gw.lossPercent}%`,
          ].join(' '))
        }
        const gwJitter = numericSummary(rows.map(row => row.gw.stddevMs))
        const rate = numericSummary(rows.map(row => row.link.transmitRateMbps))
        const widths = [...new Set(rows.map(row => row.link.widthMhz).filter(width => width !== null))].sort((a, b) => a - b)
        const blocks = [...new Set(rows
          .map(row => (row.link.channel === null ? null : blockOf(row.link.channel)?.primary ?? null))
          .filter(primary => primary !== null))].sort((a, b) => a - b)
        lines.push('')
        lines.push(gwJitter.count === 0
          ? `网关抖动：一个样本都没测到（${rows.length} 个样本全部无回应）`
          : `网关抖动：min ${gwJitter.min} / 中位 ${gwJitter.median} / max ${gwJitter.max} ms（有测量的 ${gwJitter.count}/${rows.length} 个样本）`)
        lines.push(rate.count === 0
          ? '协商速率：这些样本里没有链路数据'
          : `协商速率：min ${rate.min} / 中位 ${rate.median} / max ${rate.max} Mbps`)
        lines.push(`出现过的带宽：${widths.length === 0 ? '无链路样本' : widths.map(width => `${width}MHz`).join(', ')}`)
        lines.push(`出现过的 80MHz 块：${blocks.length === 0 ? '无链路样本' : blocks.join(', ')}`)
        if (widths.length > 1) {
          lines.push('⚠ 带宽变过 —— 这正是「某台设备突然慢」的形状：射频在降档或换道。')
        }
        if (blocks.length > 1) {
          lines.push('⚠ 换过信道块（可能遇到过雷达被迫换道，或被控制器调优）。')
        }
        for (const mark of marks) {
          const nearest = rows.reduce((best, row) => (
            best === null || Math.abs(row.epoch - mark.epoch) < Math.abs(best.epoch - mark.epoch) ? row : best
          ), null)
          lines.push('')
          lines.push(`标记「${mark.message}」@ ${stampOf(mark.epoch)} → 最近样本 ${stampOf(nearest.epoch)}`)
          lines.push(`  网关 ${nearest.gw.avgMs ?? '无回应'}ms（抖动 ${nearest.gw.stddevMs ?? '—'}ms，丢包 ${nearest.gw.lossPercent ?? '—'}%）`
            + ` 外网 ${nearest.wan.avgMs ?? '无回应'}ms（抖动 ${nearest.wan.stddevMs ?? '—'}ms）`
            + ` 链路 ${nearest.link.channel ?? '—'}/${nearest.link.widthMhz ?? '—'}MHz 协商 ${nearest.link.transmitRateMbps ?? '—'}Mbps`)
        }
        // 报告文本原样进 observed.dump（消费方都是子串正则，不需要改读法）。
        return envelope({ method: 'report', samples: rows.length, skipped, dump: lines.join('\n') }, [
          '报告覆盖的是**日志里记着的那段时间** —— 记录仪没起着的时段，它什么都不知道',
          skipped > 0
            ? '有未写完的样本被跳过（数量见 observed.skipped）：那些时刻只有半个样本，不能当证据'
            : '这次没有跳过未写完的样本；但"没跳过"只说明这次读的时候没有半截样本',
        ])
      }

      // status（默认）：永远给出可读结论，绝不返回空字符串。
      //
      // 存活探测用 `kill -0`（POSIX 的存在性测试，不投递信号）而**不是** `ps -p`：
      // `ps` 在受限沙箱里整个跑不动（连 `ps -p $$` 都 exit 126），于是「没在跑」会在
      // 进程其实活着的时候报出来 —— 一把看不见东西的尺子给出的是假结论。
      const run = await runCmd(shell, ['sh', '-c', [
        `d=${shq(paths.dir)}`,
        'echo "目录: $d"',
        'pid=""',
        'if [ -f "$d/sampler.pid" ]; then pid=$(cat "$d/sampler.pid" 2>/dev/null); fi',
        'case "$pid" in ""|*[!0-9]*) pid="" ;; esac',
        'if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then',
        '  echo "记录仪: 运行中 (pid $pid)"',
        'else',
        '  echo "记录仪: 没在跑"',
        'fi',
        'if [ -f "$d/stop" ]; then echo "停止信号: 存在（下次 start 会清掉）"; fi',
        'if [ -f "$d/samples.log" ]; then',
        '  echo "样本: $(grep -c \'^@@SAMPLE\' "$d/samples.log") 个；标记: $(grep -c \'^@@MARK\' "$d/samples.log") 个"',
        // GNU stat（-c %Y）优先、BSD stat（-f %m）兜底：直接用 -f 在 Linux 上会把文件系统表
        // 塞进 $(( ))，在 dash 里就是语法错误 —— 整个 status 的后半段都不执行。
        `  mtime=$( ${portableMtimeCommand('"$d/samples.log"')} )`,
        '  case "$mtime" in ""|*[!0-9]*) mtime=0 ;; esac',
        '  if [ "$mtime" -gt 0 ]; then',
        '    echo "日志: $d/samples.log（$(wc -c < "$d/samples.log" | tr -d \' \') 字节，最后写入 $(( $(date +%s) - mtime ))s 前）"',
        '  else',
        '    echo "日志: $d/samples.log（$(wc -c < "$d/samples.log" | tr -d \' \') 字节，mtime 读不到 —— 无法说最后写入）"',
        '  fi',
        'else',
        '  echo "还没有日志文件"',
        'fi',
      ].join('\n')], exec, { timeoutMs: 20000, stdoutMaxBytes: 262144 })
      const statusText = run.stdout.trim()
      // 「未知」与「没在跑」是两件事：状态命令没输出时不许说成没在跑。
      return envelope({ method: 'status', dump: statusText, known: statusText !== '' }, [
        statusText === ''
          ? '状态命令没有输出 ⇒ 这是「未知」，不是「没在跑」'
          : '这是记录仪自己报的状态，不是从日志推断的；它只说这一刻，不说明采样准不准',
      ])
    },
  }))

  // 这里**故意没有** ctx.provide。本包是 agent 平面（package.json 里没有 dsh.bundle），
  // preset 按会话挂载它 —— 于是 provide 落在会话上下文里，任何一个 Host 行都看不见。
  // 这是实测结论（把本包装进 e2e profile 后 /fly/netops/wifi 回 503），不是推断。
  // 工作台要的无线数据由宿主平面的 dsh-plugin-fly-diagnostics 采集，发布成
  // flyDiagnostics.wifi()。两个包不能互相 import，所以 wifi.js 在两处**逐字节相同**，
  // 由 scripts/verify-security-tools.mjs 的一致性断言守着（同 ELF 解析器的先例）。
}
