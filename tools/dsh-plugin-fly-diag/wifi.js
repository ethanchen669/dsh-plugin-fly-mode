/**
 * Link-layer report parsing for the `fly-diag` tool face.
 *
 * Pure functions only — no I/O, no `ctx`, no clock, no command execution.
 * The collector commands live in `index.js`; this module turns their stdout into
 * numbers. macOS reports come from `system_profiler`; Linux reports come from
 * `iw` / `nmcli` / `/proc/net/wireless` (see the “Linux（Ubuntu）后端” section).
 * The split exists for one reason: the tool face is only as honest as
 * this file, and this file can be pinned against captured fixtures
 * (`scripts/tests/wifi-report.spec.mjs` and `linux-portability.spec.mjs`)
 * instead of against whatever radio the host running the gate happens to have.
 *
 * ## The `0 dBm` trap — why signal parsing is stricter than it looks
 *
 * A first revision of this logic lived in a shell script and treated any value
 * that was not a literal `-` as a number:
 *
 *     s = ($4 == "-") ? -999 : $4 + 0
 *
 * Two shapes reach that expression as `0`:
 *
 *   · `system_profiler` prints **no `Signal / Noise` line at all** for many
 *     entries. In the captured fixture below, 15 of 16 neighbour entries have no
 *     such line.
 *   · When it cannot measure, it can print `0 dBm / 0 dBm`.
 *
 * Either way the channel map rendered `ch36 80MHz 0 dBm` — the strongest
 * possible reading, invented out of the *absence* of a measurement. So
 * `parseSignalDbm()` returns `null` for empty, `-`, non-numeric text, **and for
 * `0`**: 0 dBm is 1 mW at the antenna, no consumer AP ever measures it, and
 * macOS uses it as the "no reading" placeholder. `0` is a sentinel here, not a
 * measurement. Every consumer must treat `null` as "unknown" and never as 0.
 *
 * @module dsh-plugin-fly-diag/wifi
 */

/** The one "we have no measurement" value. Deliberately `null`, never `0`. */
const UNKNOWN = null

/**
 * Parse one half of a `Signal / Noise: -58 dBm / -94 dBm` line.
 *
 * @param raw - field text such as `-58 dBm`, `0 dBm`, `-`, or `''`.
 * @returns dBm as a number, or `null` when there is no real measurement.
 */
export function parseSignalDbm(raw) {
  const text = String(raw ?? '').trim()
  if (text === '' || text === '-') return UNKNOWN
  const match = /^(-?\d+(?:\.\d+)?)\s*dBm$/u.exec(text)
  if (match === null) return UNKNOWN
  const value = Number(match[1])
  if (!Number.isFinite(value) || value === 0) return UNKNOWN
  return value
}

/**
 * Parse `Channel: 149 (5GHz, 80MHz)`.
 *
 * The number is the **primary** 20MHz channel, not the block centre: a radio
 * reporting `149 (5GHz, 80MHz)` occupies 149–161, and one reporting
 * `40 (5GHz, 80MHz)` occupies the *same* 149-free block 36–48. Reading these as
 * three different "channels" is how a channel map ends up claiming four
 * neighbours where there is really one block.
 *
 * @param raw - the field text after `Channel:`.
 * @returns `{ channel, band, widthMhz }`, or `null` when unparseable.
 */
export function parseChannelLine(raw) {
  const match = /^(\d+)\s*\(([^,]+),\s*(\d+)\s*MHz\)$/u.exec(String(raw ?? '').trim())
  if (match === null) return null
  return { channel: Number(match[1]), band: match[2].trim(), widthMhz: Number(match[3]) }
}

/**
 * Parse `Supported Channels: 1 (2GHz), 36 (5GHz), …`.
 *
 * This list is a regulatory answer that macOS does **not** redact, so the
 * feasible-channel arithmetic below is derived from the host's own report
 * instead of from a hardcoded country table.
 *
 * @param raw - the field text after `Supported Channels:`.
 * @returns array of `{ channel, band }`, in report order.
 */
export function parseSupportedChannels(raw) {
  return [...String(raw ?? '').matchAll(/(\d+)\s*\(([^)]+)\)/gu)]
    .map(match => ({ channel: Number(match[1]), band: match[2].trim() }))
}

/**
 * Normalize `802.11 a/b/g/n/ac/ax` into full mode names.
 *
 * macOS puts the family prefix on the first token only, so a naive
 * `split('/')` yields `['802.11 a', 'b', 'g', 'n', 'ac', 'ax']` and every
 * `includes('802.11ax')` test — and every capability claim built on it — fails
 * while looking like the host simply does not support the mode.
 *
 * @param raw - the field text after `Supported PHY Modes:`.
 * @returns mode names such as `['802.11a', '802.11b', '802.11ax']`.
 */
export function normalizePhyModes(raw) {
  const parts = String(raw ?? '').split('/').map(part => part.trim()).filter(Boolean)
  if (parts.length === 0) return []
  const head = /^(802\.11\s*)([A-Za-z]+)$/u.exec(parts[0])
  if (head === null) return parts
  const family = head[1].replace(/\s+/gu, '')
  return [`${family}${head[2]}`, ...parts.slice(1).map(part => `${family}${part}`)]
}

/**
 * `Key: value` lines inside a network entry or an interface block.
 *
 * The key class **must** allow `/`: the field that carries the signal is spelled
 * `Signal / Noise`, and a key class of `[A-Za-z ]` silently fails to match it —
 * which yields `rssiDbm: null` for every entry in the report. That failure is
 * indistinguishable from "this host has no measurements", i.e. it renders as a
 * confidently empty report. Only a fixture asserting the concrete -58 / -94
 * values catches it (see `scripts/tests/wifi-report.spec.mjs`).
 */
const FIELD = /^\s*([A-Za-z][A-Za-z /]*?):\s*(.*)$/u

/**
 * Parse one network entry (the indented lines under a `<redacted>:` heading).
 *
 * Every absent field becomes `null`. A missing `Transmit Rate` must never
 * surface as `0`, for the same reason a missing signal must not: the renderer
 * cannot tell the difference after the fact.
 *
 * @param lines - the entry's raw lines, headed by no `<redacted>:` line itself.
 * @returns the normalized entry record.
 */
export function parseNetworkEntry(lines) {
  const fields = new Map()
  for (const line of lines) {
    const match = FIELD.exec(line)
    if (match !== null) fields.set(match[1].trim(), match[2].trim())
  }

  const channel = parseChannelLine(fields.get('Channel'))
  const signal = fields.get('Signal / Noise')
  const halves = signal === undefined ? [] : signal.split('/').map(part => part.trim())
  // A beacon with no signal line is the common case, not the exception: index 0
  // and 1 are both absent rather than defaulted, so `snrDb` stays null too.
  const rssi = parseSignalDbm(halves[0])
  const noise = parseSignalDbm(halves[1])
  const rate = Number(fields.get('Transmit Rate'))
  const mcs = Number(fields.get('MCS Index'))

  return {
    phy: fields.get('PHY Mode') ?? null,
    channel: channel?.channel ?? null,
    band: channel?.band ?? null,
    widthMhz: channel?.widthMhz ?? null,
    security: fields.get('Security') ?? null,
    rssiDbm: rssi,
    noiseDbm: noise,
    snrDb: rssi === null || noise === null ? null : rssi - noise,
    transmitRateMbps: Number.isFinite(rate) && rate > 0 ? rate : null,
    mcs: Number.isFinite(mcs) ? mcs : null,
  }
}

/**
 * Parse a whole `system_profiler SPAirPortDataType` report.
 *
 * Structure it walks: `Interfaces:` → one `<ifname>:` block per interface →
 * `Current Network Information:` and `Other Local Wi-Fi Networks:` → one
 * `<redacted>:` entry each. Indentation is **not** trusted: the real fixture
 * contains a driver banner at column 0 in the middle of the `en0` block, so the
 * walker keys off the section headings and the numeric interface names instead
 * of off indentation depth.
 *
 * @param text - raw stdout of `system_profiler SPAirPortDataType`.
 * @returns `{ interfaces }`, each with `current` (or null) and `neighbors`.
 */
export function parseWifiReport(text) {
  const interfaces = []
  let iface = null
  let section = null
  let entry = null

  const closeEntry = () => {
    if (entry === null) return
    const parsed = parseNetworkEntry(entry)
    if (section === 'neighbors') iface.neighbors.push(parsed)
    else if (section === 'current') iface.current = parsed
    entry = null
  }
  const closeInterface = () => {
    closeEntry()
    if (iface !== null) interfaces.push(iface)
    iface = null
    section = null
  }

  for (const line of String(text ?? '').split('\n')) {
    if (/^\s*Current Network Information:\s*$/u.test(line)) {
      closeEntry()
      section = 'current'
      continue
    }
    if (/^\s*Other Local Wi-Fi Networks:\s*$/u.test(line)) {
      closeEntry()
      section = 'neighbors'
      continue
    }
    // `        en0:` / `        awdl0:` — a bare interface heading.
    const heading = /^\s{4,10}([A-Za-z]+\d+):\s*$/u.exec(line)
    if (heading !== null) {
      closeInterface()
      iface = {
        name: heading[1],
        status: null,
        countryCode: null,
        phyModes: [],
        supportedChannels: [],
        current: null,
        neighbors: [],
      }
      continue
    }
    if (iface === null) continue

    if (section === null) {
      const field = FIELD.exec(line)
      if (field === null) continue
      const key = field[1].trim()
      const value = field[2].trim()
      if (key === 'Status') iface.status = value
      else if (key === 'Country Code') iface.countryCode = value
      else if (key === 'Supported PHY Modes') iface.phyModes = normalizePhyModes(value)
      else if (key === 'Supported Channels') iface.supportedChannels = parseSupportedChannels(value)
      continue
    }

    if (/^\s*<redacted>:\s*$/u.test(line)) {
      closeEntry()
      entry = []
      continue
    }
    if (entry !== null) entry.push(line)
  }
  closeInterface()

  return { interfaces }
}

/**
 * The 80MHz blocks 802.11 defines across the 5GHz band, and whether each one
 * contains DFS channels (which force a 60-second channel-availability check and
 * let a radar hit vacate the channel).
 *
 * The 5.8GHz band spans 5725–5850MHz = 125MHz, so `149+153+157+161` is the only
 * block that fits there and **160MHz cannot exist in 5.8GHz at all** — that is
 * arithmetic, not a regulatory opinion. 160MHz therefore requires two
 * *adjacent* 80MHz blocks, which in this table means 36–48 + 52–64.
 */
export const BLOCKS_5GHZ = Object.freeze([
  Object.freeze({ primary: 36, channels: Object.freeze([36, 40, 44, 48]), dfs: false }),
  Object.freeze({ primary: 52, channels: Object.freeze([52, 56, 60, 64]), dfs: true }),
  Object.freeze({ primary: 100, channels: Object.freeze([100, 104, 108, 112]), dfs: true }),
  Object.freeze({ primary: 116, channels: Object.freeze([116, 120, 124, 128]), dfs: true }),
  Object.freeze({ primary: 132, channels: Object.freeze([132, 136, 140, 144]), dfs: true }),
  Object.freeze({ primary: 149, channels: Object.freeze([149, 153, 157, 161]), dfs: false }),
])

/** The 80MHz block a primary channel belongs to, or `null`. */
export function blockOf(channel) {
  if (!Number.isFinite(channel)) return null
  return BLOCKS_5GHZ.find(block => block.channels.includes(channel)) ?? null
}

/**
 * Collapse a neighbour list into distinct occupancy, one row per
 * (band, width, primary channel).
 *
 * Deduplication must **not** include RSSI: a single AP whose signal wobbles
 * 1–2 dB between scan rounds otherwise counts as several APs. Conversely the
 * merge must prefer a *known* signal over an unknown one, because most beacons
 * carry no signal line at all — a naive `Math.max` over `null → 0` would make
 * the unknown entries win every time.
 *
 * @param neighbors - entries from `parseWifiReport`.
 * @returns rows sorted by band then channel, each with `samples` and `bestRssiDbm`.
 */
export function collapseNeighbors(neighbors) {
  const byKey = new Map()
  for (const entry of neighbors) {
    if (entry.channel === null) continue
    const key = `${entry.band}|${entry.widthMhz}|${entry.channel}`
    const row = byKey.get(key) ?? { band: entry.band, widthMhz: entry.widthMhz, channel: entry.channel, samples: 0, bestRssiDbm: UNKNOWN }
    row.samples += 1
    if (entry.rssiDbm !== null && (row.bestRssiDbm === null || entry.rssiDbm > row.bestRssiDbm)) {
      row.bestRssiDbm = entry.rssiDbm
    }
    byKey.set(key, row)
  }
  return [...byKey.values()].sort((a, b) => (a.band === b.band ? a.channel - b.channel : String(a.band).localeCompare(String(b.band))))
}

/**
 * Derive the channel plan a host can actually use, from its own report.
 *
 * Answers the questions that decide whether a wider channel is available at all:
 * which 80MHz blocks the regulatory domain permits, which of them neighbours are
 * already sitting on, and whether a 160MHz channel exists (it needs two adjacent
 * permitted blocks, so in CN that is 36–64 *including* DFS 52–64 — the only
 * option, with the mandatory radar check that implies).
 *
 * @param report - output of `parseWifiReport`.
 * @param options.band - band to analyse, default `5GHz`.
 * @returns block table plus the 160MHz verdict.
 */
export function summarizeChannels(report, { band = '5GHz' } = {}) {
  const iface = report.interfaces.find(candidate => candidate.supportedChannels.some(entry => entry.band === band))
    ?? report.interfaces[0]
  const supported = new Set((iface?.supportedChannels ?? []).filter(entry => entry.band === band).map(entry => entry.channel))
  const neighbors = collapseNeighbors(report.interfaces.flatMap(candidate => candidate.neighbors))
    .filter(entry => entry.band === band)

  const blocks = BLOCKS_5GHZ.map(block => {
    // An 80MHz block is usable only when the domain grants every 20MHz channel
    // in it; a country table that stops at 48 cannot carry 52–64.
    const permissive = block.channels.every(channel => supported.has(channel))
    const occupants = neighbors.filter(entry => block.channels.includes(entry.channel))
    return {
      primary: block.primary,
      channels: [...block.channels],
      span: `${block.channels[0]}-${block.channels[block.channels.length - 1]}`,
      dfs: block.dfs,
      permitted: permissive,
      occupants,
      occupied: occupants.length,
    }
  })

  // A 160MHz channel is exactly two adjacent 80MHz blocks, so it exists only if
  // the domain permits both halves. In CN that is 36-48 + 52-64 = 36-64, and the
  // DFS half is unavoidable — which is the whole argument against reaching for
  // 160MHz on a 5.8GHz-only-wide deployment.
  const permitted = blocks.filter(block => block.permitted)
  let pair = null
  for (let index = 0; index + 1 < permitted.length; index += 1) {
    const first = permitted[index]
    const second = permitted[index + 1]
    if (second.channels[0] === first.channels[3] + 4) {
      pair = { first, second }
      break
    }
  }

  return {
    band,
    interfaceName: iface?.name ?? null,
    permittedChannels: [...supported].sort((a, b) => a - b),
    blocks,
    width160: pair === null
      ? { possible: false, span: null, includesDfs: false, reason: `${band} 里没有两个相邻且被允许的 80MHz 块` }
      : {
          possible: true,
          span: `${pair.first.channels[0]}-${pair.second.channels[3]}`,
          includesDfs: pair.first.dfs || pair.second.dfs,
          reason: '160MHz 必须跨两个相邻 80MHz 块，其中含 DFS 段：需 60s CAC 静默期，且雷达命中即被迫换道',
        },
    widestVerdict: pair === null ? '80' : '160',
  }
}

/**
 * Parse the summary tail of `ping -q` (`round-trip min/avg/max/stddev = …`).
 *
 * @param text - captured stdout of `ping -c N -i I -q <host>`.
 * @returns `{ transmitted, received, lossPercent, minMs, avgMs, maxMs, stddevMs }`
 *   with `null` for every statistic ping did not print (a 100% loss run prints
 *   no round-trip line at all — reporting `0` there is the same invented-value
 *   bug as the 0 dBm one).
 */
export function parsePingStats(text) {
  const out = String(text ?? '')
  const counts = /(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received/u.exec(out)
  const timing = /=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/u.exec(out)
  const loss = /([\d.]+)%\s*packet loss/u.exec(out)
  const number = value => (value === undefined ? null : Number(value))
  return {
    transmitted: counts === null ? null : Number(counts[1]),
    received: counts === null ? null : Number(counts[2]),
    lossPercent: loss === null ? null : Number(loss[1]),
    minMs: timing === null ? null : number(timing[1]),
    avgMs: timing === null ? null : number(timing[2]),
    maxMs: timing === null ? null : number(timing[3]),
    stddevMs: timing === null ? null : number(timing[4]),
  }
}

/**
 * Parse a single `curl -w` speed sample.
 *
 * @param raw - the `%{speed_download}` value in bytes/second.
 * @returns bytes/second, or `null` when curl reported nothing (a failed
 *   transfer must not read as "0 B/s, successfully measured").
 */
export function parseSpeedSample(raw) {
  const value = Number(String(raw ?? '').trim())
  return Number.isFinite(value) && value > 0 ? value : null
}

// ── Linux（Ubuntu）后端 ──────────────────────────────────────────────────────
//
// macOS 的 `system_profiler` 在 Ubuntu 上不存在；Linux 侧用两张系统自带的表：
//   · `iw dev <if> link` —— 当前关联（频率、信号、tx/rx 速率、MCS）；
//   · `iw dev <if> scan dump` / `nmcli dev wifi list` —— 邻居（只读缓存，不触发扫描）。
// 解析器全部是纯函数（无 I/O），夹具在 scripts/tests/linux-portability.spec.mjs。

/**
 * `ping` 的超时/截止时间参数在 BSD（macOS）与 iputils（Linux）上**语义不同**：
 *
 *   · macOS：`-W` 是单包超时（毫秒），`-t` 是整轮截止时间（秒）；
 *   · Linux：`-W` 是单包超时（秒），`-w` 是整轮截止时间（秒），`-t` 是 **TTL**。
 *
 * 之前直接把 macOS 的 `-W 2000 -t 8` 搬到 Linux：`-W 2000` 变成 2000 秒超时，
 * `-t 8` 把 TTL 压到 8 跳 —— WAN 超过 8 跳就永远不通，而网关丢包时整条命令要挂很久。
 *
 * @param platform - `process.platform`（`darwin` / `linux` / 其他）。
 * @param host - 已校验的主机名或 IP 字面量。
 * @param count - 每轮包数。
 * @returns ping 的 argv 数组。
 */
export function pingArgv(platform, host, count) {
  const seconds = Math.max(8, Math.ceil(count * 0.4) + 4)
  if (platform === 'darwin') {
    return ['ping', '-c', String(count), '-i', '0.2', '-W', '2000', '-t', String(seconds), '-q', host]
  }
  // Linux / 其他 POSIX（iputils 形状）：单包 2s、整轮 seconds 秒。
  return ['ping', '-c', String(count), '-i', '0.2', '-W', '2', '-w', String(seconds), '-q', host]
}

/**
 * 可移植的「文件最后修改时间」shell 片段：GNU `stat -c %Y` 优先，BSD `stat -f %m` 兜底。
 *
 * 直接写 `stat -f %m` 在 GNU 上会打印**文件系统信息**并 exit 1；旧代码把它塞进
 * `$(( ... ))`，在 dash 里是语法错误 —— 整个 `status` 的后半段都不执行（不是只少一行）。
 *
 * @param quotedPath - 已经用单引号包好的路径。
 * @returns 一段可嵌进 `sh -c` 的命令替换。
 */
export function portableMtimeCommand(quotedPath) {
  return `stat -c %Y ${quotedPath} 2>/dev/null || stat -f %m ${quotedPath} 2>/dev/null || echo 0`
}

/**
 * Linux 上列监听套接字：`ss` 优先，`netstat` 兜底；都只取 TCP。
 *
 * `netstat -an` 在 Linux 上把 **unix socket** 也写成 `LISTENING`，而旧过滤只看
 * `includes('LISTEN')` —— 一张 80 行的表可能全是 unix socket，真正的 TCP 监听一个都没露出来。
 *
 * @param platform - `process.platform`。
 * @param text - `ss -ltnp` / `netstat -ltnp` / `netstat -an` 的 stdout。
 * @returns 只含 TCP 监听的行（保持原顺序）。
 */
export function filterListenerLines(platform, text) {
  const lines = String(text ?? '').split('\n').map(line => line.trim()).filter(Boolean)
  if (platform === 'linux') {
    return lines.filter(line => /\bLISTEN\b/iu.test(line) && /^(?:LISTEN|tcp|tcp6)\b/iu.test(line))
  }
  return lines.filter(line => /\bLISTEN\b/iu.test(line))
}

/** 从 `ss -ltnp` / `lsof` 的输出里取 PID（去重，保持出现顺序）。 */
export function listenerPids(text) {
  const pids = []
  for (const match of String(text ?? '').matchAll(/\bpid=(\d+)/gu)) pids.push(Number(match[1]))
  return [...new Set(pids)]
}

/** `iw dev` → `[{ name, phy }]`。 */
export function parseIwDev(text) {
  const interfaces = []
  let phy = null
  for (const line of String(text ?? '').split('\n')) {
    const phyLine = /^\s*phy#(\d+)\s*$/u.exec(line)
    if (phyLine !== null) {
      phy = `phy${phyLine[1]}`
      continue
    }
    const iface = /^\s*Interface\s+(\S+)\s*$/u.exec(line)
    if (iface !== null) interfaces.push({ name: iface[1], phy })
  }
  return interfaces
}

/** `iw reg get` → 国家码（`country CN:`）；`00`（未设）返回 null。 */
export function parseIwReg(text) {
  const match = /^\s*country\s+([A-Z0-9]{2}):/mu.exec(String(text ?? ''))
  if (match === null || match[1] === '00') return null
  return match[1]
}

/** 频率 → 信道号；不认识的频段返回 null。 */
export function channelOfFrequency(freq) {
  const value = Number(freq)
  if (!Number.isFinite(value)) return null
  if (value === 2484) return 14
  if (value >= 2412 && value <= 2472) return (value - 2407) / 5
  if (value >= 5000 && value < 5925) return (value - 5000) / 5
  if (value >= 5955 && value <= 7115) return (value - 5950) / 5
  return null
}

/** 信道号 → 报表里用的频段名（与 macOS 报表的 `2GHz` / `5GHz` 对齐）。 */
export function bandOfChannel(channel) {
  const value = Number(channel)
  if (!Number.isFinite(value)) return null
  if (value >= 1 && value <= 14) return '2GHz'
  if (value >= 32 && value <= 177) return '5GHz'
  if (value > 177 && value <= 233) return '6GHz'
  return null
}

/**
 * 频率 → 频段名。6GHz 的信道号从 1 重新开始，**只看信道号会把 6GHz ch1 认成 2.4GHz**
 * —— 有 freq 时一律以它为准，`bandOfChannel` 只在没有 freq 时兜底。
 */
export function bandOfFrequency(freq) {
  const value = Number(freq)
  if (!Number.isFinite(value)) return null
  if (value >= 2400 && value <= 2500) return '2GHz'
  if (value >= 5000 && value < 5925) return '5GHz'
  if (value >= 5925 && value <= 7125) return '6GHz'
  return null
}

/** `tx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2` → PHY 家族。 */
function phyOfRate(text) {
  const raw = String(text ?? '')
  if (/HE-MCS|HE-NSS|802\.11ax/iu.test(raw)) return '802.11ax'
  if (/VHT-MCS|VHT-NSS|802\.11ac/iu.test(raw)) return '802.11ac'
  if (/\bMCS \d+/u.test(raw) || /\b(?:40|20)MHz\b/u.test(raw)) return '802.11n'
  if (/\b(?:54|48|36|24|18|12|11|9|6|5\.5|2|1)\.?0? MBit\/s/u.test(raw)) return '802.11g'
  return null
}

/** 速率行里的宽度（`80MHz`）→ 数字；不认识返回 null。 */
function widthOfRate(text) {
  const match = /(\d+)\s*MHz/u.exec(String(text ?? ''))
  return match === null ? null : Number(match[1])
}

/** 速率行里的 MCS 号（`VHT-MCS 9` / `HE-MCS 11` / `MCS 15`）→ 数字。 */
function mcsOfRate(text) {
  const match = /(?:HE|VHT)?-?MCS\s+(\d+)/u.exec(String(text ?? ''))
  return match === null ? null : Number(match[1])
}

/**
 * `iw dev <if> link` → 与 macOS `parseNetworkEntry` 同形的当前链路记录。
 *
 * 返回 `null` 表示**没有关联**（`Not connected.`）—— 这是「没有数据」，不是「链路正常」。
 *
 * @param text - `iw dev <if> link` 的 stdout。
 * @param options.noiseDbm - 可选底噪（来自 `/proc/net/wireless`；Linux 的 iw 不给）。
 * @returns 链路记录，或 null。
 */
export function parseIwLink(text, { noiseDbm = null } = {}) {
  const raw = String(text ?? '')
  const connected = /^Connected to\s+([0-9a-f:]{17})/imu.exec(raw)
  if (connected === null) return null
  const field = key => new RegExp(`^\\s*${key}:\\s*(.*)$`, 'imu').exec(raw)?.[1]?.trim() ?? null
  const freq = Number(field('freq'))
  const channelLine = /^\s*channel:\s*(\d+)\s*\((\d+)\s*MHz\)(?:,\s*width:\s*(\d+)\s*MHz)?/imu.exec(raw)
  const txRateLine = /^\s*tx bitrate:\s*([\d.]+)\s*MBit\/s(.*)$/imu.exec(raw)
  const rxRateLine = /^\s*rx bitrate:\s*([\d.]+)\s*MBit\/s(.*)$/imu.exec(raw)
  const rateLine = txRateLine?.[0] ?? rxRateLine?.[0] ?? ''
  const signal = /^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm/imu.exec(raw)
  const rssi = signal === null ? null : (Number(signal[1]) === 0 ? null : Number(signal[1]))
  // 底噪的"没有测量"有两种写法：`0`，以及驱动的 `-256` 哨兵。把 -256 当真值会算出
  // `snr = -45 - (-256) = 211 dB` —— 一个物理上不可能的读数。（评审 2026-10-28）
  const noise = typeof noiseDbm === 'number' && Number.isFinite(noiseDbm) && noiseDbm !== 0 && noiseDbm > -256
    ? noiseDbm
    : null
  const channel = channelLine !== null
    ? Number(channelLine[1])
    : (Number.isFinite(freq) ? channelOfFrequency(freq) : null)
  const width = channelLine?.[3] !== undefined
    ? Number(channelLine[3])
    : widthOfRate(rateLine)
  return {
    phy: phyOfRate(rateLine),
    channel,
    band: bandOfFrequency(freq) ?? bandOfChannel(channel),
    widthMhz: width,
    security: null,
    rssiDbm: rssi,
    noiseDbm: noise,
    snrDb: rssi === null || noise === null ? null : rssi - noise,
    transmitRateMbps: txRateLine === null ? null : Number(txRateLine[1]),
    receiveRateMbps: rxRateLine === null ? null : Number(rxRateLine[1]),
    mcs: mcsOfRate(rateLine),
    ssid: field('SSID'),
    bssid: connected[1].toLowerCase(),
  }
}

/**
 * 一次记录仪样本的链路行 → 链路记录。
 *
 * macOS 的 `system_profiler` 片段按 `Key: value` 解析；Linux 的 `iw dev link` 片段按
 * `parseIwLink` 解析。两条路都产出同一形状，`readWatch` 因此不用知道样本来自哪个平台。
 */
export function parseLinkSample(text) {
  const raw = String(text ?? '')
  if (/^Connected to\s/mu.test(raw) || /^\s*tx bitrate:/mu.test(raw) || /^\s*freq:/mu.test(raw)) {
    return parseIwLink(raw) ?? parseNetworkEntry(raw.split('\n'))
  }
  return parseNetworkEntry(raw.split('\n'))
}

/**
 * `iw list` / `iw phy <phy> info` 的 `Frequencies:` 段 → 可用信道表。
 *
 * 跳过 `disabled`；`no IR` 仍算可用（客户端可以被动接收，只是不能主动发探测）。
 *
 * @param text - `iw list` 或 `iw phy … info` 的 stdout。
 * @returns `[{ channel, band }]`，按出现顺序去重。
 */
export function parseIwPhyChannels(text) {
  const seen = new Set()
  const channels = []
  let inFrequencies = false
  for (const line of String(text ?? '').split('\n')) {
    if (/^\s*Frequencies:\s*$/u.test(line)) { inFrequencies = true; continue }
    if (!inFrequencies) continue
    if (/^\s*valid interface combinations:/u.test(line)) break
    if (/^\s*[A-Za-z][A-Za-z ]+:\s*$/u.test(line) && !/^\s*\*/u.test(line)) { inFrequencies = false; continue }
    const match = /^\s*\*\s*(\d+)\s*MHz\s*\[(\d+)\](.*)$/u.exec(line)
    if (match === null) continue
    if (/\bdisabled\b/iu.test(match[3])) continue
    const channel = Number(match[2])
    const band = bandOfFrequency(Number(match[1])) ?? bandOfChannel(channel)
    // 去重键**必须带频段**：6GHz 的信道号从 1 重新开始（5975MHz == ch5），只按数字去重会把
    // 6GHz 的 1–14 整段吞掉 —— 而它们恰恰是 6E 上唯一能用的那一段。
    const key = `${band}|${channel}`
    if (seen.has(key)) continue
    seen.add(key)
    channels.push({ channel, band })
  }
  return channels
}

/**
 * `iw dev <if> scan dump` → 邻居列表（与 `parseWifiReport` 的 neighbors 同形）。
 *
 * 只读**已有**扫描缓存；不发探测请求，所以不会出现「工具把空口扫卡了」。
 *
 * @param text - `iw dev <if> scan dump` 的 stdout。
 * @returns 网络记录数组。
 */
export function parseIwScanNeighbors(text) {
  const blocks = []
  let lines = null
  const flush = () => {
    if (lines === null) return
    blocks.push(lines)
    lines = null
  }
  for (const line of String(text ?? '').split('\n')) {
    if (/^BSS\s+[0-9a-f:]{17}/iu.test(line)) {
      flush()
      lines = [line]
      continue
    }
    if (lines !== null) lines.push(line)
  }
  flush()
  const neighbors = []
  for (const block of blocks) {
    const body = block.join('\n')
    const freq = Number(/^\s*freq:\s*(\d+)/imu.exec(body)?.[1])
    const dsChannel = /DS Parameter set:\s*channel\s+(\d+)/iu.exec(body)?.[1]
    const primary = /\*\s*primary channel:\s*(\d+)/iu.exec(body)?.[1]
    const channel = Number(dsChannel ?? primary ?? (Number.isFinite(freq) ? channelOfFrequency(freq) : NaN))
    if (!Number.isFinite(channel)) continue
    let width = null
    const widthMhz = /\*\s*channel width:\s*(\d+)\s*MHz/iu.exec(body)
    const widthCode = /\*\s*channel width:\s*(\d+)(?:\s*\((\d+)\s*MHz\))?/iu.exec(body)
    if (widthMhz !== null) width = Number(widthMhz[1])
    else if (widthCode !== null) {
      // iw 的 VHT 宽码（0=20 / 1=40 / 2=80 / 3=160）**不能**直接当 MHz 用；不打括号 MHz 时
      // 只有码号，宁可报"未知"（null），也不要猜一个数出来（旧表把 1 当 80，与码表相反）。
      width = widthCode[2] !== undefined ? Number(widthCode[2]) : null
    } else if (/secondary channel offset:\s*(?:above|below)/iu.test(body)) {
      width = 40
    }
    const signal = /^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm/imu.exec(body)
    const rssi = signal === null ? null : (Number(signal[1]) === 0 ? null : Number(signal[1]))
    neighbors.push({
      phy: /HE Operation|HE capabilities/iu.test(body) ? '802.11ax' : /VHT Operation|VHT capabilities/iu.test(body) ? '802.11ac' : /HT Operation|HT capabilities/iu.test(body) ? '802.11n' : null,
      channel,
      band: bandOfFrequency(freq) ?? bandOfChannel(channel),
      widthMhz: width,
      security: /RSN:/u.test(body) ? 'WPA2/WPA3' : /WPA:/u.test(body) ? 'WPA' : null,
      rssiDbm: rssi,
      noiseDbm: null,
      snrDb: null,
      transmitRateMbps: null,
      mcs: null,
    })
  }
  return neighbors
}

/**
 * `nmcli -t -f CHAN,FREQ,SIGNAL dev wifi list --rescan no` → 邻居列表。
 *
 * nmcli 不报带宽 ⇒ `widthMhz: null`（未知，不是 20）。占用仍按主信道计入 80MHz 块；
 * 输出里必须把这个限制写出来，别把「未知带宽」当成「窄带」。
 *
 * `SIGNAL` 列是 **0–100 的质量百分比**，不是 dBm：直接写进 `rssiDbm` 会报出 `+70 dBm`
 * （物理上不可能，而且会与 `iw` 来源的真实负 dBm 混在同一字段里比较 —— 后者才是"谁更强"
 * 的依据）。所以 `rssiDbm` 恒为 null、质量值单独进 `quality`，调用方的 note 必须说明
 * dBm 不可得。
 *
 * @param text - nmcli 的 stdout。
 * @returns 网络记录数组（`rssiDbm` 恒 null，`quality` 是 0–100 或 null）。
 */
export function parseNmcliNeighbors(text) {
  const neighbors = []
  for (const line of String(text ?? '').split('\n')) {
    if (line.trim() === '') continue
    const [rawChannel, rawFreq, rawSignal] = line.split(':')
    const freq = Number.parseInt(String(rawFreq ?? '').replace(/[^\d]/gu, ''), 10)
    let channel = Number.parseInt(String(rawChannel ?? ''), 10)
    if (!Number.isFinite(channel) && Number.isFinite(freq)) channel = channelOfFrequency(freq)
    if (!Number.isFinite(channel)) continue
    const quality = Number(rawSignal)
    neighbors.push({
      phy: null,
      channel,
      band: bandOfFrequency(freq) ?? bandOfChannel(channel),
      widthMhz: null,
      security: null,
      rssiDbm: null,
      quality: Number.isFinite(quality) && quality > 0 ? quality : null,
      noiseDbm: null,
      snrDb: null,
      transmitRateMbps: null,
      mcs: null,
    })
  }
  return neighbors
}

/**
 * `/proc/net/wireless` 的底噪列 → dBm；**没有测量**返回 null。
 *
 * 两种写法都表示"驱动没报"：`0`，以及 `-256`（内核 docs 与实测都见到）。把 -256 当
 * 真实底噪会算出 200 多 dB 的信噪比 —— 比"没有数据"更糟，因为它看起来像一个读数。
 */
export function parseProcNetWireless(text, iface) {
  for (const line of String(text ?? '').split('\n')) {
    // 形状：`wlp3s0: 0000   70.  -30.  -256 ...`（level / noise 带尾点）。
    const match = /^\s*([^:]+):\s*[0-9a-f]+\s+([0-9a-f.]+)\s+(-?\d+)\.?\s+(-?\d+)\.?/iu.exec(line)
    if (match === null || (iface !== undefined && match[1].trim() !== iface)) continue
    const noise = Number(match[4])
    return noise === 0 || noise <= -256 ? null : noise
  }
  return null
}
