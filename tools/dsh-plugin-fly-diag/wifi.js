/**
 * Link-layer report parsing for the `fly-diag` tool face.
 *
 * Pure functions only — no I/O, no `ctx`, no clock, no `system_profiler` call.
 * The collector commands live in `index.js`; this module turns their stdout into
 * numbers. The split exists for one reason: the tool face is only as honest as
 * this file, and this file can be pinned against captured fixtures
 * (`scripts/tests/wifi-report.spec.mjs`) instead of against whatever radio the
 * host running the gate happens to have.
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
