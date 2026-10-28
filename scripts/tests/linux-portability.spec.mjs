/**
 * Linux（Ubuntu）可移植性门禁 —— **纯函数、不装依赖、不起进程**。
 *
 * 2026-10 在 Ubuntu 24.04 上实测出的平台差异，每一条都对应一次真实故障：
 *   · `ping -W 2000 -t 8` 在 Linux 上变成"2000 秒单包超时 + TTL 8"；
 *   · `nc -z -G 1` 在 OpenBSD netcat 上是非法选项 ⇒ 所有端口误报 no-response；
 *   · `stat -f%z` 在 GNU 上是"显示文件系统" ⇒ bx_har 把存在的文件报成不存在；
 *   · `security verify-cert` / `networksetup` / `scutil` 在 Ubuntu 上不存在；
 *   · `system_profiler` 在 Ubuntu 上不存在 ⇒ 无线两个工具完全没有数据源。
 *
 * 这里只钉**可测的纯逻辑**；真机端到端由 `scripts/verify.mjs` 之外的 Ubuntu 手测补。
 *
 * @returns 检查结果数组 `{ name, ok, detail? }`。
 */

import {
  filterListenerLines,
  listenerPids,
  parseIwDev,
  parseIwLink,
  parseIwPhyChannels,
  parseIwReg,
  parseIwScanNeighbors,
  parseLinkSample,
  parseNmcliNeighbors,
  parseProcNetWireless,
  parsePingStats,
  pingArgv,
  portableMtimeCommand,
} from '../../tools/dsh-plugin-fly-diag/wifi.js'
import { ncProbeArgs } from '../../tools/dsh-plugin-fly-recon/platform.js'
import {
  caInstallLines,
  caTrustNote,
  caVerifyArgv,
  gnomeProxyOffCommands,
  gnomeProxyOnCommands,
  listenerLinesForPort,
  listenerListArgv,
  listenerPidOfLine,
  mitmInstallLines,
  parseGsettingsValue,
  parseStatSize,
  statSizeArgv,
} from '../../tools/dsh-plugin-fly-blackbox/platform.js'

const IW_DEV = `phy#0
	Interface wlp3s0
		ifindex 3
		wdev 0x1
		addr 00:11:22:33:44:55
		type managed
phy#1
	Interface wlp4s0
		ifindex 4
		type managed
`

const IW_LINK = `Connected to 66:77:88:99:aa:bb (on wlp3s0)
	SSID: LabNet
	freq: 5180
	signal: -45 dBm
	rx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2
	tx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
`

const IW_PHY = `	Band 2:
		Frequencies:
			* 5180 MHz [36] (23.0 dBm)
			* 5200 MHz [40] (23.0 dBm)
			* 5220 MHz [44] (23.0 dBm)
			* 5240 MHz [48] (23.0 dBm)
			* 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
			* 5280 MHz [56] (20.0 dBm) (no IR, radar detection)
			* 5745 MHz [149] (23.0 dBm)
			* 5825 MHz [165] (disabled)
`

const IW_SCAN = `BSS 66:77:88:99:aa:01(on wlp3s0)
	freq: 5180
	signal: -45.00 dBm
	DS Parameter set: channel 36
	HT operation:
		* primary channel: 36
		* secondary channel offset: above
	VHT operation:
		* channel width: 1 (80 MHz)
BSS 66:77:88:99:aa:02(on wlp3s0)
	freq: 5745
	signal: -60.00 dBm
	DS Parameter set: channel 149
	VHT operation:
		* channel width: 1 (80 MHz)
`

const SS_LTNP = `State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      4096   127.0.0.1:31443      0.0.0.0:*
LISTEN 0      4096   127.0.0.1:8080       0.0.0.0:*    users:(("mitmdump",pid=4242,fd=3))
`
const NETSTAT_AN = `Active Internet connections (servers and established)
tcp        0      0 127.0.0.1:31443         0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
unix  2      [ ACC ]     STREAM     LISTENING     12884    /run/user/1000/gnupg/S.gpg-agent
`

const GSETTINGS = `'none'
''
8080
`

/**
 * 跑全部可移植性检查。
 *
 * @returns 检查结果数组。
 */
export function runLinuxPortabilityChecks() {
  const checks = []
  const check = (name, fn) => {
    try {
      fn()
      checks.push({ name, ok: true })
    } catch (error) {
      checks.push({ name, ok: false, detail: error.message })
    }
  }

  check('ping 参数按平台分派（Linux 不用 macOS 的 -W 毫秒 / -t 截止）', () => {
    const linux = pingArgv('linux', '10.0.0.1', 4)
    const mac = pingArgv('darwin', '10.0.0.1', 4)
    if (linux.includes('-t')) throw new Error(`Linux 参数里不该有 -t（TTL）：${linux.join(' ')}`)
    if (!linux.includes('-w')) throw new Error(`Linux 参数缺 -w 截止时间：${linux.join(' ')}`)
    if (linux[linux.indexOf('-W') + 1] !== '2') throw new Error(`Linux 的 -W 应是秒（2）：${linux.join(' ')}`)
    if (mac[mac.indexOf('-W') + 1] !== '2000') throw new Error(`macOS 的 -W 应是毫秒（2000）：${mac.join(' ')}`)
    if (mac[mac.indexOf('-t') + 1] !== '8') throw new Error(`macOS 的 -t 应是整轮秒数（8）：${mac.join(' ')}`)
  })

  check('watch 的 mtime 命令可移植（GNU -c / BSD -f 都带）', () => {
    const command = portableMtimeCommand('"/tmp/x"')
    if (!command.includes('stat -c %Y')) throw new Error(`缺 GNU 分支：${command}`)
    if (!command.includes('stat -f %m')) throw new Error(`缺 BSD 分支：${command}`)
    if (!command.includes('|| echo 0')) throw new Error(`缺兜底：${command}`)
  })

  check('Linux 监听表只留 TCP LISTEN（unix socket 不冒充 listener）', () => {
    const lines = filterListenerLines('linux', NETSTAT_AN)
    if (lines.some(line => line.startsWith('unix'))) throw new Error(`unix socket 混进来了：${lines.join(' | ')}`)
    if (!lines.some(line => line.includes('127.0.0.1:31443'))) throw new Error('TCP 监听行丢了')
    if (lines.length !== 2) throw new Error(`期望 2 条 TCP，得到 ${lines.length}`)
  })

  check('ss 输出里能取到 pid', () => {
    const pids = listenerPids(SS_LTNP)
    if (pids.length !== 1 || pids[0] !== 4242) throw new Error(`pid 解析错：${JSON.stringify(pids)}`)
  })

  check('iw dev 解析接口与 phy', () => {
    const interfaces = parseIwDev(IW_DEV)
    if (interfaces.length !== 2) throw new Error(`期望 2 个接口，得到 ${interfaces.length}`)
    if (interfaces[0].name !== 'wlp3s0' || interfaces[0].phy !== 'phy0') throw new Error(JSON.stringify(interfaces[0]))
  })

  check('iw reg get 解析国家码（00 视为未设）', () => {
    if (parseIwReg('global\ncountry CN: DFS-ETSI\n') !== 'CN') throw new Error('CN 没解出来')
    if (parseIwReg('global\ncountry 00: DFS-UNSET\n') !== null) throw new Error('00 应视为未设')
  })

  check('iw dev link 解析出 5GHz / 80MHz / 866.7 / MCS 9', () => {
    const link = parseIwLink(IW_LINK)
    if (link === null) throw new Error('应解析成已连接')
    const want = { phy: '802.11ac', channel: 36, band: '5GHz', widthMhz: 80, rssiDbm: -45, transmitRateMbps: 866.7, mcs: 9 }
    for (const [key, value] of Object.entries(want)) {
      if (link[key] !== value) throw new Error(`${key}: 期望 ${value}，得到 ${JSON.stringify(link[key])}`)
    }
    if (parseIwLink('Not connected.') !== null) throw new Error('未连接应返回 null')
  })

  check('iw phy 的频率表解析出可用信道（disabled 排除）', () => {
    const channels = parseIwPhyChannels(IW_PHY).map(entry => entry.channel)
    for (const wanted of [36, 40, 44, 48, 52, 56, 149]) {
      if (!channels.includes(wanted)) throw new Error(`缺信道 ${wanted}：${channels.join(',')}`)
    }
    if (channels.includes(165)) throw new Error('disabled 的 165 不该出现')
    if (parseIwPhyChannels(IW_PHY).find(entry => entry.channel === 52)?.band !== '5GHz') throw new Error('52 的频段不是 5GHz')
  })

  check('iw scan dump 解析出邻居（带宽 80 / 主信道 36、149）', () => {
    const neighbors = parseIwScanNeighbors(IW_SCAN)
    if (neighbors.length !== 2) throw new Error(`期望 2 个邻居，得到 ${neighbors.length}`)
    const first = neighbors.find(entry => entry.channel === 36)
    if (first === undefined) throw new Error('36 信道邻居丢了')
    if (first.widthMhz !== 80) throw new Error(`36 的带宽应是 80，得到 ${first.widthMhz}`)
    if (first.rssiDbm !== -45) throw new Error(`36 的信号应是 -45，得到 ${first.rssiDbm}`)
    if (neighbors.find(entry => entry.channel === 149)?.widthMhz !== 80) throw new Error('149 的带宽应是 80')
  })

  check('nmcli 邻居解析：带宽未知必须是 null（不是 20）', () => {
    const neighbors = parseNmcliNeighbors('36:5180 MHz:70\n149:5745 MHz:55\n')
    if (neighbors.length !== 2) throw new Error(`期望 2 个邻居，得到 ${neighbors.length}`)
    if (neighbors[0].widthMhz !== null) throw new Error(`nmcli 不报带宽，应为 null，得到 ${neighbors[0].widthMhz}`)
    if (neighbors[0].rssiDbm !== 70) throw new Error('信号没解出来')
    const six = parseNmcliNeighbors('5:5975 MHz:70\n')
    if (six[0]?.band !== '6GHz') throw new Error(`6GHz ch5 被认成 ${six[0]?.band}（只看信道号会撞上 2.4GHz）`)
  })

  check('/proc/net/wireless 底噪解析（0 是"没有测量"）', () => {
    const fixture = 'wlp3s0: 0000   70.  -45.  -90.        0      0      0      0      0        0\n'
    if (parseProcNetWireless(fixture, 'wlp3s0') !== -90) throw new Error('底噪没解出来')
    if (parseProcNetWireless('wlp3s0: 0000   70.  -45.  0.  0 0 0 0 0 0\n', 'wlp3s0') !== null) throw new Error('0 应视为没有测量')
  })

  check('记录仪样本在 Linux 上按 iw 形状解析', () => {
    const link = parseLinkSample(IW_LINK)
    if (link.channel !== 36 || link.widthMhz !== 80) throw new Error(`样本解析错：${JSON.stringify(link)}`)
  })

  check('Linux 的 ping 统计行能解析（packets received / rtt 行）', () => {
    const stats = parsePingStats('4 packets transmitted, 4 received, 0% packet loss, time 3004ms\nrtt min/avg/max/mdev = 0.500/0.800/1.200/0.200 ms\n')
    if (stats.avgMs !== 0.8 || stats.received !== 4) throw new Error(JSON.stringify(stats))
  })

  check('nc 参数按平台分派（Linux 不能带 -G）', () => {
    const linux = ncProbeArgs('linux', '127.0.0.1', 22)
    const mac = ncProbeArgs('darwin', '127.0.0.1', 22)
    if (linux.includes('-G')) throw new Error(`Linux 参数不该含 -G：${linux.join(' ')}`)
    if (!mac.includes('-G')) throw new Error(`macOS 参数应含 -G：${mac.join(' ')}`)
    if (linux.at(-1) !== '22' || linux.at(-2) !== '127.0.0.1') throw new Error(`目标/端口位置错：${linux.join(' ')}`)
  })

  check('stat 字节数参数按平台分派，输出取最后纯数字行', () => {
    if (statSizeArgv('linux', '/x').join(' ') !== 'stat -c%s /x') throw new Error(statSizeArgv('linux', '/x').join(' '))
    if (statSizeArgv('darwin', '/x').join(' ') !== 'stat -f%z /x') throw new Error(statSizeArgv('darwin', '/x').join(' '))
    if (parseStatSize('File: /x\n123\n') !== 123) throw new Error('字节数没解出来')
  })

  check('监听查询按平台分派，按端口过滤', () => {
    if (listenerListArgv('linux')[0] !== 'ss') throw new Error('Linux 应优先 ss')
    if (listenerListArgv('darwin')[0] !== 'lsof') throw new Error('macOS 应用 lsof')
    const lines = listenerLinesForPort('linux', SS_LTNP, 8080)
    if (lines.length !== 1) throw new Error(`按端口过滤错：${lines.length}`)
    if (listenerPidOfLine('linux', lines[0]) !== 4242) throw new Error('PID 没解出来')
  })

  check('CA 校验/安装命令按平台分派（Linux 用 openssl + update-ca-certificates）', () => {
    const linuxVerify = caVerifyArgv('linux', '/tmp/ca.pem').join(' ')
    if (!linuxVerify.startsWith('openssl verify')) throw new Error(linuxVerify)
    if (caVerifyArgv('darwin', '/tmp/ca.pem').join(' ') !== "security verify-cert -c /tmp/ca.pem") throw new Error('macOS 校验命令错')
    const install = caInstallLines('/tmp/ca.pem').join('\n')
    if (!install.includes('update-ca-certificates')) throw new Error('缺 update-ca-certificates')
    if (install.includes('security add-trusted-cert')) throw new Error('Linux 指引里混进了 macOS 命令')
    if (!caTrustNote('linux').includes('openssl verify')) throw new Error('Linux 的说明没指向 openssl')
  })

  check('gsettings 值解析（GVariant 引号 / 整数）', () => {
    if (parseGsettingsValue("'127.0.0.1'\n") !== '127.0.0.1') throw new Error('字符串没解出来')
    if (parseGsettingsValue('8080\n') !== '8080') throw new Error('整数没解出来')
    if (parseGsettingsValue("''\n") !== '') throw new Error('空串没解出来')
  })

  check('GNOME 代理写入顺序：先 host/port，最后才切 mode=manual', () => {
    const commands = gnomeProxyOnCommands(8080).map(argv => argv.join(' '))
    if (commands.at(-1) !== 'gsettings set org.gnome.system.proxy mode manual') throw new Error(`最后一条应是 mode：${commands.at(-1)}`)
    if (!commands.some(command => command.includes('org.gnome.system.proxy.http port 8080'))) throw new Error('http 端口没写')
    if (!commands.some(command => command.includes('org.gnome.system.proxy.https host 127.0.0.1'))) throw new Error('https host 没写')
    if (gnomeProxyOffCommands()[0].join(' ') !== 'gsettings set org.gnome.system.proxy mode none') throw new Error('关闭命令错')
  })

  check('mitmdump 安装指引按平台分派（Ubuntu 不再给 Homebrew 路径）', () => {
    const linux = mitmInstallLines('linux').join('\n')
    if (linux.includes('/opt/homebrew')) throw new Error('Linux 指引里混进了 Homebrew 路径')
    if (!linux.includes('python3 -m venv') || !linux.includes('FLY_MITM_BIN')) throw new Error('Linux 指引缺 venv / FLY_MITM_BIN')
    const mac = mitmInstallLines('darwin').join('\n')
    if (!mac.includes('/opt/homebrew/bin/python3.14')) throw new Error('macOS 原有指引被改坏了')
  })

  return checks
}
