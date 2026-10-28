/**
 * fly-blackbox 的平台差异（纯函数，无 I/O、无依赖）。
 *
 * 这个包原本按 macOS 写死：`stat -f%z`、`security verify-cert`、`networksetup`、
 * `scutil`、Homebrew 的 `/opt/homebrew/bin/python3.14`。在 Ubuntu 上这些不是
 * "命令失败"就是"返回了另一种东西"，而失败会在工具层被读成业务结论
 * （`bx_har`：文件不存在；`bx_ca`：证书不可信；`bx_proxy`：装错解释器）。
 *
 * 可测的差异全部放这里，`scripts/verify.mjs` 不装依赖就能钉住。
 */

/** 单引号 shell 引用（与各 index.js 里的 shq 同义，避免为纯函数引入依赖）。 */
export function shq(value) {
  return `'${String(value).replace(/'/gu, "'\\''")}'`
}

/**
 * 「文件有多少字节」的 stat argv。
 *
 * GNU `stat -f%z` 不是"格式 %z"——`-f` 是显示文件系统，`%z` 是无效格式；
 * Ubuntu 上直接 `stat: 无效的选项 -- %` 并且 exit 1。BSD 反过来不认 `-c`。
 *
 * @param platform - `process.platform`。
 * @param path - 文件路径。
 * @returns stat 的 argv。
 */
export function statSizeArgv(platform, path) {
  return platform === 'darwin'
    ? ['stat', '-f%z', path]
    : ['stat', '-c%s', path]
}

/** 从 stat 输出里取字节数（BSD 根目录会多一行 `File: …`，所以取最后一个纯数字行）。 */
export function parseStatSize(stdout) {
  const lines = String(stdout ?? '').split('\n').map(line => line.trim()).filter(Boolean)
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (/^\d+$/u.test(lines[index])) return Number(lines[index])
  }
  return null
}

/**
 * 列本机 TCP 监听：Linux 用 `ss -ltnp`，macOS 用 `lsof`。
 *
 * @param platform - `process.platform`。
 * @returns 命令 argv（返回全部监听，调用方再按端口过滤）。
 */
export function listenerListArgv(platform) {
  return platform === 'darwin'
    ? ['lsof', '-nP', '-iTCP', '-sTCP:LISTEN']
    : ['ss', '-ltnp']
}

/**
 * 从 `ss -ltnp` / `lsof` 的输出里挑出监听指定端口的行。
 *
 * @param platform - `process.platform`。
 * @param text - 命令 stdout。
 * @param port - 端口号。
 * @returns 行数组（已 trim、去表头）。
 */
export function listenerLinesForPort(platform, text, port) {
  const lines = String(text ?? '').split('\n').map(line => line.trim()).filter(Boolean)
  if (platform === 'darwin') {
    return lines.filter(line => line !== '' && !/^COMMAND\s/u.test(line) && new RegExp(`:${port}\\b`, 'u').test(line))
  }
  return lines.filter(line => /^LISTEN\b/u.test(line) && new RegExp(`:${port}(?:\\s|$)`, 'u').test(line))
}

/**
 * 从一行监听记录里取 PID。
 *
 * `ss -ltnp` 的形状是 `users:(("mitmdump",pid=123,fd=3))`；`lsof` 的 PID 在第二列。
 *
 * @param platform - `process.platform`。
 * @param line - 一行输出。
 * @returns PID，或 null。
 */
export function listenerPidOfLine(platform, line) {
  if (platform === 'darwin') {
    const fields = String(line ?? '').trim().split(/\s+/u)
    const pid = Number(fields[1])
    return Number.isInteger(pid) && pid > 0 ? pid : null
  }
  const match = /\bpid=(\d+)/u.exec(String(line ?? ''))
  return match === null ? null : Number(match[1])
}

/** Debian/Ubuntu 的系统 CA bundle；`SSL_CERT_FILE` 可覆盖。 */
export function caBundlePath() {
  const configured = process.env.SSL_CERT_FILE
  return typeof configured === 'string' && configured.trim() !== ''
    ? configured.trim()
    : '/etc/ssl/certs/ca-certificates.crt'
}

/**
 * 校验 CA 是否已被系统信任的 argv。
 *
 * Linux 用 `openssl verify -CAfile <系统 bundle> <ca>`：CA 若已在 bundle 里，自签名证书
 * 会验成 OK；不在则报 `self-signed certificate`（exit 2）。
 *
 * @param platform - `process.platform`。
 * @param caPem - CA 的 PEM 路径。
 * @returns argv。
 */
export function caVerifyArgv(platform, caPem) {
  return platform === 'darwin'
    ? ['security', 'verify-cert', '-c', caPem]
    : ['openssl', 'verify', '-CAfile', caBundlePath(), caPem]
}

/** 给人复制（**绝不执行**）的 Linux 信任安装命令。 */
export function caInstallLines(caPem) {
  const quoted = shq(caPem)
  return [
    `sudo cp ${quoted} /usr/local/share/ca-certificates/mitmproxy.crt`,
    'sudo update-ca-certificates',
    '',
    '# Chromium/Chrome 用 NSS 库，不读系统 bundle（可选；没有 certutil 就先装 libnss3-tools）：',
    'mkdir -p "$HOME/.pki/nssdb"',
    `certutil -d sql:"$HOME/.pki/nssdb" -A -t "C,," -n mitmproxy -i ${quoted}`,
    '',
    `# 跑完用 bx_ca verify 取事后证据（openssl verify 的退出码 + 指纹）。`,
    `# 还原：sudo rm /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates --fresh`,
    `#        （NSS）certutil -d sql:"$HOME/.pki/nssdb" -D -n mitmproxy`,
  ]
}

/** Linux CA 校验的说明（macOS 的 security verify-cert 在 Ubuntu 上不存在）。 */
export function caTrustNote(platform) {
  return platform === 'darwin'
    ? '证据：security verify-cert -c <CA> 的退出码。'
    : '证据：openssl verify -CAfile ' + caBundlePath() + ' <CA> 的退出码（0=系统 bundle 信任它）。'
}

/**
 * 缺 mitmdump 时的安装指引（按平台）。
 *
 * @param platform - `process.platform`。
 * @returns 多行文本。
 */
export function mitmInstallLines(platform) {
  if (platform === 'darwin') {
    return [
      '装上它（两行，点名解释器很重要）：',
      '  /opt/homebrew/bin/python3.14 -m venv .venv-mitm',
      '  .venv-mitm/bin/pip install -i https://pypi.org/simple mitmproxy',
      '',
      '为什么必须点名 /opt/homebrew/bin/python3.14：本机 pip3 是 3.9.6，直接 `pip3 install mitmproxy`',
      '只会得到 9.0.1，而它写的 dump 格式与 12.x 不同（读取器会按版本闸拒绝）。',
    ]
  }
  return [
    '装上它（Ubuntu；mitmproxy 需要 Python 3.11+，别用系统 pip 直接装）：',
    '  sudo apt install -y python3-venv        # 只需一次（Ubuntu 24.04 默认不带 venv）',
    '  python3 -m venv .venv-mitm',
    '  .venv-mitm/bin/pip install -i https://pypi.org/simple mitmproxy',
    '',
    '让工具找到它（二选一；设完要**重启 dsh 进程**，工具读的是宿主 env）：',
    '  export FLY_MITM_BIN="$PWD/.venv-mitm/bin/mitmdump"',
    '  # 或：pipx install mitmproxy（pipx 在 PATH 里时可直接被找到）',
    '',
    '检查：`.venv-mitm/bin/mitmdump --version` 应报 12.x（dump 格式与读取器匹配）。',
  ]
}

/**
 * GNOME 系统代理（`gsettings`）的读取键。
 *
 * 只覆盖 GNOME/NetworkManager 环境；其它桌面（KDE 等）不读这些键，所以状态输出里
 * 必须写明 backend，不能冒充"系统代理"。
 */
export const GNOME_PROXY_KEYS = Object.freeze({
  mode: 'org.gnome.system.proxy mode',
  httpHost: 'org.gnome.system.proxy.http host',
  httpPort: 'org.gnome.system.proxy.http port',
  httpsHost: 'org.gnome.system.proxy.https host',
  httpsPort: 'org.gnome.system.proxy.https port',
})

/**
 * `gsettings get` 的 stdout → 值。
 *
 * 字符串型是 `'127.0.0.1'`（GVariant 引号），整数型是 `8080`（无引号）。
 *
 * @param text - gsettings 的 stdout。
 * @returns 去掉 GVariant 引号后的字符串。
 */
export function parseGsettingsValue(text) {
  const raw = String(text ?? '').trim()
  if (raw.length >= 2 && raw.startsWith("'") && raw.endsWith("'")) {
    return raw.slice(1, -1).replace(/\\'/gu, "'")
  }
  if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) {
    return raw.slice(1, -1).replace(/\\"/gu, '"')
  }
  return raw
}

/**
 * 把 GNOME 代理指向本机端口的 argv 列表（按顺序执行）。
 *
 * 先写 host/port，最后才把 mode 切到 manual —— 反过来会有一瞬间代理指向空主机。
 *
 * @param port - 本机代理端口。
 * @returns argv 数组的数组。
 */
export function gnomeProxyOnCommands(port) {
  return [
    ['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', '127.0.0.1'],
    ['gsettings', 'set', 'org.gnome.system.proxy.http', 'port', String(port)],
    ['gsettings', 'set', 'org.gnome.system.proxy.https', 'host', '127.0.0.1'],
    ['gsettings', 'set', 'org.gnome.system.proxy.https', 'port', String(port)],
    ['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual'],
  ]
}

/** 关掉 GNOME 代理的 argv 列表。 */
export function gnomeProxyOffCommands() {
  return [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none']]
}

/** 关掉 GNOME 代理的还原命令（一行，随时可复制）。 */
export function gnomeProxyRestoreCommand() {
  return "gsettings set org.gnome.system.proxy mode 'none'"
}

/** "改完代理要重启客户端"的提示（macOS 用 ⌘Q，Linux 用正常退出）。 */
export function quitHint(platform) {
  return platform === 'darwin'
    ? '改完系统代理要 **⌘Q 那个客户端再开**（WeChatAppEx 只在启动时读系统代理）。'
    : '改完系统代理要**完全退出那个客户端再开**（很多客户端只在启动时读系统代理）。'
}
