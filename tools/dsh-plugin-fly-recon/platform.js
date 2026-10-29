/**
 * fly-recon 的平台差异（纯函数，无 I/O、无依赖）。
 *
 * 为什么单独一个文件：`nc` 的选项在 BSD（macOS）与 OpenBSD netcat（Ubuntu）上不一致，
 * 而这条差异**不能**靠"跑一遍试试"发现 —— 旧代码在 Linux 上把 `-G 1` 交给 nc，
 * nc 直接 `invalid option -- 'G'` 退出，`if nc …; then` 全部走 else，
 * 于是**每一个端口都被报成 no-response**（一个假阴性，读起来却像真扫描）。
 *
 * 解析器/命令构造放在这里，门禁 `scripts/verify.mjs` 可以不起进程、不装依赖地钉住它们。
 */

/**
 * 一次 TCP connect 探测的 argv。
 *
 * @param platform - `process.platform`。
 * @param host - 已校验的主机名或 IP 字面量。
 * @param port - 端口号。
 * @returns nc 的 argv 数组。
 */
export function ncProbeArgs(platform, host, port) {
  const args = ['nc', '-z']
  // macOS 的 nc（BSD）用 -G 设连接超时；OpenBSD netcat 没有 -G（有 -w 秒级超时）。
  if (platform === 'darwin') args.push('-G', '1')
  args.push('-w', '1', String(host), String(port))
  return args
}

/**
 * 缺 `nc` 时的可行动提示。
 *
 * @param platform - `process.platform`。
 * @returns 给人看的安装/替代建议。
 */
export function ncInstallHint(platform) {
  if (platform === 'linux') {
    return 'Ubuntu 上装一个：sudo apt install netcat-openbsd（或装 nmap 走完整扫描）。'
  }
  if (platform === 'darwin') {
    return 'macOS 自带 /usr/bin/nc；PATH 里找不到它时要检查是否被别的工具覆盖了。'
  }
  return '装 nc（netcat）或 nmap 后重试。'
}
