import { defineTool } from '@deepseek-ai/dsh-tools'

import { ncInstallHint, ncProbeArgs } from './platform.js'

/**
 * fly-recon — policy-gated recon tools.
 * Default posture: deny unless FLY_ALLOW_RECON=1 (authorization explicit).
 *
 * One apply() registers BOTH the `tools/pre-execute` guard (a Waterfall whose
 * decision is { kind: "allow" | "deny" }) and the two recon tools. It must be
 * mounted exactly once — as a single agent-preset row — or the tools and the
 * guard collide with themselves in the process-global tool scope.
 *
 * Command execution goes through the host `shell` seam so the sandbox confines
 * it (and the FLY_ALLOW_RECON gate is an ADDITIONAL authorization layer on top
 * of the sandbox, not a replacement for it).
 *
 * **失败面的口径是"大声"**（Q5）：
 *   · 没有 `nmap`（macOS 常态）⇒ 用系统自带的 `nc` 扫，并在结果里标明"这是 nc 扫的"，且**明说
 *     `no-response` 分不清 closed 与 filtered**（要区分必须换 nmap）；端口数超过内置回退的 64 上限时
 *     **一个都不扫**并说清上限与出路，绝不扫一半交差；
 *   · 目标 URL **先校验再用**（`requireHttpUrl`：只允许 http/https）—— 2026-10-13 补：此前这条只有
 *     `diag_net_throughput` 有，`recon_http_fingerprint` 会放行 `file://`，而 curl 能把本地文件读出来
 *     回显进工具结果；Q5 那次我在本注释里先写了这条保护，**当时它并不成立**，现在它成立了；
 *   · `curl` 失败 ⇒ `requireOk` 抛 `CommandError`，不给"空指纹"；
 *   · `recon_http_fingerprint` 只读响应头与 `<title>`：**不执行 JS** —— 由 JS 搭出来的界面在这把尺子里
 *     等于不存在（AGENTS.md 里那台摄像头的负结论就是这么来的），这一点写进了它的 `limitations`。
 */
export const name = 'fly-recon'
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
 * `nmap` and `curl` are optional on this host; when they are missing the recon
 * tools must say so instead of reporting an empty scan, because an empty scan
 * reads as "target closed".
 */
/**
 * 只接受主机名或 IP 字面量。2026-10-13 补：此前 `recon_ports` 的 `host` **没有**这道校验，
 * 而 diag_* 三个工具都有 —— 于是 `-oN=/tmp/x` 这种"以 - 开头的目标"会被 nmap 当成**选项**
 * （写出文件）。同族性质必须在**每个**工具上都有。
 */
function requireHost(value) {
  const host = String(value ?? '').trim()
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u.test(host)) {
    const error = new Error(
      `拒绝目标 ${JSON.stringify(host)}：只接受主机名或 IP 字面量 ——`
      + ' 不许有空格或 shell 元字符（; | & $ ` 引号 括号），也不许以 "-" 开头'
      + '（会被当成命令参数：nmap、nc 会把 `-oN=file` 之类的选项当真）。',
    )
    error.name = 'ArgumentError'
    throw error
  }
  return host
}

/** 只允许 http/https：`file:` 会让 curl 把本地文件读出来回显进工具结果（2026-10-13 发现并补上）。 */
const ALLOWED_URL_SCHEMES = ['http:', 'https:']
function requireHttpUrl(value) {
  const text = String(value ?? '').trim()
  let parsed
  try {
    parsed = new URL(text)
  } catch {
    const error = new Error(`不是合法的 URL：${text}`)
    error.name = 'ArgumentError'
    throw error
  }
  if (!ALLOWED_URL_SCHEMES.includes(parsed.protocol)) {
    const error = new Error(`拒绝 ${parsed.protocol} 目标：只允许 http/https（file: 会读本地文件）`)
    error.name = 'ArgumentError'
    throw error
  }
  return parsed.href
}

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

/**
 * Expand `22,80,8000-8010` into a port list; null when the spec is unreadable, so
 * the tool can say that instead of scanning nothing.
 */
function expandPorts(spec) {
  const ports = []
  for (const part of String(spec).split(',')) {
    const token = part.trim()
    if (token === '') continue
    const range = /^(\d{1,5})-(\d{1,5})$/u.exec(token)
    if (range !== null) {
      const from = Number(range[1])
      const to = Number(range[2])
      if (from < 1 || to > 65535 || from > to) return null
      for (let port = from; port <= to; port++) ports.push(port)
    } else if (/^\d{1,5}$/u.test(token)) {
      const port = Number(token)
      if (port < 1 || port > 65535) return null
      ports.push(port)
    } else {
      return null
    }
    if (ports.length > 4096) return null
  }
  return ports.length === 0 ? null : [...new Set(ports)]
}

/** Exit 127 / "command not found": the optional tool this host would need is absent. */
function portMissing(run) {
  return run.exitCode === 127 || /command not found/iu.test(run.stderr)
}

function reconAllowed() {
  return process.env.FLY_ALLOW_RECON === '1'
}

export function apply(ctx) {
  const shell = ctx.shell

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name?.startsWith('recon_') && !reconAllowed()) {
      return {
        kind: 'deny',
        reason: 'Recon tools require explicit authorization. Set FLY_ALLOW_RECON=1 for authorized lab targets only.',
      }
    }
    return next()
  })

  ctx.tools.register(defineTool({
    name: 'recon_ports',
    description: 'TCP connect scan of ports on a lab target (authorized use only).',
    parameters: {
      host: { type: 'string', required: true },
      ports: { type: 'string', description: 'Comma list with optional ranges, default top common' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      // 先校验再构造命令（同族性质：diag_* 三个工具早就有这道门）。
      const host = requireHost(args.host)
      // 证据形状（规划 §5.1）：逐分支迁移 —— 本轮只把 nc 回退分支包上。
      const envelope = (observed, limitations) => JSON.stringify({
        tool: 'recon_ports',
        target: args.host,
        operation: 'TCP connect scan of the requested ports (authorized lab targets only)',
        observed,
        confidence: 'observed',
        limitations,
      }, null, 2)
      const requested = args.ports === undefined || String(args.ports).trim() === '' ? '22,80,443,445,3389,8080' : String(args.ports)
      const expanded = expandPorts(requested)
      if (expanded === null) {
        return envelope({ requested, dump: `unparsable port spec ${JSON.stringify(requested)} — use a comma list with optional ranges, e.g. 22,80,8000-8010` }, ['端口规格不合法 ⇒ 一个端口都没扫：observed.dump 里是解析失败的原因与可照抄的写法'])
      }
      const nmap = await runCmd(shell, ['nmap', '-Pn', '--open', '-p', expanded.join(','), host], exec, { timeoutMs: 60_000 })
      if (nmap.exitCode === 0) {
        return envelope({ method: 'nmap', dump: nmap.stdout }, [
          'nmap 的表格原样返回，本工具不改写它；本轮参数只带 -Pn --open（没有版本探测）',
          'open 只说明 TCP 连得上，不说明服务身份或版本',
        ])
      }
      if (!portMissing(nmap)) return requireOk(nmap, 'nmap')
      // `nmap` is not installed by default on macOS (nor on a stock Ubuntu desktop).
      // Instead of failing outright (the previous behaviour) or returning an empty
      // scan that reads as "target closed", scan with `nc` when it is present; if
      // neither exists we fail loudly rather than printing a table of no-response.
      // The result is labelled: nc cannot tell closed from filtered, and does no
      // fingerprinting. Option shape differs per platform (macOS has -G, OpenBSD nc
      // does not) — see platform.js.
      if (expanded.length > 64) {
        return envelope({ method: 'nc', scanned: 0, cap: 64, requested: expanded.length, dump: [
          `nmap is not installed on this host: the built-in fallback scans with the system nc and is capped at 64 ports per call, but ${expanded.length} were requested`,
          'narrow the range, or install nmap for a full scan (no 64-port cap, service and version detection)',
        ].join('\n') }, [
          '请求超过内置回退的 64 端口上限 ⇒ **一个端口都没扫**（不是"扫了、没有开着的端口"）',
        ])
      }
      // 扫之前先确认 nc 真的在：`nc` 不在时每一条 `if nc …` 都会走 else，
      // 结果是**整张表都 no-response** —— 一个看起来完全正常的假扫描。
      const probe = await runCmd(shell, ['sh', '-c', 'command -v nc'], exec, { timeoutMs: 10_000 })
      if (probe.exitCode !== 0 || probe.stdout.trim() === '') {
        const error = new Error(
          'nmap 与 nc 都不在本机：内置回退没有可用的扫描器，拒绝返回一张"全部 no-response"的假表。\n'
          + ncInstallHint(process.platform),
        )
        error.name = 'ToolError'
        throw error
      }
      const script = expanded
        .map((port) => {
          const argv = ncProbeArgs(process.platform, host, port).map(shq).join(' ')
          return `if ${argv} >/dev/null 2>&1; then echo '${port}/tcp open'; else echo '${port}/tcp no-response'; fi`
        })
        .join('; ')
      const scan = await runCmd(shell, ['/bin/sh', '-c', script], exec, { timeoutMs: 120_000 })
      if (scan.exitCode !== 0 && scan.stdout.trim() === '') return requireOk(scan, 'nc -z')
      const rows = scan.stdout.split('\n').map((l) => l.trim()).filter(Boolean)
      return envelope({ method: 'nc', scanned: expanded.length, dump: [
        'nmap=not installed (scanned with the system nc: one TCP connect per port, no service or version detection)',
        `host=${host}`,
        `ports=${expanded.length}`,
        ...rows,
        `open=${rows.filter((l) => l.endsWith('/tcp open')).length}`,
        'note: `no-response` means closed or filtered — nc cannot tell those two apart; install nmap for a real scan',
      ].join('\n') }, [
        'nmap 不在本机：这是系统 nc 的回退结果（每端口一次 TCP connect，无服务/版本探测）',
        '**nc 分不清 closed 与 filtered**：no-response 两种都可能 —— 要区分必须换 nmap',
      ])
    },
  }))

  ctx.tools.register(defineTool({
    name: 'recon_http_fingerprint',
    description: 'Fetch HTTP headers and title from a target URL (authorized lab only).',
    parameters: {
      url: { type: 'string', required: true },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      // 证据形状（规划 §5.1）：两支都产出信封。
      const envelope = (observed, limitations) => JSON.stringify({
        tool: 'recon_http_fingerprint',
        target: args.url,
        operation: 'one-shot HTTP fingerprint: response headers + <title> only',
        observed,
        confidence: 'observed',
        limitations,
      }, null, 2)
      // 先校验再构造命令：non-http 目标在**命令构造之前**就被拒（不是事后清洗）。
      const url = requireHttpUrl(args.url)
      const headers = requireOk(await runCmd(shell, ['curl', '-sI', '-m', '8', url], exec), `curl -sI ${url}`)
      const body = await runCmd(shell, ['curl', '-s', '-m', '8', url], exec)
      if (body.exitCode !== 0) {
        return envelope({ headers: headers.trim(), title: null, bodyFetched: false, dump: `${headers.trim()}\nTITLE: unknown (body fetch failed, exit ${body.exitCode})` }, [
          'body 取不到 ⇒ 只有响应头；title 是**未知**，不是「这个页面没有标题」',
          'curl -sI 不跟随重定向：看到的是**跳转前那一跳**的响应头',
        ])
      }
      const title = /<title[^>]*>([^<]*)<\/title>/iu.exec(body.stdout)?.[1]?.trim() ?? ''
      return envelope({ headers: headers.trim(), title, bodyFetched: true, dump: `${headers.trim()}\nTITLE: ${title === '' ? '(no <title> element in the body)' : title}` }, [
        '只读响应头与第一个 <title>：**不执行 JS** —— 由 JS 搭出来的界面（登录框、动态面板、JS 表格）在这把尺子里等于不存在',
        '要判 JS 渲染出来的东西，得用真浏览器（仓库有 playwright-core），并断「页面实际请求了什么、状态码是什么」',
        '标题取的是第一个 <title>；SPA 或没有 title 的页面会给 (no <title> element in the body)',
      ])
    },
  }))
}
