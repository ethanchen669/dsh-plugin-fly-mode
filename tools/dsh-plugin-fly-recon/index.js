import { defineTool } from '@deepseek-ai/dsh-tools'

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
function requireOk(run, what) {
  if (run.exitCode === 0) return run.stdout
  const detail = run.stderr.trim().split('\n').map(line => line.trim()).filter(Boolean).slice(0, 3).join(' | ')
  const missing = run.exitCode === 127 || /command not found/iu.test(run.stderr) ? ' — the command is not installed on this host' : ''
  const error = new Error(`${what} failed (exit ${run.exitCode})${missing}: ${run.command}${detail === '' ? '' : `\n${detail}`}`)
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
    description: 'TCP connect scan of ports on a lab target: nmap when installed, else the system nc (authorized use only).',
    parameters: {
      host: { type: 'string', required: true },
      ports: { type: 'string', description: 'Comma list with optional ranges, default top common' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const requested = args.ports === undefined || String(args.ports).trim() === '' ? '22,80,443,445,3389,8080' : String(args.ports)
      const expanded = expandPorts(requested)
      if (expanded === null) {
        return `unparsable port spec ${JSON.stringify(requested)} — use a comma list with optional ranges, e.g. 22,80,8000-8010`
      }
      const nmap = await runCmd(shell, ['nmap', '-Pn', '--open', '-p', expanded.join(','), args.host], exec, { timeoutMs: 60_000 })
      if (nmap.exitCode === 0) return nmap.stdout
      if (!portMissing(nmap)) return requireOk(nmap, 'nmap')
      // `nmap` is not installed by default on macOS. Instead of failing outright
      // (the previous behaviour) or returning an empty scan that reads as "target
      // closed", scan with `nc`, which ships with the base system. The result is
      // labelled: nc cannot tell closed from filtered, and does no fingerprinting.
      if (expanded.length > 64) {
        return [
          `nmap is not installed on this host: the built-in fallback scans with the system nc and is capped at 64 ports per call, but ${expanded.length} were requested`,
          'narrow the range, or install nmap for a full scan (no 64-port cap, service and version detection)',
        ].join('\n')
      }
      const script = expanded
        .map((port) => `if nc -z -G 1 -w 1 ${shq(args.host)} ${port} >/dev/null 2>&1; then echo '${port}/tcp open'; else echo '${port}/tcp no-response'; fi`)
        .join('; ')
      const scan = await runCmd(shell, ['/bin/sh', '-c', script], exec, { timeoutMs: 120_000 })
      if (scan.exitCode !== 0 && scan.stdout.trim() === '') return requireOk(scan, 'nc -z')
      const rows = scan.stdout.split('\n').map((l) => l.trim()).filter(Boolean)
      return [
        'nmap=not installed (scanned with the system nc: one TCP connect per port, no service or version detection)',
        `host=${args.host}`,
        `ports=${expanded.length}`,
        ...rows,
        `open=${rows.filter((l) => l.endsWith('/tcp open')).length}`,
        'note: `no-response` means closed or filtered — nc cannot tell those two apart; install nmap for a real scan',
      ].join('\n')
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
      const headers = requireOk(await runCmd(shell, ['curl', '-sI', '-m', '8', args.url], exec), `curl -sI ${args.url}`)
      const body = await runCmd(shell, ['curl', '-s', '-m', '8', args.url], exec)
      if (body.exitCode !== 0) return `${headers.trim()}\nTITLE: unknown (body fetch failed, exit ${body.exitCode})`
      const title = /<title[^>]*>([^<]*)<\/title>/iu.exec(body.stdout)?.[1]?.trim() ?? ''
      return `${headers.trim()}\nTITLE: ${title === '' ? '(no <title> element in the body)' : title}`
    },
  }))
}
