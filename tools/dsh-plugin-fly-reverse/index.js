import { defineTool } from '@deepseek-ai/dsh-tools'

/** fly-reverse — imports / disasm helpers feeding the Reverse Lab narrative. */
export const name = 'fly-reverse'
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

/**
 * Gadgets ending in a return, read straight out of `objdump -d`.
 *
 * This is the fallback for hosts without ROPgadget (any stock macOS). The
 * previous fallback demanded `/\bret\b/` and `pop|leave` on the SAME LINE:
 * objdump prints `popq %rdi` and `retq` on separate lines, and `retq` does not
 * match `/\bret\b/` — so a textbook `pop rdi; ret` came back as "no gadgets
 * found" (asserted in scripts/verify-security-tools.mjs).
 */
function scanGadgets(disasm, filter) {
  const instruction = /^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*([a-z][a-z0-9.]*)\s*(.*)$/u
  const wanted = filter === undefined ? null : filter.toLowerCase().split(/\s+/u).filter(Boolean)
  const recent = []
  const found = []
  for (const line of disasm.split('\n')) {
    const match = instruction.exec(line)
    if (match === null) continue
    const [, address, mnemonic, operands] = match
    const text = `${mnemonic}${operands.trim() === '' ? '' : ` ${operands.trim()}`}`
    if (mnemonic.startsWith('ret') === false) {
      recent.push({ address, text })
      if (recent.length > 5) recent.shift()
      continue
    }
    if (recent.length === 0) continue
    const gadget = `0x${recent[0].address}: ${recent.map(step => step.text).join(' ; ')} ; ret`
    if (wanted === null || wanted.every(token => gadget.toLowerCase().includes(token))) found.push(gadget)
    recent.length = 0
    if (found.length >= 200) break
  }
  return found
}

export function apply(ctx) {
  const shell = ctx.shell

  ctx.tools.register(defineTool({
    name: 'rev_imports',
    description: 'List imported (undefined) symbols.',
    parameters: {
      path: { type: 'string', required: true },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const kindRun = await runCmd(shell, ['file', '-b', args.path], exec)
      const kind = kindRun.exitCode === 0 ? kindRun.stdout.trim() : ''
      const dynamic = await runCmd(shell, ['objdump', '-T', args.path], exec)
      const dynamicLines = dynamic.exitCode === 0
        ? dynamic.stdout.split('\n').filter((l) => l.includes('DF') && l.includes('*UND*')).map((l) => l.trim())
        : []
      if (dynamicLines.length > 0) return dynamicLines.slice(0, 300).join('\n')
      // `objdump -T` exits 0 with a bare table header for Mach-O, and a stripped
      // ELF may have no dynamic symbol table at all. `nm -u` is the portable
      // second opinion (it ships with macOS and the Xcode CLT).
      const nm = await runCmd(shell, ['nm', '-u', args.path], exec, { stdoutMaxBytes: 4194304 })
      const undefinedSymbols = nm.exitCode === 0
        ? nm.stdout.split('\n').map((l) => l.trim()).filter((l) => /^_?[A-Za-z_][\w$.@]*$/u.test(l))
        : []
      if (undefinedSymbols.length > 0) {
        return [
          `${kind === '' ? 'format unknown' : kind}: no ELF dynamic symbol table to read, so these are the undefined symbols from nm -u (${undefinedSymbols.length}):`,
          ...undefinedSymbols.slice(0, 300),
        ].join('\n')
      }
      return [
        `no undefined symbols for ${args.path}: objdump -T (exit ${dynamic.exitCode}) and nm -u (exit ${nm.exitCode}) both came back empty`,
        `format: ${kind === '' ? 'unknown (file(1) reported nothing)' : kind}`,
        `nm -u stderr: ${nm.stderr.trim().slice(0, 200) || '(empty)'}`,
        `objdump -T output follows (${dynamic.stdout.trim().length} chars), so the emptiness is inspectable:`,
        dynamic.stdout.trim().slice(0, 2000),
      ].join('\n')
    },
  }))

  ctx.tools.register(defineTool({
    name: 'rev_disasm',
    description: 'Disassemble a binary or a function window.',
    parameters: {
      path: { type: 'string', required: true },
      start: { type: 'string', description: 'Optional start address, e.g. 0x4011a6' },
      stop: { type: 'string', description: 'Optional stop address' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const argv = ['-d', args.path]
      if (args.start && args.stop) argv.splice(1, 0, `--start-address=${args.start}`, `--stop-address=${args.stop}`)
      const stdout = requireOk(await runCmd(shell, ['objdump', ...argv], exec, { stdoutMaxBytes: 1048576 }), 'objdump -d')
      return stdout.slice(0, 12000)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'rev_gadget_scan',
    description: 'Scan for simple ROP gadgets.',
    parameters: {
      path: { type: 'string', required: true },
      filter: { type: 'string', description: 'Optional gadget filter, e.g. "pop rdi"' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const argv = ['--binary', args.path, '--only', 'pop|ret|leave']
      if (args.filter) argv.push('--filter', args.filter)
      const rop = await runCmd(shell, ['ROPgadget', ...argv], exec)
      if (rop.exitCode === 0) return rop.stdout.slice(0, 8000)
      const disasm = requireOk(await runCmd(shell, ['objdump', '-d', args.path], exec, { stdoutMaxBytes: 1048576 }), 'objdump -d')
      const gadgets = scanGadgets(disasm, args.filter)
      if (gadgets.length > 0) return gadgets.slice(0, 80).join('\n')
      return `no pop/leave/ret gadgets found in ${args.path} (install ROPgadget for a deeper scan)`
    },
  }))
}
