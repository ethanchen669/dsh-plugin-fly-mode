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
 *
 * **失败面的口径是"大声"**（Q5）：
 *   · `objdump -T` 读不出动态符号表（Mach-O 常态）⇒ 换 `nm -u` 这条**回退**，并把"这是回退路径、
 *     nm 只报未定义的名字、不说是从哪个库来的"写进结果的 `limitations`；
 *   · **两把尺子都没有** ⇒ 明说"没有可读的未定义符号"，并附上两条命令的 exit 与 stderr，
 *     绝不说成"这个程序不依赖任何外部符号"（静态链接/已 strip 正是这个形状）；
 *   · `ROPgadget` 不在 ⇒ 用内置扫描器（只认 pop/leave + ret 的简单序列），并在结果里写明
 *     "**没找到 ≠ 没有**"；`objdump` 缺失时 `requireOk` 抛错，不给空反汇编。
 */
/**
 * 路径参数规范化：以 `-` 开头的路径加 `./` 前缀（2026-10-13）。
 *
 * 为什么不插 `--`：实测本机（macOS，发布目标平台）**objdump（-h/-d/-T）/ base64 -i / otool -hv 都不支持
 * `--`**，插进去直接失败；而 `file -b --version` 会打印 `file-5.41`、`nm -u --version` 会打印
 * `llvm-nm, …`，两者都 **exit 0** ⇒ 工具会把版本串当**数据**返回（`bin_sections { path: '--version' }`
 * 真发生过）。加 `./` 之后它就是一个普通相对路径：不存在就正常报错，存在就是那个文件。
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
      const path = safePath(args.path)
      const kindRun = await runCmd(shell, ['file', '-b', path], exec)
      const kind = kindRun.exitCode === 0 ? kindRun.stdout.trim() : ''
      const dynamic = await runCmd(shell, ['objdump', '-T', path], exec)
      const dynamicLines = dynamic.exitCode === 0
        ? dynamic.stdout.split('\n').filter((l) => l.includes('DF') && l.includes('*UND*')).map((l) => l.trim())
        : []
      if (dynamicLines.length > 0) {
        return JSON.stringify({
          tool: 'rev_imports',
          target: args.path,
          operation: 'list undefined (imported) symbols: objdump -T (DF *UND*)',
          observed: { method: 'objdump', shown: Math.min(dynamicLines.length, 300), dump: dynamicLines.slice(0, 300).join('\n') },
          confidence: 'observed',
          limitations: [
            '只列**动态**符号表（.dynsym）里的未定义项：静态链接进来的、或本地定义的符号不在里面',
            dynamicLines.length > 300 ? '只给前 300 条（要全量就自己按符号名筛）' : '这次没有截断（未定义符号 ≤ 300）',
          ],
        }, null, 2)
      }
      // `objdump -T` exits 0 with a bare table header for Mach-O, and a stripped
      // ELF may have no dynamic symbol table at all. `nm -u` is the portable
      // second opinion (it ships with macOS and the Xcode CLT).
      const nm = await runCmd(shell, ['nm', '-u', path], exec, { stdoutMaxBytes: 4194304 })
      const undefinedSymbols = nm.exitCode === 0
        ? nm.stdout.split('\n').map((l) => l.trim()).filter((l) => /^_?[A-Za-z_][\w$.@]*$/u.test(l))
        : []
      if (undefinedSymbols.length > 0) {
        return JSON.stringify({
          tool: 'rev_imports',
          target: args.path,
          operation: 'list undefined (imported) symbols: nm -u (objdump -T had no dynamic table)',
          observed: { method: 'nm -u', format: kind === '' ? null : kind, shown: Math.min(undefinedSymbols.length, 300), dump: [
          `${kind === '' ? 'format unknown' : kind}: no ELF dynamic symbol table to read, so these are the undefined symbols from nm -u (${undefinedSymbols.length}):`,
          ...undefinedSymbols.slice(0, 300),
          ].join('\n') },
          confidence: 'observed',
          limitations: [
            '走的是 nm -u 这条**回退**路径：objdump -T 在这个文件上没有动态符号表（Mach-O 常见）',
            'nm -u 只报"未定义"的名字，不告诉你是从哪个库来的（要库映射得看 otool -L / readelf -d）',
          ],
        }, null, 2)
      }
      return JSON.stringify({
        tool: 'rev_imports',
        target: args.path,
        operation: 'list undefined (imported) symbols: both objdump -T and nm -u came back empty',
        observed: { method: null, format: kind === '' ? null : kind, shown: 0, dump: [
        `no undefined symbols for ${args.path}: objdump -T (exit ${dynamic.exitCode}) and nm -u (exit ${nm.exitCode}) both came back empty`,
        `format: ${kind === '' ? 'unknown (file(1) reported nothing)' : kind}`,
        `nm -u stderr: ${nm.stderr.trim().slice(0, 200) || '(empty)'}`,
        `objdump -T output follows (${dynamic.stdout.trim().length} chars), so the emptiness is inspectable:`,
        dynamic.stdout.trim().slice(0, 2000),
        ].join('\n') },
        confidence: 'observed',
        limitations: [
          '**两把尺子都没给出符号**：这句话的前提是 objdump -T 与 nm -u **都跑过了**（两条 exit 与 nm 的 stderr 就在 dump 里）',
          '它说的是「这份文件里没有可读的未定义符号」，不是「这个程序不依赖任何外部符号」—— 静态链接或已 strip 的二进制正是这个形状',
          '要继续追依赖，先换个体：bin_file 看格式、bin_readelf 看动态段（.dynamic / NEEDED）',
        ],
      }, null, 2)
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
      const path = safePath(args.path)
      const argv = ['-d', path]
      if (args.start && args.stop) argv.splice(1, 0, `--start-address=${args.start}`, `--stop-address=${args.stop}`)
      const stdout = requireOk(await runCmd(shell, ['objdump', ...argv], exec, { stdoutMaxBytes: 1048576 }), 'objdump -d')
      // 证据形状（规划 §5.1）：信封 JSON，objdump 输出原样进 observed.dump。
      return JSON.stringify({
        tool: 'rev_disasm',
        target: args.path,
        operation: 'objdump -d' + (args.start && args.stop ? ` --start-address=${args.start} --stop-address=${args.stop}` : ' (whole file)'),
        observed: { window: args.start && args.stop ? { start: args.start, stop: args.stop } : null, truncated: stdout.length > 12000, dump: stdout.slice(0, 12000) },
        confidence: 'observed',
        limitations: [
          stdout.length > 12000 ? '只给前 12000 字符（truncated=true）—— 要看后面请给 start/stop 缩小窗口' : '这次没有截断（输出 ≤ 12000 字符）',
          '反汇编是**线性扫描**的结果：数据段夹在代码里时，那些字节也会被当成指令打出来（用 start/stop 框住函数能少踩这个）',
          '不看控制流、不做函数边界识别（要那些得换真正的反编译器）',
        ],
      }, null, 2)
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
      const path = safePath(args.path)
      const argv = ['--binary', path, '--only', 'pop|ret|leave']
      if (args.filter) argv.push('--filter', args.filter)
      const rop = await runCmd(shell, ['ROPgadget', ...argv], exec)
      if (rop.exitCode === 0) {
        return JSON.stringify({
          tool: 'rev_gadget_scan',
          target: args.path,
          operation: 'ROPgadget --only pop|ret|leave' + (args.filter ? ` --filter ${args.filter}` : ''),
          observed: { method: 'ROPgadget', shown: null, truncated: rop.stdout.length > 8000, dump: rop.stdout.slice(0, 8000) },
          confidence: 'observed',
          limitations: [
            'ROPgadget 的输出原样返回（本工具只做截断：>8000 字符时 truncated=true）',
            'ROPgadget 自己会做指令边界识别与去重，但**只扫 --only pop|ret|leave 这几类**（要别的指令得改本工具）',
          ],
        }, null, 2)
      }
      const disasm = requireOk(await runCmd(shell, ['objdump', '-d', path], exec, { stdoutMaxBytes: 1048576 }), 'objdump -d')
      const gadgets = scanGadgets(disasm, args.filter)
      if (gadgets.length > 0) {
        return JSON.stringify({
          tool: 'rev_gadget_scan',
          target: args.path,
          operation: 'built-in scanner over objdump -d (ROPgadget not installed)' + (args.filter ? ` filtered by ${args.filter}` : ''),
          observed: { method: 'builtin', shown: Math.min(gadgets.length, 80), truncated: gadgets.length > 80, dump: gadgets.slice(0, 80).join('\n') },
          confidence: 'observed',
          limitations: [
            '走的是**内置扫描器**（本机没有 ROPgadget）：它只在 objdump 的反汇编里找 pop/leave + 紧跟的 ret 这类**简单序列**',
            '不做指令边界校验、不做 gadget 去重：地址可能重叠，长链 gadget（多指令 + 中间跳转）它也不会给',
            gadgets.length > 80 ? '只给前 80 条（observed.truncated=true）' : '这次没有截断（≤ 80 条）',
          ],
        }, null, 2)
      }
      return JSON.stringify({
        tool: 'rev_gadget_scan',
        target: args.path,
        operation: 'built-in scanner over objdump -d: nothing matched',
        observed: { method: 'builtin', shown: 0, dump: `no pop/leave/ret gadgets found in ${args.path} (install ROPgadget for a deeper scan)` },
        confidence: 'observed',
        limitations: [
          '**没找到 ≠ 没有**：这条走的是内置扫描器（只认 pop/leave + ret 的简单序列），装 ROPgadget 后同一条命令可能给出几十条',
          '也不排除这个文件根本没有可执行段（比如被测的是数据文件）—— 先用 bin_file 看它是什么',
        ],
      }, null, 2)
    },
  }))
}
