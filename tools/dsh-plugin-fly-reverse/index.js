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
// ── Ghidra headless（2026-10-16 实测：本机可用，但有三个坑）──────────────────────
//
// 坑一（用户踩过）：`/usr/libexec/java_home` 默认指向
// `/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home` —— 那是 **x86_64 的
// Java 8**，arm64 上直接 `Bad CPU type in executable`。必须显式指 Homebrew 的 arm64 JDK：
//   `JAVA_HOME=/opt/homebrew/opt/openjdk@26`（实测 26.0.1；openjdk@11 备选）。
// 坑二（本次实测）：analyzeHeadless 的**项目目录必须已存在**（否则
// `ERROR Abort due to Headless analyzer error: Directory not found: …`）—— 它不替你建。
// 坑三（本次实测）：`os/mac_arm_64/decompile does not exist` ⇒ **反编译的原生件没编译**，
// 这条能力要先跑 `support/buildNatives`（要 C++ 工具链）才有；在此之前只有 import/分析/函数表。

/** arm64 macOS 上唯一实测可用的 JDK（doctor 会把这条写进结果）。 */
const GHIDRA_JAVA_HOME = '/opt/homebrew/opt/openjdk@26'

/** `-postScript` 里那个脚本：把函数表打成 `FLYFN ` 前缀的 JSON 行（脚本在 scratch 里现写）。 */
function flyFunctionsScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra) — prints one `FLYFN <json>` line per function.',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.program.model.listing.*;',
    'import java.io.*;',
    'public class FlyFunctions extends GhidraScript {',
    '  @Override public void run() throws Exception {',
    '    int limit = 200;',
    '    if (getScriptArgs().length > 0) limit = Integer.parseInt(getScriptArgs()[0]);',
    '    PrintWriter out = new PrintWriter(System.out);',
    '    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);',
    '    int n = 0;',
    '    while (it.hasNext() && n < limit) {',
    '      Function fn = it.next();',
    '      char q = 34;',
    '      String json = "{" + q + "name" + q + ":" + q + fn.getName().replace(String.valueOf(q), "") + q',
    '        + "," + q + "entry" + q + ":" + q + "0x" + Long.toHexString(fn.getEntryPoint().getOffset()) + q',
    '        + "," + q + "size" + q + ":" + fn.getBody().getNumAddresses()',
    '        + "," + q + "thunk" + q + ":" + fn.isThunk()',
    '        + "," + q + "external" + q + ":" + fn.isExternal() + "}";',
    '      out.println("FLYFN " + json);',
    '      n += 1;',
    '    }',
    '    out.println("FLYFN-END " + n);',
    '    out.flush();',
    '  }',
    '}',
  ].join('\n')
}

/** 经接缝写一份文件（base64 中转 ⇒ 不引号化内容、也**不靠 stdin**：runCmd 没有 stdin，cat 会挂死）。 */
async function writeViaBase64(shell, exec, path, content) {
  const encoded = Buffer.from(content, 'utf8').toString('base64')
  return runCmd(shell, ['sh', '-c', 'printf %s ' + shq(encoded) + ' | base64 -d > ' + shq(path)], exec, { timeoutMs: 15_000 })
}

/** 找 analyzeHeadless：显式 GHIDRA_HOME 优先，否则候选目录（找不到就空串）。 */
/** 反编译用的 postScript（要 `os/<平台>/decompile` 原生件；没有就由 ghidraFix 给修法）。 */
function flyDecompileScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra decompile) — prints `FLYFN-NAME` + pseudocode blocks.',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.app.decompiler.*;',
    'import ghidra.program.model.listing.*;',
    'import java.io.*;',
    'public class FlyDecompile extends GhidraScript {',
    '  @Override public void run() throws Exception {',
    '    String want = getScriptArgs().length > 0 ? getScriptArgs()[0] : "";',
    '    DecompInterface ifc = new DecompInterface();',
    '    ifc.openProgram(currentProgram);',
    '    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);',
    '    PrintWriter out = new PrintWriter(System.out);',
    '    int n = 0;',
    '    while (it.hasNext() && n < 20) {',
    '      Function fn = it.next();',
    '      if (!want.isEmpty() && !fn.getName().equals(want) && !want.equals(fn.getEntryPoint().toString()) && !fn.getEntryPoint().toString().endsWith(want.replace("0x", ""))) continue;',
    '      DecompileResults res = ifc.decompileFunction(fn, 60, monitor);',
    '      out.println("FLYFN-NAME " + fn.getName());',
    '      out.println("FLYCODE-START");',
    '      out.println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "/* decompile failed for this function */");',
    '      out.println("FLYCODE-END");',
    '      n += 1;',
    '    }',
    '    out.flush();',
    '    ifc.dispose();',
    '  }',
    '}',
  ].join('\n')
}


/** 字符串检索用的 postScript（只要**已定义**的字符串数据；输出 `FLYSTR 地址 长度 类型 值`）。 */
function flyStringsScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra strings).',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.program.model.listing.*;',
    'import java.io.*;',
    'public class FlyStrings extends GhidraScript {',
    '  @Override public void run() throws Exception {',
    '    int limit = 200;',
    '    if (getScriptArgs().length > 0) limit = Integer.parseInt(getScriptArgs()[0]);',
    '    PrintWriter out = new PrintWriter(System.out);',
    '    DataIterator it = currentProgram.getListing().getDefinedData(true);',
    '    int n = 0;',
    '    while (it.hasNext() && n < limit) {',
    '      Data d = it.next();',
    '      if (!d.hasStringValue()) continue;',
    '      Object v = d.getValue();',
    '      String s = v == null ? "" : String.valueOf(v).replace(String.valueOf((char) 10), " ");',
    '      out.println("FLYSTR " + d.getAddress() + " " + s.length() + " " + d.getDataType().getName() + " " + s);',
    '      n += 1;',
    '    }',
    '    out.println("FLYSTR-END " + n);',
    '    out.flush();',
    '  }',
    '}',
  ].join('\n')
}

/** 交叉引用用的 postScript（谁引用了这个符号/地址；输出 `FLYXREF 来自地址 引用类型 -> 目标`）。 */
function flyXrefsScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra xrefs).',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.program.model.symbol.*;',
    'import ghidra.program.model.address.*;',
    'import java.io.*;',
    'public class FlyXrefs extends GhidraScript {',
    '  @Override public void run() throws Exception {',
    '    String want = getScriptArgs().length > 0 ? getScriptArgs()[0] : "";',
    '    PrintWriter out = new PrintWriter(System.out);',
    '    Address target = null;',
    '    SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(want);',
    '    if (symbols.hasNext()) target = symbols.next().getAddress();',
    '    if (target == null) {',
    '      try { target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(want); }',
    '      catch (Exception ignore) { target = null; }',
    '    }',
    '    if (target == null) {',
    '      out.println("FLYXREF-ERR no symbol or address named " + want);',
    '      out.flush();',
    '      return;',
    '    }',
    '    ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);',
    '    int n = 0;',
    '    while (it.hasNext() && n < 200) {',
    '      Reference ref = it.next();',
    '      out.println("FLYXREF " + ref.getFromAddress() + " " + ref.getReferenceType() + " -> " + target);',
    '      n += 1;',
    '    }',
    '    out.println("FLYXREF-END " + n + " target=" + target);',
    '    out.flush();',
    '  }',
    '}',
  ].join('\n')
}

/** 一条跑 postScript 的通路（新动作共用；老的 functions/decompile 两条保留原样不动）。 */
async function runGhidraPostScript(shell, exec, { headless, javaHome, work, binary, scriptName, scriptText, arg, timeoutMs = 240_000 }) {
  await runCmd(shell, ['mkdir', '-p', work], exec, { timeoutMs: 10_000 })
  await writeViaBase64(shell, exec, work + '/' + scriptName + '.java', scriptText)
  const run = await runCmd(shell, ['sh', '-c', [
    'JAVA_HOME=' + javaHome + ' ' + shq(headless) + ' ' + shq(work) + ' flyproj',
    '-import ' + shq(binary) + ' -deleteProject',
    '-scriptPath ' + shq(work) + ' -postScript ' + scriptName + (arg === undefined || arg === '' ? ''
      : ' ' + (Array.isArray(arg) ? arg.map(item => shq(String(item))).join(' ') : shq(arg))),
  ].join(' ')], exec, { timeoutMs, stdoutMaxBytes: 8 * 1024 * 1024 })
  const text = (run.stdout ?? '') + (run.stderr ?? '')
  if (run.exitCode !== 0) {
    const fix = ghidraFix(text)
    throw new Error('rev_ghidra ' + scriptName + ' 跑失败（exit ' + run.exitCode + '）：'
      + text.trim().split('\n').filter(Boolean).slice(0, 3).join(' | ')
      + (fix === '' ? '' : '\n\n' + fix))
  }
  return { stdout: run.stdout }
}


/** 引用链用的 postScript（BFS 往上走：谁引用了它、谁又引用了那个函数…）。 */
function flyTraceScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra trace).',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.program.model.symbol.*;',
    'import ghidra.program.model.address.*;',
    'import ghidra.program.model.listing.*;',
    'import java.io.*;',
    'import java.util.*;',
    'public class FlyTrace extends GhidraScript {',
    '  @Override public void run() throws Exception {',
    '    String want = getScriptArgs().length > 0 ? getScriptArgs()[0] : "";',
    '    int depth = getScriptArgs().length > 1 ? Integer.parseInt(getScriptArgs()[1]) : 3;',
    '    int limit = getScriptArgs().length > 2 ? Integer.parseInt(getScriptArgs()[2]) : 200;',
    '    PrintWriter out = new PrintWriter(System.out);',
    '    Address target = null;',
    '    SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(want);',
    '    if (symbols.hasNext()) target = symbols.next().getAddress();',
    '    if (target == null) {',
    '      try { target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(want); }',
    '      catch (Exception ignore) { target = null; }',
    '    }',
    '    if (target == null) {',
    '      out.println("FLYTRACE-ERR target not found: " + want);',
    '      out.flush();',
    '      return;',
    '    }',
    '    FunctionManager fm = currentProgram.getFunctionManager();',
    '    LinkedHashSet<String> seenEdges = new LinkedHashSet<>();',
    '    LinkedHashSet<String> seenNodes = new LinkedHashSet<>();',
    '    ArrayDeque<Address> queue = new ArrayDeque<>();',
    '    ArrayDeque<Integer> levels = new ArrayDeque<>();',
    '    queue.add(target);',
    '    levels.add(0);',
    '    int edges = 0;',
    '    boolean truncated = false;',
    '    while (!queue.isEmpty() && !truncated) {',
    '      Address current = queue.poll();',
    '      int level = levels.poll();',
    '      if (level >= depth) continue;',
    '      ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(current);',
    '      while (it.hasNext()) {',
    '        Reference ref = it.next();',
    '        Address from = ref.getFromAddress();',
    '        Function fromFn = fm.getFunctionContaining(from);',
    '        Function toFn = fm.getFunctionContaining(current);',
    '        String fromName = fromFn == null ? from.toString() : fromFn.getName();',
    '        String toName = toFn == null ? current.toString() : toFn.getName();',
    '        String key = fromName + " -> " + toName + " " + ref.getReferenceType();',
    '        if (seenEdges.add(key)) {',
    '          out.println("FLYTRACE " + level + " " + fromName + " " + toName + " " + ref.getReferenceType());',
    '          edges += 1;',
    '          if (edges >= limit) { truncated = true; break; }',
    '          if (fromFn != null && seenNodes.add(fromFn.getName())) {',
    '            queue.add(fromFn.getEntryPoint());',
    '            levels.add(level + 1);',
    '          }',
    '        }',
    '      }',
    '    }',
    '    out.println("FLYTRACE-END " + edges + " target=" + target + " depth=" + depth + " truncated=" + truncated);',
    '    out.flush();',
    '  }',
    '}',
  ].join('\n')
}


/** 批量反编译用的 postScript：按选择器挑函数，伪代码**落盘**（带函数索引头），只回摘要。 */
function flyDecompileBatchScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra decompile --batch).',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.app.decompiler.*;',
    'import ghidra.program.model.listing.*;',
    'import ghidra.program.model.address.*;',
    'import java.io.*;',
    'public class FlyDecompileBatch extends GhidraScript {',
    '  private String arg(int index) {',
    '    String[] list = getScriptArgs();',
    '    return index < list.length ? list[index] : "";',
    '  }',
    '  @Override public void run() throws Exception {',
    '    String pattern = arg(0);',
    '    String loStr = arg(1);',
    '    String hiStr = arg(2);',
    '    String minSizeStr = arg(3);',
    '    String maxFuncsStr = arg(4);',
    '    String outPath = arg(5);',
    '    int minSize = minSizeStr.isEmpty() ? 0 : Integer.parseInt(minSizeStr);',
    '    int maxFuncs = maxFuncsStr.isEmpty() ? 20 : Integer.parseInt(maxFuncsStr);',
    '    Address lo = null;',
    '    Address hi = null;',
    '    AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();',
    '    if (!loStr.isEmpty()) lo = space.getAddress(loStr);',
    '    if (!hiStr.isEmpty()) hi = space.getAddress(hiStr);',
    '    DecompInterface ifc = new DecompInterface();',
    '    ifc.openProgram(currentProgram);',
    '    PrintWriter out = new PrintWriter(new FileWriter(outPath));',
    '    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);',
    '    int written = 0;',
    '    boolean truncated = false;',
    '    while (it.hasNext()) {',
    '      Function fn = it.next();',
    '      if (fn.isThunk() || fn.isExternal()) continue;',
    '      if (!pattern.isEmpty() && !fn.getName().matches(pattern)) continue;',
    '      Address entry = fn.getEntryPoint();',
    '      if (lo != null && entry.compareTo(lo) < 0) continue;',
    '      if (hi != null && entry.compareTo(hi) > 0) continue;',
    '      long size = fn.getBody().getNumAddresses();',
    '      if (size < minSize) continue;',
    '      if (written >= maxFuncs) { truncated = true; break; }',
    '      DecompileResults res = ifc.decompileFunction(fn, 60, monitor);',
    '      out.println("// function: " + fn.getName() + " @ " + entry + " size=" + size);',
    '      out.println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "/* decompile failed */");',
    '      out.println();',
    '      written += 1;',
    '    }',
    '    out.flush();',
    '    out.close();',
    '    ifc.dispose();',
    '    PrintWriter summary = new PrintWriter(System.out);',
    '    summary.println("FLYDEC-SUMMARY count=" + written + " truncated=" + truncated + " file=" + outPath);',
    '    summary.flush();',
    '  }',
    '}',
  ].join('\n')
}


/** 跨二进制批量用的 postScript：**每个程序**按自己的名字落盘（一次 headless 跑多个 -import）。 */
function flyDecompileMultiScript() {
  return [
    '// Generated by fly-reverse (rev_ghidra decompile-many).',
    'import ghidra.app.script.GhidraScript;',
    'import ghidra.app.decompiler.*;',
    'import ghidra.program.model.listing.*;',
    'import ghidra.program.model.address.*;',
    'import java.io.*;',
    'public class FlyDecompileMulti extends GhidraScript {',
    '  private String arg(int index) {',
    '    String[] list = getScriptArgs();',
    '    return index < list.length ? list[index] : "";',
    '  }',
    '  @Override public void run() throws Exception {',
    '    String pattern = arg(0);',
    '    String loStr = arg(1);',
    '    String hiStr = arg(2);',
    '    int minSize = arg(3).isEmpty() ? 0 : Integer.parseInt(arg(3));',
    '    int maxFuncs = arg(4).isEmpty() ? 20 : Integer.parseInt(arg(4));',
    '    String outDir = arg(5);',
    '    String programName = currentProgram.getName();',
    '    String outPath = outDir + "/" + programName + "-decompiled.c";',
    '    AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();',
    '    Address lo = loStr.isEmpty() ? null : space.getAddress(loStr);',
    '    Address hi = hiStr.isEmpty() ? null : space.getAddress(hiStr);',
    '    DecompInterface ifc = new DecompInterface();',
    '    ifc.openProgram(currentProgram);',
    '    PrintWriter out = new PrintWriter(new FileWriter(outPath));',
    '    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);',
    '    int written = 0;',
    '    boolean truncated = false;',
    '    while (it.hasNext()) {',
    '      Function fn = it.next();',
    '      if (fn.isThunk() || fn.isExternal()) continue;',
    '      if (!pattern.isEmpty() && !fn.getName().matches(pattern)) continue;',
    '      Address entry = fn.getEntryPoint();',
    '      if (lo != null && entry.compareTo(lo) < 0) continue;',
    '      if (hi != null && entry.compareTo(hi) > 0) continue;',
    '      long size = fn.getBody().getNumAddresses();',
    '      if (size < minSize) continue;',
    '      if (written >= maxFuncs) { truncated = true; break; }',
    '      DecompileResults res = ifc.decompileFunction(fn, 60, monitor);',
    '      out.println("// function: " + fn.getName() + " @ " + entry + " size=" + size);',
    '      out.println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "/* decompile failed */");',
    '      out.println();',
    '      written += 1;',
    '    }',
    '    out.flush();',
    '    out.close();',
    '    ifc.dispose();',
    '    PrintWriter summary = new PrintWriter(System.out);',
    '    summary.println("FLYDEC-SUMMARY prog=" + programName + " count=" + written + " truncated=" + truncated + " file=" + outPath);',
    '    summary.flush();',
    '  }',
    '}',
  ].join('\n')
}


function ghidraHeadless(shell, exec) {
  return runCmd(shell, ['sh', '-c', 'if [ -n "$GHIDRA_HOME" ]; then echo "$GHIDRA_HOME/support/analyzeHeadless"; else ls -d "$HOME"/tools/ghidra_*/support/analyzeHeadless 2>/dev/null | sort | tail -1; fi'], exec, { timeoutMs: 10_000 })
}

/** JDK 探针直接跑 javaHome 下的 java —— **别**写 `JAVA_HOME=x "$JAVA_HOME/bin/java"`：
 *  POSIX 里同一命令的变量展开发生在赋值生效**之前**，`$JAVA_HOME` 会取到旧值（= 那个 x86_64
 *  Java 8）⇒ doctor 会把"能用"报成"不能用"（两处口径不一致，测试当场抓到）。 */
/** 两类"跑不了"都要给**可复制的修法**（不是"工具缺失"四个字）。 */
function ghidraFix(text) {
  if (/Bad CPU type|Unable to prompt user for JDK path/u.test(text)) {
    return [
      'Ghidra 起不来：/usr/libexec/java_home 默认指向 /Library/Internet Plug-Ins/JavaAppletPlugin.plugin',
      '（那是 **x86_64 的 Java 8**，arm64 上直接 Bad CPU type in executable）。',
      '修法（arm64 macOS，实测可用）：',
      '  export JAVA_HOME=/opt/homebrew/opt/openjdk@26',
      '  ~/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless …',
    ].join('\n')
  }
  if (/decompile does not exist|Building Native Components/u.test(text)) {
    return [
      'Ghidra 的反编译原生件还没编译（os/mac_arm_64/decompile 不存在）——',
      '这只影响**反编译**，import / 分析 / 函数表照旧能用。',
      '修法（要 C++ 工具链，一次性）：',
      '  cd ~/tools/ghidra_12.1.4_PUBLIC/support/gradle/ && gradle buildNatives   # 或自带 wrapper（需联网）：./gradlew buildNatives',
      '  # 编完在 <模块>/build/os/<平台>/ 下，**要装进** <模块>/os/<平台>/（release 布局里 Ghidra 找的是后者）：',
      '  cp Ghidra/Features/Decompiler/build/os/mac_*/decompile Ghidra/Features/Decompiler/os/mac_*/',
    ].join('\n')
  }
  return ''
}



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
  // ── rev_ghidra（Ghidra headless：doctor / functions）───────────────
  ctx.tools.register(defineTool({
    name: 'rev_ghidra',
    description: 'Run Ghidra headless (analyzeHeadless) on a binary. doctor = probe the local install (JAVA_HOME trap, native decompiler); functions = import + analyse and list functions as JSON lines. arm64 macOS needs JAVA_HOME=/opt/homebrew/opt/openjdk@26.',
    parameters: {
      action: { type: 'string', required: true, description: 'doctor | functions' },
      binary: { type: 'string', description: 'binary to analyse (required for functions)' },
      limit: { type: 'number', description: 'max functions to list (default 200, clamped 1..2000)' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const action = String(args.action ?? '').trim()
      if (action !== 'doctor' && action !== 'functions' && action !== 'decompile' && action !== 'strings' && action !== 'xrefs' && action !== 'trace' && action !== 'decompile-many') {
        const error = new Error('rev_ghidra 的 action 只认 doctor / functions / decompile / strings / xrefs / trace / decompile-many（收到 ' + JSON.stringify(args.action) + '）')
        error.name = 'ArgumentError'
        throw error
      }
      const found = await ghidraHeadless(shell, exec)
      const headless = found.stdout.trim().split('\n').filter(Boolean).at(-1) ?? ''
      if (headless === '') {
        const error = new Error([
          'rev_ghidra：找不到 analyzeHeadless —— 这台机器上 Ghidra 要么没装，要么没装在 ~/tools/ghidra_*/ 下。',
          '两条路：设 GHIDRA_HOME=<你的 Ghidra 目录>（我只找 $GHIDRA_HOME/support/analyzeHeadless 与 ~/tools/ghidra_*/support/analyzeHeadless），',
          '或者装一个：https://ghidra-sre.org/ （下载 zip 解压即可，不需要安装器）。',
        ].join('\n'))
        error.name = 'ToolError'
        throw error
      }
      const javaHome = typeof process.env.GHIDRA_JAVA_HOME === 'string' && process.env.GHIDRA_JAVA_HOME.trim() !== ''
        ? process.env.GHIDRA_JAVA_HOME.trim()
        : GHIDRA_JAVA_HOME
      const work = (process.env.TMPDIR || '/tmp').replace(/\/$/u, '') + '/fly-reverse-ghidra'
      // 注意：`analyzeHeadless` 是**文件**，`<文件>/../…` 在 POSIX 里解析不了（ENOTDIR）——
    // 第一版探针就是这么把"装好了"读成"不在"的（手跑同一条命令复现）。要先 `$(dirname …)`。
    // 平台目录名是 `mac_arm_64`（**有下划线**）：拿 `uname -m` 的 `arm64` 直接拼 `mac_${P}` 会得到
    // `mac_arm64` ⇒ test -e 恒假，而 ls 明明看得见那个文件 —— 两个读数矛盾就是尺子拼错了。
    const nativeProbe = headless === '' ? null : await runCmd(shell, ['sh', '-c', 'P=$(uname -m | sed s/arm64/arm_64/); D=$(dirname "' + headless + '"); test -e "$D/../Ghidra/Features/Decompiler/os/mac_${P}/decompile" || test -e "$D/../../os/mac_${P}/decompile"'], exec, { timeoutMs: 10_000 })
      const javaRun = await runCmd(shell, ['sh', '-c', shq(javaHome + '/bin/java') + ' -version'], exec, { timeoutMs: 15_000 })
      if (action === 'doctor') {
        const probes = []
        probes.push({ what: 'analyzeHeadless', ok: headless !== '', detail: headless === '' ? '不在 ~/tools/ghidra_*/support/ 下（装了的话设 GHIDRA_HOME）' : headless })
        probes.push({ what: 'arm64 JDK', ok: javaRun.exitCode === 0, detail: javaRun.stdout.trim().split('\n')[0] ?? javaRun.stderr.trim().split('\n')[0] })
        probes.push({ what: '反编译原生件 os/mac_arm_64/decompile', ok: nativeProbe !== null && nativeProbe.exitCode === 0, detail: nativeProbe !== null && nativeProbe.exitCode === 0 ? '在' : '不在 —— 反编译不可用，函数表照旧（修法见 limitations）' })
        return JSON.stringify({
          tool: 'rev_ghidra',
          target: headless === '' ? '(未找到 analyzeHeadless)' : headless,
          operation: '三个探针：analyzeHeadless 在不在 / arm64 JDK 能不能跑 / 反编译原生件在不在',
          observed: { probes, usable: { functions: headless !== '' && javaRun.exitCode === 0, decompile: nativeProbe !== null && nativeProbe.exitCode === 0 } },
          confidence: 'observed',
          limitations: [
            'arm64 macOS 上**必须**显式设 JAVA_HOME=/opt/homebrew/opt/openjdk@26：'
              + '/usr/libexec/java_home 默认指向 JavaAppletPlugin（x86_64 Java 8），arm64 直接 Bad CPU type',
            'analyzeHeadless 的**项目目录必须已存在**（它不替你建）—— 实测出来的形状',
            '反编译原生件缺失 ≠ "这个包没有反编译"：那是装机器的事，修法在下一条',
            '修法（反编译，官方 GettingStarted.md §Building Native Components）：cd ~/tools/ghidra_12.1.4_PUBLIC/support/gradle/ && gradle buildNatives   # 或自带 wrapper（需联网）：./gradlew buildNatives',
          ],
        }, null, 2)
      }
      if (action === 'strings' || action === 'xrefs') {
        if (typeof args.binary !== 'string' || args.binary.trim() === '') {
          const error = new Error('rev_ghidra ' + action + ' 需要 binary 参数（要分析哪个文件）')
          error.name = 'ArgumentError'
          throw error
        }
        const target = safePath(args.binary.trim())
        const limit = Math.min(2000, Math.max(1, Math.round(Number(args.limit ?? 200) || 200)))
        const wanted = typeof args.function === 'string' && args.function.trim() !== '' ? args.function.trim() : ''
        if (action === 'xrefs' && wanted === '') {
          const error = new Error('rev_ghidra xrefs 需要 function（符号名或地址）—— 到底问谁被引用了')
          error.name = 'ArgumentError'
          throw error
        }
        const run = await runGhidraPostScript(shell, exec, {
          headless, javaHome, work, binary: target,
          scriptName: action === 'strings' ? 'FlyStrings' : 'FlyXrefs',
          scriptText: action === 'strings' ? flyStringsScript() : flyXrefsScript(),
          arg: action === 'strings' ? String(limit) : wanted,
        })
        const out = run.stdout
        if (action === 'strings') {
          if (!/FLYSTR-END/u.test(out)) {
            throw new Error('rev_ghidra strings：一行都没产出（退出码却是 0）—— 脚本多半没编译过（Ghidra 静默跳过）。跑 rev_ghidra doctor 看环境。')
          }
          const rows = out.split('\n').filter(line => line.startsWith('FLYSTR ')).map(line => {
            const matched = /^FLYSTR (\S+) (\d+) (\S+) (.*)$/u.exec(line)
            return matched === null ? null : { address: matched[1], length: Number(matched[2]), type: matched[3], value: matched[4] }
          }).filter(row => row !== null)
          return JSON.stringify({
            tool: 'rev_ghidra',
            target: target,
            operation: 'analyzeHeadless import + 分析 → FlyStrings postScript（最多 ' + limit + ' 条）',
            observed: { count: rows.length, strings: rows },
            confidence: 'observed',
            limitations: [
              '只列 Ghidra **已定义**的字符串（分析阶段认定成字符串数据的那些）—— "没有"不等于"文件里没有这串字节"',
              '值里的换行被换成空格（一行一条，便于读）；二进制安全的判读请另行取证',
              'limit 是**条数**上限（默认 200）：条数可能少于 limit，也可能正好等于（说明被截断）',
              '整个二进制会被完整分析一遍（headless 的语义），大文件会慢',
              '项目目录与脚本写在 scratch（TMPDIR/fly-reverse-ghidra/），-deleteProject 用完即删，不碰仓库',
            ],
          }, null, 2)
        }
        if (/FLYXREF-ERR/u.test(out)) {
          throw new Error('rev_ghidra xrefs：目标里找不到这个符号或地址 —— ' + (/FLYXREF-ERR (.*)/u.exec(out)?.[1] ?? ''))
        }
        if (!/FLYXREF-END/u.test(out)) {
          throw new Error('rev_ghidra xrefs：一行都没产出（退出码却是 0）—— 脚本多半没编译过（Ghidra 静默跳过）。跑 rev_ghidra doctor 看环境。')
        }
        const refs = out.split('\n').filter(line => line.startsWith('FLYXREF ')).map(line => {
          const matched = /^FLYXREF (\S+) (\S+) -> (\S+)$/u.exec(line)
          return matched === null ? null : { from: matched[1], type: matched[2], to: matched[3] }
        }).filter(row => row !== null)
        return JSON.stringify({
          tool: 'rev_ghidra',
          target: target + ' · ' + wanted,
          operation: 'analyzeHeadless import + 分析 → FlyXrefs postScript',
          observed: { references: refs.length, refs },
          confidence: 'observed',
          limitations: [
            '这是**直接引用**（Ghidra 的 reference manager）：间接调用（函数指针表、动态解析、RTTI）不会出现在这里',
            '"没有引用"读作"Ghidra 在这一遍分析里没建立引用"，不是"运行时永远不会走到"',
            '符号名按 Ghidra 的命名（可能带前缀/后缀）；找不到时工具**大声报错**，不会给空清单当答案',
            '整个二进制会被完整分析一遍（headless 的语义），大文件会慢',
          ],
        }, null, 2)
      }

      if (action === 'decompile-many') {
        const raw = typeof args.binaries === 'string' ? args.binaries : ''
        const wantedList = raw.split(/[,\n]/u).map(item => item.trim()).filter(item => item !== '')
        if (wantedList.length === 0) {
          const error = new Error('rev_ghidra decompile-many 需要 binaries（多个路径，用逗号或换行分隔）')
          error.name = 'ArgumentError'
          throw error
        }
        const cap = Math.min(10, Math.max(1, Math.round(Number(args.maxBinaries ?? 3) || 3)))
        const chosen = wantedList.slice(0, cap)
        const skippedByCap = wantedList.length - chosen.length
        const missingFiles = []
        for (const item of chosen) {
          const probe = await runCmd(shell, ['test', '-e', safePath(item)], exec, { timeoutMs: 10_000 })
          if (probe.exitCode !== 0) missingFiles.push(item)
        }
        if (missingFiles.length > 0) {
          throw new Error('rev_ghidra decompile-many：这些文件不存在 —— ' + missingFiles.join(', '))
        }
        const stamp = new Date().toISOString().replace(/[:.]/gu, '-')
        const outDir = typeof args.out === 'string' && args.out.trim() !== '' ? safePath(args.out.trim()) : work + '/multi-' + stamp
        const pattern = typeof args.pattern === 'string' ? args.pattern.trim() : ''
        const range = typeof args.range === 'string' ? args.range.trim() : ''
        let lo = ''
        let hi = ''
        if (range !== '') {
          const matched = /^(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)$/u.exec(range)
          if (matched === null) {
            const error = new Error('rev_ghidra decompile-many 的 range 要写成 0x开始-0x结束（收到 ' + range + '）')
            error.name = 'ArgumentError'
            throw error
          }
          lo = matched[1]
          hi = matched[2]
        }
        const minSize = args.minSize === undefined ? '' : String(Math.max(0, Math.round(Number(args.minSize) || 0)))
        const maxFunctions = String(Math.min(2000, Math.max(1, Math.round(Number(args.maxFunctions ?? 20) || 20))))
        await runCmd(shell, ['sh', '-c', 'mkdir -p ' + shq(outDir)], exec, { timeoutMs: 10_000 })
        await writeViaBase64(shell, exec, work + '/FlyDecompileMulti.java', flyDecompileMultiScript())
        const run = await runCmd(shell, ['sh', '-c', [
          'JAVA_HOME=' + javaHome + ' ' + shq(headless) + ' ' + shq(work) + ' flyproj',
          '-import ' + chosen.map(item => shq(safePath(item))).join(' '),
          '-deleteProject',
          '-scriptPath ' + shq(work) + ' -postScript FlyDecompileMulti '
            + [pattern, lo, hi, minSize, maxFunctions, outDir].map(value => shq(String(value))).join(' '),
        ].join(' ')], exec, { timeoutMs: Math.min(900_000, 180_000 * chosen.length), stdoutMaxBytes: 16 * 1024 * 1024 })
        const text = (run.stdout ?? '') + (run.stderr ?? '')
        if (run.exitCode !== 0) {
          const fix = ghidraFix(text)
          throw new Error('rev_ghidra decompile-many 跑失败（exit ' + run.exitCode + '）：'
            + text.trim().split('\n').filter(Boolean).slice(0, 4).join(' | ')
            + (fix === '' ? '' : '\n\n' + fix))
        }
        const summaries = [...(run.stdout ?? '').matchAll(/FLYDEC-SUMMARY prog=(\S+) count=(\d+) truncated=(true|false) file=(\S+)/gu)]
          .map(matched => ({ program: matched[1], functions: Number(matched[2]), truncated: matched[3] === 'true', file: matched[4] }))
        if (summaries.length === 0) {
          throw new Error('rev_ghidra decompile-many：一个程序的摘要都没拿到（退出码却是 0）—— 脚本多半没编译过（Ghidra 静默跳过）。跑 rev_ghidra doctor 看环境。')
        }
        const rows = []
        let totalFunctions = 0
        let totalBytes = 0
        for (const summary of summaries) {
          const sizeRun = await runCmd(shell, ['sh', '-c', 'wc -c < ' + shq(summary.file)], exec, { timeoutMs: 10_000 })
          const bytes = Number((sizeRun.stdout ?? '').trim()) || 0
          totalFunctions += summary.functions
          totalBytes += bytes
          rows.push({ ...summary, bytes })
        }
        return JSON.stringify({
          tool: 'rev_ghidra',
          target: chosen.join(' , '),
          operation: 'analyzeHeadless **一次 JVM** 多文件 -import → FlyDecompileMulti（每个程序按自己的名字落盘）',
          observed: {
            requested: chosen.length,
            produced: rows.length,
            skippedByCap,
            outDir,
            binaries: rows,
            totals: { functions: totalFunctions, bytes: totalBytes },
          },
          confidence: 'observed',
          limitations: [
            '每个二进制都要**完整分析一遍**（实测 /bin/echo 约 5~8 秒，大文件更慢）—— 一次 JVM 省的是启动，不是分析',
            'maxBinaries 上限 10（本次 cap=' + cap + '）' + (skippedByCap > 0 ? '；**有 ' + skippedByCap + ' 个输入因超上限被跳过**（省略不藏起来）' : ''),
            '输出文件名取自 Ghidra 的 `currentProgram.getName()`（通常是文件基名）—— 不同目录下的同名文件会互相覆盖，请给每次调用独立的 out',
            '每个文件里每块伪代码以 `// function: <名字> @ <地址> size=N` 打头 ⇒ 可直接 grep；索引头条数 === 该文件的 functions',
            '每函数最多等 60 秒反编译；超时写成 decompile failed；跳过 thunk / external',
            rows.length < chosen.length
              ? '⚠️ 只拿到 ' + rows.length + '/' + chosen.length + ' 个程序的摘要（有的没导入成功？）—— 结果只含产出的那些'
              : '全部 ' + chosen.length + ' 个程序都产出了摘要',
            '需要 os/<平台>/decompile 原生件；缺失时按 rev_ghidra doctor 的修法补',
          ],
        }, null, 2)
      }

      if (action === 'trace') {
        if (typeof args.binary !== 'string' || args.binary.trim() === '') {
          const error = new Error('rev_ghidra trace 需要 binary 参数（要分析哪个文件）')
          error.name = 'ArgumentError'
          throw error
        }
        const wanted = typeof args.function === 'string' && args.function.trim() !== '' ? args.function.trim() : ''
        if (wanted === '') {
          const error = new Error('rev_ghidra trace 需要 function（符号名或地址）—— 从哪个点往上追')
          error.name = 'ArgumentError'
          throw error
        }
        const target = safePath(args.binary.trim())
        const depth = Math.min(6, Math.max(1, Math.round(Number(args.depth ?? 3) || 3)))
        const limit = Math.min(2000, Math.max(1, Math.round(Number(args.limit ?? 200) || 200)))
        const run = await runGhidraPostScript(shell, exec, {
          headless, javaHome, work, binary: target,
          scriptName: 'FlyTrace', scriptText: flyTraceScript(),
          arg: [wanted, String(depth), String(limit)],
        })
        const out = run.stdout
        if (/FLYTRACE-ERR/u.test(out)) {
          throw new Error('rev_ghidra trace：目标里找不到这个符号或地址 —— ' + (/FLYTRACE-ERR (.*)/u.exec(out)?.[1] ?? ''))
        }
        if (!/FLYTRACE-END/u.test(out)) {
          throw new Error('rev_ghidra trace：一行都没产出（退出码却是 0）—— 脚本多半没编译过（Ghidra 静默跳过）。跑 rev_ghidra doctor 看环境。')
        }
        const edges = out.split('\n').filter(line => line.startsWith('FLYTRACE ')).map(line => {
          const matched = /^FLYTRACE (\d+) (\S+) (\S+) (\S+)$/u.exec(line)
          return matched === null ? null : { level: Number(matched[1]), from: matched[2], to: matched[3], type: matched[4] }
        }).filter(row => row !== null)
        const summary = /FLYTRACE-END (\d+) target=(\S+) depth=(\d+) truncated=(true|false)/u.exec(out)
        return JSON.stringify({
          tool: 'rev_ghidra',
          target: target + ' · ' + wanted,
          operation: 'analyzeHeadless import + 分析 → FlyTrace postScript（BFS 往上追，depth=' + depth + '）',
          observed: {
            target: summary?.[2] ?? wanted,
            depth,
            edges: edges.length,
            truncated: (summary?.[4] ?? 'false') === 'true',
            nodes: [...new Set(edges.flatMap(edge => [edge.from, edge.to]))].length,
            chain: edges,
          },
          confidence: 'observed',
          limitations: [
            '这是 Ghidra 的**静态直接引用**切片，**不是运行时调用链** —— 别把它读成"实际执行顺序"',
            '间接调用（函数指针、虚表、动态解析、PLT/GOT 跳板）**不会**出现在这里：链会在这些地方断掉',
            '"没有引用"只能读成"这一遍静态分析里没建立引用"，**不能**读成"运行时永远走不到"',
            '混淆 / 位置无关代码下，链可能断在不该断的地方 —— 那正是需要人判的地方',
            '节点上限 ' + limit + ' 与 depth ' + depth + ' 都可调；被截断时 truncated=true（省略不藏起来）',
            '整个二进制会被完整分析一遍（headless 的语义），大文件会慢',
          ],
        }, null, 2)
      }

      // 批量模式：给了任一选择器或 out 就走"落盘 + 摘要"（§10.2.B）；否则仍是单函数内联那条老路。
        const wantBatch = (typeof args.pattern === 'string' && args.pattern.trim() !== '')
          || (typeof args.range === 'string' && args.range.trim() !== '')
          || args.minSize !== undefined || args.maxFunctions !== undefined || typeof args.out === 'string'
        if (wantBatch) {
          if (typeof args.binary !== 'string' || args.binary.trim() === '') {
            const error = new Error('rev_ghidra decompile（批量）需要 binary 参数')
            error.name = 'ArgumentError'
            throw error
          }
          const binaryPath = safePath(args.binary.trim())
          const pattern = typeof args.pattern === 'string' ? args.pattern.trim() : ''
          const range = typeof args.range === 'string' ? args.range.trim() : ''
          let lo = ''
          let hi = ''
          if (range !== '') {
            const matched = /^(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)$/u.exec(range)
            if (matched === null) {
              const error = new Error('rev_ghidra decompile 的 range 要写成 0x开始-0x结束（收到 ' + range + '）')
              error.name = 'ArgumentError'
              throw error
            }
            lo = matched[1]
            hi = matched[2]
          }
          const minSize = args.minSize === undefined ? '' : String(Math.max(0, Math.round(Number(args.minSize) || 0)))
          const maxFunctions = String(Math.min(2000, Math.max(1, Math.round(Number(args.maxFunctions ?? 20) || 20))))
          const stamp = new Date().toISOString().replace(/[:.]/gu, '-')
          const outPath = typeof args.out === 'string' && args.out.trim() !== ''
            ? safePath(args.out.trim())
            : work + '/' + binaryPath.split('/').pop() + '-decompiled-' + stamp + '.c'
          const outDir = outPath.slice(0, outPath.lastIndexOf('/')) || '.'
          await runCmd(shell, ['sh', '-c', 'mkdir -p ' + shq(outDir)], exec, { timeoutMs: 10_000 })
          const run = await runGhidraPostScript(shell, exec, {
            headless, javaHome, work, binary: binaryPath,
            scriptName: 'FlyDecompileBatch', scriptText: flyDecompileBatchScript(),
            arg: [pattern, lo, hi, minSize, maxFunctions, outPath],
          })
          const summary = /FLYDEC-SUMMARY count=(\d+) truncated=(true|false) file=(\S+)/u.exec(run.stdout)
          if (summary === null) {
            throw new Error('rev_ghidra decompile（批量）：没拿到摘要（退出码却是 0）—— 脚本多半没编译过（Ghidra 静默跳过）。跑 rev_ghidra doctor 看环境。')
          }
          const written = Number(summary[1])
          const truncated = summary[2] === 'true'
          const sizeRun = await runCmd(shell, ['sh', '-c', 'wc -c < ' + shq(summary[3])], exec, { timeoutMs: 10_000 })
          const bytes = Number((sizeRun.stdout ?? '').trim()) || 0
          return JSON.stringify({
            tool: 'rev_ghidra',
            target: binaryPath,
            operation: 'analyzeHeadless import + 分析 → FlyDecompileBatch（选择器：pattern=' + (pattern || '-')
              + ' range=' + (range || '-') + ' minSize=' + (minSize || '-') + ' maxFunctions=' + maxFunctions + '）',
            observed: { functions: written, bytes, truncated, file: summary[3] },
            confidence: 'observed',
            limitations: [
              '伪代码**落盘**在 ' + summary[3] + '（按函数切块，每块以 `// function: <名字> @ <地址> size=N` 开头 ⇒ 可直接 grep）',
              '返回值只有摘要（函数数 / 字节数 / 是否截断 / 路径）—— 几千行不会塞进上下文；要看细节请 grep 那个文件',
              truncated
                ? '⚠️ 命中了 maxFunctions=' + maxFunctions + '，**还有匹配的函数没反**（truncated=true）—— 调大它或缩小选择器再跑'
                : '选择器命中的函数已全部反完（没有截断）',
              '每函数最多等 60 秒反编译；超时的会在文件里写成 decompile failed',
              '跳过 thunk / external（没有实体可反）；地址区间按 entry 比较',
              '整个二进制会被完整分析一遍（headless 的语义），大文件会慢',
              '需要 os/<平台>/decompile 原生件；缺失时按 rev_ghidra doctor 的修法补',
            ],
          }, null, 2)
        }

      if (action === 'decompile') {
        if (typeof args.binary !== 'string' || args.binary.trim() === '') {
          const error = new Error('rev_ghidra decompile 需要 binary 参数（要反编译哪个文件）')
          error.name = 'ArgumentError'
          throw error
        }
        const decBinary = safePath(args.binary.trim())
        const want = typeof args.function === 'string' && args.function.trim() !== '' ? args.function.trim() : ''
        await runCmd(shell, ['mkdir', '-p', work], exec, { timeoutMs: 10_000 })
        await writeViaBase64(shell, exec, work + '/FlyDecompile.java', flyDecompileScript())
        const run = await runCmd(shell, ['sh', '-c', [
          'JAVA_HOME=' + javaHome + ' ' + shq(headless) + ' ' + shq(work) + ' flyproj',
          '-import ' + shq(decBinary) + ' -deleteProject',
          '-scriptPath ' + shq(work) + ' -postScript FlyDecompile ' + shq(want),
        ].join(' ')], exec, { timeoutMs: 240_000, stdoutMaxBytes: 8 * 1024 * 1024 })
        const text = (run.stdout ?? '') + (run.stderr ?? '')
        if (run.exitCode !== 0) {
          const fix = ghidraFix(text)
          throw new Error('rev_ghidra decompile 跑失败（exit ' + run.exitCode + '）：'
            + text.trim().split('\n').filter(Boolean).slice(0, 3).join(' | ')
            + (fix === '' ? '' : '\n\n' + fix))
        }
        const out = run.stdout
        if (!/FLYCODE-END/u.test(out)) {
          throw new Error('rev_ghidra decompile：一行伪代码都没产出（退出码却是 0）—— 脚本多半没编译过或原生反编译器没装，'
            + 'Ghidra 对两种情况都可能只打日志不报错；跑 rev_ghidra doctor 看反编译原生件在不在。')
        }
        const blocks = []
        const pattern = /FLYFN-NAME (\S+)\r?\nFLYCODE-START\r?\n([\s\S]*?)\r?\nFLYCODE-END/gu
        for (const match of out.matchAll(pattern)) blocks.push({ name: match[1], code: match[2] })
        return JSON.stringify({
          tool: 'rev_ghidra',
          target: decBinary + (want === '' ? '' : ' · ' + want),
          operation: 'analyzeHeadless import + 分析 → FlyDecompile postScript（DecompInterface）',
          observed: { functions: blocks.length, blocks: blocks.slice(0, 20) },
          confidence: 'observed',
          limitations: [
            '这是 Ghidra 反编译器的**伪代码**（C 风格）：不是源码、不是汇编，变量名多是 Ghidra 起的（FUN_xxx 等）',
            '每个函数最多等 60 秒反编译（DecompInterface 的超时）；超时的会标注 decompile failed',
            '需要 os/<平台>/decompile 原生件 —— 没装时 Ghidra 只在日志里说，这里把它抬成大声报错 + 修法',
            '同一函数的伪代码会随 Ghidra 版本/分析深度变化，别当稳定接口用',
          ],
        }, null, 2)
      }
      if (typeof args.binary !== 'string' || args.binary.trim() === '') {
        const error = new Error('rev_ghidra functions 需要 binary 参数（要分析哪个文件）')
        error.name = 'ArgumentError'
        throw error
      }
      const binary = safePath(args.binary.trim())
      const limit = Math.min(2000, Math.max(1, Math.round(Number(args.limit ?? 200) || 200)))
      await runCmd(shell, ['mkdir', '-p', work], exec, { timeoutMs: 10_000 })
      await writeViaBase64(shell, exec, work + '/FlyFunctions.java', flyFunctionsScript())
      const run = await runCmd(shell, ['sh', '-c', [
        'JAVA_HOME=' + javaHome + ' ' + shq(headless) + ' ' + shq(work) + ' flyproj',
        '-import ' + shq(binary) + ' -deleteProject',
        '-scriptPath ' + shq(work) + ' -postScript FlyFunctions ' + limit,
      ].join(' ')], exec, { timeoutMs: 240_000, stdoutMaxBytes: 4 * 1024 * 1024 })
      const text = (run.stdout ?? '') + (run.stderr ?? '')
      if (run.exitCode !== 0) {
        const fix = ghidraFix(text)
        throw new Error('rev_ghidra functions 跑失败（exit ' + run.exitCode + '）：'
          + text.trim().split('\n').filter(Boolean).slice(0, 3).join(' | ')
          + (fix === '' ? '' : '\n\n' + fix))
      }
      const rows = run.stdout.split('\n').filter(line => line.startsWith('FLYFN {')).map(line => JSON.parse(line.slice(6)))
      const total = Number(/FLYFN-END (\d+)/u.exec(run.stdout)?.[1] ?? rows.length)
      if (!/FLYFN-END/u.test(run.stdout)) {
        // Ghidra 对**编译不过**的 postScript 是 exit 0 + 一行都不打（实测）—— 这里必须大声，
        // 不许把"脚本没跑"读成"这个二进制没有函数"。
        throw new Error('rev_ghidra functions：FlyFunctions 一行都没产出（退出码却是 0）—— 脚本多半没编译过。'
          + 'Ghidra 对编译失败的 postScript 是静默跳过的；请看命令日志里的 javac/脚本错误，'
          + '或照审计里的命令原样跑一遍看它说什么。')
      }
      return JSON.stringify({
        tool: 'rev_ghidra',
        target: binary,
        operation: 'analyzeHeadless import + 分析 → FlyFunctions postScript（最多 ' + limit + ' 条）',
        observed: { count: rows.length, listed: rows.length, total, functions: rows.slice(0, limit) },
        confidence: 'observed',
        limitations: [
          '这是 Ghidra 的**函数表**（按地址顺序、最多 limit 条）：不是全部符号，也不是反编译输出',
          'thunk / external 两个标志原样给出（Ghidra 的判断），没有再做二次解释',
          '整个二进制**会被完整分析一遍**（headless 的语义），大文件会慢 —— 请给 limit 或等',
          '项目目录与脚本写在 scratch（TMPDIR/fly-reverse-ghidra/）里，-deleteProject 用完即删，不碰仓库',
          '反编译（函数体的伪代码）还没接：原生件缺失时 Ghidra 自己会报，修法见 rev_ghidra doctor',
        ],
      }, null, 2)
    },
  }))
}
