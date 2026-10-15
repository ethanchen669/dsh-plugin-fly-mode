import { defineTool } from '@deepseek-ai/dsh-tools'

/** fly-pwn — local analysis helpers: checksec, cyclic, rop planning hints. */
export const name = 'fly-pwn'
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
 *   · 没有 `checksec`（macOS 就是）⇒ 走**仓库内置的原生解析器**算 PIE/NX/RELRO/canary，并在
 *     `limitations` 里明说"这是内置解析器算的"；**绝不**再出现"缺工具 ⇒ 静默回退 ⇒ 对所有文件
 *     都报 pie=no"那种事故（2026-10-01 的原始缺陷正是它）；
 *   · `pwn_cyclic` 的长度会被夹到 1..4096 —— 夹取是**读数**（`observed.clamped`），不是沉默；
 *   · `pwn_rop_hint` **不看文件**：它的清单用 `confidence: 'inferred'` 标出来，并在 `limitations`
 *     里写清"前提必须先由 pwn_checksec / rev_* / bin_* 验过"。
 */
/**
 * 路径参数规范化：以 `-` 开头的路径加 `./` 前缀（2026-10-13）。
 *
 * 为什么不插 `--`：实测本机（macOS，发布目标平台）**objdump（-h/-d/-T）/ base64 -i / otool -hv 都不支持
 * `--`**，插进去直接失败；而 `file -b --version` 会打印 `file-5.41`、`nm -u --version` 会打印
 * `llvm-nm, …`，两者都 **exit 0** ⇒ 工具会把版本串当**数据**返回。加 `./` 之后它就是一个普通相对路径：
 * 不存在就正常报错，存在就是那个文件。
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
 * are simply absent. The old code turned that into "no output" — which read
 * exactly like "nothing found" — and, in `pwn_checksec`, into a fabricated
 * `pie=no` for every binary.
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

/** The 26-letter alphabet every cyclic pattern in this family uses. */
const CYCLIC_ALPHABET = 'abcdefghijklmnopqrstuvwxyz'

/**
 * Cyclic pattern for offset discovery: a prefix of the de Bruijn sequence of
 * order 4 over 26 letters, so every 4-byte window occurs exactly once and a
 * needle searched in it names its offset uniquely. The prefix matches the
 * sequence `pwntools.cyclic()` produces, so `cyclic_find()` offsets from a
 * pwntools workflow line up.
 *
 * The previous generator emitted 4-byte counter groups whose windows repeated
 * after ~100 bytes (`aaaa` at offsets 0 and 101; 158 repeats in the first 4096
 * bytes), so an offset past the prologue could not be resolved at all. Asserted
 * in scripts/verify-security-tools.mjs.
 */
function cyclic(n) {
  const order = 4
  const digits = new Array(order + 1).fill(0)
  const out = []
  const visit = (t, p) => {
    if (out.length >= n) return
    if (t > order) {
      if (order % p === 0) {
        for (let j = 1; j <= p && out.length < n; j++) out.push(CYCLIC_ALPHABET[digits[j]])
      }
      return
    }
    digits[t] = digits[t - p]
    visit(t + 1, p)
    for (let j = digits[t - p] + 1; j < CYCLIC_ALPHABET.length && out.length < n; j++) {
      digits[t] = j
      visit(t + 1, t)
    }
  }
  visit(1, 1)
  return out.join('')
}

// ── BEGIN fly-elf-probe ────────────────────────────────────────────────────
// Native ELF reader, duplicated byte-for-byte in fly-binary and fly-pwn. The
// `verify security-tools` gate compares the two copies and fails when they
// drift: a mis-parse in one copy would silently mislabel mitigations in the
// other. Duplicated rather than imported because a plugin ships as a tarball
// (it cannot reach out of its own package) and because this repo never patches
// upstream. Why it exists: macOS ships neither `readelf` (GNU binutils) nor
// `checksec`, and a shipped DMG must not require the user to install Homebrew.
// File bytes are still read through the sandboxed `shell` seam (`od`); only the
// decoding happens here.

const ELF_MAGIC = 0x7f454c46
const ELF_CLASSES = { 1: 32, 2: 64 }
const ELF_TYPES = { 0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE' }
const ELF_OSABI = { 0: 'UNIX - System V', 3: 'UNIX - GNU/Linux', 6: 'UNIX - Solaris', 9: 'UNIX - FreeBSD', 12: 'UNIX - OpenBSD' }
const ELF_MACHINES = {
  2: 'SPARC', 3: 'Intel 80386', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 22: 'IBM S/390',
  40: 'ARM', 42: 'SuperH', 50: 'IA-64', 62: 'Advanced Micro Devices X86-64', 183: 'AArch64',
  243: 'RISC-V', 258: 'LoongArch',
}
const ELF_PTYPES = {
  0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
  0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY',
}
const ELF_DTAGS = {
  0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB',
  7: 'RELA', 8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 12: 'INIT', 13: 'FINI',
  14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT', 20: 'PLTREL',
  21: 'DEBUG', 22: 'TEXTREL', 23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY', 26: 'FINI_ARRAY',
  27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ', 29: 'RUNPATH', 30: 'FLAGS', 32: 'PREINIT_ARRAY',
  33: 'PREINIT_ARRAYSZ', 35: 'RELRSZ', 36: 'RELR', 37: 'RELRENT',
  0x6ffffef5: 'GNU_HASH', 0x6ffffff0: 'VERSYM', 0x6ffffff9: 'RELACOUNT', 0x6ffffffa: 'RELCOUNT',
  0x6ffffffb: 'FLAGS_1', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM',
}

const ELF_PT_LOAD = 1
const ELF_PT_DYNAMIC = 2
const ELF_PT_INTERP = 3
const ELF_PT_GNU_STACK = 0x6474e551
const ELF_PT_GNU_RELRO = 0x6474e552
const ELF_PF_X = 0x1
const ELF_DT_HASH = 4
const ELF_DT_STRTAB = 5
const ELF_DT_SYMTAB = 6
const ELF_DT_STRSZ = 10
const ELF_DT_BIND_NOW = 24
const ELF_DT_FLAGS = 30
const ELF_DT_FLAGS_1 = 0x6ffffffb
const ELF_DF_BIND_NOW = 0x8
const ELF_DF_1_NOW = 0x1
const ELF_SHT_DYNAMIC = 6
const ELF_SHN_UNDEF = 0

/**
 * Read `length` bytes at `offset` through the shell seam (`od`) as a Buffer.
 *
 * `run` hands back the raw command result (not just stdout) because `od` refuses
 * to start at or past EOF — "cannot skip past end of input", exit 1 — and that is
 * a SHORT READ, not a failure: a truncated file must yield short tables rather
 * than blowing up the whole tool. Every other non-zero exit (missing file,
 * permission) still goes through `requireOk` and stays loud.
 */
async function elfReadRange(run, path, offset, length) {
  const result = await run(['od', '-An', '-v', '-tx1', '-j', String(offset), '-N', String(length), path], { stdoutMaxBytes: 8388608 })
  if (result.exitCode !== 0 && !/cannot skip|past end of input/iu.test(result.stderr)) requireOk(result, `od -j ${offset}`)
  const hex = String(result.stdout).replace(/[^0-9a-fA-F]/gu, '')
  return Buffer.from(hex.slice(0, hex.length - (hex.length % 2)), 'hex')
}

/**
 * Parse an ELF file's header, program headers, sections and `.dynamic`.
 *
 * Returns null when the file is not ELF at all (the caller then falls through to
 * its Mach-O path). Anything that could not be read stays `null` and is rendered
 * `unknown` by the caller — never guessed. Every table is bounded by the bytes
 * that actually arrived, so a truncated file yields a short table instead of
 * invented rows.
 */
async function elfProbe(run, path) {
  const head = await elfReadRange(run, path, 0, 64)
  if (head.length < 16 || head.readUInt32BE(0) !== ELF_MAGIC) return null
  const bits = ELF_CLASSES[head[4]]
  const endian = head[5] === 1 ? 'little' : head[5] === 2 ? 'big' : null
  if (!bits || endian === null) return null
  const wide = bits === 64
  const le = endian === 'little'
  const u16 = (b, o) => (o + 2 <= b.length ? (le ? b.readUInt16LE(o) : b.readUInt16BE(o)) : null)
  const u32 = (b, o) => (o + 4 <= b.length ? (le ? b.readUInt32LE(o) : b.readUInt32BE(o)) : null)
  const u64 = (b, o) => (o + 8 <= b.length ? Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)) : null)

  const eType = u16(head, 16)
  const eMachine = u16(head, 18)
  const entry = wide ? u64(head, 24) : u32(head, 24)
  const phoff = wide ? u64(head, 32) : u32(head, 28)
  const shoff = wide ? u64(head, 40) : u32(head, 32)
  const ehsize = wide ? u16(head, 52) : u16(head, 40)
  const phentsize = wide ? u16(head, 54) : u16(head, 42)
  const phnumRaw = wide ? u16(head, 56) : u16(head, 44)
  const shentsize = wide ? u16(head, 58) : u16(head, 46)
  const shnumRaw = wide ? u16(head, 60) : u16(head, 48)
  const shstrndxRaw = wide ? u16(head, 62) : u16(head, 50)

  // Section header #0 doubles as the escape hatch for the two "too many to fit"
  // encodings (e_shnum 0, e_phnum/shstrndx 0xffff), so read it first.
  const shdr0 = shoff !== null && shoff > 0 && shentsize !== null && shentsize >= (wide ? 64 : 40)
    ? elfParseSection(await elfReadRange(run, path, shoff, shentsize), wide, le)
    : null
  const shnum = shnumRaw === 0 && shdr0 ? shdr0.size : shnumRaw
  const shstrndx = shstrndxRaw === 0xffff && shdr0 ? shdr0.info : shstrndxRaw
  const phnum = phnumRaw === 0xffff && shdr0 ? shdr0.info : phnumRaw

  const sections = []
  if (shoff !== null && shoff > 0 && shnum !== null && shnum > 0 && shentsize) {
    const table = await elfReadRange(run, path, shoff, shentsize * shnum)
    for (let i = 0; i < shnum; i++) {
      const at = i * shentsize
      if (at + shentsize > table.length) break
      const section = elfParseSection(table.subarray(at, at + shentsize), wide, le)
      if (section) sections.push({ ...section, index: i })
    }
  }
  const phdrs = []
  if (phoff !== null && phoff > 0 && phnum !== null && phnum > 0 && phentsize) {
    const table = await elfReadRange(run, path, phoff, phentsize * phnum)
    for (let i = 0; i < phnum; i++) {
      const at = i * phentsize
      if (at + phentsize > table.length) break
      const seg = elfParseSegment(table.subarray(at, at + phentsize), wide, le)
      if (seg) phdrs.push({ ...seg, index: i })
    }
  }

  const shstrtab = sections[shstrndx] ?? null
  if (shstrtab && shstrtab.size > 0) {
    const names = await elfReadRange(run, path, shstrtab.offset, Math.min(shstrtab.size, 65536))
    for (const section of sections) {
      section.name = section.nameOffset < names.length ? elfCString(names, section.nameOffset) : ''
    }
  }

  const loadSegments = phdrs.filter(p => p.type === ELF_PT_LOAD)
  const readAt = (offset, length) => elfReadRange(run, path, offset, length)
  const fileOffsetOfVaddr = (addr) => {
    const seg = loadSegments.find(p => addr >= p.vaddr && addr < p.vaddr + p.memsz)
    return seg ? seg.offset + (addr - seg.vaddr) : null
  }
  const readVaddr = (addr, length) => {
    const offset = fileOffsetOfVaddr(addr)
    return offset === null ? null : readAt(offset, length)
  }

  // PT_DYNAMIC is the normal source; a stripped file that kept only the section
  // table still works through .dynamic.
  const dynSegment = phdrs.find(p => p.type === ELF_PT_DYNAMIC)
  const dynSection = sections.find(s => s.type === ELF_SHT_DYNAMIC)
  const dynAt = dynSegment ? { offset: dynSegment.offset, size: dynSegment.filesz }
    : dynSection ? { offset: dynSection.offset, size: dynSection.size } : null
  const dynamic = []
  if (dynAt && dynAt.size > 0) {
    const bytes = await readAt(dynAt.offset, Math.min(dynAt.size, 262144))
    const step = wide ? 16 : 8
    for (let at = 0; at + step <= bytes.length; at += step) {
      const tag = wide ? u64(bytes, at) : u32(bytes, at)
      const val = wide ? u64(bytes, at + (wide ? 8 : 4)) : u32(bytes, at + 4)
      if (tag === null || val === null) break
      dynamic.push({ tag, val })
      if (tag === 0) break
    }
  }
  const dynTag = (tag) => dynamic.find(d => d.tag === tag)

  const strtab = dynTag(ELF_DT_STRTAB)
  const strsz = dynTag(ELF_DT_STRSZ)
  /** Resolve a byte offset inside DT_STRTAB to its string (null if not resolvable). */
  const dynamicString = async (offsetInStrtab) => {
    if (!strtab || strsz === undefined) return null
    if (!Number.isSafeInteger(offsetInStrtab) || offsetInStrtab < 0 || offsetInStrtab >= strsz.val) return null
    const bytes = await readVaddr(strtab.val + offsetInStrtab, 512)
    return bytes ? elfCString(bytes, 0) : null
  }

  const stack = phdrs.find(p => p.type === ELF_PT_GNU_STACK) ?? null
  const relro = phdrs.find(p => p.type === ELF_PT_GNU_RELRO) ?? null
  const interp = phdrs.find(p => p.type === ELF_PT_INTERP) ?? null
  const flags = dynTag(ELF_DT_FLAGS)?.val ?? 0
  const flags1 = dynTag(ELF_DT_FLAGS_1)?.val ?? 0

  return {
    path, bits, endian, type: eType, machine: eMachine, osabi: head[7], entry, ehsize,
    phoff, phnum, phentsize, shoff, shnum, shentsize, shstrndx,
    phdrs, sections, dynamic, dynAt,
    stack, relro, interp, loadSegments,
    bindNow: dynamic.some(d => d.tag === ELF_DT_BIND_NOW)
      || (flags & ELF_DF_BIND_NOW) !== 0 || (flags1 & ELF_DF_1_NOW) !== 0,
    dynamicString, readAt, readVaddr, fileOffsetOfVaddr,
  }
}

/** `R`/`W`/`E` triplet with `-` for absent bits (readelf's three-column flags). */
function elfFlagsText(pFlags) {
  return `${pFlags & 4 ? 'R' : '-'}${pFlags & 2 ? 'W' : '-'}${pFlags & 1 ? 'E' : '-'}`
}

function elfParseSegment(bytes, wide, le) {
  if (!bytes || bytes.length < (wide ? 56 : 32)) return null
  const u16 = (o) => (le ? bytes.readUInt16LE(o) : bytes.readUInt16BE(o))
  const u32 = (o) => (le ? bytes.readUInt32LE(o) : bytes.readUInt32BE(o))
  const u64 = (o) => Number(le ? bytes.readBigUInt64LE(o) : bytes.readBigUInt64BE(o))
  return wide
    ? { type: u32(0), flags: u32(4), offset: u64(8), vaddr: u64(16), paddr: u64(24), filesz: u64(32), memsz: u64(40), align: u64(48) }
    : { type: u32(0), flags: u32(24), offset: u32(4), vaddr: u32(8), paddr: u32(12), filesz: u32(16), memsz: u32(20), align: u32(28) }
}

function elfParseSection(bytes, wide, le) {
  if (!bytes || bytes.length < (wide ? 64 : 40)) return null
  const u32 = (o) => (le ? bytes.readUInt32LE(o) : bytes.readUInt32BE(o))
  const u64 = (o) => Number(le ? bytes.readBigUInt64LE(o) : bytes.readBigUInt64BE(o))
  return wide
    ? { nameOffset: u32(0), type: u32(4), flags: u64(8), addr: u64(16), offset: u64(24), size: u64(32), link: u32(40), info: u32(44), align: u64(48), entsize: u64(56), name: '' }
    : { nameOffset: u32(0), type: u32(4), flags: u32(8), addr: u32(12), offset: u32(16), size: u32(20), link: u32(24), info: u32(28), align: u32(32), entsize: u32(36), name: '' }
}

function elfCString(bytes, at) {
  let end = at
  while (end < bytes.length && bytes[end] !== 0) end++
  return bytes.subarray(at, end).toString('latin1')
}

/**
 * Dynamic symbol names, used for the canary question ("is `__stack_chk_fail`
 * referenced?"). The symbol count is not stored in ELF; it is recovered from
 * DT_HASH's `nchain`, or by walking DT_GNU_HASH's chains for the highest index.
 * When neither is usable the caller falls back to its documented heuristic.
 */
async function elfDynamicSymbols(run, elf) {
  const symtab = elf.dynamic.find(d => d.tag === ELF_DT_SYMTAB)
  const strtab = elf.dynamic.find(d => d.tag === ELF_DT_STRTAB)
  if (!symtab || !strtab) return null
  const hash = elf.dynamic.find(d => d.tag === ELF_DT_HASH)
  const gnuHash = elf.dynamic.find(d => d.tag === 0x6ffffef5)
  let count = null
  if (hash) {
    const head = await elf.readVaddr(hash.val, 8)
    if (head && head.length >= 8) count = readU32At(head, 4, elf.endian)
  } else if (gnuHash) {
    const head = await elf.readVaddr(gnuHash.val, 16)
    if (head && head.length >= 16) {
      const nbuckets = readU32At(head, 0, elf.endian)
      const symoffset = readU32At(head, 4, elf.endian)
      const bloomSize = readU32At(head, 8, elf.endian)
      const wordSize = elf.bits === 64 ? 8 : 4
      const bucketsAt = gnuHash.val + 16 + bloomSize * wordSize
      const buckets = await elf.readVaddr(bucketsAt, nbuckets * 4)
      if (buckets && buckets.length >= nbuckets * 4) {
        const chainsAt = bucketsAt + nbuckets * 4
        let max = symoffset
        for (let i = 0; i < nbuckets; i++) {
          let index = readU32At(buckets, i * 4, elf.endian)
          if (index < symoffset) continue
          for (let guard = 0; guard < 65536; guard++) {
            const chain = await elf.readVaddr(chainsAt + (index - symoffset) * 4, 4)
            if (!chain || chain.length < 4) break
            const value = readU32At(chain, 0, elf.endian)
            if ((value & 1) === 1) break
            index++
          }
          if (index + 1 > max) max = index + 1
        }
        count = max
      }
    }
  }
  if (count === null || count <= 0) return null
  const entrySize = elf.bits === 64 ? 24 : 16
  const bytes = await elf.readVaddr(symtab.val, Math.min(count, 65536) * entrySize)
  if (!bytes) return null
  const symbols = []
  for (let i = 0; i < count; i++) {
    const at = i * entrySize
    if (at + entrySize > bytes.length) break
    const nameOffset = readU32At(bytes, at, elf.endian)
    const shndx = elf.bits === 64 ? readU16At(bytes, at + 6, elf.endian) : readU16At(bytes, at + 14, elf.endian)
    const value = elf.bits === 64 ? readU64At(bytes, at + 8, elf.endian) : readU32At(bytes, at + 4, elf.endian)
    const strOffset = strtab.val + nameOffset
    const strBytes = await elf.readVaddr(strOffset, 256)
    symbols.push({ name: strBytes ? elfCString(strBytes, 0) : '', shndx, value })
  }
  return symbols
}

function readU16At(bytes, at, endian) {
  if (at + 2 > bytes.length) return null
  return endian === 'little' ? bytes.readUInt16LE(at) : bytes.readUInt16BE(at)
}

function readU32At(bytes, at, endian) {
  if (at + 4 > bytes.length) return null
  return endian === 'little' ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at)
}

function readU64At(bytes, at, endian) {
  if (at + 8 > bytes.length) return null
  return Number(endian === 'little' ? bytes.readBigUInt64LE(at) : bytes.readBigUInt64BE(at))
}
// ── END fly-elf-probe ──────────────────────────────────────────────────────

/** Adapter for the shared ELF probe: it wants the raw command result. */
const rawRun = (shell, exec) => (argv, opts) => runCmd(shell, argv, exec, opts)

/**
 * Canary probe of last resort: `strings`. Documented as a heuristic on purpose —
 * it can see a copied `__stack_chk_fail` string in a binary that never calls it.
 */
async function canaryFromStrings(shell, path, exec, why) {
  const run = await runCmd(shell, ['strings', '-n', '8', path], exec, { stdoutMaxBytes: 1048576 })
  if (run.exitCode !== 0) return [`canary=unknown (neither .dynsym nor strings could be read: ${why})`]
  if (run.stdout.includes('__stack_chk_fail')) return [`canary=present (heuristic: __stack_chk_fail in strings — ${why})`]
  const truncated = run.stdout.length >= 1048576
  return [`canary=${truncated ? 'unknown (strings output truncated)' : 'absent'} (heuristic: __stack_chk_fail in strings — ${why})`]
}

/**
 * Mitigations read out of the ELF itself, used when `checksec` is absent.
 *
 * PIE from e_type + PT_INTERP, NX from PT_GNU_STACK's X bit, RELRO from
 * PT_GNU_RELRO plus DT_BIND_NOW/DF_BIND_NOW, canary from `.dynsym` (whose symbol
 * count has to be recovered from DT_HASH's nchain or DT_GNU_HASH's chains, since
 * ELF does not store it). Anything the file does not state stays `unknown` with
 * the reason attached.
 *
 * The previous fallback is why this exists: it probed `readelf -h` and matched
 * /Type:\s+DYN/, which on a host without readelf failed silently and reported
 * `pie=no` for EVERY binary — a fabricated answer that flips the exploit
 * strategy. Asserted in scripts/verify-security-tools.mjs against ELF32/ELF64,
 * ET_EXEC/ET_DYN (with and without PT_INTERP), DT_HASH and DT_GNU_HASH fixtures.
 */
async function elfMitigationLines(shell, path, exec, kind) {
  const run = rawRun(shell, exec)
  const elf = await elfProbe(run, path)
  const lines = [
    `path=${path}`,
    'checksec=not installed (install checksec.sh — brew install checksec — for the vendor verdict)',
    `format=${kind === '' ? 'unknown (file(1) reported nothing)' : kind}`,
  ]
  if (elf === null) {
    lines.push('pie=unknown (not ELF: nothing was parsed)')
    lines.push('note: nothing here is guessed — see rev_* tools for non-ELF formats')
    return lines
  }
  lines.push(`arch=ELF${elf.bits} ${ELF_MACHINES[elf.machine] ?? `machine 0x${Number(elf.machine).toString(16)}`}, ${elf.endian} endian`)
  if (elf.type === 2) lines.push('pie=no (ELF e_type ET_EXEC)')
  else if (elf.type === 3 && elf.interp !== null) lines.push('pie=yes (ET_DYN with PT_INTERP)')
  else if (elf.type === 3) lines.push('pie=unknown (ET_DYN without PT_INTERP — a shared object or a static PIE; the header alone does not say)')
  else lines.push(`pie=unknown (ELF e_type ${ELF_TYPES[elf.type] ?? elf.type})`)
  lines.push(elf.stack === null
    ? 'nx=unknown (no PT_GNU_STACK segment: the file does not state a stack permission)'
    : (elf.stack.flags & ELF_PF_X) !== 0
      ? 'nx=no (PT_GNU_STACK is executable)'
      : 'nx=yes (PT_GNU_STACK without X)')
  lines.push(elf.relro === null
    ? 'relro=no (no PT_GNU_RELRO)'
    : elf.bindNow
      ? 'relro=full (PT_GNU_RELRO + BIND_NOW)'
      : 'relro=partial (PT_GNU_RELRO without BIND_NOW)')
  const symbols = await elfDynamicSymbols(run, elf)
  if (symbols === null) {
    lines.push(...await canaryFromStrings(shell, path, exec, 'the symbol count is not recoverable: no DT_HASH and no DT_GNU_HASH'))
  } else if (symbols.length === 0) {
    lines.push(...await canaryFromStrings(shell, path, exec, '.dynsym parsed but empty'))
  } else {
    lines.push(symbols.some(sym => sym.shndx === ELF_SHN_UNDEF && sym.name.includes('__stack_chk_fail'))
      ? 'canary=present (__stack_chk_fail is an undefined dynamic symbol)'
      : 'canary=absent (no __stack_chk_fail in .dynsym)')
  }
  lines.push('note: read from the file itself (ELF header, program headers, .dynamic, .dynsym); every `unknown` above means the file does not state it — nothing is guessed')
  return lines
}

/** Mach-O counterpart: otool -hv for the header flags, nm -u for the symbols. */
async function machoMitigationLines(shell, path, exec, kind) {
  const lines = [
    `path=${path}`,
    'checksec=not installed (install checksec.sh — brew install checksec — for the vendor verdict)',
    `format=${kind}`,
  ]
  const otool = await runCmd(shell, ['otool', '-hv', path], exec)
  if (otool.exitCode === 0) {
    lines.push(`pie=${/\bPIE\b/u.test(otool.stdout) ? 'yes (MH_PIE set in the Mach-O header flags)' : 'no (MH_PIE absent from the Mach-O header flags)'}`)
    lines.push(/\bALLOW_STACK_EXECUTION\b/u.test(otool.stdout)
      ? 'nx=no (MH_ALLOW_STACK_EXECUTION is set in the Mach-O header flags)'
      : 'nx=yes (no MH_ALLOW_STACK_EXECUTION in the Mach-O header flags)')
  } else {
    lines.push('pie=unknown (otool unavailable)', 'nx=unknown (otool unavailable)')
  }
  lines.push('relro=n/a (GNU_RELRO is an ELF concept; Mach-O has no direct equivalent)')
  const nm = await runCmd(shell, ['nm', '-u', path], exec, { stdoutMaxBytes: 4194304 })
  const undefinedSymbols = nm.exitCode === 0
    ? nm.stdout.split('\n').map(line => line.trim()).filter(line => /^_?[A-Za-z_][\w$.@]*$/u.test(line))
    : []
  if (nm.exitCode === 0 && undefinedSymbols.length > 0) {
    lines.push(undefinedSymbols.some(name => name.includes('stack_chk_fail'))
      ? 'canary=present (__stack_chk_fail is among the undefined symbols from nm -u)'
      : 'canary=absent (no __stack_chk_fail among the undefined symbols from nm -u)')
  } else {
    lines.push(...await canaryFromStrings(shell, path, exec, `nm -u listed no undefined symbols (exit ${nm.exitCode})`))
  }
  lines.push('note: read from the Mach-O header flags (otool -hv) and the undefined symbols (nm -u); every `unknown` above means the host could not read it — nothing is guessed')
  return lines
}

/** Dispatch on what the file actually is; `file(1)` is POSIX, unlike checksec. */
async function mitigationLines(shell, path, exec) {
  const kindRun = await runCmd(shell, ['file', '-b', path], exec)
  if (kindRun.exitCode !== 0) requireOk(kindRun, 'file -b')
  const kind = kindRun.stdout.trim()
  if (kind.startsWith('Mach-O')) return await machoMitigationLines(shell, path, exec, kind)
  if (kind.startsWith('ELF') || kind === '') return await elfMitigationLines(shell, path, exec, kind)
  return [
    `path=${path}`,
    'checksec=not installed (install checksec.sh — brew install checksec — for the vendor verdict)',
    `format=${kind}`,
    'pie=unknown (neither ELF nor Mach-O — this tool does not guess for other formats)',
  ]
}

export function apply(ctx) {
  const shell = ctx.shell

  ctx.tools.register(defineTool({
    name: 'pwn_checksec',
    description: 'Summarize binary mitigations (checksec when installed, else computed from the ELF or Mach-O itself).',
    parameters: {
      path: { type: 'string', required: true },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args, exec) {
      const path = safePath(args.path)
      const ck = await runCmd(shell, ['checksec', '--file=' + path], exec)
      if (ck.exitCode === 0) {
        return JSON.stringify({
          tool: 'pwn_checksec',
          target: args.path,
          operation: 'read mitigations with the installed checksec',
          observed: { method: 'checksec', dump: ck.stdout },
          confidence: 'observed',
          limitations: [
            'checksec 的输出原样返回（本工具不改写它）',
            'checksec 的判断基于它自己支持的格式/段：**没提到的项不代表不存在**（要逐条核就用 bin_readelf）',
          ],
        }, null, 2)
      }
      // 本机没有 checksec（macOS 就是）：这份读数来自仓库内置的原生解析器。
      const nativeLines = (await mitigationLines(shell, path, exec)).join('\n')
      return JSON.stringify({
        tool: 'pwn_checksec',
        target: args.path,
        operation: 'compute mitigations from the file itself (no checksec on this host)',
        observed: { method: 'native', dump: nativeLines },
        confidence: 'observed',
        limitations: [
          '**本机没有 checksec** ⇒ 这份读数是**仓库内置解析器**算的，不是 checksec 的输出',
          '内置解析器只覆盖本工具声明的字段（arch/pie/nx/relro/canary）；checksec 的其它判断（如 fortify）它不做',
          '它对 Mach-O 与 ELF 各有一套路子：看 method 与 dump 里的措辞，别把 macho 的 relro=n/a 读成"没开"',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'pwn_cyclic',
    description: 'Generate a cyclic de Bruijn pattern for offset discovery.',
    parameters: {
      length: { type: 'number', required: true, description: 'Pattern length in bytes' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args) {
      const n = Math.max(1, Math.min(4096, Number(args.length) || 64))
      // 证据形状（规划 §5.1）：信封 JSON（模式本身进 observed，不塞进 dump 的文本里）。
      return JSON.stringify({
        tool: 'pwn_cyclic',
        target: 'de Bruijn pattern',
        operation: 'generate a cyclic pattern for offset discovery (pwntools-compatible alphabet)',
        observed: { length: n, clamped: n !== (Number(args.length) || 64), dump: cyclic(n) },
        confidence: 'observed',
        limitations: [
          '模式只帮你**定位**偏移：它不告诉你偏移在哪，也不说明那条路径可达（配合真实崩溃日志/调试器才有意义）',
          '长度会被夹到 1..4096：传大了会**静默变短** ⇒ 用 observed.length（或 clamped=true）核对实际给的位数',
          '字母表与 pwntools 的 cyclic 一致，但**只保证前缀相同**：拿别处的 offset 表来查时，先确认两边是同一套字母表',
        ],
      }, null, 2)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'pwn_rop_hint',
    description: 'Produce a ret2libc / ROP planning checklist for a non-PIE NX binary.',
    parameters: {
      binary: { type: 'string', required: true },
      goal: { type: 'string', description: 'e.g. system("/bin/sh") or shell' },
    },
    output: {
      schema: { type: 'string' },
      render: (_a, v) => [{ type: 'text', text: v }],
    },
    async execute(args) {
      // 证据形状（规划 §5.1）：清单型工具 —— 清单本身就是它给出的东西（进 dump）。
      return JSON.stringify({
        tool: 'pwn_rop_hint',
        target: args.binary,
        operation: 'produce a ret2libc/ROP planning checklist (does not read the binary at all)',
        observed: { binary: args.binary, goal: args.goal ?? 'shell', dump: [
        `# ROP plan for ${args.binary}`,
        `goal: ${args.goal ?? 'shell'}`,
        '1. confirm overflow offset via cyclic + crash RIP',
        '2. leak libc via puts@plt(puts@got) and return to main',
        '3. compute libc base, locate system and /bin/sh',
        '4. second payload: pop rdi; ret → binsh → system (align stack with extra ret)',
        '5. prefer local lab targets only; never against unauthorized hosts',
        'note: this tool is a planning checklist only — it does not inspect the binary; pair it with pwn_checksec, rev_imports and rev_gadget_scan',
        ].join('\n') },
        confidence: 'inferred',
        limitations: [
          '**这是清单，不是结论**：本工具**根本不看文件** —— 不读 ELF、不找 gadget、不算偏移',
          '所以它的前提（PIE/NX/canary/RELRO、溢出偏移、libc 版本）必须先由 pwn_checksec / rev_* / bin_* 验过；没验过就不能按它动手',
          '步骤顺序是**一种**常见打法（ret2libc），不是唯一解：目标有 seccomp、特殊 libc 或栈保护时整条路可能不成立',
          '只用在与授权范围一致的目标上（本地 lab 优先）',
        ],
      }, null, 2)
    },
  }))
}
