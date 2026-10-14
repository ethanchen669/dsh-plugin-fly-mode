import { defineTool } from '@deepseek-ai/dsh-tools'

/**
 * fly-binary — ELF / strings / sections toolkit for DSH Fly.
 * Registers model-facing analysis tools on ctx.tools. All command execution
 * goes through the host `shell` capability seam so the sandbox confines it;
 * a tool never shells out via node:child_process directly.
 */
export const name = 'fly-binary'
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

const elfHex = (value, width = 6) => `0x${Number(value).toString(16).padStart(width, '0')}`
const elfSay = (value) => (value === null || value === undefined ? 'unknown' : value)

function renderElfHeader(elf) {
  return [
    'ELF Header (parsed natively — this host has no readelf):',
    `  File: ${elf.path}`,
    `  Class: ${elf.bits === 64 ? 'ELF64' : 'ELF32'}`,
    `  Data: 2's complement, ${elf.endian} endian`,
    `  OS/ABI: ${ELF_OSABI[elf.osabi] ?? `0x${Number(elf.osabi).toString(16)}`}`,
    `  Type: ${ELF_TYPES[elf.type] ?? `0x${Number(elf.type).toString(16)}`}`,
    `  Machine: ${ELF_MACHINES[elf.machine] ?? `0x${Number(elf.machine).toString(16)}`}`,
    `  Entry point: ${elfSay(elf.entry === null ? null : elfHex(elf.entry))}`,
    `  Program headers: ${elfSay(elf.phnum)} x ${elfSay(elf.phentsize)} bytes at ${elfSay(elf.phoff === null ? null : elfHex(elf.phoff))}`,
    `  Section headers: ${elfSay(elf.shnum)} x ${elfSay(elf.shentsize)} bytes at ${elfSay(elf.shoff === null ? null : elfHex(elf.shoff))} (shstrndx ${elfSay(elf.shstrndx)})`,
    elf.interp === null ? '  PT_INTERP: none' : '  PT_INTERP: present (dynamically linked executable)',
  ].join('\n')
}

function renderElfSegments(elf) {
  if (elf.phdrs.length === 0) {
    return `no program headers could be read from ${elf.path} (e_phnum=${elfSay(elf.phnum)}) — a relocatable object, or a file whose header is unreadable`
  }
  const rows = elf.phdrs.map(ph => `  ${(ELF_PTYPES[ph.type] ?? `0x${ph.type.toString(16)}`).padEnd(14)} ${elfHex(ph.offset, 8)} ${elfHex(ph.vaddr, 8)} ${elfHex(ph.filesz, 8)} ${elfHex(ph.memsz, 8)}  ${elfFlagsText(ph.flags)}`)
  return [
    `Program Headers (${elf.phdrs.length}) — parsed natively:`,
    '  Type           Offset   VirtAddr FileSiz  MemSiz   Flg',
    ...rows,
  ].join('\n')
}

async function renderElfDynamic(elf) {
  if (elf.dynamic.length === 0) {
    return `no PT_DYNAMIC segment and no .dynamic section in ${elf.path} — statically linked, so it has no run-time linker entries`
  }
  const lines = [`Dynamic section (${elf.dynamic.length} entries) — parsed natively:`]
  for (const entry of elf.dynamic) {
    const name = ELF_DTAGS[entry.tag] ?? `0x${entry.tag.toString(16)}`
    let value = elfHex(entry.val, 8)
    if (entry.tag === 1 || entry.tag === 14 || entry.tag === 15 || entry.tag === 29) {
      const text = await elf.dynamicString(entry.val)
      value = text === null ? `${elfHex(entry.val, 8)} (string not resolvable)` : `"${text}"`
    }
    lines.push(`  ${elfHex(entry.tag, 8)} (${name}) ${value}`)
  }
  return lines.join('\n')
}

export function apply(ctx) {
  const shell = ctx.shell

  ctx.tools.register(defineTool({
    name: 'bin_file',
    description: 'Identify a binary file (file(1) + size + basic ELF sanity).',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path to the binary' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const wc = await runCmd(shell, ['wc', '-c', args.path], exec)
      const size = requireOk(wc, 'wc -c').trim().split(/\s+/)[0] ?? '0'
      const identify = await runCmd(shell, ['file', '-b', args.path], exec)
      return `size=${size}\n${requireOk(identify, 'file -b').trim()}`
    },
  }))

  ctx.tools.register(defineTool({
    name: 'bin_strings',
    description: 'Extract printable strings from a binary, optionally filtered.',
    parameters: {
      path: { type: 'string', required: true },
      min: { type: 'number', description: 'Minimum string length (default 4)' },
      grep: { type: 'string', description: 'Substring filter' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const min = String(args.min ?? 4)
      const run = await runCmd(shell, ['strings', '-n', min, args.path], exec, { stdoutMaxBytes: 1048576 })
      let lines = requireOk(run, `strings -n ${min}`).split('\n').filter(Boolean)
      if (args.grep) {
        const g = args.grep.toLowerCase()
        lines = lines.filter((l) => l.toLowerCase().includes(g))
      }
      if (lines.length === 0) {
        return args.grep === undefined
          ? `no printable strings of length ${min} or more in ${args.path}`
          : `no printable strings matching ${JSON.stringify(args.grep)} (min length ${min}) in ${args.path}`
      }
      return lines.slice(0, 400).join('\n')
    },
  }))

  ctx.tools.register(defineTool({
    name: 'bin_readelf',
    description: 'Dump ELF headers / program headers / dynamic section.',
    parameters: {
      path: { type: 'string', required: true },
      mode: { type: 'string', description: 'headers | segments | dynamic' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const mode = args.mode === 'segments' || args.mode === 'dynamic' ? args.mode : 'headers'
      const flag = mode === 'segments' ? '-l' : mode === 'dynamic' ? '-d' : '-h'
      // GNU binutils is not part of macOS. When readelf is absent (or refuses the
      // file) the ELF is parsed here instead: the previous revision threw
      // "command not found" on every Mac, which made four of the five binary
      // tools useless on the platform this app ships for.
      const real = await runCmd(shell, ['readelf', flag, args.path], exec)
      if (real.exitCode === 0 && real.stdout.trim() !== '') return real.stdout
      const elf = await elfProbe(rawRun(shell, exec), args.path)
      if (elf === null) {
        const kind = requireOk(await runCmd(shell, ['file', '-b', args.path], exec), 'file -b').trim()
        return [
          `readelf ${flag} is unavailable on this host (${real.exitCode === 127 ? 'not installed' : `exit ${real.exitCode}`})`,
          `${args.path} is not ELF, so a native ELF reader has nothing to report either — file(1) says: ${kind}`,
          'for Mach-O use rev_disasm / rev_imports (objdump, otool and nm ship with macOS)',
        ].join('\n')
      }
      if (mode === 'segments') return renderElfSegments(elf)
      if (mode === 'dynamic') return await renderElfDynamic(elf)
      return renderElfHeader(elf)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'bin_sections',
    description: 'List ELF section headers.',
    parameters: {
      path: { type: 'string', required: true },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      // 证据形状（规划 §5.1 的第一个试点）：返回值是**信封 JSON**，不再是裸表格文本。
      // 真值判据不变（observed.dump 里是 objdump 原文），新增 confidence 与 limitations ——
      // 逼这个工具回答"这个结论看不见什么"（本仓最贵的那条教训）。
      const run = await runCmd(shell, ['objdump', '-h', args.path], exec)
      const ok = run.exitCode === 0 && run.stdout.trim() !== ''
      // GNU binutils is not part of macOS. Instead of an opaque "command not found",
      // say which method failed and what to use instead (same shape as bin_readelf).
      const kind = ok ? null : await runCmd(shell, ['file', '-b', args.path], exec)
      return JSON.stringify({
        tool: 'bin_sections',
        target: args.path,
        operation: 'read ELF section headers (table only: no flags, no relocations, no disassembly)',
        observed: {
          dump: ok ? run.stdout : '',
          method: ok ? 'objdump -h' : null,
          format: ok ? null : ((kind.stdout || '').trim() || null),
          exitCode: run.exitCode,
        },
        confidence: 'observed',
        limitations: ok
          ? ['读的是 objdump -h 的表格原文，未解析节标志 / 重定位 / 节内容']
          : [`objdump -h 不在本机或读不了这个文件（exit ${run.exitCode}），observed.dump 因此为空 —— 节表没有被读到`,
             'macOS 不带 GNU binutils；Mach-O 用 rev_imports (nm -u) 或 rev_disasm (objdump -d)'],
      }, null, 2)
    },
  }))
}
