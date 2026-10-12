#!/usr/bin/env node
/**
 * 本仓的本地门禁（CI 与 release 都跑它）。
 *
 * 为什么这么小：本仓是**纯声明包**（`dsh.bundle.patch` → `./cordis.patch.yml`，没有代码、
 * 没有构建步骤）。它真正的同源检查在 **dsh-fly 仓**（生成器住在那儿：`--check` 断"包里的
 * 声明 == 生成器输出"）；本仓能自证的是**包形状**与**声明内容的两条红线**。
 *
 * 红线（2026-10-10 的产物决策，写进 dsh-fly 的 shipping-hygiene 门禁，这里再断一次）：
 *   ① 三个模型路由键（brain/hand/review）**不许**出现在声明里 —— 那是**用户机器**上的状态
 *      （镜像文件 + 本机 provider）；写了等于替用户选模型，写成空串更会让整棵 preset 挂载被拒。
 *   ② registry 的 `default:` 覆盖**不许**出现 —— 默认模式归上游 `standard`：装本包 ≠ 默认变 fly。
 *
 * 依赖**不求装**：8 个 `dsh-plugin-fly-*` 目前都还是 private/未发布，现在装一定失败 ——
 * 那是"假红"而不是本包的缺陷。等它们发布后再加 `pnpm install --frozen-lockfile`。
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
/** 列出一个目录下的所有文件（相对路径）。 */
function walkFiles(dir, prefix = '', found = []) {
  if (!existsSync(dir)) return found
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isDirectory()) walkFiles(join(dir, entry.name), rel, found)
    else found.push(rel)
  }
  return found
}

const checks = []
const check = (name, ok, detail = '') => {
  checks.push({ name, ok })
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail === '' ? '' : `   ${detail}`}`)
}

const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const patchPath = join(ROOT, String(manifest.dsh?.bundle?.patch ?? 'cordis.patch.yml'))
const patch = existsSync(patchPath) ? readFileSync(patchPath, 'utf8') : ''

check('包里声明文件在（dsh.bundle.patch 指得对）', patch.length > 0, patchPath)
check('声明是 `- insert:` 形式', /^- insert:$/mu.test(patch))
check('声明 id 是 preset-fly', /^ {4}- id: preset-fly$/mu.test(patch))
check('引擎认的声明行名在多', /^\s+name: '@deepseek-ai\/dsh-agent-preset'$/mu.test(patch))
/**
 * 数某条 preset 的行表（**含条目自身那一行**，与既有 41 行的口径一致）。
 *
 * 边界：条目行之后，遇到下一个**缩进不更深且以 `- ` 开头**的行就算结束（同级条目）。
 * 第一版把边界写成三个条件与或，读成 34/32 这种飘忽的数 —— 尺子本身要能一句话说清。
 */
function presetRowsOf(entryId) {
  const lines = patch.split('\n')
  const start = lines.findIndex(line => new RegExp(`^\\s*- id: ${entryId}\\s*$`, 'u').test(line))
  if (start === -1) return null
  const indent = lines[start].match(/^\s*/u)[0].length
  const block = [lines[start]]
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index]
    if (line.trim() !== '' && line.match(/^\s*/u)[0].length <= indent && line.trimStart().startsWith('- ')) break
    block.push(line)
  }
  return block
}
const flyBlock = presetRowsOf('preset-fly')
const standardBlock = presetRowsOf('preset-fly-standard')
check('安全模式行表齐（41 行 + 声明自身）', flyBlock !== null && flyBlock.filter(line => /^\s+- id: /u.test(line)).length === 42)
check('标准模式行表齐（33 行 + 声明自身）', standardBlock !== null && standardBlock.filter(line => /^\s+- id: /u.test(line)).length === 34)
check('① 不含三个模型路由键（用户机器状态）', !/^\s*(brain|hand|review)Route\s*:/mu.test(patch))
check('② 不含 registry 的 default 覆盖（默认归上游 standard）', !/^\s+default:/mu.test(patch))
check('不带浏览器半边（dsh.client）', manifest.dsh?.client === undefined)
check('不带 Fly 外壳（dsh-plugin-fly-shell）', !JSON.stringify(manifest.dependencies ?? {}).includes('fly-shell'))
// 形状（用户 2026-10-11 裁决）：**7 个工具内联进包**（行表用本包子路径）+ **fly-smart 单独一个
// plugin**（本包 dependencies 里唯一的一项，由 npm 装进 profile，行表保持裸名）。
const INLINED = ['dsh-plugin-fly-binary', 'dsh-plugin-fly-reverse', 'dsh-plugin-fly-pwn', 'dsh-plugin-fly-diag', 'dsh-plugin-fly-recon', 'dsh-plugin-fly-blackbox', 'dsh-plugin-fly-guard']
check('dependencies 只有 fly-smart 一个（其余 7 个已内联）', JSON.stringify(manifest.dependencies ?? {}) === JSON.stringify({ 'dsh-plugin-fly-smart': manifest.dependencies?.['dsh-plugin-fly-smart'] }), JSON.stringify(manifest.dependencies))
for (const tool of INLINED) {
  const entry = `tools/${tool}/index.js`
  check(`内联：${entry} 在包里`, existsSync(join(ROOT, entry)))
  check(`内联：行表用子路径引用 ${tool}`, patch.includes(`name: '@dsh-fly/dsh-plugin-fly-mode/${entry}'`))
  check(`内联：${tool} 不再以裸名出现在行表`, !new RegExp(`^\\s*name:\\s*'?${tool}'?\\s*$`, 'mu').test(patch))
}
check('fly-smart 行保持裸名（单独一个 plugin）', /^\s*name:\s*'?dsh-plugin-fly-smart'?\s*$/mu.test(patch))
// 第二个 preset：**Fly 标准模式**（上游 standard 的行表 + smart，**不含**安全工具行）。
check('preset-fly-standard 在包里', /^\s*- id: preset-fly-standard\s*$/mu.test(patch))
check('preset-fly-standard 的 config.id 是 fly-standard', /^\s*id: fly-standard\s*$/mu.test(patch))
{
  const smartRows = standardBlock.filter(line => /^\s+- id: tool-fly-smart$/u.test(line))
  const securityRows = standardBlock.filter(line => line.includes('tools/dsh-plugin-fly-'))
  const totalRows = patch.split('\n').filter(line => /^\s+- id: /u.test(line)).length
  check('标准模式恰好一行 smart', smartRows.length === 1)
  check('标准模式**不含**任何安全工具行', securityRows.length === 0, securityRows.slice(0, 2).join(' | '))
  check('整份 patch 的行数 == 两个 preset 之和（42 + 34）', totalRows === 76, String(totalRows))
}
check('files 里有声明文件与 tools/', (manifest.files ?? []).some(name => name.endsWith('cordis.patch.yml')) && (manifest.files ?? []).includes('tools'))
// 内网 provider / 内网模型 id 不许进包（同 dsh-fly 主仓 shipping-hygiene 的两条红线）
const INTERNAL = [/llm-mioffice/iu, /xiaomi\/mimo-/iu, /gpt-6-astra/iu, /ppio\/pa\//iu]
const shippedText = [
  patch,
  ...INLINED.flatMap(tool => walkFiles(join(ROOT, 'tools', tool), `tools/${tool}`)).map(rel => readFileSync(join(ROOT, rel), 'utf8')),
]
const internalHits = shippedText.flatMap(text => String(text).split('\n').filter(line => INTERNAL.some(pattern => pattern.test(line))))
// 本地垃圾（python 缓存、编辑器临时文件）不许进包：它们会随 `files: ['tools']` 一起被 npm 打包。
// 2026-10-11 实测撞到过：源包目录里有一份未被 git 跟踪的 `__pycache__/*.pyc`，被生成器整目录拷进包里。
const JUNK = /(^|\/)(__pycache__|\.DS_Store)($|\/)|(\.pyc|\.swp|\.orig)$/u
const junkHits = walkFiles(join(ROOT, 'tools'), 'tools').filter(rel => JUNK.test(rel))
check('交付字节里没有本地垃圾（__pycache__/.pyc/.DS_Store/…）', junkHits.length === 0, junkHits.slice(0, 3).join(' | '))
check('交付字节里不出现内网 provider / 内网模型 id', internalHits.length === 0, internalHits.slice(0, 3).join(' | '))
// 判据：URL 里必须出现**仓名**（= 包名去掉 scope 之后的那一段）。
// 第一版写成 `name.replace('@dsh-fly/', 'dsh-plugin-fly-')` ⇒ 拼出
// `dsh-plugin-fly-dsh-plugin-fly-mode`（包名里本来就有 `dsh-plugin-fly-`），于是这条断言
// 恒假、把一个完全正确的 package.json 报成红 —— 检查自己写错，比漏检查更坏（它会让人去改
// 本来对的东西）。
const repoName = String(manifest.name ?? '').replace(/^@[^/]+\//u, '')
check(
  'repository.url 与仓名一致（npm --provenance 会校验；写错=直接拒发）',
  repoName.length > 0 && String(manifest.repository?.url ?? '').includes(repoName),
  `${String(manifest.repository?.url ?? '(缺)')}  ← 仓名 ${repoName}`,
)

const failed = checks.filter(entry => !entry.ok)
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`)
process.exitCode = failed.length === 0 ? 0 : 1
