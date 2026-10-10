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

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
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
check('行表齐（41 行 + 声明自身）', patch.split('\n').filter(line => /^\s+- id: /u.test(line)).length === 42)
check('① 不含三个模型路由键（用户机器状态）', !/^\s+(brain|hand|review)Route:/mu.test(patch))
check('② 不含 registry 的 default 覆盖（默认归上游 standard）', !/^\s+default:/mu.test(patch))
check('不带浏览器半边（dsh.client）', manifest.dsh?.client === undefined)
check('不带 Fly 外壳（dsh-plugin-fly-shell）', !JSON.stringify(manifest.dependencies ?? {}).includes('fly-shell'))
check('files 里有声明文件', (manifest.files ?? []).some(name => name.endsWith('cordis.patch.yml')))
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
