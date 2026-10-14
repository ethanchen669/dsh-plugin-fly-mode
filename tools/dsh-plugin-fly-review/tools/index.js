/**
 * `dsh-plugin-fly-review` —— **评审姿态**（agent 平面插件，照 `@deepseek-ai/dsh-plan-mode` 的形状 ✓）。
 *
 * 它做的事只有一件：当会话处在评审姿态时，给**每次模型请求**插一段引导（`review:policy` 段），
 * 告诉模型"只读地看、先讲阻塞问题、给 path:line 证据、不夸不复述"；收口工具 `exit_review_mode`
 * 把判词交用户裁决，用户接受即退出姿态。
 *
 * 三条来自上游的实测事实（决定了本文件的写法）：
 *   · 姿态的**效果全部**来自那段引导 —— 进/出姿态只改提示词段，**不改工具目录**（收口工具常驻注册）；
 *   · 状态记在**会话日志**里（`session.append('review/mode', {active})`），由会话投影折叠
 *     ⇒ resume / fork 自动恢复；切态落在**下一个被接受的 turn 边界**（`agent/pre-step`）；
 *   · **权限不归它管**：沙箱与审批策略独立执行 ⇒ 这里的"只读"是**引导**，不是强制（README 写明 ✓，
 *     不许在文案里说成强制 ✗）。
 *
 * 纪律文本取自 smart 的 `consultPrompt`（`dsh-plugin-fly-smart/tools/index.js:352-365`，2026-10-13 版）。
 * 用户裁决"**不动 smart 自己**" ⇒ 两份文本**共存**（本文件一份、smart 一份）；要收敛时走
 * "抽库 + 两个消费者构建期内联"那条老路（同 `@dsh-fly/fly-panel-style` 的姿势），不在这里做跨仓钉死。
 */
import { Service } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import { z } from 'zod'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { UserQuestionError } from '@deepseek-ai/dsh-user-questions'

/** 本包的 npm 名（命令/段的定义 id 用它，插件实例的 data 归属也用它）。 */
const PACKAGE = 'dsh-plugin-fly-review'
/** 收口工具名。**常驻注册**（模式关闭时也在），所以进/出姿态不改工具目录。 */
export const EXIT_REVIEW_MODE = 'exit_review_mode'
/** 会话日志里的事件名；投影键同源。 */
const MODE_EVENT = 'review/mode'
const PROJECTION_KEY = 'review'
/** 提示词段的段名与槽位（槽位沿用上游那一族的 policy 槽：`getSectionOrder` 是按名取值的具名槽）。 */
const SECTION_NAME = 'review:policy'
const SECTION_ORDER = 'PLAN_POLICY'
/** 命令名。斜杠菜单里就是这个。 */
const COMMAND_NAME = 'review'
/** 裁决卡的选项标签：**逐字相等**分派（前缀只能当手打兜底；改了文案必须同改分支）。 */
const ACCEPT_LABEL = '接受评审并退出'
const KEEP_LABEL = '继续评审'
const REVIEW_QUESTION_ID = 'review-mode'
/** 默认纪律文本（行配置 `section` 可整段覆写）。 */
export const DEFAULT_SECTION = [
  'You are reviewing, not authoring: this session is in review mode.',
  '',
  'Read-only posture: do not edit files, do not run commands with side effects, and do not "fix it while you are there".',
  'If something must be changed, say what and why — the change itself happens after the review.',
  '',
  'Order your findings:',
  '1. Blocking problems first — what cannot ship, what is provably wrong, what is missing.',
  '2. Then concrete additions, each one actionable.',
  '',
  'Every claim carries evidence: a `path:line`, a command with its output, or steps that reproduce it.',
  'No praise. Do not restate the thing under review. If you found nothing blocking, say that plainly.',
  '',
  'Finish by handing the verdict to the user with `exit_review_mode`; their decision ends the posture.',
].join('\n')

const REVIEW_DESCRIPTION = `Use only in review mode. Present your review verdict to the user with ${EXIT_REVIEW_MODE}: blocking problems first, then additions, every claim with evidence. On acceptance the review posture ends (the verdict does not authorise any further change by itself).`

/**
 * 校验行配置。`section` 可省（用内置纪律文本 ✓）；**未知键直接抛** —— 配置写错了要在
 * 加载期就大声失败，而不是被忽略（照上游 `resolveConfig` 的口径）。
 */
export function resolveConfig(config = {}) {
  const section = config.section ?? DEFAULT_SECTION
  if (typeof section !== 'string' || section.trim() === '') {
    throw new Error(`${PACKAGE}: config.section must be a non-empty string (omit it to use the built-in discipline text)`)
  }
  const unknown = Object.keys(config).filter(key => key !== 'section')
  if (unknown.length > 0) throw new Error(`${PACKAGE}: unknown config key(s) ${unknown.join(', ')} — config is { section }`)
  return { section }
}

/** 会话日志投影：折叠命令与事件，重建"现在是不是评审姿态"。 */
export const reviewProjectionDefinition = {
  key: PROJECTION_KEY,
  stateVersion: 1,
  stateSchema: z.object({
    active: z.boolean(),
    wanted: z.boolean().nullable(),
    running: z.object({ commandId: z.string(), wanted: z.boolean() }).strict().nullable(),
    activeAtLastHeader: z.boolean().nullable(),
  }).strict(),
  init: () => ({ active: false, wanted: null, running: null, activeAtLastHeader: null }),
  apply: (state, event) => {
    if (event.type === 'command/run' && event.data.name === COMMAND_NAME) {
      if (event.data.args === undefined) return state
      return { ...state, running: { commandId: event.data.commandId, wanted: event.data.args.trim() !== 'off' } }
    }
    if (event.type === 'command/done' && event.data.commandId === state.running?.commandId) {
      const wanted = event.data.kind === 'success' && state.running.wanted !== state.active ? state.running.wanted : null
      return { ...state, wanted, running: null }
    }
    if (event.type === MODE_EVENT) return { ...state, active: event.data.active, wanted: null }
    if (event.type === 'request/header') return { ...state, activeAtLastHeader: state.active }
    return state
  },
  wire: {
    viewSchema: z.object({ active: z.boolean(), pending: z.boolean() }),
    view: state => ({ active: state.active, pending: state.wanted !== null }),
  },
}

/** 评审姿态的服务：拥有日志态、段、命令与收口工具。 */
export class ReviewModeController extends Service {
  static inject = ['tools', 'systemPrompt', 'sessionProjections']

  /** 校验过的纪律文本（默认内置，行配置可覆写）。 */
  section

  /** 等待"下一个被接受的 turn 边界"落地的选择（`narrate` = 是否顺带注入一句通知）。 */
  pendingIntents = new WeakMap()

  constructor(ctx, config = {}) {
    super(ctx, 'reviewMode')
    this.section = resolveConfig(config).section
    let disposed = false

    // ① 边界：下一个被接受的 turn 之前把待定选择写进日志（同一步里前后一致）。
    ctx.on('agent/pre-step', async ({ agent, signal }, next) => {
      const decision = await next()
      const pending = this.pendingIntents.get(agent.session)
      if (decision.kind === 'reject' || signal.aborted || pending === undefined) return decision
      let narration
      try {
        narration = this.onBoundary(agent.session)
      } catch (error) {
        ctx.logger.warn(`${PACKAGE}: failed to append the selected review mode at step start: %o`, error)
        return decision
      }
      return !pending.narrate || narration === undefined ? decision : { ...decision, messages: [...decision.messages, narration] }
    })

    ctx.effect(() => () => { disposed = true }, `${PACKAGE}: close service lifetime`)

    // ② 引导段：只在姿态激活时非空（进/出姿态的全部效果就是这个）。
    ctx.systemPrompt.section({
      name: SECTION_NAME,
      order: ctx.systemPrompt.getSectionOrder(SECTION_ORDER),
      text: (context) => {
        if (context.agent === undefined) return ''
        const active = this.pendingIntents.get(context.agent.session)?.active ?? this.loggedActive(context.agent.session)
        return active ? this.section : ''
      },
    })

    // ③ 状态进会话日志 ⇒ resume/fork 自动恢复。
    ctx.sessionProjections.register(reviewProjectionDefinition)

    // ④ 命令：`/review` 开，`/review off` 关，`/review <文字>` 附带一句焦点。
    ctx.inject(['commands'], (commandCtx) => {
      commandCtx.commands.register({
        definitionId: brandString(PACKAGE),
        name: COMMAND_NAME,
        description: 'Enter or leave review mode',
        input: { hint: '[off|focus]', attachments: true },
        handler: ({ agent, rawInput, attachments }) => {
          const message = rawInput.trim()
          if (message === 'off' && attachments.length > 0) {
            return { kind: 'error', text: 'Attachments cannot accompany /review off.' }
          }
          if (message === 'off') {
            switch (this.set(agent, false)) {
              case 'committed': return { kind: 'success', text: 'Review mode off.' }
              case 'queued': return { kind: 'success', text: 'Leaving review mode (applies from the next step).' }
              case 'cancelled': return { kind: 'success', text: 'Review mode entry cancelled.' }
              default: return this.loggedActive(agent.session)
                ? { kind: 'success', text: 'Leaving review mode (applies from the next step).' }
                : { kind: 'success', text: 'Review mode is already inactive.' }
            }
          }
          const outcome = this.set(agent, true)
          if (message !== '' || attachments.length > 0) {
            agent.steer(createUserMessage({
              content: [...attachments, ...(message === '' ? [] : [{ type: 'text', text: message }])],
              source: { kind: PACKAGE },
            }))
          }
          return {
            kind: 'success',
            text: outcome === 'committed'
              ? 'Review mode on. Use /review off to leave. (The posture is guidance: the sandbox and approval policy still decide what runs.)'
              : 'Entering review mode (applies from the next step). Use /review off to leave.',
          }
        },
      })
    })

    // ⑤ 收口工具：常驻注册，把判词交用户裁决。
    ctx.tools.register(defineTool({
      name: EXIT_REVIEW_MODE,
      description: REVIEW_DESCRIPTION,
      parameters: {
        review: { type: 'string', required: true, description: 'The complete review verdict, as markdown, starting with a # heading that names it.' },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: { accepted: { type: 'boolean', const: true, required: true } },
        },
        // 收口旁白：这句是**给模型的指令**，所以口径必须是我们自己的 —— 接受评审**不授权**任何改动
        //（上游 plan 模式这里的原文是 "carry out the plan starting with your next step"，评审不能这么写 ✗）。
        render: () => [{
          type: 'text',
          text: 'Review accepted — the review posture is over. The verdict is the user\'s now; acceptance by itself authorises no further change.',
        }],
      },
      // **箭头函数**：`defineTool` 调 execute 时不绑 this（上游 plan-mode 同样用箭头 ✓）。
      // 写成方法简写 ⇒ 运行期 `this` 是 undefined ⇒ 收口工具一调用就炸 ✗（本轮单测抓到的真 bug）。
      execute: async (args, exec) => {
        const agent = exec.agent
        if (agent === undefined) throw new Error(`${EXIT_REVIEW_MODE} requires a calling agent (no session to switch)`)
        if (!this.loggedActive(agent.session)) throw new Error(`${EXIT_REVIEW_MODE} is only available in review mode`)
        if (!/^#\s+\S/.test(args.review.trim())) throw new Error(`${EXIT_REVIEW_MODE} requires a non-empty markdown review starting with a # heading`)
        const interaction = ctx.get('userQuestions')
        if (interaction === undefined) throw new Error('no user-questions channel is available to decide the review; ask the user to switch the session mode instead')
        const answer = await interaction.ask({
          questions: [{
            id: REVIEW_QUESTION_ID,
            header: '评审裁决',
            question: '接受这份评审并退出评审姿态？',
            detail: args.review,
            options: [
              { label: ACCEPT_LABEL, description: '退出评审姿态。判词归你；这本身不授权任何后续改动。' },
              { label: KEEP_LABEL, description: '留在评审姿态，你的反馈回到模型，继续看。' },
            ],
            intent: { kind: 'review-mode', accept: ACCEPT_LABEL, callId: exec.callId },
          }],
          agent,
          signal: exec.signal,
        }).catch((cause) => {
          if (cause instanceof UserQuestionError && cause.code === 'ASK_CANCELLED') throw new Error('The user dismissed the review card to speak instead; stay in review mode and keep going.')
          throw cause
        })
        if (disposed) throw new Error('the review-mode service was reloaded while the review was under decision; present the review again')
        const items = answer.answers.filter(entry => entry.id === REVIEW_QUESTION_ID)
        const item = items.length === 1 ? items[0] : undefined
        if (item?.selected.length !== 1 || item.selected[0] !== ACCEPT_LABEL || item.custom !== undefined) {
          const feedback = item?.custom ?? ''
          throw new Error(feedback === ''
            ? 'The user chose to keep reviewing; revise the review and present it again.'
            : `The user chose to keep reviewing; their feedback: ${feedback}`)
        }
        this.pendingIntents.set(agent.session, { active: false, narrate: false })
        return { accepted: true }
      },
    }))
  }

  /** 日志态 + 待定选择。 */
  get(agent) {
    const active = this.loggedActive(agent.session)
    const pending = this.pendingIntents.get(agent.session)
    return pending === undefined ? { active } : { active, pending: pending.active }
  }

  /**
   * 选择评审姿态是否激活。
   * 回合之间直接落日志（不会再有 in-turn pre-step）；回合开着就排队等下一个被接受的 pre-step。
   * 重复选择当前/已待定的状态是 no-op。
   */
  set(agent, active) {
    const session = agent.session
    if (active === (this.pendingIntents.get(session)?.active ?? this.loggedActive(session))) return 'noop'
    if (this.hasOpenTurn(session)) {
      this.pendingIntents.set(session, { active, narrate: true })
      return this.loggedActive(session) === active ? 'cancelled' : 'queued'
    }
    if (active === this.loggedActive(session)) {
      this.pendingIntents.delete(session)
      return 'cancelled'
    }
    session.append(MODE_EVENT, { active })
    this.pendingIntents.delete(session)
    const narration = this.narration(session, active)
    if (narration !== undefined) agent.inject(narration)
    return 'committed'
  }

  /** 把待定选择写进日志（下一个请求组装之前）。返回要追加的通知消息（若有）。 */
  onBoundary(session) {
    const pending = this.pendingIntents.get(session)
    if (pending === undefined) return undefined
    const target = pending.active
    this.pendingIntents.delete(session)
    if (target === this.loggedActive(session)) return undefined
    session.append(MODE_EVENT, { active: target })
    return this.narration(session, target)
  }

  /** 用户切远近态时的通知（只在"上一次请求头描述的是另一种姿态"时才说）。 */
  narration(session, target) {
    const told = this.loggedActiveAtLastHeader(session)
    if (told === undefined || told === target) return undefined
    const text = target
      ? 'The user switched this session into review mode: read-only posture, blocking problems first, evidence for every claim.'
      : 'The user switched this session back out of review mode.'
    return createUserMessage({
      content: [{ type: 'text', text }],
      source: { kind: PACKAGE, form: 'notice', summary: text },
    })
  }

  loggedActive(session) {
    return this.reviewState(session).active
  }

  loggedActiveAtLastHeader(session) {
    return this.reviewState(session).activeAtLastHeader ?? undefined
  }

  hasOpenTurn(session) {
    const state = this.ctx.sessionProjections.stateOf(session, 'turnBoundary')
    if (state === undefined) throw new Error(`${PACKAGE} requires the turnBoundary session projection`)
    return state.openTurnStartSeq !== null
  }

  /** 读本包的投影态；读不到就**大声抛**（静默返回 false 会让姿态看起来"没生效"却查不出原因）。 */
  reviewState(session) {
    const state = this.ctx.sessionProjections.stateOf(session, PROJECTION_KEY)
    if (state === undefined) throw new Error(`${PACKAGE} requires the ${PROJECTION_KEY} session projection`)
    return state
  }
}

export default ReviewModeController
