# dsh-plugin-fly-review —— Fly 评审姿态

`/review` 开关一个**每会话的评审姿态**：只读地看、**先讲阻塞问题**、每条结论都带证据
（`path:line` / 命令输出 / 复现步骤）、不夸奖也不复述；看完用 `exit_review_mode` 把判词**交用户裁决**。

它是 **agent 平面插件** —— 由 preset 的**行表**挂载（像 `@deepseek-ai/dsh-plan-mode` 那样），
不是 profile 层（没有 `dsh.bundle`）。形状照上游 plan 模式实现，名字与文案全归本包：

| 机制 | 说明 |
| --- | --- |
| 姿态的效果 | **一段引导**（`review:policy` 段）—— 进/出姿态只改提示词段，**不改工具目录**（收口工具常驻注册） |
| 状态 | 记在**会话日志**（`review/mode`），由会话投影折叠 ⇒ **resume / fork 自动恢复** |
| 切态时机 | **下一个被接受的 turn 边界**（`agent/pre-step`）⇒ 同一步里前后一致 |
| 命令 | `/review` 开 · `/review off` 关 · `/review <文字>` 附带一句焦点（文字会作为用户消息交给模型） |
| 收口 | `exit_review_mode(review)` 弹裁决卡（`接受评审并退出` / `继续评审`），判词正文进卡片 detail |

## ⚠️ 只读是**引导**，不是强制

姿态**不限制权限** —— 这正是上游 plan 模式的口径（它的注释：sandbox mode 与 approval policy
*独立*执行，不读也不写模式状态）。要**硬**只读，请配合权限/沙箱策略，或者用一个**不含写工具行**的 preset。

本包不在文案里把引导说成强制；命令回执里也明确写着这一点。

## 配置（行配置）

```yaml
- id: fly-review
  name: 'dsh-plugin-fly-review'
  config:
    section: |
      …你的纪律文本（整段覆写内置那份）…
```

· `section` 可省（用内置纪律文本）· **未知键在加载期直接抛**（配置写错要大声失败，不能被忽略）

## 纪律文本的来源

内置文本取自 `dsh-plugin-fly-smart` 的 `consultPrompt`
（`tools/index.js:352-365`，2026-10-13 版），改写成"模式"口吻。用户裁决"不动 smart 自己"
⇒ 两份文本**共存**：本包一份、smart 一份。要收敛时走"抽库 + 两个消费者构建期内联"
（同 `@dsh-fly/fly-panel-style` 那次的姿势），不做跨仓钉死。

## 测试

```bash
node --test tests/          # 桩按真接缝形状喂：投影读写、命令注册、段注入、收口工具
```
