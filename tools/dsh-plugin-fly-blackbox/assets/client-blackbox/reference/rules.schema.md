# `rules.json` schema 与纪律

规则文件固定 `<workspace>/.fly-blackbox/rules.json`；`bx_proxy start` **只读并校验**它，
校验不过就**拒绝启动**。写入者是 agent / 用户，用现成的文件工具写。

---

## 1. 顶层

```json
{
  "enabled": true,
  "hosts": ["<业务域名>"],
  "watch": { "paths": ["…"], "log_bodies": true, "log_all_requests": true, "noise_hosts": ["…"] },
  "patch_request": [ { "path": "…", "methods": ["POST"], "mode": "set_if_empty", "set": { "…": "…" } } ],
  "patch_response": [ { "path": "…", "mode": "force", "set": { "…": true } } ]
}
```

| 键 | 类型 | 语义 |
| --- | --- | --- |
| `enabled` | boolean | **`false` = 显式关掉注入**（只记录不改包）。缺省（不写这个键）= 注入口打开但只按 `patch_*` 里的规则动 |
| `hosts` | string[] | 生效的 host 子串白名单；**空数组 = 不过滤**（所有 host 都处理） |
| `watch` | object | 只读记录：`paths`（正则数组，命中就记完整请求 / 响应）、`log_bodies`、`log_all_requests`、`noise_hosts`（日志降噪） |
| `patch_request` | object[] | 改**请求**（补字段 / 改值 / 绕前端校验） |
| `patch_response` | object[] | 改**响应**（解除客户端门禁 / 伪造状态 / 诱出前端请求） |

---

## 2. `patch_request` / `patch_response` 条目

| 字段 | 必填 | 语义 |
| --- | --- | --- |
| `path` | ✅ | **正则字符串**（大小写不敏感），对请求路径做 `search` |
| `methods` | — | 仅 `patch_request`：只对这些方法生效，缺省 `POST` / `PUT` / `PATCH` |
| `mode` | — | `set_if_empty`（缺省）/ `force` / `only_missing` |
| `set` | ✅ | 要写入的 `{字段: 值}` |
| `create_missing` | — | 配合 `mode: "only_missing"`：键不存在时新增 |

**三种 mode 的差别（选错就白干）**

| mode | 什么时候写 | 典型用途 |
| --- | --- | --- |
| `set_if_empty` | 原值是"空"（`null` / `""` / `0` / `"0"` / `[]` / `{}`）时 | 补一个前端认为"没填"的字段 |
| `force` | 无条件覆盖 | 解除客户端门禁（`state` / `confirm`） |
| `only_missing` | 键**不存在**时（需 `create_missing: true`） | 补一个上游根本没有的键 |

> **`0` 与 `"0"` 都算"空"** —— 这正是 T5 假值陷阱的来源，也是 `set_if_empty` 的判定口径。
> 要让 `0` 被写进去，用 `mode: "force"`，或注入**字符串** `"0"`（JS 真值，能同时过判假与判空）。

---

## 3. 纪律（每条都有代价）

1. **永远先只开 `watch` 跑一遍**，看清真实流量，再加 `patch`。
2. **`patch` 一次只动一个字段**，并事先写明"观察点"（界面显示？发包？响应码？）。
3. **显式 off、无静默默认值**：关掉注入必须写 `{"enabled": false}`。
   **空文件是非法**（`bx_proxy start` 会拒绝启动）—— 反面教材：一次性脚本 `set_inject.sh off`
   写了个空文件，addon 于是**静默回退到默认注入**继续改包，排查结论跟着一起坏掉。
   `bx_proxy start` / `bx_doctor` 都按这条口径校验并回显 `rules: none / invalid / valid`。
4. **热加载**：改完保存即生效，不用重启代理（addon 按 mtime 重读；加载失败沿用旧规则并大声报错）。
5. **存档优先于篡改**：响应先落盘再改，证据不能被自己改没了。
6. **规则文件不进仓库、不带真实标识**：`hosts` 写企业域名前先想清楚这份文件会不会被提交。

---

## 4. 校验失败会看到什么

`bx_proxy start` 拒绝启动并给出路径 + 原因，例如：

- `规则文件是空的：<path> —— 空文件曾经静默回退成"默认注入"，所以这里一律当非法。要关掉注入请显式写 {"enabled": false}`
- `规则文件不是合法 JSON：<path> —— <解析器原话>`
- `patch_response[0] 缺少 path（正则字符串）：<path>`
- `patch_response[0].mode 只能是 set_if_empty / force / only_missing：<path>`

示例文件见 `code/rules.example.json`（含 `_说明` / `_场景` 这类注释键，addon 会忽略它们）。
