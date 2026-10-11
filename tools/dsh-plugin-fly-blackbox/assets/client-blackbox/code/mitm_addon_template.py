#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mitm_addon_template.py —— 客户端黑盒排查用的 mitmproxy 插件（声明式 + 热加载）

设计原则（都是实战踩坑换来的）
  1. **声明式**：行为全写在 rules.json 里，不写死在代码里 —— 换个目标只改 json
  2. **热加载**：改完 rules.json 立即生效，**不重启代理**
     （排查中最浪费时间的就是"改一行配置 → 重启 → 等客户端重连"）
  3. **永远先 watch，再 patch**；patch 一次只动一个字段
  4. **每一处篡改都在日志里吼一声**，让你不可能忘记自己改过什么
  5. **缺规则 / 规则非法 = 拒绝启动**，绝不回退到"默认注入"
     （反面教材：一次性脚本把规则文件写空，addon 静默继续改包，结论跟着一起坏掉）
  6. **改动路径要显式授权**：只有 `FLY_ALLOW_INTERCEPT=1` 时才允许注入；
     否则退化成只读记录 —— 只读路径永远可用

用法（由 `bx_proxy start` 拼出来，这里是它的形状）
    mitmdump -s mitm_addon_template.py -w <workspace>/.fly-blackbox/flows.mitm \
             --set confdir=<workspace>/.fly-blackbox/mitmproxy \
             -p 8080
    # 规则路径与授权开关走**环境变量**（不是 `--set`）：
    #   MITM_RULES=<workspace>/.fly-blackbox/rules.json
    #   MITM_CAPTURE=<workspace>/.fly-blackbox/capture
    #   FLY_ALLOW_INTERCEPT=1        （只有 =1 才允许注入；否则只读记录）
    #
    # 为什么不用 `--set fly_rules=…`：实测 mitmdump 12.2.3 里 `--set` 的值要到 addon 的
    # `load()` **之后**才写进 `ctx.options`（`load()` 里读到的是空串、`running()` 里才是
    # 给定值），而本 addon 的纪律是"规则文件缺失/非法 = 在 `load()` 里拒绝启动"。用
    # `--set` 传规则路径会静默退回默认的 `rules.json`、当场抛 RuleError、mitmdump 退出 1
    # —— 代理根本起不来，而症状看起来像"规则文件没写"。

规则示例见同目录 rules.example.json，schema 见 reference/rules.schema.md。
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from mitmproxy import ctx, http

# ---------------------------------------------------------------- 基础配置

# 规则路径走**环境变量**：这是唯一在 addon 的 import / load() 期就生效的通道
# （`--set` 要等 load() 之后才写进 ctx.options —— 见文件头"为什么不用 --set"）。
RULES_PATH = Path(
    os.environ.get("MITM_RULES")
    or getattr(ctx.options, "fly_rules", "")
    or "rules.json"
)
CAPTURE_DIR = Path(os.environ.get("MITM_CAPTURE", "./capture"))

# 值是"空"的判定 —— 注意 0 与 "0" 都算空（这正是大量线上 bug 的来源，见 playbook T5）。
# patch 时按需选择 mode。
EMPTY_VALUES = (None, "", 0, "0", [], {})

_rules_cache: dict | None = None
_rules_mtime: float = -1.0
_seen_hosts: set[str] = set()


def _intercept_allowed() -> bool:
    """改动路径的授权开关。未设/不等于 1 → 只记录、不注入。"""
    return os.environ.get("FLY_ALLOW_INTERCEPT") == "1"


# ---------------------------------------------------------------- 规则加载


class RuleError(RuntimeError):
    """规则文件缺失或非法 —— 一律拒绝启动，绝不静默回退。"""


def _load_rules() -> dict:
    """
    读规则。**缺文件、空文件、非法 JSON、缺关键键都抛错**。

    这里刻意不提供"默认规则"：默认规则意味着"用户以为关掉了，其实还在注入"，
    而那种静默正是本框架最贵的一个坑。
    """
    path = RULES_PATH
    if not path.is_file():
        raise RuleError(f"规则文件不存在：{path} —— 拒绝启动（不提供默认注入）")
    raw = path.read_text(encoding="utf-8")
    if raw.strip() == "":
        raise RuleError(
            f"规则文件是空的：{path} —— 空文件曾被静默当成'默认注入'，"
            '所以这里一律当非法。要关掉注入请显式写 {"enabled": false}'
        )
    try:
        loaded = json.loads(raw)
    except Exception as exc:  # noqa: BLE001 - 原话要透给用户
        raise RuleError(f"规则文件不是合法 JSON：{path} —— {exc}") from exc
    if not isinstance(loaded, dict):
        raise RuleError(f"规则文件顶层必须是对象：{path}")

    watch = loaded.get("watch") or {}
    if not isinstance(watch, dict):
        raise RuleError(f"watch 必须是对象：{path}")
    for key in ("patch_request", "patch_response"):
        if key in loaded and not isinstance(loaded[key], list):
            raise RuleError(f"{key} 必须是数组：{path}")
    return {
        "enabled": bool(loaded.get("enabled", True)),
        "hosts": list(loaded.get("hosts") or []),
        "watch": {
            "paths": list(watch.get("paths") or []),
            "log_bodies": bool(watch.get("log_bodies", True)),
            "log_all_requests": bool(watch.get("log_all_requests", True)),
            "noise_hosts": list(watch.get("noise_hosts") or []),
        },
        "patch_request": list(loaded.get("patch_request") or []),
        "patch_response": list(loaded.get("patch_response") or []),
    }


def rules() -> dict:
    """热加载：mtime 变了就重读。所以改完 json 不用重启代理。"""
    global _rules_cache, _rules_mtime
    try:
        mtime = RULES_PATH.stat().st_mtime
    except OSError:
        # 文件在运行中被删了：缓存还在就继续用缓存（进程内的规则不会凭空变），
        # 没有缓存说明启动时就没读到 —— 那时已经抛错退出了。
        if _rules_cache is None:
            raise RuleError(f"规则文件不见了：{RULES_PATH}") from None
        return _rules_cache
    if _rules_cache is None or mtime != _rules_mtime:
        loaded = _load_rules()  # 非法就在下一次请求时抛出来
        _rules_cache = loaded
        _rules_mtime = mtime
        ctx.log.warn(
            f"[RULES] 已加载 {RULES_PATH}（改动自动生效）：enabled={loaded['enabled']} "
            f"patch_request {len(loaded['patch_request'])} 条 / patch_response {len(loaded['patch_response'])} 条"
        )
    return _rules_cache


# ---------------------------------------------------------------- 工具函数


def _log_file(name: str, line: str) -> None:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    with (CAPTURE_DIR / name).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _host_ok(host: str, r: dict) -> bool:
    hosts = r.get("hosts") or []
    return (not hosts) or any(h in host for h in hosts)


def _match(patterns, path: str) -> bool:
    return any(re.search(p, path, re.I) for p in (patterns or []))


def _json_of(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _apply(node, updates: dict, mode: str, create_missing: bool) -> list[str]:
    """递归地把 updates 应用到 JSON 树里所有"含有这些 key"的 dict。

    mode:
      set_if_empty  仅当原值为空（None/""/0/"0"/[]/{}）时写入
      force         无条件覆盖
      only_missing  仅当 key 不存在时新增（配合 create_missing）
    """
    hits: list[str] = []

    if isinstance(node, dict):
        for key, value in updates.items():
            if key in node:
                old = node[key]
                if mode == "force" or (mode == "set_if_empty" and old in EMPTY_VALUES):
                    node[key] = value
                    hits.append(f"{key}: {old!r} -> {value!r}")
            elif create_missing and mode == "only_missing":
                node[key] = value
                hits.append(f"{key}: <缺失> -> {value!r}")
        for value_node in node.values():
            hits.extend(_apply(value_node, updates, mode, create_missing))
    elif isinstance(node, list):
        for item in node:
            hits.extend(_apply(item, updates, mode, create_missing))

    return hits


def _patch_message(message, rule: dict, kind: str) -> None:
    """kind: 'REQ' | 'RESP'。只处理 JSON。"""
    if not _intercept_allowed():
        ctx.log.warn(
            f"[PATCH-{kind}] 规则命中 {rule.get('path')}，但 FLY_ALLOW_INTERCEPT != 1 —— "
            "只读模式，拒绝改动。要注入请先显式授权。"
        )
        return
    ctype = (message.headers.get("content-type", "") or "").lower()
    text = message.get_text(strict=False) or ""
    data = _json_of(text)
    if data is None:
        if "json" in ctype:
            ctx.log.warn(f"[PATCH-{kind}] {rule.get('path')} 命中但 body 不是合法 JSON，跳过")
        return

    mode = rule.get("mode", "set_if_empty")
    hits = _apply(data, rule.get("set", {}), mode, bool(rule.get("create_missing")))
    if hits:
        message.set_text(json.dumps(data, ensure_ascii=False))
        ctx.log.warn(f"[PATCH-{kind}] {rule.get('path')} :: " + "; ".join(hits))


# ---------------------------------------------------------------- hooks


def request(flow: http.HTTPFlow) -> None:
    r = rules()
    host = flow.request.pretty_host
    if not _host_ok(host, r):
        return

    watch = r["watch"]
    if watch.get("log_all_requests", True):
        line = f"{time.strftime('%H:%M:%S')} REQ  {flow.request.method} {flow.request.pretty_url}"
        _log_file("all.log", line)
        if host and host not in _seen_hosts:
            _seen_hosts.add(host)
            ctx.log.warn(f"[NEW HOST] {host}")
            _log_file("all.log", f"*** NEW HOST: {host}")
        if not any(n in host for n in (watch.get("noise_hosts") or [])):
            ctx.log.info(line)

    if watch.get("log_bodies") and _match(watch.get("paths"), flow.request.path):
        body = flow.request.get_text(strict=False) or ""
        _log_file(
            "watch.log",
            f"\n===== REQ {time.strftime('%H:%M:%S')} =====\n"
            f"{flow.request.method} {flow.request.pretty_url}\n"
            f"--- headers ---\n"
            + "\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())
            + f"\n--- body ---\n{body[:4000]}",
        )

    if not r["enabled"]:
        return
    for rule in r.get("patch_request", []):
        if not _match([rule.get("path", "")], flow.request.path):
            continue
        methods = [m.upper() for m in rule.get("methods", ["POST", "PUT", "PATCH"])]
        if flow.request.method.upper() not in methods:
            continue
        _patch_message(flow.request, rule, "REQ")


def response(flow: http.HTTPFlow) -> None:
    r = rules()
    host = flow.request.pretty_host
    if not _host_ok(host, r):
        return

    watch = r["watch"]
    if watch.get("log_all_requests", True):
        _log_file(
            "all.log",
            f"{time.strftime('%H:%M:%S')} RESP {flow.response.status_code} "
            f"{flow.request.method} {flow.request.pretty_url}",
        )

    # 先记录原始响应（存档优先于篡改 —— 证据不能被自己改没了）
    if watch.get("log_bodies") and _match(watch.get("paths"), flow.request.path):
        _log_file(
            "watch.log",
            f"\n----- RESP {time.strftime('%H:%M:%S')} {flow.response.status_code} "
            f"{flow.request.path} -----\n"
            f"{(flow.response.get_text(strict=False) or '')[:4000]}",
        )

    if not r["enabled"]:
        return
    for rule in r.get("patch_response", []):
        if not _match([rule.get("path", "")], flow.request.path):
            continue
        _patch_message(flow.response, rule, "RESP")


def load(_loader) -> None:
    """启动即校验规则：缺文件 / 空文件 / 非法 → 直接抛，进程不进入服务状态。"""
    loaded = rules()
    ctx.log.info(
        f"fly-blackbox addon 就绪：规则 {RULES_PATH} · enabled={loaded['enabled']} · "
        f"注入授权 FLY_ALLOW_INTERCEPT={'1（开）' if _intercept_allowed() else '未设（只读）'}"
    )


def done() -> None:
    ctx.log.info(f"抓包存档目录：{CAPTURE_DIR}（all.log / watch.log）")
