# Handoff — 第一轮内部检查点（checkpoint-1）

> 交付定义：**bash 命令改了工作区里的文件，wsbox 必须正确识别出 diff** —— 不漏报、
> 不误报、diff 与真实字节一致、`apply` / `restore` 能复现。
>
> 状态：**内部检查点，不是 release**。tag `checkpoint-1`，用于内部测试；
> 未发布、未建 GitHub Release、未承诺对外兼容。工作区干净，无未提交改动。

---

## 1. 验收（5 个门，全部可执行）

```bash
# 门 1 构建与测试：期望 22 + 51 + 59 + 4 = 136 全绿
cargo test --workspace --all-features
cargo +1.92.0 test --workspace --all-features      # MSRV（1.92.0 已在本机安装）
cargo +1.92.0 check --workspace --all-features

# 门 2 lint 与格式：期望均无输出
cargo clippy --workspace --all-features --all-targets -- -D warnings
rustfmt --edition 2024 --check src/*.rs tests/*.rs

# 门 3 DoD 功能矩阵：见 docs/production-readiness.md §2（每条 bash 操作 → 测试名）

# 门 4 CLI 冒烟（真实 overlay）
wsbox capabilities                              # 期望 full capability set
wsbox open --session s --workspace <ws> --ledger-dir <ledger>
wsbox exec --session s --call c1 -- bash -c 'sed -i …; rm -rf dir; mkdir -p a/b; \
    chmod 600 f; ln -sfn x y; printf z > "$(printf "\377")"'
wsbox changes --session s                       # 每类变更都在，diff 正确
wsbox apply   --session s                       # applied 列出全部，真实工作区一致
wsbox verify  --session s                       # 链完整

# 门 5 CI：.github/workflows/ci.yml 的命令与门 1/2 相同
```

⚠️ `tests/live.rs` 的 4 条在未设 `TYPESAFE_API_KEY` 时是**空跑通过**，不作为 Jev 后端的证据。

---

## 2. 本轮做了什么

| 提交 | 内容 |
|---|---|
| `653a0be` | 变更识别主干：目录/文件互换、目录删除、`chmod`、symlink、fifo、反斜杠文件名、退出码 125、overlay `userxattr`、passthrough 越界、session id 越界、spill 路径、MSRV 声明 |
| `3be0042` | `docs/production-readiness.md`：DoD 覆盖矩阵、剩余缺口、v0.2 设计输入 |
| `02f6ea4` | CI：test + clippy `-D warnings` + MSRV job（装 bwrap、放开 AppArmor userns 限制） |
| `411def6` | MSRV 声明为 1.92 并在 1.92.0 上实测 |
| `2aa842e` | 非 UTF-8 路径字节精确（`!hex:` 单射编码） |
| `b453d6d` | 大文件不读进内存（8 MiB 上限、流式入 CAS、`diffTruncated` + warning） |
| `753d03a` | session 级写锁（`flock`，取锁后重读状态） |
| `9943e8f` | review 组件：区分"人点的"与"窗口超时"（`HumanSource`、`observed`、`readyToPromote`） |

其中 5 个缺陷是**直接破坏 DoD** 的，值得记住它们的存在方式：

1. 命令 `exit 125` 被当成沙箱启动失败 → **整个变更集丢失**（改用 close-on-exec 状态管道）；
2. 文件被替换成目录时**完全不上报**（目录跳过用的是"存在"而非"是目录"）；
3. `chmod` 被内容短路吃掉（`Op::Chmod` 曾是死代码）；
4. 非 UTF-8 文件名被 `to_string_lossy` 压成 U+FFFD，两个文件塌缩成一条；
5. 并发 `exec` 丢 index 更新并写出两条 `seq` 相同的账本条目（哈希链断掉）。

---

## 3. 协议约定（接收方必读，全文见 `docs/protocol.md`）

1. **`diff` 描述调用结束态**：同一次调用内先改后恢复 = 无变更。中间态不可观测（需 fanotify/FUSE）。
2. **`path` 是 key，不是文件名**：合法 UTF-8 即自身；否则 `!hex:<原始字节>`；marker 本身也转义。
   显示前请 `wsbox::fsutil::decode_key`。
3. **> 8 MiB 不内联 diff**：`diff: null` + `diffTruncated: true` + `warnings`；字节在 CAS，`apply`/`restore` 正常。
4. **`Spec.backend`（landlock）与 `CopyMode::Full` 被接受但未实现** —— 不要依赖。
5. **call id 复用时 `changes --call` 归因到第一条**；`sanitize()` 可能让不同 call id 落到同一目录。

---

## 4. 明确不在本轮

- **自动审批**（v0.2）：默认 `Mode::RulesOnly`，真实变更永不自动放行。设计输入（生命周期、类型级不变量、需要与其他组件协商的 5 个问题、落地前要关掉的 6 项风险）已写在 `docs/production-readiness.md` §6。
- **跨 session 互斥**：锁是 per-session 的；两个 session 指向同一 workspace 时 `apply` 仍会互相覆盖。
- **崩溃 reconcile**：`exec` 中途被杀 → upper 有未归因的写入，下一次调用可能把它算到自己头上。
- **daemon / 流式 stdout**：每次 `exec` 都是 fork + unshare + mount overlay。
- **chunk 级 CAS、自动 gc**：重复大文件重写是已知最坏情况（`wsbox status` 会诚实提示 CAS 比快照贵）。

---

## 5. 建议的下一步（按优先级）

**阶段 A 收尾（都在 DoD 之外，但属于生产必需）**

1. **崩溃 reconcile**：`exec` 前写 `calls/<id>/inflight`，返回后删除；下次 `open`/`exec` 发现残留标记时，把未归因的 upper 变更记成一条 `recovered` 条目。
   ⚠️ 需要先定协议：是给 `LedgerEntry` 加 `kind`，还是复用现有字段？这会改变账本语义，属协议级决定。
2. **跨 session workspace 互斥**：workspace 级锁（`<workspace>/.wsbox.lock`，但会污染工作区）或由 daemon 统一持有。

**阶段 B**：daemon + 流式输出、metrics/tracing、结构化错误码、workspace 互斥。

**阶段 C**：chunk 级 CAS（内容定义分块）、自动 gc、并发压测。

**v0.2**：先与能力闸门 / 沙箱 / apply 三方对齐 §6 的 5 个问题，再实现审批窗口。

---

## 6. 未决问题（需要 owner 决策）

1. reconcile 的账本语义（见 §5.1）。
2. 跨 session 互斥的粒度：workspace 锁 vs daemon。
3. v0.2 的 5 个协调问题（窗口归谁、超时语义、review 与 ledger 的锚定粒度、谁有权声明"已校准"、并发下的 review id）。
4. `!hex:` key 的下游消费方：编辑器/前端如何显示与回传。
5. `Spec.backend` / `CopyMode::Full`：实现，还是从协议里删掉。

---

## 7. 环境与运维备注

- **MSRV 1.92**：`rustup toolchain install 1.92.0` 已在本机完成；CI 的 `msrv` job 用同一版本。
- **overlay 测试需要**：`bubblewrap` + 非特权 user namespace。Ubuntu 23.10+ 默认用 AppArmor 限制，CI 里显式 `sysctl kernel.apparmor_restrict_unprivileged_userns=0`。
- **测试在能力不足时会 SKIP 并打印原因**（不静默通过）。看到 `SKIPPED:` 就说明这次没验到 overlay。
- **overlay 的四个目录（lower/upper/work/merged）必须在同一文件系统**；ledger 与 workspace 分处不同 fs 时 mount 会失败。
- 非特权 overlayfs 需要 `userxattr` 挂载选项（已加），否则 unlink/rename 下层目录会返回 `EIO`。
- `Cargo.lock` 里的 `time` / `cookie_store` 写着 `rust-version = 1.88`，但它们被 ureq 的非默认 `cookies` feature 挡住，**不参与构建** —— 不要据此推断 MSRV。
