# wsbox 基本生产就绪评估

> **目标（DoD）**：bash 命令改了工作区里的文件，wsbox 必须**正确识别出 diff**。
> 判定口径分四条，缺一条就不算达成：
>
> 1. **不漏报** —— 命令结束后与调用前存在的任何差异，都出现在 change set 里；
> 2. **不误报** —— 没有差异的路径不出现；回到 baseline 的路径不算 pending；
> 3. **diff 正确** —— 文本 diff 与真实内容一致；二进制/被截断有显式标记，不假装完整；
> 4. **可复现** —— `apply` 后真实工作区等于会话视图，`restore` 后等于 baseline。
>
> 退出码、审计归因、审批都不在这条线内：**审批是 v0.2 的进阶打磨**（§6）。

验收命令：

```bash
cargo test --workspace --all-features    # 当前 135 项全绿
cargo clippy --workspace --all-features --all-targets
```

---

## 1. 结论

DoD 的**主干已经达成**：本轮把 bash 常见的写文件方式逐条钉成了端到端测试（§2），
并修掉了 11 个会直接破坏"正确识别 diff"的缺陷（§3）。

距离"能长期无人值守跑"还差三类东西，都不在 DoD 之内但属于生产必需：
**并发/崩溃语义**（§4 P1）、**内存与规模上限**（§4 P0-3）、
以及**一个真正无歧义的路径编码**（§4 P0-1，唯一还会漏报的常见场景）。

---

## 2. DoD 覆盖矩阵

每一行都是一个端到端测试（`tests/e2e.rs`），跑在真实 overlay 上。

| bash 操作 | 期望 | 测试 |
|---|---|---|
| `python -c "open(f,'w').write('')"` 截断 | 报 modify + suspicious | `python_truncation_is_reported_and_the_workspace_survives` |
| `rm` | 报 delete | `deletion_is_reported_as_a_delete` |
| 重写为相同字节 | **不报** | `no_op_rewrite_produces_no_change` |
| 同尺寸不同内容 | 报 modify，且有 diff | `same_size_rewrite_is_reported_with_a_diff` |
| 文件名含 `\`（Unix 普通字节） | 路径不失真，`apply` 生效 | `a_backslash_in_a_filename_is_not_a_directory_separator` |
| 文件名不是合法 UTF-8 | 两个不同文件**不塌缩**，`apply`/`restore` 按原始字节生效 | `non_utf8_filenames_are_distinct_and_applied` |
| 文件 > 8 MiB 改写 | `diff` 为 null + `diffTruncated` + warning，但 sha/apply/restore 全部正确 | `a_file_too_large_to_diff_is_still_reproducible` |
| `sed -i`（临时文件 + rename） | 报一个 modify | `atomic_rename_is_one_modify` |
| 二进制改写 | 报 modify，`diff: null` | `binary_change_is_reported_without_a_text_diff` |
| `chmod` | 报 chmod 并落到真实文件 | `a_mode_change_is_journaled_and_applied`、`snapshot_mode_reports_a_mode_change` |
| `ln -s` / `ln -sfn` | 报 add / modify，`apply` 重建链接 | `a_symlink_is_journaled_and_applied` |
| 链接目标与旧文件字节相同 | 仍是 modify（按类型判定） | `file_to_symlink_with_equal_bytes_is_a_modify` |
| `mkfifo` | 报 add，`apply` 建出 fifo | `a_fifo_is_applied_as_a_fifo` |
| `rm f && mkdir f && …`（文件→目录） | 报 modify + 子项 add，`apply` 生效 | `apply_replaces_a_file_with_a_directory`、`replacing_a_file_with_an_empty_directory_is_reported` |
| 删除目录树 | 报 delete，`apply` 连目录一起删除 | `deleting_a_directory_is_reported_and_applied` |
| 目录→文件 | 报 modify，`restore` 还原 | `restore_replaces_a_directory_with_its_baseline_file` |
| 新增目录树 | `restore` 连目录一起清掉 | `restore_removes_an_added_directory_tree` |
| 先改、后写回 baseline | 累计变更集为空（账本仍留两次） | `returning_to_the_baseline_clears_the_cumulative_change` |
| 命令以 **125** 退出 | 仍报变更、仍记账 | `a_command_exiting_125_still_reports_its_changes` |
| 输出超过上限 | 截断标记 + spill 指向真实文件 | `a_truncated_stream_spills_to_a_real_file` |
| 用户中途改动内容/权限/链接 | `apply` 报冲突而不是覆盖 | `apply_aborts_on_a_user_edit_conflict`、`apply_aborts_on_a_user_mode_conflict`、`a_retargeted_symlink_applies_and_a_user_edit_conflicts` |

判定口径之外但已加固的：`--passthrough` 不能借 `..` 或符号链接越出工作区
（`passthrough_cannot_escape_with_a_parent_dir`、`passthrough_may_not_follow_a_symlink_out_of_the_workspace`），
session id 不能借 `../` 写到账本目录之外（`a_session_id_cannot_escape_the_ledger_directory`）。

---

## 3. 本轮修掉的缺陷

| # | 缺陷 | 后果 | 修复 |
|---|---|---|---|
| 1 | `--passthrough ../x` 通过校验 | 工作区外目录被绑成可写，违反 README 的不变量 | 拒绝 `..`、解析符号链接后再比较、校验先于建目录 |
| 2 | 符号链接内容不参与哈希 | retarget 完全不可见；`apply` 报成功却不建链接 | 链接目标即内容：进 CAS、进 diff、`apply`/`restore` 重建链接 |
| 3 | `chmod` 被内容短路吃掉 | mode 变更既不记录也不落盘（`Op::Chmod` 是死代码） | mode 参与比较；index 记录 `st_mode`；`apply`/`restore` 恢复权限位 |
| 4 | 命令退出 125 被当成沙箱启动失败 | **整个变更集丢失**，但 upper 里已经改了文件 | 用 close-on-exec 状态管道区分"没启动"和"启动了并退出 125" |
| 5 | 目录跳过用"存在"而不是"是目录" | 文件被替换成目录时**完全不上报**，`apply` 因此冲突/失败 | 比较 baseline 的真实类型 |
| 6 | fifo 报 add 但 `apply` 静默跳过 | 报成功却没写 | fifo 用 `mkfifo` 复现；socket/设备节点显式报错而不是静默 |
| 7 | `stdoutSpill` 指向不存在的 `stdout.full.txt` | 调用方按路径取全文会失败 | 指向真实的 `calls/<id>/stdout.txt` |
| 8 | `rust-version = "1.85"` 但用了 let-chains（1.88 才有） | 声明的 MSRV 是假的 | 先改为 `1.88`（真实下限），再按维护策略提到 **1.92** 并在 1.92.0 上实测（§4 P1-9） |
| 9 | Unix 文件名中的 `\` 被改写成 `/` | diff 路径不存在，两个文件可能塌缩成一个，`apply` 失败 | 保留反斜杠原始字节；只有 `/` 是 Unix 路径分隔符 |
| 10 | 非特权 overlayfs 未启用 `userxattr` | 删除/移动 lower 目录返回 `EIO`，bash 无法完成操作 | 挂载选项加 `userxattr`，在真实 overlay 上验证目录删除 |
| 11 | baseline 目录在状态比较中按“不存在”处理 | 目录 whiteout 被静默丢弃，`rm -rf dir` 报 0 个变更 | 目录作为有类型、无内容的状态参与比较，并可按 baseline 重建 |
| 12 | 非 UTF-8 文件名被 `to_string_lossy` 压成 U+FFFD | 两个不同文件塌缩成一条 `add �`，`apply` 报"content for � is missing" | 路径 key 字节精确：UTF-8 名字即自身，否则 `!hex:<原始字节>`；marker 也参与转义，保证单射（`docs/protocol.md`） |
| 13 | 大文件被整体读进内存做 diff；且 `diff::unified` 把 `None` 当空内容 | GB 级文件 OOM；涨过阈值的文件会被渲染成"整个文件被删除"的假 diff；`before_state` 还把读不出来的 baseline 当成不存在，变更类型误判为 add | 超过 8 MiB 不读入内存（CAS 仍流式写入），缺失内容时**不渲染** diff 并置 `diffTruncated` + warning；baseline 用 `symlink_metadata` 判存在、流式 `hash_path` 算 sha |

---

## 4. 剩余缺口

### P0 —— 会破坏 DoD 正确性

**1. 非 UTF-8 文件名 —— 本轮已修复。** 路径 key 现在字节精确（UTF-8 名字即自身，
否则 `!hex:<原始字节>`，marker 本身也转义以保证单射），两个不同文件不再塌缩，
`apply`/`restore`/`history` 都按原始字节工作。见 §3 第 12 条与 `docs/protocol.md`。
剩下的是**调用方**要处理的事：拿到 `!hex:` 前缀的 path 时不要当成文件名直接显示，
需要解码（`wsbox::fsutil::decode_key`）或原样回传。

**2. 单次调用内的中间态不可见。** 只观测调用结束态：命令先截断再恢复，diff 为空。
README 已承认（fanotify/FUSE 未做）。对 DoD 来说这是"定义边界"而非缺陷，
但要在协议文档里写明：**diff 描述的是 end state，不是过程中的每一次写**。

**3. 大文件全量读内存 —— 本轮已修复。** 超过 8 MiB 的文件不再读进内存渲染 diff
（字节仍流式进 CAS，`apply`/`restore` 照常工作），变更标记为 `diffTruncated` 并带 warning，
所以 review 的硬规则会把它拦住而不是放行。修的过程中发现并一并处理了两个陷阱：
`diff::unified` 把缺失的一侧当空内容（会把涨过阈值的文件渲染成整文件删除），
以及 `before_state` 把读不出来的 baseline 当成不存在（会把变更误判成 add）。
见 §3 第 13 条。

### P1 —— 生产运维必需

**4. 无守护进程、无并发会话保护。** 每次 `exec` 都是 fork + unshare + mount overlay；
同一 workspace 上两个 session 各自持有 overlay，`apply` 会互相覆盖且无人检测。
**5. 账本与索引无锁。** `ledger.jsonl` 追加、`index.json` 读-改-写都没有文件锁；
同一 session 两个进程并发 `exec` 会交错或丢更新。
**6. 崩溃后无 reconcile。** 调用中途进程被杀：upper 里有已发生的写入，
但账本没有对应条目，下一次调用会把它们算到下一次头上（125 那类问题的近亲）。
需要在 `open`/`exec` 时检测"上次未完成的调用"。
**7. 超时只杀进程组。** 非 sandboxed 模式下孙进程可能存活。
**8. `gc` 手动、CAS 无 chunk 级去重**（README 已承认；重复大文件重写是已知最坏情况）。
**9. CI 已补上，但 MSRV 只是一个声明。** `.github/workflows/ci.yml` 现在跑
`cargo test --workspace --all-features` + `cargo clippy -- -D warnings`，
并用 `cargo check` 在声明的最低版本上验证。
当前声明是 **1.92**（1.92.0 已在本机实测：check / 全量测试 / clippy -D warnings 全绿）。
注意这是**维护策略**而非技术下限 —— 代码真正需要的是 1.88（2024 edition 的 let-chains），
依赖图里最高的只有 1.85（clap / getrandom / ureq）；`Cargo.lock` 里的
`time 0.3.55`、`cookie_store 0.22.1` 虽然写着 `rust-version = 1.88.0`，
但它们被 ureq 的非默认 `cookies` feature 挡住，**不参与构建**，不要被它们误导。

### P2 —— 协议与接口

**10. 协议承诺了没实现的语义。** `Spec.backend`（`landlock`）与 `CopyMode::Full`
被接受但完全忽略。要么实现，要么在 `session.open`/`exec` 的结果里显式报告"未生效"。
**11. `changes_for_call` 取第一个同名 call**（`ledger::read_all().find(...)`），
call id 复用时归因到旧记录；`sanitize()` 还会让不同 call id 落到同一目录。
**12. `ledger.verify` 对不存在的账本返回 io 错误**，空账本应报 0 条。
**13. workspace 在 `/tmp` 下时 `/tmp` 只读**（有意的安全取舍），
但多数构建工具写 `TMPDIR`；需要在协议里暴露额外的 `writableRoots` 约定。
**14. `changes()` 的 `op` 取 `ops.last()`**，一条路径在一次会话里"改→删→加"后
只显示最后一次的类型，历史靠 ledger —— 符合设计，但要在协议文档里写明。

---

## 5. 建议路线

| 阶段 | 内容 | 出口条件 |
|---|---|---|
| A（钉死 DoD） | 非 UTF-8 路径编码（§4 P0-1）、大文件上限（P0-3）、账本/索引加锁（P1-5）、崩溃 reconcile（P1-6） | §2 全部测试 + 新增 4 条用例在 CI 上绿 |
| B（可运维） | `wsboxd` 常驻 + 流式 stdout、workspace 互斥、结构化错误码、metrics、最小 CI（P1-9） | 一次 8 小时无人值守跑批无丢失归因 |
| C（性能） | chunk 级 CAS、自动 gc、并发会话压测 | 500 MB 仓库 50 次调用 CAS 占用 < 快照方案的 20% |

---

## 6. v0.2：自动审批（DoD 之外）

**定位不变**：它只回答"这份变更集能不能不经人看就 apply"，与"命令能不能跑"正交，
因此开启它不改变任何现有审批行为（`docs/review.md` §1）。

当前状态：默认 `Mode::RulesOnly`，永不自动放行真实变更；
`HumanSource { Explicit, Timeout }`、`observed`、`readyToPromote` 已在途（工作区未提交）。
三条类型级不变量已经成立：缺答案 → Review、`AutoApply` 只能由 `route()` 构造、
shadow 模式下 `may_auto_apply()` 恒为 false。

需要**与其他组件协商**的问题（不是本仓库能单方面定的）：

1. **窗口归谁**：编辑器、agent SDK 还是 CLI 持有倒计时？窗口从 *verdict 就绪* 开始，
   不是从变更发生开始 —— 需要调用方在协议里表达"verdict 就绪"这个时刻。
2. **超时语义**：本仓库的设计是"超时只对 approve 方向生效，且沉默记为 `timeout` 而非 `approve`"；
   需要确认各宿主是否接受"headless/CI 没有窗口，退回到只有硬规则能自动放行"。
3. **review 记录与账本锚定**：`review.jsonl` 每行要带 wsbox `ledgerHead` +
   battery fingerprint + policy 快照，才能复现一次决策。锚定粒度（每次 apply 还是每次 call）需要一致。
4. **校准声明归谁**：`CalibrationClaim::{Native, Fitted, Raw}` 现在由端点/环境变量声明；
   自托管模型默认 `Raw`（不参与阈值）。需要约定"谁有权声明已校准"，否则 fail-closed 会被绕过。
5. **并发与多租户**：review id 目前是"同 session 内自增"，多写者下不唯一；
   需要与账本的并发方案（§4 P1-5）一起定。

本轮已派两个子 agent 并行产出设计输入（API surface / 对抗性风险清单），
两边独立收敛到同一组结论，可以直接作为与其他组件对齐的基线：

### 6.1 生命周期（两个 agent 一致）

```
verdict 就绪 ──▶ 打开窗口(deadline) ──┬─ explicit apply   → 记录 explicit/apply
                                     ├─ explicit reject  → 记录 explicit/reject（最高价值样本）
                                     └─ deadline 到期    → 记录 timeout，按策略处理
```

- 窗口从 **verdict 就绪**开始计时，不是从变更发生开始（推理耗时不能算进用户思考时间）。
- `timeout` 只对 approve 方向生效：模型说 `review`/`hold` 时到期即不落盘。
- **headless/CI 没有窗口**，退回到"只有硬规则能自动放行"，其余挂起等人。
- 晋级按风险类别分开统计：`auto_apply` 类别需要 ≥30 个 **observed** 样本且
  `dangerousAutoApprove == 0`；`review` 永不晋级；`hold` 必须显式确认。

### 6.2 必须由类型保证（不是靠文档）

- `Decision` 无 "allow command" 变体，`ChangeSetState` 不承载 argv/能力 ——
  自动放行在构造上无法扩大权限边界；
- `AutoApply` 只能由 `route()` 产生；缺答案、未校准、后端失败一律落到 `Review`；
- shadow 模式下 `may_auto_apply()` 恒为 false（`ReviewOutcome` 的字段，而非调用方约定）。

### 6.3 落地前必须关掉的风险（对抗性评审输出）

| 风险 | 机制 | 要求 |
|---|---|---|
| 注入 | `task` 与 diff 都受攻击者影响，可诱导 battery 答案 | 记录原始输入哈希；把"模型看到的 state"与"决策"一起存档 |
| 规则规避 | 缩水刚好低于硬阈值、内容被"搬到别处"而非删除 | 硬规则只是下界；`lost_content` 的答案必须与 shrink 分开记录 |
| 校准滥用 | 自托管端点误标 `Calibrated` 即可参与阈值 | `CalibrationClaim` 的声明权与审计（谁在何时声明）必须落库 |
| 弱标签 | 人的 accept/reject 是变更集标签，battery 是 8 个独立问题 | 导出保持 `q_*`（模型）与 `human_outcome`（人）分离，禁止当逐题真值 |
| 不可复现 | 决策需要 policy + battery fingerprint + model + ledger head | 四者都写进 `review.jsonl`，缺一即 fail closed |
| 并发写 | `review.jsonl` 追加无锁，review id 自增 | 与账本并发方案（§4 P1-5）一起加锁 |

落地前需要与能力闸门、沙箱、apply 三方的所有者对齐 §6 的 5 个问题 + 6.3 的 6 项要求。
