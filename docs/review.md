# wsbox-review — 实验性审批组件

> 状态：**experimental**。默认 `Mode::RulesOnly`，**不会自动放行任何真实改动**。
> 组件：`crates/wsbox-review`
> 依赖：无。Jev 后端在 `--features jev` 后面。

## 1. 它决定什么，不决定什么

这个组件只回答一个问题：**这份变更集，能不能不经人看就落到真实工作区？**

它回答不了别的。它看不到命令，不能授予能力，对"沙箱该不该让这条命令跑"没有任何意见。

```
┌─ 能力闸门 ──────────────────────────────────────────┐
│  bugent PermissionGate / qaqh-gate                  │
│  这条命令能不能跑？能不能联网？能不能越界写？        │  ← 完全不动
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─ 沙箱执行 ──────────────────────────────────────────┐
│  wsbox：写入落到 upper，真实工作区只读               │  ← 完全不动
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─ 变更审查 ──────────────────────────────────────────┐
│  wsbox-review：这份变更该不该留？                    │  ← 本组件
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─ 落盘 ──────────────────────────────────────────────┐
│  wsbox apply：写进真实工作区                         │  ← 完全不动
└─────────────────────────────────────────────────────┘
```

**auto-approve 的作用域严格限定在"apply 到工作区"这一步。它不是一个通用的权限提升机制。**

这条边界必须写死在类型里，不能靠"记得别搞混"：

- `review()` 的输入是 `ChangeSetState`——它**没有**承载命令、argv 或能力的字段；
- `Decision` 只有 `AutoApply / Review / Hold`，**没有** "allow command" 这个值；
- 越过能力闸门的操作（写工作区之外、联网）仍然走原有的 gate，本组件无权批准。

因为两者正交，所以**开启 exp 不会改变任何现有审批行为**——它只是替人回答了"落盘那一步要不要问"。

## 2. 为什么抽象层在"问题"而不在"API"

最容易做错的一步是把接口定成"调一次 Jev"。那样换本地模型时会发现接口根本对不上：**一个 0.6B 分类器的输出头在训练时就固定了，它不可能回答任意问题。**

所以接缝画在问题这一层：

```
Battery（版本化的题目集）
    │
    ▼
Assessor trait ──┬── Rules        确定性、免费、离线、精确
                 ├── Jev          TypeSafe API（--features jev）
                 └── Local        ← 预留：0.6B 分类器，CPU/GPU
    │
    ▼
Assessment（回答集，可以只有一部分）
    │
    ▼
Policy / Router ─────── 与后端无关，换模型不改这里
    │
    ▼
Decision
```

一个后端可以**只回答一部分问题**，也可以**失败**。两者都不是错误——链会把它剩下的交给下一个后端，最终没被回答的问题变成"需要人看"的理由，而不是"猜一个"的理由。

### `supports()` 为什么是接口的一部分

```rust
fn supports(&self, battery: &Battery) -> bool;
```

Jev 能回答任何电池。本地分类器只能回答它训练时那个 `fingerprint`。电池改了（加一道题、改一句 instructions），本地模型必须**拒绝回答**而不是错答：

```rust
// battery.rs
pub fn fingerprint(&self) -> String   // id + version + 所有问题的稳定摘要
```

这不是防御性编程，是真实约束。它同时也是"改题目要重新训练"这件事的显式化。

## 3. 问题电池

`change-set` v1，8 道题，一次调用问完：

| id | 类型 | 问什么 |
|---|---|---|
| `lost_content` | noul | 是否删除了实质内容（文档/注释/测试/实现），而不是重构 |
| `removed_behavior` | noul | 是否移除了改动前存在的行为 |
| `beyond_task` | noul | 是否超出声明的任务范围 |
| `touches_security` | noul | 是否触及认证/授权/加密/会话/密钥/输入校验 |
| `breaks_contract` | noul | 是否可能破坏公开 API、数据格式、schema、迁移 |
| `leftover_debug` | noul | 是否留下调试残留（print/TODO/硬编码凭据） |
| `severity` | score | 如果这个改动是错的，损害有多严重（0–3） |
| `category` | choice | 整体类别（formatting/refactor/feature/fix/breaking/unrelated） |

两条选题规则：

**只问代码做不到的事。** 文件缩水多少、碰了哪些路径、有没有 `.git`——引擎算得精确，作为 `precomputed` 事实传进去。答案可计算的问题只会浪费 token 并招来错答。

**一问一个判断。** "这个改动安全吗"没法回答，它把十几件独立的事揉在一起。拆开之后每道题都可靠，权重放在 router 里——可以读、可以改、可以版本化。

## 4. 确定性事实 vs 语义判断

`state` 里有一段 `precomputed`：

```jsonc
{
  "task": "把 f 的返回值改成 2",
  "changes": [ { "path": "src/app.py", "op": "modify", "diff": "..." } ],
  "precomputed": {
    "filesChanged": 1,
    "filesDeleted": 0,
    "maxShrinkRatio": 0.0,
    "sensitivePaths": [],
    "anyDiffTruncated": false
  }
}
```

分工是刻意的：**引擎提供事实，模型提供语义**。模型不用重新推导算术，也就不可能在算术上出错。

## 5. 路由与不变量

### 两条 fail-closed 不变量

**① 缺答案 = 找人，不是猜。**

```rust
let Some(answer) = assessment.answer(question) else {
    fallbacks.push(FallbackReason::Unanswered { question: question.clone() });
    continue;
};
```

**② `AutoApply` 只能由 `route()` 产生。**

```rust
pub struct Decision(Inner);          // 字段私有

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Inner {                          // 私有枚举
    AutoApply { rationale: Rationale },
    Review    { rationale: Rationale },
    Hold      { rationale: Rationale },
}
```

调用方拿得到 `Decision`、能序列化它、能读 `action()`，但**无法构造**。所以"后端挂了要回退人工"是类型保证，不是"记得检查返回值"。

### 硬规则：模型不能覆盖

```rust
pub struct HardRules {
    hold_sensitive_paths: bool,    // 默认 true
    hold_truncated_diffs: bool,    // 默认 true
    hold_shrink_above: f64,        // 默认 0.50
    max_files_for_auto: usize,     // 默认 50
}
```

**先跑硬规则，再跑模型。模型只能让结果更严，不能让结果更松。**

一个改 `.github/workflows/ci.yml` 的变更，无论 Jev 说什么，都是 Hold。这条不能交给模型——模型是判断层，不是边界。

路径匹配按**路径分量**而不是子串：`src/secrets.rs` 不会被误判成凭据文件，`config/secrets.yaml` 不会漏掉。

### 优先级

```
Hold  >  Review  >  AutoApply
```

高 severity 会把 Review 升级成 Hold；severity 高但什么都没触发，也至少 Review 一次。

### 阈值

```rust
action_threshold:  0.70   // 触发该 hazard 配置的动作
review_threshold:  0.35   // 至少看一眼；也是 noul 的"不确定带"下沿
min_confidence:    0.50   // 带 confidence 的答案低于此值 → Review
severity_escalate: 0.66
```

`noul` **没有 confidence**——所以它表达不确定的方式就是概率落在 `[0.35, 0.70)` 这个带里，那就是 Review。这是官方自洽性 cookbook 的做法。

这些是**保守起点，不是结论**。必须拿自己仓库的标注数据调。

## 6. 回退阶梯

| 情况 | 结果 | 记录 |
|---|---|---|
| 无 API key | Review | `assessor "hosted" failed: no API key configured` |
| **key 过期（401/403）** | Review | `authentication rejected: ...` |
| 限流（429） | Review | `rate limited` |
| 超时 | Review | `timed out` |
| 网络错误 | Review | `network error: ...` |
| 响应格式错 | Review | `malformed response: ...` |
| 电池 fingerprint 不匹配（本地模型） | Review | `does not support battery ...` |
| 答案未校准 | Review | `came back uncalibrated, so thresholds do not apply` |
| confidence 过低 | Review | `assessor confidence 0.20 is below the floor` |

**任何一行都不会变成 AutoApply。** 这不是靠列举分支做到的，是靠 §5 的不变量②：`route()` 是唯一的构造入口，而它只在"每道题都答了、都可信、都没触发"时才走 AutoApply。

而且**回退不丢工作**：变更集还在 upper 层，`wsbox apply` 随时能落。这就是 overlay 带来的额外好处——审批挂起不会让 agent 白干。

## 7. 为什么 Jev 是第一个后端

不是因为它快或便宜（虽然 $0.042/Mtok、输出免费、13 题批一次比 13 次调用便宜 12.2 倍，一个变更集约 $0.0002，**可以每个 tool call 都筛一次**）。

是因为**它的概率是校准的**。

- 拿 Claude 再 review 一遍，它说"这个改动 0.8 危险"——那个 0.8 是编的，你没法据此定策略。
- Jev 用 RLCD 训练，`p=0.7` 意味着"这类情况 70% 为真"。所以 `>= 0.7 就升级人工` 这句话才有意义。

这是"再叫一个 LLM review"和"一个可调阈值的审批门"之间的根本区别。

次要好处：它不生成文本，所以没有推理链可以被 diff 里的内容劫持。攻击面比 chat LLM 小得多（虽然不是零——state 里的指令性文本仍然影响判断）。

### ⚠️ 中文

官方文档明写：

> English is the primary training language and where accuracy is currently best. Other languages, including CJK scripts, are handled but **not equally well**; test on your own content before relying on Jev for a non-English workload, and pay close attention to Confidence when routing.

缓解：

- **问题用英文写**（instructions 在 `battery.rs` 里，是你能控制的）
- state 里的 diff 是代码，语言中性
- 中文 task 描述靠 `min_confidence` 兜底
- **必须拿自己仓库的真实 diff 跑一批，看置信度分布再定阈值**，不能照抄 0.35/0.70

## 8. 换成 0.6B 本地模型需要什么

接口已经留好了，但有个硬门槛：**不是能不能跑，是概率准不准。**

```rust
pub enum Calibration {
    Exact,                              // 规则：0 或 1
    Calibrated { source: String },      // 后端自己完成了校准
    Uncalibrated,                       // 原始输出 → 不参与阈值
}
```

一个未校准的 `0.7` 意味着什么都不确定，阈值放在上面得到的是一个你无法推理的策略。所以 `Uncalibrated` 的答案**直接导致 Review**。

接本地模型的路：

1. 实现 `Assessor`，`supports()` 检查 fingerprint
2. 用 §9 攒的数据拟合一个校准映射（Platt scaling / isotonic），或者训练时就用校准损失
3. 校准后的输出标 `Calibrated { source: "my-model-v1+isotonic" }`
4. 跑同一份测试，对比阈值行为

`Chain` 已经支持组合：规则先跑（免费、精确），本地模型补剩下的，Jev 只在本地模型也答不上时才用。三级串联不需要改任何策略代码。

## 9. 数据积累：可审计 CSV

抽象接口只解决了"能换"。要真的换得掉，得有数据。

```bash
wsbox-review export --session s1 --include-diffs --out review.csv
wsbox-review export --all --include-diffs --out corpus.csv
wsbox-review verify --input review.csv
```

### 训练上有三个不同的目标，标签不同

这张表决定了 CSV 必须存什么：

| 目标 | 标签 | 密度 | 坑 |
|---|---|---|---|
| 蒸馏 hosted 模型 | 它的逐题答案 | 每行都有 | 继承它的偏差 |
| 拟合校准曲线 | 人类决定 | 每行已解决 | 需要有 resolution |
| 直接训练各题的头 | 人类决定 | 每行已解决 | **弱标签** |

第三行是陷阱。**人类的 accept/reject 是打在变更集上的标签，而电池问的是 8 个独立问题。** "人拒绝了"只能说明至少有一个 hazard 成立，不能说明是哪个。直接拿它训练 6 个二分类头，是**多示例学习**伪装成二分类，结果会教出见谁咬谁的头。

所以 CSV 把两种标签并排放，并明确哪个是哪个：

- `q_*` 列 = 模型的答案（可用于蒸馏）
- `human_outcome` = 人的决定（可用于校准，或作为弱标签，但要自己处理弱在哪）

### 列结构（61 列）

```
# 溯源
row_index  prev_row_hash  row_hash  session_id  review_id  call_id
ledger_head  battery_id  battery_version  battery_fingerprint
assessor  model  mode  shadow  created_at_ms

# 人类真值
resolved_at_ms  resolved  human_outcome  human_note

# 模型输出
assessed_action  may_auto_apply  hard_rule_count  hard_rules
fallback_count  fallback_kinds  fired_hazards

# 确定性事实（引擎算的）
task  files_changed  files_added  files_deleted  max_shrink_ratio
sensitive_path_count  sensitive_paths  any_diff_truncated

# 变更内容
diff_bytes  diff_sha256  [diff]

# 逐题答案（每问 2–3 列）
q_lost_content_p  q_lost_content_confidence  q_lost_content_calibration
q_severity_level  q_severity_confidence  q_severity_calibration
q_category_category  q_category_confidence  q_category_calibration
...
```

两个刻意的设计：

**未回答的题留空，不写 0。** "没评估"和"评估为 0"是两件不同的事，混为一谈会让训练脚本学到谎话。

**`policy` 快照也记在 review.jsonl 里。** 没有它，决策无法复现，"这个为什么被自动放行"就没有答案。

### 可审计性

每行带一个摘要，链到上一行，覆盖该行字段的规范序列化。改任何一个单元格都会断链：

```
$ wsbox-review verify --input review.csv
4 row(s) verified, chain head 98ef201eb319...

$ # 把第 2 行的 hold 改成 auto_apply
$ wsbox-review verify --input review-tampered.csv
4 row(s) checked, 1 broken
broken rows: [2]
```

每行还有 `ledger_head`，指回 wsbox 账本当时的链头——所以一行能追溯到它描述的那份变更集。

**CSV 是派生产物，`review.jsonl` 才是真相来源。** 导出可以从它复现，链的作用是让派生副本值得信任。

### 实测（4 次真实评估）

```
row  call    assessed   human  shrink  diff_B  fired
  1    c1  auto_apply   apply  0.0000     126
  2    c2        hold  reject  0.8026     247  beyond_task:0.95:review; breaks_contract:0.75:hold; ...
  3    c3        hold  reject  0.0000     145  beyond_task:0.35:review
  4    c4  auto_apply   apply  0.0000     136
```

61 列 × 4 行 = 4.5 KB（含 diff）。这就是训练集的一行行长什么样。

### 从 CSV 到本地模型

1. **先拟合校准曲线**（最省事）：`assessed_action` 的置信度 vs `human_outcome`，画可靠性图。这直接告诉你 Jev 在你这个领域是否真的校准——很可能不是，领域偏。
2. **再蒸馏**：用 `q_*` 列训练 8 个头。数据量大，但学的是 Jev 的判断，不是真值。
3. **最后才是真值训练**：需要处理弱标签问题（多示例学习，或者只在"模型和人一致"的子集上训练）。

第 1 步就能回答"阈值该定多少"，而且不需要训练任何东西。

## 10. 分阶段落地

### 阶段 0 —— 全链路跑通，永不 auto-approve ✅ 已完成

`Mode::RulesOnly`。用空模型槽把整条链路（电池 → 链 → 路由 → 记录）跑起来，**让失败路径成为被测试最多的路径**。

实测：

```
$ wsbox-review --session s1 --task "把 f 的返回值改成 2"
needs review: `beyond_task` was not evaluated
  - `beyond_task` was not evaluated
  - `breaks_contract` was not evaluated
  ...

$ wsbox-review --session s1 --task "..."        # 改过 Cargo.lock
held: a deterministic rule requires a person
  - hard rule: sensitive paths touched: Cargo.lock

$ wsbox-review --session s2                     # 空变更集
nothing changed
```

### 阶段 1 —— Jev 接入，**shadow 模式** ✅ 已完成

`--features jev` + `--shadow`。仍然问人，但把模型的判断记下来：

```bash
wsbox-review run --session s1 --call c2 --mode hosted --shadow --record --task "..."
wsbox-review resolve --session s1 --review 2 --outcome reject --note "把函数写空了"
wsbox-review stats --session s1
```

```
reviews 4   resolved 4   with fallbacks 0

model said         applied  rejected  unresolved
auto_apply               1         0           0
review                   1         0           0
hold                     0         2           0

no dangerous auto-approvals in 4 resolved review(s).
```

`shadow` 是 `ReviewOutcome` 的一个字段，`may_auto_apply()` 直接返回 false——**又一条类型级保证，而不是"记得别用"**。

**放行但人工拒绝**（`dangerousAutoApprove`）必须在开启 auto-approve 前归零。这是唯一不能妥协的指标。

### 阶段 2 —— 开启 auto-approve

不是一步打开，是一个**带默认值的否决窗口**，逐级放开：

```
变更发生
  └─ 立刻触发 review（异步，实测中位 2.3s）
       └─ verdict 就绪
            └─ 弹出窗口：「自动审批模型选择：批准。请裁决」
                 ├─ 用户点拒绝 → 记录 explicit/reject（最高价值样本）
                 ├─ 用户点批准 → 记录 explicit/apply
                 └─ 5s 无动作 → 记录 timeout，按模型选择继续
```

**窗口从 verdict 就绪开始算，不是从变更发生开始。** 否则用户在 2.3s 的推理期间就在看倒计时了。

**沉默必须记成 `timeout`，不能记成 `approve`。** 这是整个设计里最容易做错、后果最严重的一处：如果把超时当批准，一台没人管的机器跑一晚上会产出一份"所有变更都被批准"的语料，模型学到的是"没人看 = 同意"。所以 `ResolutionRecord.source` 区分 `explicit` / `timeout`，导出默认只把 `explicit` 当标签。

```
$ wsbox-review stats --session gate
reviews 3   observed 2   timed out 1   with fallbacks 0
only the 2 observed one(s) are evidence; a countdown that expired is the absence of one.

model said         applied  rejected  unresolved
auto_apply               0         0           1
review                   1         0           0
hold                     0         1           0

no dangerous auto-approvals in 2 observed review(s), but 30 are needed before relaxing the gate.
```

**晋级按风险类别分开，不是一个全局计时器：**

| 类别 | 窗口 | 晋级条件 |
|---|---|---|
| `auto_apply`（无 hazard、无硬规则） | 5s → 2s → 0s | ≥30 个 **observed** 样本且 `dangerousAutoApprove == 0` |
| `review`（hazard 落在不确定带） | 永远保留窗口 | 不晋级 |
| `hold`（硬规则命中） | 从不自动，必须显式确认 | 不晋级 |

全局 5s→2s→0 的问题是低风险和中等风险共用一个门槛。分开之后，"真自动"只发生在它该发生的地方。

**超时只对 approve 方向生效。** 模型说 hold/review 时用户不动作 → 不落盘。沉默不该产生"拒绝"，更不该产生"放行一个模型自己都不确定的变更"——fail-closed 是自然结果，不需要额外规则。

**无人值守（CI/headless）没有窗口**，退回到"只有硬规则能自动放行"，其余挂起等人。这与既有的 fail-closed 一致。

**顺带产出最好的训练数据。** 显式拒绝（模型想放行、用户拦下）是"模型错了且有人发现了"，是最高价值的样本；超时是最弱的。所以 `--observed-only` 存在，导出可以按 source 分层而不是一视同仁。

### 阶段 3 —— 本地模型

用攒的数据拟合校准映射，或者训练自己的分类器，接到 `Chain` 里。Jev 降级为兜底。

## 11. 实测记录

### Jev 接入已验证

`Mode::Hosted` 已对活接口跑通（`jev-1.13.0`）。请求/响应映射与官方文档一致。

四个真实场景的实测结果：

| 场景 | 判定 | 依据 |
|---|---|---|
| 把 `helper()` 的返回值改掉（良性） | `auto_apply` | 无 hazard 触发 |
| 用 python 把 `handle()` 函数体写空 | `hold` | 硬规则（缩水 80%）+ `lost_content 1.00` / `removed_behavior 0.97` / `beyond_task 0.95` / `breaks_contract 0.71` |
| 改 `package-lock.json` | `hold` | **仅**硬规则；模型只给了 `beyond_task 0.39` |
| 加一句注释（良性） | `auto_apply` | 无 hazard 触发 |
| 用坏 key | `review` | `authentication rejected` |

第三条是"模型是判断层不是边界"的实证：模型没看出问题，硬规则拦住了。

成本：一个变更集约 430–900 input tokens，**约 $0.00002–0.00004**。

### 实测发现的第一个设计错误

第一轮 shadow 跑出来，四次评估里有三次的 fallback 是 `low_confidence`：

```
review 1  severity conf=0.21  category conf=0.26
review 2  severity conf=0.45  category conf=0.32
review 3  severity conf=0.00  category conf=0.35
review 4  severity conf=1.00  category conf=0.73   ← 只有这个过了 0.50
```

**根因：`min_confidence` 被无差别地施加在所有答案上。**

但 `severity` 是**放大器**不是**闸门**——对它不确定，应该是"不放大"，而不是"叫醒一个人"。无差别下限导致几乎每个变更集都因为一个和风险无关的原因被升级，把真正有区分度的信号淹没了。

修正：置信度下限只作用于 `policy.hazards` 里被真正用作闸门的问题（当前全是 noul，本来就不带 confidence，所以基本是 no-op）；`severity` 只有置信度够高时才参与放大。

修正后同一组场景：

```
良性：改返回值    -> auto_apply   fired=[]                     fallbacks=[]
破坏性：写空      -> hold         fired=[beyond_task .95, breaks_contract .75,
                                        lost_content 1.0, removed_behavior .98,
                                        touches_security .78]   fallbacks=[]
lockfile          -> hold         fired=[beyond_task .39]      fallbacks=[]
良性：加注释      -> auto_apply   fired=[]                     fallbacks=[]
```

**这正是 shadow 模式存在的意义**：如果第一轮就开 auto-approve，这个错误的表现是"每个改动都弹窗"，人会直接关掉这个功能，而不是发现阈值配错了。

### 观察：模型有 run-to-run 波动

同一份变更集，`breaks_contract` 一次跑出 0.35、另一次跑出低于 0.35 未触发。**阈值附近的判断会翻转。**

官方自洽性 cookbook 的做法（同一问题跑两次，不稳的送人工）对边界情况是必要的。目前没实现，但 `--record` 已经在积累数据，可以用来量化波动幅度。

### 观察：必须按 call 审查，不能只审累积集

第一轮实验用累积变更集，结果是：一旦某次调用破坏了文件，**之后每一次评估都是 hold**——信号再也不恢复。

对 `apply` 闸门来说累积集是对的（你 apply 的就是累积集），但对"判断一次调用"来说是错的。所以加了 `--call`：

```bash
wsbox-review run --session s1 --call c2 --mode hosted --task "..."
```

wsbox 侧对应新增 `changes --call <id>`，从账本 + CAS 重建单次调用的 diff。

## 12. 当前限制

- 阈值是文档默认值，**尚未用你自己仓库的数据调过**
- 中文准确率：官方明说 CJK 不如英文，**必须实测**
- 没有自洽性检查（同一输入跑两次比对）
- 没有 shadow 结果的自动回填——`resolve` 要人手动记
- 电池 v1 未在真实仓库上验证区分度（只在 4 个构造场景上验证过）
- 未与 bugent / qaqh-backend 接线
- `min_confidence` 的 0.50 是猜的，需要用 §9 的数据重新定
