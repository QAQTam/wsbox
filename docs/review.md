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

## 9. 数据积累——这才是"抽掉 Jev 强依赖"的真正路径

抽象接口只解决了"能换"。要真的换得掉，得有数据。

`--record` 把每次评估写进 `<session>/review.jsonl`：

```jsonc
{
  "atMs": 1758800000000,
  "mode": "hosted",
  "task": "把 f 的返回值改成 2",
  "decision": { "action": "review", "rationale": { ... } },
  "batteryFingerprint": "a3f1c9d2e8b70456",
  "precomputed": { ... }
}
```

**每一次模型评估 + 人类最终决定 = 一条标注样本。**

跑几个月就有了自己的数据集，可以：
- 拟合校准曲线，看 Jev 在你这个领域是否真的校准（很可能不是，领域偏）
- 训练/微调本地分类器
- 验证阈值：把历史决策重放一遍，看新阈值会放行哪些当时人工拒绝的

所以 `--record` 不是日志装饰。**跑 Jev 是在为不再需要 Jev 攒资本。**

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

### 阶段 1 —— Jev 接入，**shadow 模式**

`--features jev` + `Mode::Hosted`，但 **`may_auto_apply()` 的结果只记录、不执行**。仍然问人。

这是接 LLM 审批的正确第一步：先观察它会不会放行你不该放行的东西。跑够样本后对比：

```
放行且人工也放行   → 一致，可以进入阶段 2
放行但人工拒绝     → 危险，说明阈值太松或问题没覆盖
拒绝但人工放行     → 太吵，会消耗耐心
```

### 阶段 2 —— 开启 auto-approve

阈值保守起步，只对"每道题都答了、都可信、都没触发"的变更集放行。配合 `--record` 持续验证。

### 阶段 3 —— 本地模型

用攒的数据拟合校准映射，或者训练自己的分类器，接到 `Chain` 里。Jev 降级为兜底。

## 11. 当前限制

- **`Mode::Hosted` 未经真实 API 验证**——没有 API key，请求/响应映射是按官方文档写的，未对活接口跑过
- 阈值是文档默认值，不是实测值
- 没有 shadow 模式的一等支持（现在靠调用方忽略 `may_auto_apply()`）
- 电池 v1 未在真实仓库上验证过区分度
- 评估结果写进 `review.jsonl`，还没有回读/统计工具
- 未与 bugent / qaqh-backend 接线
