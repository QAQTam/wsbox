# Training a local decision model (Laya)

> 状态：**已验证协议兼容**，训练路径已就绪，语料尚未开始收集
> 上游：[convaiinnovations/laya](https://huggingface.co/convaiinnovations/laya)（Apache 2.0）

## 1. 为什么是它

Laya 和 Jev 是**同一个范式**：非自回归、类型化问题（`choice`/`score`/`noul`）、RLCD 训练出的校准概率。区别是它**开源、可微调、能本地跑**。

| checkpoint | encoder | 参数 | context | 用途 |
|---|---|---|---|---|
| `convaiinnovations/laya` | ModernBERT-large | 421M | 512 | 英文 |
| `convaiinnovations/laya-multilingual` | mmBERT-base | 322M | 1024（编码器支持到 8192） | **100+ 语言** |
| `convaiinnovations/laya-typed-decisions` | ModernBERT-large | 421M | 1024 | 他们的四个示例工作流 |

**多语言 checkpoint 直接解决了我之前标记的 Jev 最大风险**：官方文档明说 Jev 对 CJK "not equally well"，而 Laya 有专门的多语言编码器。

## 2. 协议兼容性：已实测

`laya-serve` 暴露的是**同一个 `POST /v1/systemone`**：

```bash
pip install "laya[serve]"
LAYA_DEVICE=cpu LAYA_PORT=8099 laya-serve
```

本机实测（CPU，无 CUDA）：

```
$ TYPESAFE_ENDPOINT=http://127.0.0.1:8099/v1/systemone \
  wsbox-review run --session laya --mode hosted --task "..."

held: a deterministic rule requires a person
  - `beyond_task` came back uncalibrated, so thresholds do not apply
  - `removed_behavior` came back uncalibrated, so thresholds do not apply
  - hard rule: largest shrink 80% exceeds the hard limit 50%
  - lost_content = 1.00 -> Hold
```

**零代码改动，只换了一个 URL。** `Assessor` 接缝一次都没白设计。

响应形状与 Jev 一致，另带 `confidence` / `answer_confidence` / `action`。延迟：CPU 上 8 题约 2.8s，T4 上约 72ms。

## 3. 校准陷阱（必须处理）

我的代码最初把任何端点的返回都标成 `Calibrated`。**对自托管 checkpoint 这是错的。**

Laya 官方文档：

> **Ships over-confident:** Refitting one temperature per (question type, option count) moves mean ECE **0.466 → 0.081** (`laya`) and **0.314 → 0.106** (`laya-multilingual`). Do this on your own data before trusting the probabilities.

所以加了 `CalibrationClaim`：

```rust
pub enum CalibrationClaim {
    Native,                      // 托管 Jev：RLCD 原生校准
    Fitted { source: String },   // 自己在数据上拟合过温度
    Raw,                         // 原始输出 → 不参与阈值
}
```

**自托管端点的默认是 `Raw`**——fail closed。要声明已校准必须显式做：

```bash
WSBOX_REVIEW_CALIBRATION=fitted:isotonic-v1 TYPESAFE_ENDPOINT=... wsbox-review run ...
```

这个顺序是对的：先拟合，再声明。反过来会得到一个你无法推理的策略。

## 4. 训练路径

### 4.1 格式

Laya 的训练目标是**完整分布**，不是 argmax 标签。官方 notebook 里：

```python
target = [gold_q["probabilities"].get(k, 0.0) for k in keys]   # keys 来自题目 criteria
```

所以我们导出这个形状：

```bash
wsbox-review export --session s1 --format laya --out corpus.jsonl
wsbox-review export --all --format laya --agreed-only --out corpus.jsonl
```

```jsonc
{
  "id": "corpus#1",
  "state": { "task": "...", "changes": [...], "precomputed": {...} },
  "questions": { "lost_content": {"type":"noul","instructions":"..."}, ... },
  "gold": {
    "lost_content": {"probabilities": {"false": 0.9, "true": 0.1}},
    "severity":      {"probabilities": {"0": 0.39, "1": 0.43, "2": 0.17, "3": 0.01}}
  },
  "meta": { "sessionId": "...", "batteryFingerprint": "...", "humanAgreed": false }
}
```

`meta` 训练器会忽略，但审计和切分数据时有用。

### 4.2 标签从哪来

**这是整件事的关键。** 三种来源，各自的强弱不同：

| 来源 | 覆盖 | 质量 | 成本 |
|---|---|---|---|
| **规则评估器** | 2–3 题（`lost_content` / `leftover_debug` / `category=formatting`） | **精确** | 零 |
| Jev（蒸馏） | 全部 8 题 | 继承 Jev 的偏差 | $0.00003/次 |
| 人类 | 决策层面 | 真值，但**弱标签** | 昂贵 |

规则那部分值得强调：**它是唯一的免费精确标签，而且可以无限量产出**。实测一次导出：

```
lost_content      noul    point-mass ['false']     ← 规则，精确
leftover_debug    noul    point-mass ['false']     ← 规则，精确
severity          score   point-mass ['0']         ← 规则，精确
beyond_task       noul    {'false': 0.86, 'true': 0.14}   ← Jev 蒸馏
removed_behavior  noul    {'false': 0.97, 'true': 0.03}   ← Jev 蒸馏
```

所以导出会**把 Exact 答案物化成点质量**而不是丢掉——它们是最值钱的训练信号。

### 4.3 ⚠️ 中文不要蒸馏 Jev

Jev 对 CJK 不擅长，**把 Jev 的答案当教师训中文数据，是在蒸馏坏标签。**

中文的可行路径：
1. `laya-multilingual` 零样本 + 温度拟合 + 人工抽检
2. 人工标注中文变更集（贵，但是真值）
3. **规则标签照常用**——它们与语言无关

### 4.4 训练

官方 notebook 在 Kaggle 免费 2×T4 上跑完整流程（建数据集 → RLCD 训练 → 拟合温度 → 评测 → 推送 Hub）。**约 30k 问题上跑 4 epoch 是 4–5 小时。**

```bash
# 1. 收集（shadow 模式，仍然问人）
wsbox-review run --session s1 --call c2 --mode hosted --shadow --record --task "..."
wsbox-review resolve --session s1 --review 2 --outcome reject

# 2. 导出
wsbox-review export --all --format laya --resolved-only --out corpus.jsonl

# 3. 上 Kaggle 跑 notebook，换成自己的 corpus.jsonl

# 4. 拟合温度后声明校准
LAYA_DEVICE=cuda LAYA_MODELS=mine laya-serve
WSBOX_REVIEW_CALIBRATION=fitted:laya-mine-v1 \
TYPESAFE_ENDPOINT=http://127.0.0.1:8000/v1/systemone \
  wsbox-review run --session s1 --mode hosted --task "..."
```

**但基础 checkpoint 零样本接近随机。** 官方明说：

> Base checkpoints are near chance on typed-decisions zero-shot — 0.362 here and 0.352 for multilingual, against a 0.318 random and a 0.461 majority-class baseline. **Laya is a fast base to specialise, not a zero-shot decision engine.**

所以微调不是可选项，是前提。

## 5. 三个必须先决策的事

### 5.1 电池要在收数据前定稿

`batteryFingerprint` 在每一行里。改了电池，旧语料就对不上了。**收数据前先定。**

### 5.2 noul vs 2-option choice

Laya 的已知问题（[#156](https://github.com/NandhaKishorM/laya/issues/156)）：

> **`noul` can follow its option labels instead of the state**, most strongly on this English checkpoint... returns a confident "no" for clearly positive input. If they look stuck, ask the same question as a two-option `choice` with neutral keys.

**我的电池 8 题里 6 题是 noul。** 本机实测没触发（`beyond_task 0.615`、`touches_security 0.436`，不是卡在 0），但这个风险必须在收数据前决定。

两种做法：
- **保持 noul**：Jev 处理得好，微调也可能修掉它。风险是基础 checkpoint 上答案不可靠。
- **改成 2-option choice**：两个后端都支持，绕开已知问题，代价是题目变长、占更多 context。

我倾向后者，但**应该先在真实数据上 A/B 一下再定**，因为改了就作废语料。

### 5.3 context 预算——最硬的约束

这是我原来没意识到的：

| checkpoint | `max_len` | `head_max_len` | 留给 state 的 |
|---|---|---|---|
| `laya`（英文） | 512 | 192 | **~320 tokens（≈1.3KB）** |
| `laya-typed-decisions` | 1024 | 256 | ~768 tokens（≈3KB） |
| `laya-multilingual`（`max_len=8192`） | 8192 | 256 | ~7.9k tokens（≈32KB） |

**我的 diff 预算是 48KB（≈12k tokens），远超英文 checkpoint 的总 context。** 对 Laya 来说这个预算必须按后端配，而且默认应该选 `laya-multilingual` 并设 `max_len=8192`——**不是因为语言，而是因为 state 预算才是瓶颈**。

官方也说了，约 4000 tokens 以内准确率稳定，再往上会波动。

所以：
- 默认 diff 预算应降到 ~16KB（≈4k tokens）
- 或者改变粒度：一题一文件，而不是一题一变更集

这一条会直接影响电池设计，**应该在 5.1 之前定**。

## 6. 当前状态

已就绪：
- `Assessor` 接缝，`TYPESAFE_ENDPOINT` 指向任何兼容端点
- `CalibrationClaim`，自托管默认 fail-closed
- `--format laya` 导出，标签键与题目 criteria 对齐（有测试锁住）
- Exact 答案物化成点质量
- `--resolved-only` / `--agreed-only` / 默认排除未校准答案

未做：
- 语料尚未收集（只有测试数据）
- 温度拟合脚本（官方 notebook 里有，未接进来）
- 电池定稿（§5）
- 未在多语言 checkpoint 上实测中文

## 7. 参考

- 模型：[convaiinnovations/laya](https://huggingface.co/convaiinnovations/laya)
- 微调 notebook：`notebooks/laya_finetune_typed_decisions_2xT4_kaggle.ipynb`
- 基准数据集：[LocalLLaMA/typed-decisions](https://huggingface.co/datasets/LocalLLaMA/typed-decisions)（400 用例 / 2000 决策）
- 实测数字：微调后 0.766 准确率 / ECE 0.213，超过 Jev 发布的 0.727
