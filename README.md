# DSH Privacy Router

在同一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 对话中，根据本地隐私检查结果自动选择本地模型或云端模型。敏感和不确定请求留在本地；只有判定为 `public`、完成 PII 处理并通过出站复扫的纯文本请求会进入重建后的云端白名单上下文。本仓库发布 Host 侧路由和 DSH bundle 配置，不包含 DSH 源码补丁。

## 工作方式

```text
用户请求
  -> 本地确定性规则
  -> 强制本地中文 NER
  -> 本地模型结合最近对话分类
  -> PII 授权卡（仅手机号/邮箱可占位）
  -> public:    最小化、脱敏、复扫后由云端模型直接流式回复
  -> sensitive/unknown: 原始 Harness 请求由本地模型处理
```

- 确定性硬拦截覆盖私钥、常见凭证、Token、身份证、银行卡、本地绝对路径、自定义敏感词和配置的内部、客户、供应商单位及项目名。
- 本地中文 NER 识别人名、单位、地址、职务和项目；不可用、畸形、低置信度、冲突或不确定时返回 `unknown` 并留在本地。Presidio 不是首版依赖。
- 手机号和邮箱是首版仅有的可占位实体。它们未经授权仍留在本地；授权后只在发送前替换为占位符。
- 授权和脱敏成功后，插件会对完整的计划云端文本（重建的白名单历史加上脱敏后的当前消息）重新运行一次本地 NER；发现硬实体或结果不确定时降级为 `unknown` 留在本地。云端派发前还有独立的最终复扫。
- 本地分类器返回 `public`、`sensitive` 或 `unknown`，并提供一句简短理由。
- 分类失败、上下文不足、非纯文本输入和超出限制的输入全部留在本地。
- 同一用户 Turn 内的工具续步和 Provider 重试复用第一次判定。
- 云端回复直接进入当前 Assistant 消息，不使用 subagent，也不经过本地模型二次转写。

## PII 检测与授权

| 类型 | 首版处理 |
| --- | --- |
| 手机号、邮箱 | 可占位；默认弹出 DSH `ctx.userQuestions.ask()` 授权卡 |
| 身份证、银行卡、密钥、凭证、本地路径 | 硬拦截，始终本地 |
| 自定义敏感词、内部/客户/供应商单位、内部项目名 | 硬拦截，始终本地 |
| 人名、精确地址、准标识符组合 | 始终本地，授权不可覆盖 |
| 普通公开单位或单独的通用职务 | 交给本地 NER 和分类器继续判断；不作为占位实体 |

授权卡只展示实体类型、数量和掩码预览，不展示完整值。用户可以选择“允许，仅本次具体值”、“本会话记住这些实体类别”或“拒绝，留在本地”。授权保存在当前会话内存中，默认有效 12 小时；系统不提供 workspace、global 或永久授权，也不接受聊天口令作为授权。身份证、银行卡和硬拦截词没有授权入口。

授权卡通过 `ctx.userQuestions.ask()` 一次性弹出，属于瞬态交互：DSH 没有持久的授权状态面板，也没有针对授权卡的撤销 API（`ctx.dshAuth.logout()` 只用于 OAuth，与此无关）。因此本版不提供持久的授权状态指示，也不提供撤销入口；这是已知限制，“本会话记住”的授权无法手动撤回，只能等待 TTL 过期或重启 DSH。

会话类别授权只保存在进程内存的 Map 中，TTL 由 `authorizationTtlMs` 控制（默认 43200000，即 12 小时），不写入 Session 事件日志，也不落盘。DSH 重启后授权全部丢失，此前授权过的实体类别需要重新授权。这是有意的 fail-closed 设计。

授权和占位符脱敏成功后，插件会对完整的计划云端文本重新运行实体分析：重建的白名单历史（`cloudMessages`）拼接脱敏后的当前消息，而不只是当前用户消息。若全文复扫发现人名、精确地址、内部项目、非公开单位或危险的准标识符组合，或结果不确定、畸形，本轮降级为 `unknown` 并留在本地。这堵住了伪造或遗留 Session 事件把隐私历史重放、绕过纯正则检查的缺口。云端派发前仍会独立执行最终复扫，历史因此受到双重保护。该守卫只保存硬实体的类型和数量元数据，绝不保存实体值或哈希。

全文复扫只是闸门，不是新的授权来源：授权卡只由当前用户消息中的实体触发。历史中的实体可以阻断云端请求，但本身不会弹出授权卡。

本地 NER 请求抛出异常（传输错误、中止或其他意外异常）时，本轮按 `method: entity-analysis`、`reason: ner-error` 记录，标记为不确定并分类 `unknown`，留在本地。NER 不能通过配置关闭，NER 失败也绝不会被静默跳过。

完整 tool-call 只有在终止状态为 `tool-calls` 时才可产生可信分类。`max-tokens` 只允许恢复截断在 `reason` 字符串内部的窄范围结果，并标记 `reasonTruncated: true`；缺失、`stop`、未知、畸形 JSON、额外字段或尾随内容全部返回 `unknown` 并留在本地。

## 配套项目

本插件与 [Local AI Discovery Server](https://github.com/LYiHub/pub-local-ai-discovery-server) 配套使用。发现服务运行在提供本地推理的主机上，通过 mDNS / DNS-SD 广播 OpenAI-compatible API 的主机、端口、基础路径、模型列表路径和认证要求；DSH 侧的本地发现集成将其注册为 `local-ai-*` Provider，本插件再将该 Provider 作为受信任的本地 A 路由。

Local AI Discovery Server 只负责 `_local-ai._tcp.local.` 服务广播，不负责模型推理或 API 代理。本仓库也不包含 mDNS 发现客户端，需要由 DSH 的本地 Provider 集成消费该广播。

## 云端数据边界

B 在官方 DSH 的默认配置下只能收到：

- 本轮通过分类的纯文本用户消息；
- 一段固定的无项目上下文系统提示词；
- 空工具列表。

在兼容的 Harness fork 中开启 `recordSessionEvents` 后，白名单上下文还可以包含此前已经通过检查并发送给 B 的纯文本用户消息，以及对应的 B 纯文本回复。

B 不会收到本地处理的对话、项目系统提示词、本地文件结果或本地工具定义。若 B 仍返回工具调用，插件会终止该请求，避免云端触发本地工具。启用内部事件记录时，每次实际云端调用前写入的 `privacy-router/cloud-dispatch` 只保存消息 ID 和角色，不会再复制消息正文。

本地分类器可以查看最近的既有会话文本，并以 `cloudSafe` 标记区分可发送和仅限本地的上下文。云端历史在组装时重新扫描；当前用户消息只投影为 `id`、`role`、纯文本内容和 `source.kind: user`。上下文投影与本轮文本共用 `maxPromptBytes`，超出部分从最旧消息开始省略并明确标记为已截断。最终出站前还会执行一次独立隐私复扫，失败则阻断云端请求。

`session-title` 和 `compaction` 等辅助请求不绕过隐私路由。已知有可信本地路由时，辅助云端请求会强制改到该本地路由；无法确认本地路由时直接阻断。

## 安装

本仓库采用 DSH 官方 bundle 结构：`package.json` 声明 `dsh.bundle`，`cordis.patch.yml` 负责挂载 Host 插件。源码是可直接运行的 JavaScript，不需要安装时构建。

从 GitHub 安装：

```sh
dsh plugin --profile web add github:LYiHub/pub-dsh-privacy-router
dsh --profile web
```

本地开发安装：

```sh
dsh plugin --profile web add /absolute/path/to/pub-dsh-privacy-router
dsh --profile web
```

发布到 npm 后也可直接安装：

```sh
dsh plugin --profile web add dsh-privacy-router
```

使用前先在 DSH 的 Models 页面配置并选择一个 OpenAI-compatible 本地 Provider。oMLX 等本地服务只需在 DSH UI 中填写其 base URL、模型名和凭据；例如 base URL 可以是 `http://127.0.0.1:8000/v1`，模型名使用 UI 中显示的本地模型 ID。凭据只保存在 DSH 的本地配置中，不写入本仓库、环境报告或提交记录。默认信任 `local-ai-*`；使用其他 Provider ID 时，在 `$DSH_HOME/profiles/web/cordis.patch.yml` 覆盖插件配置：

```yaml
- id: privacy-cloud-router
  config:
    cloudProvider: deepseek-official
    cloudModel: deepseek-v4-flash
    trustedProviders:
      - my-local-ollama
```

Provider ID 必须完整匹配 `trustedProviders`，或匹配 `trustedProviderPrefixes`（默认前缀为 `local-ai-`）。只配置 endpoint 或模型名而没有把 Provider ID 纳入信任列表时，主 Agent 请求会被阻断。

修改 profile patch 后重启 DSH。配置层会整体替换该行的 `config`；未写字段使用插件默认值。

## 配置

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `cloudProvider` | `deepseek-official` | 云端 Provider ID |
| `cloudModel` | `deepseek-v4-flash` | 云端模型 ID |
| `trustedProviders` | `[]` | 完整的本地 Provider ID 白名单 |
| `trustedProviderPrefixes` | `["local-ai-"]` | 本地 Provider ID 前缀白名单 |
| `privacyPolicy` | 内置策略 | 交给本地分类器的隐私定义 |
| `sensitiveTerms` / `customSensitiveTerms` | `[]` | 大小写不敏感的额外敏感词；命中后始终本地 |
| `internalOrgTerms` | `[]` | 内部单位词典；命中后始终本地 |
| `customerOrgTerms` | `[]` | 客户单位词典；命中后始终本地 |
| `supplierOrgTerms` | `[]` | 供应商单位词典；命中后始终本地 |
| `sensitiveJobTitleTerms` | 内置中文/英文职务词典 | 与单位或项目共现时按准标识符组合处理 |
| `projectTerms` | `[]` | 内部项目名词典；命中后始终本地 |
| `maxPromptBytes` | `32768` | 本轮文本和最近分类上下文的 UTF-8 总大小 |
| `classifierMaxTokens` | `512` | 本地分类输出上限 |
| `nerConfidenceThreshold` | `0.85` | NER 结果的最低置信度；低于此值留在本地 |
| `nerMaxTokens` | `512` | 本地 NER 输出上限 |
| `authorizationTtlMs` | `43200000` | 会话类别授权的内存 TTL（12 小时）；授权只存进程内存，重启 DSH 后失效 |
| `cloudMaxTokens` | `8192` | 云端回复输出上限 |
| `recordSessionEvents` | `false` | 内部兼容开关；仅供能够识别 `privacy-router/*` 事件的定制 Harness 使用 |

`PRIVACY_ROUTER_CLOUD_PROVIDER` 和 `PRIVACY_ROUTER_CLOUD_MODEL` 可在 shell 或 `$DSH_HOME/.env` 中覆盖 bundle 默认值。

本地中文 NER 是强制安全层，不能通过配置或环境变量关闭；`nerEnabled: false` 会被拒绝，旧的 `PRIVACY_ROUTER_NER_ENABLED` 环境变量不再生效。`cordis.patch.yml` 支持通过环境变量覆盖首版的非敏感数值：`PRIVACY_ROUTER_CLASSIFIER_MAX_TOKENS`、`PRIVACY_ROUTER_NER_CONFIDENCE_THRESHOLD`、`PRIVACY_ROUTER_NER_MAX_TOKENS` 和 `PRIVACY_ROUTER_AUTHORIZATION_TTL_MS`。词典覆盖变量使用 JSON 字符串数组，例如 `PRIVACY_ROUTER_INTERNAL_ORG_TERMS_JSON`；可用变量包括 `PRIVACY_ROUTER_SENSITIVE_TERMS_JSON`、`PRIVACY_ROUTER_CUSTOM_SENSITIVE_TERMS_JSON`、`PRIVACY_ROUTER_INTERNAL_ORG_TERMS_JSON`、`PRIVACY_ROUTER_CUSTOMER_ORG_TERMS_JSON`、`PRIVACY_ROUTER_SUPPLIER_ORG_TERMS_JSON`、`PRIVACY_ROUTER_SENSITIVE_JOB_TITLE_TERMS_JSON` 和 `PRIVACY_ROUTER_PROJECT_TERMS_JSON`。不要通过这些变量传递 API key 或模型凭据。

## UI 展示构想

UI 原型不在本仓库的开源范围内。理想的展示包括：

- 在请求开始和完成时显示可展开的“隐私检查”节点，包括分类、理由、耗时和分类器原始输出；
- 由官方 DSH 前端渲染 PII 授权卡，展示类型、数量和掩码预览，并提供本次值、会话类别和拒绝三个选项；
- 在 Assistant 操作栏显示实际处理回复的 Provider 和 Model；
- 在每条消息、上下文和 Tool 记录旁标记 Public、Sensitive、Unknown、云端生成或仅保留本地；
- 在 Trajectory 中展示一次请求从隐私检查、路由决策到云端出站过滤的完整路径。

内部原型使用三个 Session 事件传递这些信息：

- `privacy-router/check-start`：隐私检查开始；
- `privacy-router/check-result`：分类、理由、耗时和最终 Provider/Model；
- `privacy-router/cloud-dispatch`：实际发送和保留在本地的消息 ID、上下文截断状态和 Tools 排除状态。

事件不会复制用户正文或规则命中的敏感值。`privacy-router/check-result` 事件在发现实体或 NER 不确定时会同时省略分类器的原始输出 `classifier.output` 和自由文本理由 `classifier.reason`，因为二者都可能复述用户输入；事件仍记录终止 `finish` 状态、结构化 reason 码、`reasonTruncated` 和错误码。路由事件有意避免复制用户文本，但本地 Session 和导出仍应按敏感数据处理。

## UI 集成限制

官方 DSH 已支持通过 `dsh.client` 加载前端插件，也提供 Chat 自定义节点和 Assistant 操作栏插槽。因此，“隐私检查”节点和 Provider/Model badge 原理上可以独立插件化。当前完整原型仍有三个接口障碍：

1. `privacy-router/*` 是仓库外自定义 Session 事件，不在 DSH 的静态已知事件表中。持久层要求未知事件带 `ignorable: true`，但公开的 `Session.append()` 尚未提供设置该标记的接口。
2. Trajectory 当前按内置记录类型渲染，没有供外部插件注册自定义记录行的通用插槽。
3. Assistant 操作栏已有扩展点，但 User、Tool、Context 等既有 Chat 节点没有统一的 metadata 插槽，无法仅靠外部插件把数据路径标签放到所有目标位置。

因此，本插件在官方 DSH 中默认关闭 `recordSessionEvents`，只执行后端隐私路由；授权卡通过官方 `ctx.userQuestions.ask()` 交给 DSH 前端呈现。完整的隐私检查节点和 Provider/Model badge 仍需要定制 Harness，或等待上述通用扩展点进入官方 DSH。

## 安全说明

- `public` 是本地规则、NER 和模型给出的判定，不是绝对证明；本插件通过硬拦截、授权、上下文最小化和最终复扫降低误放行风险。
- Provider 信任只看 ID：完整匹配 `trustedProviders`，或以 `trustedProviderPrefixes`（默认 `local-ai-`）中的前缀开头，即被视为受信任本地路由。这不能证明 endpoint 物理位于本机——一个名为 `local-ai-foo` 却指向远程主机的 Provider 同样会被信任。管理员必须只把 `local-ai-*` ID 分配给真正本地的 endpoint。
- 插件只保护带 `sessionId` 的主 Agent 模型请求，以及 `purpose` 已知（`session-title`、`compaction`）的辅助请求；不拦截其他插件自行发起的网络请求。
- 本地 Session 保存完整对话，分类器原始输出也可能复述输入；Session 文件和导出仍应按敏感数据处理。
- 路由事件只复制消息 ID 和角色，不复制原始请求正文或规则命中的值；发现实体或 NER 不确定时，`check-result` 事件还会同时省略分类器的原始输出 `classifier.output` 和自由文本理由 `classifier.reason`。

## 验证

```sh
npm test
npm run pack:check
node --check index.js
```

## License

[MIT](LICENSE)
