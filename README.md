# DSH Privacy Router

在同一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 对话中，根据本地隐私检查结果自动选择本地模型或云端模型。敏感和不确定请求留在本地；只有判定为 `public` 的纯文本请求会进入经过重建的云端白名单上下文。本仓库只发布 Host 侧路由，不包含 Web UI 实现或 DSH 源码补丁。

## 工作方式

```text
用户请求
  -> 本地确定性规则
  -> 本地模型结合最近对话分类
  -> public:    过滤上下文后由云端模型直接流式回复
  -> sensitive: 原始 Harness 请求由本地模型处理
  -> unknown:   原始 Harness 请求由本地模型处理
```

- 确定性规则覆盖私钥、常见凭证、Token、邮箱、电话号码、本地绝对路径和自定义敏感词。
- 本地分类器返回 `public`、`sensitive` 或 `unknown`，并提供一句简短理由。
- 分类失败、上下文不足、非纯文本输入和超出限制的输入全部留在本地。
- 同一用户 Turn 内的工具续步和 Provider 重试复用第一次判定。
- 云端回复直接进入当前 Assistant 消息，不使用 subagent，也不经过本地模型二次转写。

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

本地分类器可以查看最近的既有会话文本，并以 `cloudSafe` 标记区分可发送和仅限本地的上下文。默认配置不批准历史消息进入云端，因此依赖“继续”“那个”等上文指代的请求会保守地留在 A；开启兼容事件记录后，引用此前公开云端对话的请求才可以继续走 B。上下文投影与本轮文本共用 `maxPromptBytes`，超出部分从最旧消息开始省略并明确标记为已截断。

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

使用前先在 DSH 的 Models 页面配置并选择一个本地 Provider。默认信任 `local-ai-*`；使用其他 Provider ID 时，在 `$DSH_HOME/profiles/web/cordis.patch.yml` 覆盖插件配置：

```yaml
- id: privacy-cloud-router
  config:
    cloudProvider: deepseek-official
    cloudModel: deepseek-v4-flash
    trustedProviders:
      - my-local-ollama
```

修改 profile patch 后重启 DSH。配置层会整体替换该行的 `config`；未写字段使用插件默认值。

## 配置

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `cloudProvider` | `deepseek-official` | 云端 Provider ID |
| `cloudModel` | `deepseek-v4-flash` | 云端模型 ID |
| `trustedProviders` | `[]` | 完整的本地 Provider ID 白名单 |
| `trustedProviderPrefixes` | `["local-ai-"]` | 本地 Provider ID 前缀白名单 |
| `privacyPolicy` | 内置策略 | 交给本地分类器的隐私定义 |
| `sensitiveTerms` | `[]` | 大小写不敏感的额外敏感词 |
| `maxPromptBytes` | `32768` | 本轮文本和最近分类上下文的 UTF-8 总大小 |
| `classifierMaxTokens` | `128` | 本地分类输出上限 |
| `cloudMaxTokens` | `8192` | 云端回复输出上限 |
| `recordSessionEvents` | `false` | 内部兼容开关；仅供能够识别 `privacy-router/*` 事件的定制 Harness 使用 |

`PRIVACY_ROUTER_CLOUD_PROVIDER` 和 `PRIVACY_ROUTER_CLOUD_MODEL` 可在 shell 或 `$DSH_HOME/.env` 中覆盖 bundle 默认值。

## UI 展示构想

UI 原型不在本仓库的开源范围内。理想的展示包括：

- 在请求开始和完成时显示可展开的“隐私检查”节点，包括分类、理由、耗时和分类器原始输出；
- 在 Assistant 操作栏显示实际处理回复的 Provider 和 Model；
- 在每条消息、上下文和 Tool 记录旁标记 Public、Sensitive、Unknown、云端生成或仅保留本地；
- 在 Trajectory 中展示一次请求从隐私检查、路由决策到云端出站过滤的完整路径。

内部原型使用三个 Session 事件传递这些信息：

- `privacy-router/check-start`：隐私检查开始；
- `privacy-router/check-result`：分类、理由、耗时和最终 Provider/Model；
- `privacy-router/cloud-dispatch`：实际发送和保留在本地的消息 ID、上下文截断状态和 Tools 排除状态。

事件不会复制用户正文或规则命中的敏感值，但分类器原始输出可能复述输入，因此本地 Session 和导出仍应按敏感数据处理。

## UI 集成限制

官方 DSH 已支持通过 `dsh.client` 加载前端插件，也提供 Chat 自定义节点和 Assistant 操作栏插槽。因此，“隐私检查”节点和 Provider/Model badge 原理上可以独立插件化。当前完整原型仍有三个接口障碍：

1. `privacy-router/*` 是仓库外自定义 Session 事件，不在 DSH 的静态已知事件表中。持久层要求未知事件带 `ignorable: true`，但公开的 `Session.append()` 尚未提供设置该标记的接口。
2. Trajectory 当前按内置记录类型渲染，没有供外部插件注册自定义记录行的通用插槽。
3. Assistant 操作栏已有扩展点，但 User、Tool、Context 等既有 Chat 节点没有统一的 metadata 插槽，无法仅靠外部插件把数据路径标签放到所有目标位置。

因此，本插件在官方 DSH 中默认关闭 `recordSessionEvents`，只执行后端隐私路由。此时不会把历史消息批准给云端，依赖上文的请求会保守地留在本地。完整 UI 需要定制 Harness，或等待上述通用扩展点进入官方 DSH。

## 安全说明

- `public` 是本地规则和模型给出的判定，不是绝对证明；本插件通过 `unknown -> local` 降低误放行风险。
- 受信任 Provider 由 ID 或前缀配置，插件不会验证其 endpoint 是否物理位于本机。
- 插件保护带 `sessionId` 的主 Agent 模型请求，不拦截其他插件自行发起的网络请求。
- 本地 Session 保存完整对话，分类器原始输出也可能复述输入；Session 文件和导出仍应按敏感数据处理。
- 路由事件只复制消息 ID 和角色，不复制原始请求正文或规则命中的值。

## 验证

```sh
npm test
npm run pack:check
```

## License

[MIT](LICENSE)
