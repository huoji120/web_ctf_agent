# One-URL Web CTF Solver（分阶段版）

输入一个已授权的 CTF 题目 URL，模型分三个阶段解题，每阶段全新上下文，只携带压缩后的全局结论，最大限度减少上下文占用。
阅读
《[2026]从模型注意力角度创建一个简单但高效的Agent》 
https://key08.com/index.php/2026/08/10/3275.html 

## 流程

```
🔍 阶段 1 · 识别题型   工具: curl + python + 虚拟文件 + answer → 全局: 题型判断、受控侦察摘要
🧭 阶段 2 · 生成手段   工具: curl + python + 虚拟文件 + answer → 全局: 候选手段列表
⚔️ 阶段 3 · 逐个测试   工具: curl + python + 虚拟文件 + finish + method_failed（每个手段独立全新上下文）
```

- 工具按阶段锁定：前两个阶段拿不到 `finish`/`method_failed`，执行阶段拿不到 `answer`；越权调用会被拒绝并提示当前可用工具。
- `finish(flag)` 只允许报告已在本阶段工具结果中观察到的 FLAG。单个候选手段不可行时只能调用 `method_failed(reason)`；它只标记当前手段未成立，控制器必定继续所有其余候选。仅所有候选手段结束且均未得到 flag，才报告整题无法完成。
- 跨阶段只携带受控的题型结论、侦察摘要和手段状态；没有模型自由写入的事实台账，避免未经验证的信息污染后续工作流。
- 分类、规划、每个候选手段均有独立步数预算；某一阶段耗尽不会终止其他阶段。手段失败或耗尽后把结论压缩成一行写入全局「已试过的手段与结果」，下一个手段带着它继续，不再重复。

## 使用

```bat
start.bat http://127.0.0.1:18080/ "可选的题目介绍，帮模型保持方向"
```

- Agent 通过 `/v1/responses` 的原生 `tools` 发送函数定义；一个模型回合可以返回多个 native `function_call`，Agent 按服务端返回顺序全部串行执行，并把对应的多个 `function_call_output` 一起回传。每个调用各消耗一个阶段动作预算；`maxNativeCallsPerTurn` 只用于约束模型请求上限。
- 🧠 reasoning 流只显示，不解析、不执行、也不作为下一轮工具协议；其中看似工具调用的文本会被忽略。
- `python` 默认最多运行 60 秒；模型可在调用中填写 `timeout_seconds`，但不超过 `maxPythonTimeoutSeconds`（默认 600 秒）。
- 默认启用 Rich TUI：左侧固定显示目标、阶段、候选手段、动作预算、当前工具、上下文/压缩进度和虚拟文件数量，右侧显示最近活动；Rich 负责布局、按右侧面板宽度自动换行、颜色、Unicode、alternate screen 和终端尺寸适配。活动区可用 `↑/↓`、`PageUp/PageDown`、`Home/End` 浏览已保留历史，`End` 回到尾部；默认最多保留 24,000 个字符，超出后丢弃最旧日志。窗口过小或不支持 ANSI 时自动回退为普通流式日志，需要普通日志时加 `--no-tui`。
- `curl/python` 的大结果只返回限长 preview，并放入本阶段内存临时 buffer；模型用 `read_tool_result(result_id, offset, limit)` 分页读取。`limit: 0` 或省略 `limit` 表示从 offset 读取剩余内容，单页最多 32 KiB，足够一次读取常见 HTML。结果连续 4 个回合未读取会过期删除。
- 每个任务的本地上下文预算为 `compactTokens`（默认 64000 tokens）。阶段开始会显示压缩阈值；接近阈值时显示进度，实际开始/完成本地或官方压缩时都会在日志和 TUI 状态栏提示。默认使用本地摘要压缩并重建 Responses 链；启用 `useOfficialCompactionApi` 时提交有界的完整 Responses item 历史到 `/v1/responses/compact`，校验返回的 opaque `compaction.encrypted_content`，把返回窗口中的用户消息和 opaque 状态作为下一次 `/v1/responses` 的完整 `input`（QWEN-EXO 接口要求将 opaque compaction item 以 `reasoning` encrypted item 形式透传），不把 compaction response ID 当作 `previous_response_id`。本地服务实测：直接用该 ID 续接返回 404，完整窗口续接恢复了压缩前的秘密事实；当前配置仍保持关闭。
- 每个执行手段失败或耗尽后，Agent 都会用配置模型生成一份“前序执行失败总结”，包含已观察证据、尝试顺序、失败原因和不可重复路径。下一执行阶段的 prompt 与 TUI 日志都会展示它。模型总结输入严格限制为 `maxSummaryInputTokens`（默认 12000 tokens）的最新工具历史；更早的工具文本会带明确标记截断，绝不会挤占下一阶段上下文。

## 虚拟文件工作区

- 每次运行会在当前目录的 `./virtual_files/session-<随机ID>/` 创建独立工作区；该目录跨所有三个阶段和所有 Python 回合持久保留，方便把枚举结果、下载内容或分析脚本留给下一回合使用。
- 模型可见的文件系统根目录固定为虚拟 `/`：所有原生文件工具路径都必须写成 `/scripts/check.py`、`/data/input.txt` 这类 POSIX 绝对虚拟路径；它们永远不会映射为宿主机根目录、盘符或网络路径。
- Python 的实际工作目录就是虚拟 `/`。可使用相对路径（例如 `open("data/input.txt")`），需要显式虚拟根路径时使用注入的 `vfs("/data/input.txt")`；写好 `/scripts/check.py` 后可直接调用 `python(path="/scripts/check.py")` 执行。
- `write_file`、`edit_file` 和 Python 均按 UTF-8 文本处理；Python 以 UTF-8 mode 启动。`curl(body_path="/upload/payload.bin")` 会把该虚拟文件的原始字节作为请求体上传；`download_file(url, path)` 的 `path` 同样使用虚拟 `/` 路径。
- `list_files()` 返回 `/` 根下的文件；`read_file(path, offset, limit)` 按 UTF-8 **字节**分页读取，`limit: 0` 表示读取一页上限。默认单文件最多 8 MiB、单次读/写/替换文本最多 32 KiB、每个工作区最多 128 个文件；这些上限均可在 `agent.yml` 调整。

界面：🧠 思考（暗黄流式）/ 💬 回答（青色流式）/ 🛠️ 工具 / 🏁 FLAG（退出码 0）/ 🚫 无法完成（退出码 1）。
TUI 依赖 `rich`，启动脚本会在缺少 `requests`、`PyYAML` 或 `rich` 时自动安装 `requirements.txt`。

## 配置

`agent.yml`（环境变量 `MODEL_BASE_URL` / `MODEL_API_KEY` / `MODEL_ID` 可覆盖 model 段）：

| 键 | 默认 | 含义 |
|---|---|---|
| `classifyBudget` | 128 | 阶段 1（识别题型）独立步数预算 |
| `planBudget` | 128 | 阶段 2（生成手段）独立步数预算 |
| `methodBudget` | 128 | 每个候选手段独立步数预算 |
| `maxMethods` | 5 | 最多测试的候选手段数 |
| `compactTokens` | 64000 | 单任务上下文预算；达到后触发选择的压缩策略 |
| `maxCompactionInputTokens` | 8192 | 官方 `/v1/responses/compact` 请求的最大历史输入预算；超出时保留首段和最新证据并标记截断 |
| `maxSummaryInputTokens` | 12000 | 每次模型总结可接收的工具历史上限；超过后仅保留最新证据并标记截断 |
| `maxMethodSummaryChars` | 600 | 写入后续执行阶段的单个失败手段总结最大字符数 |
| `useOfficialCompactionApi` | false | true 时调用 `/v1/responses/compact`，把返回的完整压缩窗口作为下一轮 `input`；不复用不可检索的 compaction response ID，当前配置保持关闭 |
| `maxToolCaptureBytes` | 262144 | 单个 curl/python 结果最多暂存的字节数 |
| `maxInlineToolResultBytes` | 2048 | 首次工具结果直接展示的 preview 字节数 |
| `maxToolReadBytes` | 32768 | 单次 `read_tool_result` 最大读取字节数；`limit: 0` 读取至该上限 |
| `maxToolResultBytes` | 40960 | 单次 Responses function output 最大序列化字节数 |
| `maxToolArgumentBytes` | 16384 | 单次 native 函数 arguments 最大字节数 |
| `maxToolBuffers` | 16 | 每个任务最多保留的临时结果 buffer 数 |
| `toolResultIdleRounds` | 4 | 结果未被分页读取的最大空闲回合数 |
| `maxNativeCallsPerTurn` | 8 | 请求模型每回合最多生成的 native 调用数；服务端意外返回更多时仍按阶段剩余预算顺序执行 |
| `maxTuiChars` | 24000 | Rich 活动区最多保留的字符数；超出后丢弃最旧日志，避免长输出拖慢刷新 |
| `pythonTimeoutSeconds` | 60 | Python 工具默认执行超时（秒） |
| `maxPythonTimeoutSeconds` | 600 | 模型可请求的 Python 超时上限（秒） |
| `virtualWorkspaceDir` | `virtual_files` | 当前目录下的虚拟工作区根目录；每次运行创建一个 session 子目录 |
| `maxVirtualFileBytes` | 8388608 | 单个虚拟文件最大字节数 |
| `maxVirtualFileReadBytes` | 32768 | `read_file` 单页最大读取字节数 |
| `maxVirtualFileWriteBytes` | 32768 | `write_file` 和 `edit_file` 单次文本写入最大字节数 |
| `maxVirtualFiles` | 128 | 每个 session 工作区最多文件数 |

模型输出超 token 上限（incomplete）不崩溃：已完整返回的 native `function_call` 仍会按协议处理；文本或 reasoning 中的伪调用永不执行。
