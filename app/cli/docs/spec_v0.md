
# AgenticCLI 架构设计文档 v1.0（草案）

> **目标**：构建一个 **完全兼容传统 Shell 行为**，同时 **原生支持 AgenticDSL 静态 DAG 图驱动** 的下一代终端。v1.0 聚焦于 **打通 OS 命令执行通路**，**不依赖 LLM 推理、记忆或动态生成**，为未来演进奠定坚实基础。

---

## 一、核心理念

1.  **Shell 兼容性优先**：所有标准 OS 命令（`ls`, `cat`, `curl`, `ps` 等）必须能像在 Bash/Zsh 中一样直接执行。
2.  **DAG 驱动执行**：所有命令执行（包括 Shell 模式和未来的 Agent 模式）都必须通过 AgenticDSL 的静态 DAG 图进行。
3.  **安全与确定性**：所有 OS 操作必须在 **沙箱** 中执行，遵循 **最小权限原则**。
4.  **无缝演进**：v1.0 的架构必须能平滑地在未来版本中引入 LLM 推理、记忆系统和动态 DAG 生成能力。

---

## 二、整体架构

```
+--------------------------------------------------+
|                 AgenticCLI (Main)                |
|                                                  |
|  +----------------+    +----------------------+  |
|  | Command Parser |<-->| AgenticDSL Executor  |  |
|  +----------------+    +----------+-----------+  |
|                                    |              |
+------------------------------------+--------------+
                                     |
                                     v
+--------------------------------------------------+
|               OS Primitives Layer                |
|  +-------------+  +-------------+  +----------+  |
|  | /lib/os/fs  |  | /lib/os/net |  | /lib/... |  |
|  +------+------+  +------+------+  +----+-----+  |
|         |                |               |        |
+---------+----------------+---------------+--------+
          |                |               |
          v                v               v
+---------+----------------+---------------+--------+
|              C++ OS Tool Modules                 |
|    (Sandboxed, Seccomp-BPF protected)            |
+--------------------------------------------------+
```

### 核心组件说明

1.  **`Command Parser`**:
    *   **职责**：解析用户输入。
    *   **v1.0 行为**：
        *   如果输入**完全匹配**一个已注册的 OS 命令（如 `ls -l /home`），则进入 **Shell Mode**。
        *   否则，尝试将其解析为一个 **完整的 AgenticDSL 静态图**（以 `### AgenticDSL` 开头）。如果成功，则进入 **DAG Mode**。
        *   如果两者都不匹配，则报错。
    *   **输出**：一个 **AgenticDSL `ParsedGraph` 对象**。

2.  **`AgenticDSL Executor`**:
    *   **职责**：执行由 `Command Parser` 生成的 `ParsedGraph`。
    *   **实现**：直接复用 **参考执行器 v1.0** 的 `DSLEngine` 和 `TopoScheduler`。
    *   **v1.0 限制**：
        *   **禁用** `llm_call`, `llm_generate_dsl`, `fork`, `join` 等需要推理或并发的节点类型。
        *   **仅支持** `start`, `end`, `assign`, `tool_call`, `assert` 等基础执行原语。
        *   **权限检查**：仅验证与 `/lib/os/**` 相关的权限（如 `os:fs:read`）。

3.  **`OS Primitives Layer (/lib/os/**)`**:
    *   **职责**：提供符合 AgenticDSL v3.9+ 规范的 **标准原语层** 接口，封装所有 OS 能力。
    *   **路径**：所有子图必须位于 `/lib/os/**` 命名空间下，例如：
        *   `/lib/os/fs/read@v1`
        *   `/lib/os/fs/list@v1`
        *   `/lib/os/net/http_get@v1`
        *   `/lib/os/process/list@v1`
    *   **规范要求**：
        *   必须包含 `signature`。
        *   必须声明 `permissions`（如 `os:fs:read`）。
        *   必须通过 `tool_call` 节点调用底层 C++ 模块。

4.  **`C++ OS Tool Modules`**:
    *   **职责**：实现具体的、安全的 OS 操作逻辑。
    *   **安全要求**：
        *   **沙箱化**：每个模块必须在 **seccomp-BPF** 沙箱中运行，仅允许有限的系统调用（如 `openat`, `read`, `write`, `close`）。
        *   **无状态**：模块函数必须是纯函数，输入决定输出，不持有任何内部状态。
        *   **路径安全**：所有文件路径操作必须基于一个 **安全的根目录**（如 `$HOME` 或 `$PWD`），并**严格禁止**路径遍历（`..`）和对绝对路径的访问。

---

## 三、C++ 模块详细设计

### 3.1 模块通用接口

所有 C++ OS 工具模块必须遵循以下接口模式：

```cpp
// include/os_tools/fs_tool.h
#include "agentic_native/tool_interface.hpp" // 复用 AgenticDSL C++ 模块模板

namespace agentic_cli {

// 通用返回结构
struct OsResult {
    AgResultType type; // SUCCESS 或 ERROR
    std::string message; // 错误信息或成功结果
    nlohmann::json data; // 结构化数据（如文件列表）
};

// 工具函数签名
using OsToolFunc = std::function<OsResult(const nlohmann::json& args)>;

// 工具注册函数（由模块实现）
void register_os_tools(agentic::ToolRegistry& reg);

} // namespace agentic_cli
```

### 3.2 关键模块实现示例

#### **`fs_tool.cpp` (文件系统模块)**

```cpp
// src/os_tools/fs_tool.cpp
#include "os_tools/fs_tool.h"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

agentic_cli::OsResult os_fs_read(const nlohmann::json& args) {
    // 1. 输入校验
    if (!args.contains("path") || !args["path"].is_string()) {
        return {AgResultType::ERROR, "ERR_INVALID_INPUT: 'path' (string) is required", {}};
    }
    std::string rel_path = args["path"].get<std::string>();
    
    // 2. 安全检查：禁止 ".." 和绝对路径
    if (rel_path.find("..") != std::string::npos || rel_path.empty() || rel_path[0] == '/') {
        return {AgResultType::ERROR, "ERR_PATH_VIOLATION: Path traversal is not allowed", {}};
    }
    
    // 3. 拼接安全路径 (假设根目录为 ~/.agenticcli/sandbox)
    fs::path safe_root = fs::path(getenv("HOME")) / ".agenticcli" / "sandbox";
    fs::path full_path = safe_root / rel_path;
    
    // 4. 执行操作
    std::ifstream file(full_path);
    if (!file.is_open()) {
        return {AgResultType::ERROR, "ERR_FILE_NOT_FOUND: " + full_path.string(), {}};
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    
    return {AgResultType::SUCCESS, "OK", {{"content", content}}};
}

agentic_cli::OsResult os_fs_list(const nlohmann::json& args) {
    // 实现逻辑类似，返回目录项列表
    // ...
}

// 模块注册入口
void agentic_cli::register_os_tools(agentic::ToolRegistry& reg) {
    reg.registerTool(
        "os_fs_read",
        os_fs_read,
        agentic::ToolSchema{
            .inputs = {{"path", "string"}},
            .outputs = {{"content", "string"}},
            .required_permissions = {"os:fs:read"}
        }
    );
    
    reg.registerTool(
        "os_fs_list",
        os_fs_list,
        agentic::ToolSchema{
            .inputs = {{"path", "string"}},
            .outputs = {{"files", "array"}},
            .required_permissions = {"os:fs:read"}
        }
    );
}
```

#### **`net_tool.cpp` (网络模块)**

```cpp
// src/os_tools/net_tool.cpp
#include "os_tools/net_tool.h"
// ... (使用 libcurl 或类似库)

agentic_cli::OsResult os_net_http_get(const nlohmann::json& args) {
    // 1. 输入校验
    if (!args.contains("url") || !args["url"].is_string()) {
        return {AgResultType::ERROR, "ERR_INVALID_INPUT: 'url' (string) is required", {}};
    }
    std::string url = args["url"].get<std::string>();
    
    // 2. 安全检查：限制域名白名单（从配置读取）
    if (!is_domain_allowed(url)) {
        return {AgResultType::ERROR, "ERR_DOMAIN_NOT_ALLOWED", {}};
    }
    
    // 3. 执行 HTTP GET
    std::string response = perform_http_get(url);
    
    return {AgResultType::SUCCESS, "OK", {{"body", response}}};
}

void agentic_cli::register_os_tools(agentic::ToolRegistry& reg) {
    reg.registerTool(
        "os_net_http_get",
        os_net_http_get,
        agentic::ToolSchema{
            .inputs = {{"url", "string"}},
            .outputs = {{"body", "string"}},
            .required_permissions = {"os:net:http"}
        }
    );
}
```

---

## 四、原语层 (`/lib/os/**`) 设计

### 4.1 `/lib/os/fs/read@v1` (YAML DSL)

```yaml
### AgenticDSL '/lib/os/fs/read@v1'
signature:
  inputs:
    - name: path
      type: string
      required: true
      description: "Relative path to the file to read"
  outputs:
    - name: content
      type: string
      description: "The content of the file"
  version: "1.0"
  stability: stable
permissions:
  - os:fs:read
nodes:
  - id: call_read
    type: tool_call
    tool: os_fs_read
    arguments:
      path: "{{ $.path }}"
    output_mapping:
      content: "result.content"
    next: "end"
  - id: end
    type: end
```

### 4.2 `/lib/os/net/http_get@v1` (YAML DSL)

```yaml
### AgenticDSL '/lib/os/net/http_get@v1'
signature:
  inputs:
    - name: url
      type: string
      required: true
  outputs:
    - name: body
      type: string
  version: "1.0"
  stability: stable
permissions:
  - os:net:http
nodes:
  - id: call_http
    type: tool_call
    tool: os_net_http_get
    arguments:
      url: "{{ $.url }}"
    output_mapping:
      body: "result.body"
    next: "end"
  - id: end
    type: end
```

---

## 五、Shell Mode 到 DAG Mode 的转换

`Command Parser` 的核心任务是将 Shell 命令转换为一个等效的 `ParsedGraph`。

### 转换示例

**用户输入**:
```bash
ls -l /projects
```

**`Command Parser` 内部生成的 `ParsedGraph` (伪代码)**:

```yaml
### AgenticDSL '/dynamic/shell_123'
nodes:
  - id: start
    type: start
    next: "call_ls"
  - id: call_ls
    type: tool_call
    tool: /lib/os/fs/list@v1
    arguments:
      path: "/projects"
    output_mapping:
      files: "shell_output"
    next: "print_result"
  - id: print_result
    type: assign
    assign:
      expr: "{{ $.shell_output | join('\\n') }}"
      path: "stdout"
    next: "end"
  - id: end
    type: end
```

> **关键点**：这个转换必须是 **确定性** 和 **安全** 的。`Command Parser` 必须内置一个 **命令到原语的映射表**，并严格校验参数。

---

## 六、启动与初始化流程

1.  **`main()`**:
    *   初始化 `DSLEngine`。
    *   加载内置的 `/lib/os/**` 标准库。
    *   调用 `agentic_cli::register_os_tools(engine->get_tool_registry())`。
    *   进入 REPL 循环。

2.  **`REPL Loop`**:
    *   `read_line()`: 读取用户输入。
    *   `CommandParser::parse(input)`: 解析输入。
    *   `engine->run(parsed_graph)`: 执行生成的 DAG。
    *   `print_result()`: 打印最终上下文中的 `stdout` 字段到终端。
    *   循环。

---

## 七、v1.0 范围与演进路径

### v1.0 范围 (MVP)

- [x] 支持 `assign`, `tool_call`, `assert`, `start`, `end` 节点。
- [x] 实现 `/lib/os/fs/**` 和 `/lib/os/net/**` 原语。
- [x] 实现安全的 C++ OS 工具模块（沙箱、路径检查）。
- [x] 实现 Shell Mode 命令到 DAG 的转换。
- [x] 实现权限声明与检查（`os:fs:read` 等）。

### 未来演进

- **v2.0**: 引入 `/__meta__/resources` 声明，支持用户自定义工具注册。
- **v3.0**: 集成 LLM 推理 (`llm_call`)，支持 Agent Mode。
- **v4.0**: 支持动态 DAG 生成 (`llm_generate_dsl`) 和记忆系统 (`/lib/memory/**`)。
