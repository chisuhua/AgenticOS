# AgenticCLI v1.0 跨平台架构设计：安全沙箱统一实现

## 一、整体架构

```
+----------------------------------------------------------+
|                    AgenticCLI (v1.0)                     |
|                                                          |
|  +----------------+    +----------------------+          |
|  | Command Parser |<-->| AgenticDSL Executor  |          |
|  +----------------+    +----------+-----------+          |
|                                   |                      |
+-----------------------------------+----------------------+
                                    |
                                    v
+----------------------------------------------------------+
|                OS Abstraction Layer (Cross-platform)     |
|  +-------------+  +-------------+  +----------+  +-----+ |
|  | fs_adapter  |  | net_adapter |  | proc_... |  | ... | |
|  +------+------+  +------+------+  +----+-----+  +-----+ |
|         |                |               |              |
+---------+----------------+---------------+--------------+
          |                |               |
          v                v               v
+---------+----------------+---------------+--------------+
|              Platform-specific Sandboxes                |
|  +------------+  +------------+  +------------+         |
|  | Linux:     |  | macOS:     |  | Windows:   |         |
|  | seccomp-bpf|  | Seatbelt   |  | AppContainer|        |
|  | namespaces |  | sandbox-exec|  | Job Objects|        |
|  +------------+  +------------+  +------------+         |
+----------------------------------------------------------+
```

## 二、跨平台沙箱统一接口设计

### 2.1 通用沙箱接口（C++头文件）

```cpp
// include/sandbox/sandbox_interface.hpp
#pragma once
#include <string>
#include <vector>
#include <functional>
#include "agentic_native/types.hpp"

namespace agentic_cli::sandbox {

enum class SandboxLevel {
  RESTRICTED,  // 最严格，仅允许基础IO
  WORKSPACE,   // 允许工作区读写
  NETWORKED,   // 允许网络访问
  DANGEROUS    // 宽松模式（仅开发使用）
};

struct SandboxConfig {
  SandboxLevel level = SandboxLevel::RESTRICTED;
  std::string workspace_root;  // 安全根目录
  std::vector<std::string> allowed_domains;  // 仅NETWORKED级别有效
  bool enable_network = false;
  size_t max_memory_mb = 256;
  size_t max_cpu_time_ms = 5000;
};

struct SandboxResult {
  bool success;
  std::string output;
  std::string error;
  size_t execution_time_ms;
};

using SandboxOperation = std::function<AgResult(const nlohmann::json& args)>;

class ISandboxProvider {
public:
  virtual ~ISandboxProvider() = default;
  
  // 初始化沙箱环境
  virtual bool init(const SandboxConfig& config) = 0;
  
  // 在沙箱中执行操作
  virtual SandboxResult execute(const std::string& operation_name, 
                               const nlohmann::json& args,
                               SandboxOperation operation) = 0;
  
  // 验证路径是否安全
  virtual bool validate_path(const std::string& path) = 0;
  
  // 获取沙箱信息
  virtual std::string get_info() const = 0;
};

// 工厂方法，根据平台创建沙箱提供者
std::unique_ptr<ISandboxProvider> create_platform_sandbox();
}
```

### 2.2 安全路径验证策略

```cpp
// 路径验证核心逻辑（跨平台）
bool validate_safe_path(const std::string& path, const std::string& root_dir) {
  // 1. 禁止空路径
  if (path.empty()) return false;
  
  // 2. 禁止绝对路径
  if (path[0] == '/' || (path.length() >= 2 && path[1] == ':')) return false;
  
  // 3. 禁止路径遍历
  if (path.find("..") != std::string::npos) return false;
  
  // 4. 规范化路径并检查是否在根目录内
  fs::path normalized = fs::weakly_canonical(fs::path(root_dir) / path);
  fs::path root_abs = fs::weakly_canonical(root_dir);
  
  // 5. 确保规范化后仍在根目录下
  return normalized.string().find(root_abs.string()) == 0;
}
```

## 三、各平台沙箱实现策略

### 3.1 Linux实现

```cpp
// src/sandbox/linux_sandbox.cpp
#include <seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include "sandbox/sandbox_interface.hpp"

namespace agentic_cli::sandbox {

class LinuxSandboxProvider : public ISandboxProvider {
private:
  SandboxConfig config_;
  bool initialized_ = false;
  
  bool setup_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) return false;
    
    // 基础系统调用
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    
    // 文件系统操作
    if (config_.level != SandboxLevel::RESTRICTED) {
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    }
    
    // 应用规则
    return seccomp_load(ctx) == 0;
  }
  
  bool setup_namespaces() {
    // 创建挂载命名空间
    if (unshare(CLONE_NEWNS) != 0) return false;
    
    // 使挂载私有
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return false;
    
    // 挂载tmpfs作为工作区
    if (mount("tmpfs", config_.workspace_root.c_str(), "tmpfs", 0, "size=64m") != 0) {
      return false;
    }
    
    return true;
  }
  
  bool setup_resource_limits() {
    struct rlimit rl;
    
    // CPU时间限制
    rl.rlim_cur = config_.max_cpu_time_ms / 1000;
    rl.rlim_max = rl.rlim_cur;
    setrlimit(RLIMIT_CPU, &rl);
    
    // 内存限制
    rl.rlim_cur = config_.max_memory_mb * 1024 * 1024;
    rl.rlim_max = rl.rlim_cur;
    setrlimit(RLIMIT_AS, &rl);
    
    // 禁止创建新进程
    if (config_.level == SandboxLevel::RESTRICTED) {
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    
    return true;
  }

public:
  bool init(const SandboxConfig& config) override {
    config_ = config;
    if (!setup_resource_limits()) return false;
    if (!setup_seccomp()) return false;
    if (!setup_namespaces()) return false;
    initialized_ = true;
    return true;
  }
  
  SandboxResult execute(const std::string& operation_name,
                        const nlohmann::json& args,
                        SandboxOperation operation) override {
    auto start = std::chrono::steady_clock::now();
    
    try {
      // 在fork中执行以隔离资源
      pid_t pid = fork();
      if (pid == 0) {
        // 子进程
        AgResult result = operation(args);
        exit(0);
      } else if (pid > 0) {
        // 父进程
        int status;
        waitpid(pid, &status, 0);
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        SandboxResult result;
        result.success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        result.execution_time_ms = duration.count();
        return result;
      } else {
        throw std::runtime_error("fork failed");
      }
    } catch (const std::exception& e) {
      SandboxResult result;
      result.success = false;
      result.error = e.what();
      return result;
    }
  }
  
  bool validate_path(const std::string& path) override {
    return ::validate_safe_path(path, config_.workspace_root);
  }
  
  std::string get_info() const override {
    return "Linux seccomp-bpf + namespaces sandbox";
  }
};

std::unique_ptr<ISandboxProvider> create_platform_sandbox() {
  return std::make_unique<LinuxSandboxProvider>();
}

} // namespace agentic_cli::sandbox
```

### 3.2 macOS实现

```cpp
// src/sandbox/macos_sandbox.cpp
#include <sandbox.h>
#include <sys/resource.h>
#include "sandbox/sandbox_interface.hpp"

namespace agentic_cli::sandbox {

class MacOSSandboxProvider : public ISandboxProvider {
private:
  SandboxConfig config_;
  bool initialized_ = false;
  std::string sandbox_profile_;
  
  void generate_sandbox_profile() {
    std::ostringstream profile;
    
    profile << "(version 1)\n";
    profile << "(allow default)\n";
    profile << "(deny network*)\n";
    profile << "(deny process*)\n";
    profile << "(deny file-write*)\n";
    profile << "(deny sysctl*)\n";
    
    // 允许读取工作区
    profile << "(allow file-read* (subpath \"" << config_.workspace_root << "\"))\n";
    
    // 根据级别调整权限
    if (config_.level != SandboxLevel::RESTRICTED) {
      profile << "(allow file-read*)\n";
      profile << "(allow file-write* (subpath \"" << config_.workspace_root << "\"))\n";
    }
    
    if (config_.level == SandboxLevel::NETWORKED) {
      profile << "(allow network*)\n";
      // 添加允许的域名
      for (const auto& domain : config_.allowed_domains) {
        profile << "(allow network* (remote ip \"" << domain << "\"))\n";
      }
    }
    
    sandbox_profile_ = profile.str();
  }
  
  bool setup_resource_limits() {
    struct rlimit rl;
    
    // CPU时间限制
    rl.rlim_cur = config_.max_cpu_time_ms / 1000;
    rl.rlim_max = rl.rlim_cur;
    setrlimit(RLIMIT_CPU, &rl);
    
    // 内存限制
    rl.rlim_cur = config_.max_memory_mb * 1024 * 1024;
    rl.rlim_max = rl.rlim_cur;
    setrlimit(RLIMIT_AS, &rl);
    
    return true;
  }

public:
  bool init(const SandboxConfig& config) override {
    config_ = config;
    generate_sandbox_profile();
    if (!setup_resource_limits()) return false;
    initialized_ = true;
    return true;
  }
  
  SandboxResult execute(const std::string& operation_name,
                        const nlohmann::json& args,
                        SandboxOperation operation) override {
    auto start = std::chrono::steady_clock::now();
    char* errorbuf = nullptr;
    
    // 应用沙箱
    int result = sandbox_init(sandbox_profile_.c_str(), SANDBOX_NAMED, &errorbuf);
    if (result != 0) {
      SandboxResult res;
      res.success = false;
      res.error = errorbuf ? errorbuf : "Unknown sandbox error";
      if (errorbuf) sandbox_free_error(errorbuf);
      return res;
    }
    
    // 执行操作
    try {
      AgResult ag_result = operation(args);
      sandbox_free_error(errorbuf);
      
      auto end = std::chrono::steady_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
      
      SandboxResult result;
      result.success = ag_result.type == AgResultType::SUCCESS;
      result.output = ag_result.message;
      result.execution_time_ms = duration.count();
      return result;
    } catch (const std::exception& e) {
      sandbox_free_error(errorbuf);
      SandboxResult result;
      result.success = false;
      result.error = e.what();
      return result;
    }
  }
  
  bool validate_path(const std::string& path) override {
    return ::validate_safe_path(path, config_.workspace_root);
  }
  
  std::string get_info() const override {
    return "macOS Seatbelt sandbox";
  }
};

std::unique_ptr<ISandboxProvider> create_platform_sandbox() {
  return std::make_unique<MacOSSandboxProvider>();
}

} // namespace agentic_cli::sandbox
```

### 3.3 Windows实现

```cpp
// src/sandbox/windows_sandbox.cpp
#include <windows.h>
#include <jobapi2.h>
#include <sddl.h>
#include "sandbox/sandbox_interface.hpp"

namespace agentic_cli::sandbox {

class WindowsSandboxProvider : public ISandboxProvider {
private:
  SandboxConfig config_;
  bool initialized_ = false;
  HANDLE job_handle_ = nullptr;
  
  bool setup_job_object() {
    job_handle_ = CreateJobObject(nullptr, nullptr);
    if (!job_handle_) return false;
    
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = 
        JOB_OBJECT_LIMIT_PROCESS_TIME |
        JOB_OBJECT_LIMIT_JOB_MEMORY |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    
    // CPU时间限制（100纳秒单位）
    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 
        config_.max_cpu_time_ms * 10000;
    
    // 内存限制
    limits.JobMemoryLimit = config_.max_memory_mb * 1024 * 1024;
    
    if (!SetInformationJobObject(job_handle_, 
        JobObjectExtendedLimitInformation, 
        &limits, 
        sizeof(limits))) {
      CloseHandle(job_handle_);
      job_handle_ = nullptr;
      return false;
    }
    
    return true;
  }
  
  bool create_restricted_token() {
    HANDLE token, restricted_token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
      return false;
    }
    
    // 创建受限令牌
    if (!CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, nullptr, 
                              0, nullptr, 0, nullptr, &restricted_token)) {
      CloseHandle(token);
      return false;
    }
    
    // 应用受限令牌
    if (!SetThreadToken(nullptr, restricted_token)) {
      CloseHandle(token);
      CloseHandle(restricted_token);
      return false;
    }
    
    CloseHandle(token);
    CloseHandle(restricted_token);
    return true;
  }
  
  bool setup_app_container() {
    // Windows 8+支持AppContainer
    // 需要创建一个低特权的应用容器
    // 这里简化实现，实际应该使用CreateAppContainerProfile API
    return true;
  }

public:
  bool init(const SandboxConfig& config) override {
    config_ = config;
    if (!setup_job_object()) return false;
    if (!create_restricted_token()) return false;
    if (!setup_app_container()) return false;
    initialized_ = true;
    return true;
  }
  
  SandboxResult execute(const std::string& operation_name,
                        const nlohmann::json& args,
                        SandboxOperation operation) override {
    auto start = std::chrono::steady_clock::now();
    
    // 创建子进程
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
      SandboxResult result;
      result.success = false;
      result.error = "Failed to create pipe";
      return result;
    }
    
    STARTUPINFO si = {sizeof(STARTUPINFO)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    
    PROCESS_INFORMATION pi;
    
    // 创建受限进程
    std::string cmd = "agentic_sandbox_child.exe " + operation_name;
    if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, 
                        TRUE, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 
                        nullptr, nullptr, &si, &pi)) {
      CloseHandle(hRead);
      CloseHandle(hWrite);
      SandboxResult result;
      result.success = false;
      result.error = "Failed to create process";
      return result;
    }
    
    // 将进程分配给作业对象
    AssignProcessToJobObject(job_handle_, pi.hProcess);
    
    // 恢复进程
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    
    // 读取输出
    char buffer[4096];
    DWORD bytes_read;
    std::string output;
    
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytes_read, nullptr) && bytes_read > 0) {
      buffer[bytes_read] = '\0';
      output += buffer;
    }
    
    // 等待进程结束
    WaitForSingleObject(pi.hProcess, config_.max_cpu_time_ms);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    CloseHandle(hWrite);
    
    SandboxResult result;
    result.success = (exit_code == 0);
    result.output = output;
    result.execution_time_ms = duration.count();
    return result;
  }
  
  bool validate_path(const std::string& path) override {
    return ::validate_safe_path(path, config_.workspace_root);
  }
  
  std::string get_info() const override {
    return "Windows Job Objects + Restricted Token sandbox";
  }
};

std::unique_ptr<ISandboxProvider> create_platform_sandbox() {
  return std::make_unique<WindowsSandboxProvider>();
}

} // namespace agentic_cli::sandbox
```

## 四、可借鉴的开源项目

### 4.1 核心沙箱技术参考

1. **Firecracker** (Amazon)
   - 微VM技术，轻量级虚拟化
   - 适用于Linux平台
   - 参考点：内存安全、最小攻击面设计
   - 仓库: https://github.com/firecracker-microvm/firecracker

2. **gVisor** (Google)
   - 容器运行时沙箱，实现自己的内核子集
   - 支持seccomp和KVM模式
   - 参考点：系统调用拦截和过滤
   - 仓库: https://github.com/google/gvisor

3. **Deno** (Ryan Dahl)
   - 安全的JavaScript/TypeScript运行时
   - 基于V8和Rust
   - 参考点：权限模型、沙箱API设计
   - 仓库: https://github.com/denoland/deno

4. **WasmEdge** (CNCF)
   - WebAssembly runtime with sandboxing
   - 跨平台支持
   - 参考点：WASM沙箱模型、资源限制
   - 仓库: https://github.com/WasmEdge/WasmEdge

5. **Chromium Sandbox**
   - 跨平台浏览器沙箱
   - 支持Windows、macOS、Linux
   - 参考点：多平台沙箱统一接口
   - 代码位置: https://source.chromium.org/chromium/chromium/src/+/main:sandbox/

### 4.2 安全抽象层参考

1. **libSandbox** (OpenBSD)
   - 简单但严格的沙箱API
   - 参考点：最小权限原则实现

2. **OpenSSF Scorecard**
   - 安全评估工具
   - 参考点：安全最佳实践

3. **osquery** (Facebook)
   - 操作系统监控工具
   - 参考点：跨平台系统API抽象
   - 仓库: https://github.com/osquery/osquery

## 五、技术路线图

### 5.1 阶段1：核心引擎与基础沙箱（1-2个月）

1. **DAG执行引擎**
   - 实现AgenticDSL v1.0解析器
   - 基础调度器（TopoScheduler）
   - 上下文管理

2. **跨平台基础库**
   - 抽象层接口定义
   - 路径处理与验证
   - 资源限制基础

3. **Linux沙箱实现**
   - seccomp-bpf规则集
   - 命名空间隔离
   - 资源限制

4. **基础OS原语**
   - `/lib/os/fs/read@v1`
   - `/lib/os/fs/list@v1`
   - `/lib/os/process/list@v1`

### 5.2 阶段2：多平台沙箱与Shell兼容（2-3个月）

1. **macOS沙箱实现**
   - Seatbelt策略
   - 代码签名要求

2. **Windows沙箱实现**
   - Job Objects
   - 受限令牌
   - AppContainer集成

3. **统一沙箱管理**
   - 策略配置中心
   - 运行时策略切换

4. **Shell模式集成**
   - 命令解析与转换
   - Shell兼容性测试

### 5.3 阶段3：优化与生态建设（3-4个月）

1. **性能优化**
   - 沙箱启动时间优化
   - 资源使用监控
   - 内存占用优化

2. **安全审计**
   - 模糊测试集成
   - 安全边界测试
   - 漏洞奖励计划

3. **开发者工具**
   - SDK与文档
   - 调试工具
   - 示例库

4. **CI/CD集成**
   - 跨平台构建流水线
   - 安全测试自动化
   - 发布流程

## 六、实施建议

### 6.1 关键技术决策

1. **沙箱策略选择**
   - 优先选择系统原生沙箱技术（seccomp, Seatbelt, AppContainer）
   - 避免维护自定义内核模块
   - 保持最小攻击面

2. **跨平台抽象设计**
   - 采用策略模式，隐藏平台差异
   - 使用C++接口类，支持运行时多态
   - 避免#ifdef洪水

3. **安全默认设置**
   - 默认使用最严格沙箱级别
   - 显式声明权限需求
   - 审计日志默认开启

### 6.2 风险缓解

1. **平台支持不均**
   - 优先保证Linux支持，其次是macOS，最后是Windows
   - 为每个平台设立明确的兼容性目标

2. **性能开销**
   - 提供沙箱级别选择，平衡安全与性能
   - 沙箱预热机制
   - 资源使用监控和告警

3. **安全漏洞**
   - 定期安全审计
   - 模糊测试集成
   - 快速补丁流程

### 6.3 开源策略

1. **逐步开源**
   - 首先开源抽象层和Linux实现
   - 随后开源macOS和Windows实现
   - 鼓励社区贡献平台特定优化

2. **安全披露流程**
   - 建立明确的安全报告渠道
   - 承诺响应时间和补丁周期
   - 感谢安全研究人员

## 七、总结

AgenticCLI v1.0的跨平台沙箱设计采用"抽象层+平台特定实现"的方法，确保在不同操作系统上提供统一的安全体验。通过借鉴Firecracker、gVisor、Deno等项目的成功经验，结合现代操作系统提供的安全原语，构建一个既安全又实用的基础架构。

关键成功因素包括：
- 保持核心设计简单，避免过度工程
- 优先实现Linux支持，逐步扩展到其他平台
- 严格遵循最小权限原则
- 提供清晰的开发者体验和文档

# AgenticCLI的能力边界与分层架构

## 一、AgenticCLI的核心能力范围

### 1.1 **基础OS能力（v1.0提供）**
- **文件系统操作**：安全的读写、列出目录、创建/删除文件
- **网络基础**：HTTP/HTTPS请求、DNS解析
- **进程管理**：列出进程、执行命令（在沙箱中）
- **系统信息**：获取系统状态、资源使用情况

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
```

### 1.2 **工作流与编排能力（v2.0+）**
- **DAG驱动的工作流**：多个操作的条件执行、并行处理
- **状态管理**：跨步骤的上下文保持
- **错误处理**：异常捕获和恢复机制
- **资源预算**：执行时间、内存、网络请求的限制

### 1.3 **智能代理能力（v3.0+）**
- **LLM集成**：调用大模型进行决策、生成和验证
- **动态DAG生成**：运行时根据上下文生成新的执行计划
- **记忆系统**：短期和长期记忆的存储与检索
- **自我改进**：通过`archive_to`将成功模式沉淀为标准库

## 二、HTTPS上网能力：分层实现策略

### 2.1 **基础网络能力（AgenticCLI直接提供）**
- **简单HTTP/HTTPS请求**：通过`/lib/os/net/http_get@v1`等原语
- **请求参数处理**：headers、cookies、认证
- **响应解析**：JSON、HTML片段提取
- **安全限制**：域名白名单、请求频率限制

```cpp
// C++模块实现示例
agentic_cli::OsResult os_net_http_get(const nlohmann::json& args) {
    // 1. 输入校验
    if (!args.contains("url") || !args["url"].is_string()) {
        return {AgResultType::ERROR, "ERR_INVALID_INPUT: 'url' required", {}};
    }
    
    std::string url = args["url"].get<std::string>();
    
    // 2. 安全检查：域名白名单
    if (!is_domain_allowed(url)) {
        return {AgResultType::ERROR, "ERR_DOMAIN_NOT_ALLOWED", {}};
    }
    
    // 3. 执行HTTPS请求（使用libcurl等）
    std::string response = perform_https_get(url, {
        .timeout_ms = 5000,
        .verify_ssl = true,
        .max_redirects = 3
    });
    
    return {AgResultType::SUCCESS, "OK", {{"body", response}}};
}
```

### 2.2 **高级Web交互能力（需要AgenticWeb层）**
对于完整浏览器体验，需要更高层抽象：

| 能力 | AgenticCLI基础层 | AgenticWeb扩展层 |
|------|------------------|-----------------|
| 基础HTTP请求 | ✅ 直接提供 | ✅ 复用基础能力 |
| HTTPS加密 | ✅ TLS/SSL支持 | ✅ 复用基础能力 |
| Cookie管理 | ⚠️ 基础支持 | ✅ 会话管理 |
| JavaScript执行 | ❌ 不支持 | ✅ 沙箱化JS引擎 |
| DOM操作 | ❌ 不支持 | ✅ 虚拟DOM |
| 页面渲染 | ❌ 不支持 | ✅ 无头浏览器集成 |
| 用户交互 | ❌ 不支持 | ✅ 事件模拟 |

## 三、分层架构设计

### 3.1 **能力分层模型**
```
+------------------------------------------------+
|              Application Layer                 |
|  • 用户应用 (邮件客户端、数据分析工具等)       |
|  • 领域特定工具 (科研计算、金融分析等)         |
+------------------------------------------------+
|              AgenticWeb Layer                  |
|  • Web浏览与交互 (/lib/web/browser@v1)        |
|  • 表单填充 (/lib/web/form_fill@v1)           |
|  • 页面分析 (/lib/web/content_analyze@v1)     |
+------------------------------------------------+
|              AgenticCLI Core Layer            |
|  • OS基础能力 (/lib/os/fs/read@v1)            |
|  • 网络能力 (/lib/os/net/http_get@v1)         |
|  • LLM集成 (/lib/reasoning/generate_text@v1)  |
+------------------------------------------------+
|              OS Primitive Layer               |
|  • 文件系统 • 网络栈 • 进程管理 • 内存管理    |
+------------------------------------------------+
```

### 3.2 **AgenticWeb的设计原则**
1. **构建在AgenticCLI之上**：不是替代，而是扩展
2. **标准化接口**：`/lib/web/**`命名空间，遵循相同契约原则
3. **安全第一**：JavaScript执行在额外沙箱中，DOM操作受限制
4. **能力声明**：明确声明需要的权限（`web:javascript`, `web:dom_access`）

```yaml
### AgenticDSL '/lib/web/page_load@v1'
signature:
  inputs:
    - name: url
      type: string
      required: true
    - name: wait_for_selector
      type: string
      required: false
  outputs:
    - name: html
      type: string
    - name: screenshots
      type: array
  permissions:
    - os:net:http
    - web:javascript
    - web:dom_access
resources:
  - type: runtime
    name: headless_browser
    capabilities: [javascript, screenshot, dom_traversal]
nodes:
  - id: validate_url
    type: assert
    condition: "{{ is_valid_url($.url) }}"
    on_failure: "error_invalid_url"
    
  - id: fetch_page
    type: tool_call
    tool: /lib/os/net/http_get@v1
    arguments:
      url: "{{ $.url }}"
    next: "render_js"
    
  - id: render_js
    type: tool_call
    tool: web_js_renderer
    arguments:
      html: "{{ $.result.body }}"
      wait_for: "{{ $.wait_for_selector }}"
    output_mapping:
      html: "dom.html"
      screenshots: "dom.screenshots"
    next: "end"
```

## 四、实际应用场景分析

### 4.1 **场景1：简单数据抓取**
```yaml
### AgenticDSL '/app/data_scraper'
nodes:
  - id: fetch_data
    type: tool_call
    tool: /lib/os/net/http_get@v1
    arguments:
      url: "https://api.example.com/data"
    output_mapping:
      data: "json.parse(result.body)"
    next: "process_data"
    
  - id: process_data
    type: assign
    assign:
      expr: "{{ $.data.items | filter_by_criteria }}"
      path: "result.filtered_items"
    next: "end"
```
✅ **完全由AgenticCLI提供**，无需AgenticWeb

### 4.2 **场景2：登录网站并提取数据**
```yaml
### AgenticDSL '/app/login_scraper'
nodes:
  - id: load_login_page
    type: tool_call
    tool: /lib/web/page_load@v1
    arguments:
      url: "https://example.com/login"
    next: "fill_credentials"
    
  - id: fill_credentials
    type: tool_call
    tool: /lib/web/form_fill@v1
    arguments:
      form_selector: "#login-form"
      fields:
        username: "user@example.com"
        password: "{{ get_secret('example_password') }}"
    next: "submit_login"
    
  - id: submit_login
    type: tool_call
    tool: /lib/web/form_submit@v1
    arguments:
      form_selector: "#login-form"
    output_mapping:
      session_cookie: "browser.cookies['session']"
    next: "fetch_protected_data"
```
⚠️ **需要AgenticWeb层**，涉及JavaScript执行和DOM操作

## 五、技术实现建议

### 5.1 **基础网络能力（AgenticCLI v1.0）**
- **C++模块**：使用libcurl实现HTTPS请求
- **沙箱限制**：域名白名单、请求超时、响应大小限制
- **证书验证**：强制验证SSL证书
- **代理支持**：可配置的HTTP/HTTPS代理

### 5.2 **高级Web能力（AgenticWeb v1.0）**
- **核心引擎**：集成无头浏览器（Playwright/Puppeteer）
- **安全沙箱**：
  - 网络请求继承AgenticCLI的限制
  - JavaScript执行在额外沙箱中
  - DOM操作受CSP策略限制
- **资源管理**：页面加载超时、内存限制、CPU使用限制
- **隐私保护**：自动清除cookies、本地存储

### 5.3 **统一安全模型**
```cpp
// 权限检查贯穿所有层
bool check_permissions(const std::vector<std::string>& required, 
                      const Context& ctx) {
  auto granted = ctx.get_permissions();
  
  for (const auto& perm : required) {
    // 多层权限检查
    if (!granted.contains(perm)) {
      // 检查是否为web权限，需要额外验证
      if (perm.starts_with("web:")) {
        return check_web_permissions(perm, ctx);
      }
      return false;
    }
  }
  return true;
}
```

## 六、演进路线

### 6.1 **短期（v1.0-1.5）**
- 完成基础OS能力（包括HTTPS请求）
- 构建AgenticWeb原型，支持简单页面加载
- 建立统一权限模型和安全边界

### 6.2 **中期（v2.0）**
- AgenticWeb正式版，支持完整Web交互
- 标准库扩展：`/lib/web/**`系列原语
- 跨层能力协调（CLI ↔ Web）

### 6.3 **长期（v3.0+）**
- 智能Web代理：LLM驱动的页面理解和交互
- 多模态能力：结合视觉理解和文本处理
- 自适应Web策略：根据内容自动调整交互方式

## 七、结论

**AgenticCLI直接提供**：
- 基础OS能力，包括HTTPS请求
- 安全的网络通信
- 数据获取和简单处理

**需要AgenticWeb层提供**：
- 完整浏览器体验
- JavaScript执行
- DOM操作和页面渲染
- 复杂的Web交互（登录、表单提交等）

**不是互斥关系，而是分层协作**：
- AgenticCLI提供安全、标准化的基础能力
- AgenticWeb构建在CLI之上，提供高级Web能力
- 两者共享相同的安全模型和权限体系

# AgenticWeb与AgenticCLI的调用关系设计

**核心原则：AgenticWeb应通过AgenticDSL标准化接口调用AgenticCLI，而非直接C++层调用**

## 一、架构设计原则

### 1.1 **分层解耦原则**
- **AgenticCLI**：提供标准化OS能力接口（`/lib/os/**`）
- **AgenticWeb**：作为独立扩展层，通过标准接口消费底层能力
- **清晰边界**：两层之间通过接口契约交互，而非内部实现细节

### 1.2 **权限统一原则**
- 所有调用必须经过统一的权限验证
- 避免"后门"调用绕过安全检查
- 保持完整的审计轨迹

### 1.3 **演进兼容原则**
- 独立版本控制：AgenticWeb v1.0 可以使用 AgenticCLI v2.0
- 接口兼容性优先于性能优化
- 避免因内部重构导致的上层失效

## 二、具体调用方式

### 2.1 **不推荐：直接C++层调用（紧耦合）**
```cpp
// ❌ 不推荐：直接内部调用，绕过安全边界
class BadWebRenderer {
private:
    // 直接持有CLI内部对象
    AgenticCLI::Internal::HttpClient* internal_client;
    
public:
    WebResult renderPage(const std::string& url) {
        // 直接调用内部实现，绕过权限检查
        auto response = internal_client->rawHttpGet(url); // ⚠️ 安全风险！
        return processHtml(response);
    }
};
```

**问题**：
- 绕过权限验证和资源限制
- 无法追踪审计
- 版本升级时容易断裂
- 无法应用统一的安全策略

### 2.2 **推荐：通过AgenticDSL标准化接口调用**
```cpp
// ✅ 推荐：通过标准接口调用
class WebRenderer {
private:
    // 仅依赖接口，不依赖内部实现
    std::shared_ptr<AgenticCLI::IToolRegistry> tool_registry;
    
public:
    WebResult renderPage(const ExecutionContext& ctx, const std::string& url) {
        // 1. 创建标准化调用上下文
        ExecutionContext web_ctx = ctx.clone();
        web_ctx.setTool("lib/web/page_load@v1");
        
        // 2. 通过标准接口调用网络功能
        AgResult http_result = tool_registry->executeTool(
            web_ctx,
            "/lib/os/net/http_get@v1", // 标准化接口
            {{"url", url}}
        );
        
        // 3. 结果处理（仍在安全上下文中）
        if (http_result.type != AgResultType::SUCCESS) {
            throw WebException("Failed to fetch page: " + http_result.message);
        }
        
        std::string html = http_result.data["body"].get<std::string>();
        return processHtmlSafely(html);
    }
};
```

## 三、实现架构详解

### 3.1 **接口调用流程**
```
+---------------------+    +---------------------+    +---------------------+
|   AgenticWeb Layer  |    |  AgenticDSL Layer   |    |  AgenticCLI Layer   |
+---------------------+    +---------------------+    +---------------------+
| 1. 请求web/page_load| -> | 2. 解析DSL规范      | -> | 3. 验证权限         |
|                     |    |                     |    |    • web:page_load  |
|                     |    |                     |    |    • os:net:http    |
+---------------------+    +---------------------+    +---------------------+
                                                           |
                                                           v
+---------------------+    +---------------------+    +---------------------+
|   AgenticWeb Layer  | <- |  AgenticDSL Layer   | <- | 4. 调用os/net/http_get|
| 5. 处理响应结果     |    |                     |    |    • 安全沙箱执行   |
|    • DOM解析        |    |                     |    |    • 资源限制       |
|    • JavaScript执行 |    |                     |    |    • 审计记录       |
+---------------------+    +---------------------+    +---------------------+
```

### 3.2 **具体代码实现**

#### 3.2.1 C++层工具注册（AgenticCLI）
```cpp
// src/cli/tool_registry.cpp
namespace agentic_cli {

class ToolRegistry : public IToolRegistry {
private:
    std::unordered_map<std::string, ToolHandler> tools_;
    
public:
    void registerTool(const std::string& name, ToolHandler handler) {
        tools_[name] = handler;
    }
    
    AgResult executeTool(const ExecutionContext& ctx, 
                        const std::string& tool_name,
                        const nlohmann::json& args) override {
        // 1. 权限验证
        if (!ctx.hasPermission(tool_name)) {
            return {AgResultType::ERROR, "ERR_PERMISSION_DENIED", {}};
        }
        
        // 2. 资源预算检查
        if (!ctx.checkResourceBudget(tool_name)) {
            return {AgResultType::ERROR, "ERR_RESOURCE_LIMIT_EXCEEDED", {}};
        }
        
        // 3. 执行工具，自动审计
        auto start_time = std::chrono::steady_clock::now();
        auto result = tools_[tool_name](ctx, args);
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time
        );
        
        // 4. 记录审计日志
        audit_log_.record(tool_name, args, result, duration);
        
        return result;
    }
};

// 注册网络工具
void registerStdOsNetTools(ToolRegistry& registry) {
    registry.registerTool("/lib/os/net/http_get@v1", [](const ExecutionContext& ctx, const nlohmann::json& args) {
        // 实际的HTTP GET实现
        return os_net_http_get(ctx, args);
    });
    
    registry.registerTool("/lib/os/net/http_post@v1", [](const ExecutionContext& ctx, const nlohmann::json& args) {
        // HTTP POST实现
        return os_net_http_post(ctx, args);
    });
}
}
```

#### 3.2.2 AgenticWeb的工具实现
```cpp
// src/web/web_tools.cpp
namespace agentic_web {

// 注册Web工具，这些工具内部会调用CLI的标准接口
void registerWebTools(agentic_cli::IToolRegistry& registry) {
    registry.registerTool("/lib/web/page_load@v1", [](const ExecutionContext& ctx, const nlohmann::json& args) {
        return web_page_load(ctx, args);
    });
    
    registry.registerTool("/lib/web/form_fill@v1", [](const ExecutionContext& ctx, const nlohmann::json& args) {
        return web_form_fill(ctx, args);
    });
}

// Web工具的具体实现
AgResult web_page_load(const ExecutionContext& ctx, const nlohmann::json& args) {
    if (!args.contains("url") || !args["url"].is_string()) {
        return {AgResultType::ERROR, "ERR_INVALID_INPUT: 'url' required", {}};
    }
    
    std::string url = args["url"].get<std::string>();
    
    // ✅ 通过标准接口调用CLI能力，而非直接C++调用
    AgResult http_result = ctx.tool_registry->executeTool(
        ctx,
        "/lib/os/net/http_get@v1",  // 标准化接口名称
        {
            {"url", url},
            {"headers", args.contains("headers") ? args["headers"] : nlohmann::json::object()}
        }
    );
    
    if (http_result.type != AgResultType::SUCCESS) {
        return http_result;
    }
    
    // 处理HTML内容（可能需要JS执行）
    std::string html = http_result.data["body"].get<std::string>();
    
    // 如果需要JavaScript执行，再调用另一个标准接口
    if (args.contains("execute_js") && args["execute_js"].get<bool>()) {
        return execute_javascript_in_sandbox(ctx, html, args);
    }
    
    return {AgResultType::SUCCESS, "OK", {{"html", html}}};
}

AgResult execute_javascript_in_sandbox(const ExecutionContext& ctx, 
                                      const std::string& html,
                                      const nlohmann::json& args) {
    // ✅ 再次通过标准接口调用，保持安全边界
    return ctx.tool_registry->executeTool(
        ctx,
        "/lib/web/js_execute@v1",  // Web层的标准接口
        {
            {"html", html},
            {"scripts", args["scripts"]}
        }
    );
}
}
```

### 3.3 **DSL层面的调用示例**
```yaml
### /lib/web/page_load@v1 的DSL实现
signature:
  inputs:
    - name: url
      type: string
      required: true
    - name: execute_js
      type: boolean
      default: true
    - name: wait_for_selector
      type: string
      required: false
  outputs:
    - name: html
      type: string
    - name: screenshots
      type: array
      items:
        type: string  # base64编码的图片
  permissions:
    - os:net:http    # 依赖CLI的网络权限
    - web:javascript # Web特有的权限
    - web:screenshot
resources:
  - type: runtime
    name: browser_sandbox
    memory_mb: 256
    cpu_ms: 5000
nodes:
  - id: fetch_html
    type: tool_call
    tool: /lib/os/net/http_get@v1  # ✅ 通过标准接口调用CLI
    arguments:
      url: "{{ $.url }}"
      headers:
        User-Agent: "AgenticWeb/1.0"
    output_mapping:
      html_content: "result.body"
    next: "decide_js_execution"
    
  - id: decide_js_execution
    type: switch
    condition: "{{ has_javascript($.html_content) && $.execute_js }}"
    cases:
      true: "execute_js"
      false: "process_dom"
      
  - id: execute_js
    type: tool_call
    tool: /lib/web/js_execute@v1  # Web层内部工具
    arguments:
      html: "{{ $.html_content }}"
      wait_for: "{{ $.wait_for_selector }}"
    output_mapping:
      final_html: "result.html"
      screenshots: "result.screenshots"
    next: "end"
    
  - id: process_dom
    type: assign
    assign:
      final_html: "{{ $.html_content }}"
      screenshots: []
    next: "end"
```

## 四、性能优化策略

### 4.1 **内部优化，保持接口不变**
```cpp
// 优化1：工具引用缓存
class WebRendererOptimized {
private:
    std::weak_ptr<agentic_cli::IToolRegistry> tool_registry_;
    std::shared_ptr<agentic_cli::ITool> http_get_tool_; // 缓存工具引用
    
public:
    void init(std::shared_ptr<agentic_cli::IToolRegistry> registry) {
        tool_registry_ = registry;
        // 缓存常用工具
        http_get_tool_ = registry->getTool("/lib/os/net/http_get@v1");
    }
    
    AgResult optimizedPageLoad(const ExecutionContext& ctx, const std::string& url) {
        if (!http_get_tool_) {
            // 重新获取（如果缓存失效）
            auto registry = tool_registry_.lock();
            if (!registry) return {AgResultType::ERROR, "ERR_REGISTRY_DESTROYED", {}};
            http_get_tool_ = registry->getTool("/lib/os/net/http_get@v1");
        }
        
        // 仍然通过标准接口调用，但减少查找开销
        return http_get_tool_->execute(ctx, {{"url", url}});
    }
};
```

### 4.2 **批量操作优化**
```cpp
// 优化2：批量网络请求
AgResult batch_fetch_urls(const ExecutionContext& ctx, const std::vector<std::string>& urls) {
    // 通过单个工具调用执行批量操作，减少上下文切换
    return ctx.tool_registry->executeTool(
        ctx,
        "/lib/os/net/http_batch_get@v1",  // 批量版本的接口
        {{"urls", urls}}
    );
}
```

### 4.3 **异步执行支持**
```cpp
// 优化3：异步接口
class AsyncWebRenderer {
public:
    // 异步版本，但仍然通过标准接口
    std::future<AgResult> asyncPageLoad(const ExecutionContext& ctx, const std::string& url) {
        return std::async(std::launch::async, [this, ctx, url]() {
            return ctx.tool_registry->executeTool(
                ctx,
                "/lib/os/net/http_get@v1",
                {{"url", url}}
            );
        });
    }
};
```

## 五、安全边界维护

### 5.1 **权限继承与限制**
```cpp
ExecutionContext createWebContext(const ExecutionContext& parent) {
    ExecutionContext web_ctx = parent.clone();
    
    // Web层有自己的权限范围，不能超越父上下文
    web_ctx.limitPermissions({
        "os:net:http",    // 仅允许HTTP请求
        "web:javascript", // 允许JS执行
        "web:dom_read"    // 仅允许读取DOM，不允许修改
    });
    
    // 资源限制更严格
    web_ctx.setResourceBudget({
        {"time_ms", 3000},    // 3秒超时
        {"memory_mb", 128},   // 128MB内存
        {"network_bytes", 10 * 1024 * 1024} // 10MB网络流量
    });
    
    return web_ctx;
}
```

### 5.2 **审计与监控**
```cpp
// 所有调用都经过审计，包括Web层对CLI的调用
class AuditingToolRegistry : public IToolRegistry {
private:
    IToolRegistry* base_registry_;
    AuditLogger audit_logger_;
    
public:
    AgResult executeTool(const ExecutionContext& ctx, 
                        const std::string& tool_name,
                        const nlohmann::json& args) override {
        // 记录调用链
        audit_logger_.logCallStack(ctx.getCallStack());
        
        // 检查是否是Web层调用
        if (ctx.getCallStack().contains("/lib/web/**")) {
            audit_logger_.logWebToCliCall(tool_name, args);
            
            // 额外安全检查
            if (!isWebSafeTool(tool_name)) {
                return {AgResultType::ERROR, "ERR_WEB_UNSAFE_TOOL", {}};
            }
        }
        
        return base_registry_->executeTool(ctx, tool_name, args);
    }
    
private:
    bool isWebSafeTool(const std::string& tool_name) {
        // Web层只能调用白名单中的安全工具
        static const std::unordered_set<std::string> web_safe_tools = {
            "/lib/os/net/http_get@v1",
            "/lib/os/net/http_post@v1",
            "/lib/os/fs/read@v1",      // 仅读取
            "/lib/os/crypto/hash@v1"
        };
        return web_safe_tools.find(tool_name) != web_safe_tools.end();
    }
};
```

## 六、总结与建议

### 6.1 **架构决策**
- ✅ **AgenticWeb必须通过AgenticDSL标准化接口调用AgenticCLI**
- ❌ **禁止直接C++层调用内部实现**
- 🔒 **保持统一的权限验证和审计机制**

### 6.2 **实现建议**
1. **接口设计**：
   - 为Web层定义清晰的工具接口 (`/lib/web/**`)
   - 这些接口内部通过标准方式调用CLI能力 (`/lib/os/**`)

2. **安全边界**：
   - Web层只能调用预定义的"安全"CLI工具
   - 不能直接访问文件系统、进程管理等高风险能力

3. **性能优化**：
   - 通过工具缓存、批量操作、异步执行优化性能
   - 但不破坏接口契约和安全边界

4. **演进策略**：
   - CLI层专注基础OS能力，保持稳定
   - Web层可以独立演进，通过标准接口消费CLI能力
   - 两者通过语义化版本控制解耦

### 6.3 **最终架构图**
```
+-------------------------------------------------+
|                Application Layer                |
|  • User Scripts • Custom Tools • Integrations   |
+-------------------------------------------------+
|               AgenticWeb Layer                  |
|  • /lib/web/browser@v1 • /lib/web/form_fill@v1 |
|  • Calls /lib/os/** via standard interfaces     |
+-------------------------------------------------+
|               AgenticCLI Layer                  |
|  • /lib/os/fs/read@v1 • /lib/os/net/http_get@v1|
|  • Core execution engine • Security framework   |
+-------------------------------------------------+
|               OS Primitive Layer                |
|  • File System • Network Stack • Process Mgmt   |
+-------------------------------------------------+
```

通过这种设计，AgenticWeb既获得了AgenticCLI的安全基础能力，又保持了架构的清晰和可维护性。标准接口调用方式确保了安全边界的完整性，同时通过内部优化保持了性能竞争力。这种分层架构为未来的扩展（如AgenticDB、AgenticMobile等）建立了可复用的模式。


# 可视化界面与3D图形应用的架构设计：分层协作模式

**核心原则：AgenticCLI不应重复造轮子，而是作为智能协调层，与专业UI/3D框架协作**

## 一、架构定位与职责划分

### 1.1 **分层架构模型**
```
+-------------------------------------------------+
|              Application Layer                  |
|  • 完整应用 (数据可视化工具、3D设计软件等)       |
|  • 业务逻辑与用户体验                           |
+-------------------------------------------------+
|           Specialized Services Layer            |
|  • UI Service (Qt/WinUI/SwiftUI)                |
|  • 3D Graphics Service (Vulkan/DirectX/WebGL)   |
|  • Media Processing Service                     |
+-------------------------------------------------+
|              Agentic Integration Layer          |
|  • /lib/ui/** • /lib/graphics/** • /lib/media/**|
|  • 标准化接口 • 安全边界 • 资源协调             |
+-------------------------------------------------+
|              AgenticCLI Core Layer             |
|  • 智能工作流编排 • 安全沙箱 • 能力协调         |
|  • /lib/os/** • /lib/reasoning/**              |
+-------------------------------------------------+
|               OS Primitive Layer               |
|  • 文件系统 • 网络 • GPU驱动 • 系统服务         |
+-------------------------------------------------+
```

### 1.2 **职责明确划分**
| 层级 | 负责内容 | 不负责内容 | 技术栈 |
|------|----------|------------|--------|
| **Application** | 业务价值、用户体验 | 底层渲染、安全沙箱 | 业务代码、领域知识 |
| **Specialized Services** | 专业能力实现 (UI渲染、3D处理) | 工作流编排、权限管理 | Qt、OpenGL、Vulkan等 |
| **Agentic Integration** | 标准化接口、安全边界、资源协调 | 具体实现细节、性能优化 | AgenticDSL、接口规范 |
| **AgenticCLI Core** | 智能代理、工作流引擎、安全框架 | 专业领域能力、UI交互 | C++核心、LLM集成 |

## 二、可视化UI界面的实现策略

### 2.1 **不推荐：UI框架完全重建在AgenticCLI上**
```cpp
// ❌ 反模式：在AgenticCLI内部重新实现UI框架
class BadUICore {
public:
    // 试图在CLI内部实现按钮、窗口等UI元素
    void createButton(const std::string& text) {
        // 重新实现UI框架的核心功能
        // ⚠️ 重复造轮子，性能差，生态孤立
    }
};
```

### 2.2 **推荐：专业UI框架 + AgenticDSL接口**
```cpp
// ✅ 正确模式：独立UI服务，通过标准化接口与CLI交互
class UIService {
private:
    std::shared_ptr<QtApplication> qt_app_;
    std::shared_ptr<AgenticCLI::IToolRegistry> cli_registry_;
    
public:
    void initialize() {
        // 1. 启动专业UI框架 (Qt)
        qt_app_ = std::make_shared<QtApplication>();
        
        // 2. 注册AgenticDSL接口
        cli_registry_->registerTool("/lib/ui/show_window@v1", 
            [this](const ExecutionContext& ctx, const nlohmann::json& args) {
                return this->showWindow(ctx, args);
            });
    }
    
    AgResult showWindow(const ExecutionContext& ctx, const nlohmann::json& args) {
        // 3. 权限验证
        if (!ctx.hasPermission("ui:window:create")) {
            return {AgResultType::ERROR, "ERR_PERMISSION_DENIED", {}};
        }
        
        // 4. 调用专业UI框架
        auto window = qt_app_->createWindow({
            .title = args["title"].get<std::string>(),
            .width = args["width"].get<int>(),
            .height = args["height"].get<int>(),
            .type = args.contains("type") ? args["type"].get<std::string>() : "standard"
        });
        
        // 5. 返回标准化结果
        return {AgResultType::SUCCESS, "OK", {
            {"window_id", window->getId()},
            {"visible", true}
        }};
    }
};
```

### 2.3 **DSL接口定义示例**
```yaml
### /lib/ui/show_chart@v1
signature:
  description: "显示数据可视化图表"
  inputs:
    - name: chart_type
      type: enum
      enum: ["line", "bar", "pie", "scatter", "3d_surface"]
      required: true
    - name: data
      type: object
      required: true
    - name: title
      type: string
      required: false
    - name: dimensions
      type: object
      properties:
        width: {type: integer, minimum: 100}
        height: {type: integer, minimum: 100}
      required: false
  outputs:
    - name: chart_id
      type: string
    - name: image_url
      type: string
      description: "生成的图表截图URL"
  permissions:
    - ui:chart:create
    - ui:screenshot
  resources:
    - type: gpu
      memory_mb: 64
      compute_units: 1
    - type: memory
      mb: 128
nodes:
  - id: validate_data
    type: assert
    condition: "{{ validate_chart_data($.data, $.chart_type) }}"
    on_failure: "error_invalid_data"
    
  - id: render_chart
    type: tool_call
    tool: /lib/graphics/render_chart@v1  # 调用3D/图形服务
    arguments:
      type: "{{ $.chart_type }}"
      data: "{{ $.data }}"
      options:
        title: "{{ $.title }}"
        dimensions: "{{ $.dimensions }}"
    output_mapping:
      chart_buffer: "result.buffer"
      chart_metadata: "result.metadata"
    next: "save_screenshot"
    
  - id: save_screenshot
    type: tool_call
    tool: /lib/os/fs/write@v1
    arguments:
      path: "/tmp/charts/{{ generate_uuid() }}.png"
      content: "{{ $.chart_buffer }}"
      encoding: "base64"
    output_mapping:
      image_path: "result.path"
    next: "generate_url"
```

## 三、3D图形应用的架构设计

### 3.1 **3D服务的独立性原则**
```cpp
// ✅ 3D引擎作为独立服务，不耦合到AgenticCLI核心
class GraphicsService {
private:
    // 专业3D引擎实例（Vulkan/DirectX/Metal）
    std::unique_ptr<IGraphicsEngine> engine_;
    
    // GPU资源管理
    GpuResourceManager gpu_manager_;
    
public:
    GraphicsService(const GraphicsConfig& config) {
        // 根据平台选择合适的3D引擎
        #ifdef _WIN32
        engine_ = std::make_unique<DirectXEngine>(config);
        #elif __APPLE__
        engine_ = std::make_unique<MetalEngine>(config);
        #else
        engine_ = std::make_unique<VulkanEngine>(config);
        #endif
    }
    
    // 提供标准化接口
    AgResult renderScene(const SceneDescription& scene, const RenderOptions& options) {
        // 1. 资源验证
        if (!gpu_manager_.checkResources(options)) {
            return {AgResultType::ERROR, "ERR_GPU_RESOURCES_EXCEEDED", {}};
        }
        
        // 2. 专业3D渲染
        RenderResult result = engine_->render(scene, options);
        
        // 3. 返回标准化结果
        return {AgResultType::SUCCESS, "OK", {
            {"buffer", result.frameBuffer},
            {"width", result.width},
            {"height", result.height},
            {"render_time_ms", result.renderTimeMs}
        }};
    }
};
```

### 3.2 **AgenticDSL 3D接口规范**
```yaml
### /lib/graphics/render_3d_scene@v1
signature:
  description: "渲染3D场景"
  inputs:
    - name: scene
      type: object
      properties:
        meshes: {type: array}
        lights: {type: array}
        camera: {type: object}
        materials: {type: array}
      required: true
    - name: viewport
      type: object
      properties:
        width: {type: integer, minimum: 100, maximum: 4096}
        height: {type: integer, minimum: 100, maximum: 4096}
      required: true
    - name: quality_preset
      type: enum
      enum: ["low", "medium", "high", "ultra"]
      default: "medium"
  outputs:
    - name: image_path
      type: string
    - name: performance_metrics
      type: object
  permissions:
    - graphics:3d:render
    - gpu:high_performance
  resources:
    - type: gpu
      memory_mb: 256  # 根据quality_preset动态调整
      compute_units: 4
    - type: memory
      mb: 512
nodes:
  - id: validate_scene
    type: assert
    condition: "{{ validate_3d_scene($.scene) }}"
    on_failure: "error_invalid_scene"
    
  - id: adjust_quality
    type: assign
    assign:
      actual_quality: "{{ calculate_quality($.quality_preset, $.resources.gpu.memory_mb) }}"
      actual_resolution: "{{ calculate_resolution($.viewport, $.actual_quality) }}"
    next: "call_graphics_service"
    
  - id: call_graphics_service
    type: tool_call
    tool: graphics_service_render  # 内部调用3D服务
    arguments:
      scene: "{{ $.scene }}"
      resolution: "{{ $.actual_resolution }}"
      quality: "{{ $.actual_quality }}"
      timeout_ms: 5000
    output_mapping:
      render_buffer: "result.buffer"
      metrics: "result.performance_metrics"
    next: "save_result"
    
  - id: save_result
    type: tool_call
    tool: /lib/os/fs/write@v1
    arguments:
      path: "/tmp/renders/{{ timestamp() }}.png"
      content: "{{ $.render_buffer }}"
      encoding: "base64"
    output_mapping:
      image_path: "result.path"
    next: "end"
```

## 四、跨平台实现策略

### 4.1 **平台特定实现的抽象**
```cpp
// ✅ 通过抽象接口统一不同平台的3D实现
class IGraphicsEngine {
public:
    virtual RenderResult render(const SceneDescription& scene, 
                               const RenderOptions& options) = 0;
    virtual GpuCapabilities getCapabilities() const = 0;
    virtual ~IGraphicsEngine() = default;
};

// 平台特定实现
#ifdef _WIN32
class DirectXEngine : public IGraphicsEngine {
    // Windows-specific DirectX implementation
};

#elif __APPLE__
class MetalEngine : public IGraphicsEngine {
    // Apple-specific Metal implementation
};

#else
class VulkanEngine : public IGraphicsEngine {
    // Cross-platform Vulkan implementation
};
#endif

// 运行时选择
std::unique_ptr<IGraphicsEngine> createGraphicsEngine(const PlatformConfig& config) {
    if (config.preferred_api == "directx" && isWindows()) {
        return std::make_unique<DirectXEngine>(config);
    } else if (config.preferred_api == "metal" && isApple()) {
        return std::make_unique<MetalEngine>(config);
    } else {
        return std::make_unique<VulkanEngine>(config);
    }
}
```

### 4.2 **AgenticDSL的平台无关性**
```yaml
### /lib/graphics/create_3d_model@v1
signature:
  platform_independent: true  # 标记为平台无关接口
  inputs:
    - name: geometry
      type: object
      platform_mappings:
        windows: "directx_geometry_format"
        macos: "metal_geometry_format"
        linux: "vulkan_geometry_format"
    - name: material
      type: object
  outputs:
    - name: model_id
      type: string
  # 平台特定的资源要求
  platform_resources:
    windows:
      - type: gpu
        memory_mb: 128
        features: ["directx12"]
    macos:
      - type: gpu
        memory_mb: 128
        features: ["metal2"]
    linux:
      - type: gpu
        memory_mb: 128
        features: ["vulkan1.2"]
```

## 五、性能与安全的平衡

### 5.1 **资源隔离策略**
```cpp
class GraphicsServiceManager {
private:
    // 每个服务实例独立的资源配额
    std::unordered_map<std::string, ResourceQuota> service_quotas_;
    
public:
    AgResult executeWithQuota(const std::string& service_id, 
                            const std::function<AgResult()>& task) {
        auto& quota = service_quotas_[service_id];
        
        // 1. 预检查资源
        if (!quota.canAllocate(ResourceType::GPU_MEMORY, 256)) {
            return {AgResultType::ERROR, "ERR_GPU_MEMORY_LIMIT", {}};
        }
        
        // 2. 设置执行上下文
        ExecutionContext ctx;
        ctx.setResourceLimits(quota.getCurrentLimits());
        ctx.setDeadline(std::chrono::milliseconds(5000));
        
        // 3. 在沙箱中执行
        SandboxGuard guard(ctx);
        auto result = task();
        
        // 4. 更新资源使用
        quota.updateUsage(guard.getResourceUsage());
        
        return result;
    }
};
```

### 5.2 **零拷贝数据传输优化**
```cpp
// 高性能数据传输，避免不必要的拷贝
class ZeroCopyDataManager {
public:
    // 创建共享内存区域
    SharedMemoryHandle createSharedBuffer(size_t size) {
        return os_create_shared_memory(size);
    }
    
    // 在服务间安全传输
    bool transferToGraphicsService(SharedMemoryHandle handle, 
                                 const SecurityContext& ctx) {
        // 验证权限
        if (!ctx.hasPermission("graphics:shared_memory")) {
            return false;
        }
        
        // 设置访问控制
        os_set_memory_acl(handle, ctx.getProcessId(), READ_ONLY);
        
        return true;
    }
    
    // DSL层使用示例
    AgResult renderLargeDataset(const nlohmann::json& args) {
        // 1. 创建共享内存
        auto handle = createSharedBuffer(args["data_size"].get<size_t>());
        
        // 2. 填充数据
        void* buffer = mapSharedMemory(handle);
        memcpy(buffer, args["data"].get_binary(), args["data_size"].get<size_t>());
        
        // 3. 传递句柄而非数据
        return graphics_service_->render({
            "shared_memory_handle": handle.getHandleValue(),
            "format": args["format"]
        });
    }
};
```

## 六、实际应用案例

### 6.1 **科学数据3D可视化**
```yaml
### /app/scientific_visualization
description: "科学数据3D可视化工作流"
nodes:
  - id: fetch_data
    type: tool_call
    tool: /lib/os/net/http_get@v1
    arguments:
      url: "https://data.example.com/simulation/results"
    output_mapping:
      raw_data: "json.parse(result.body)"
    next: "preprocess_data"
    
  - id: preprocess_data
    type: tool_call
    tool: /lib/reasoning/process_data@v1
    arguments:
      data: "{{ $.raw_data }}"
      operation: "convert_to_3d_voxels"
    output_mapping:
      voxel_data: "result.processed_data"
    next: "render_visualization"
    
  - id: render_visualization
    type: tool_call
    tool: /lib/graphics/render_volume@v1
    arguments:
      volume: "{{ $.voxel_data }}"
      colormap: "viridis"
      quality: "high"
      interactive: true
    output_mapping:
      visualization_id: "result.scene_id"
      preview_url: "result.preview_url"
    next: "show_ui"
    
  - id: show_ui
    type: tool_call
    tool: /lib/ui/show_window@v1
    arguments:
      title: "Scientific Visualization"
      content_type: "3d_viewer"
      content_data: 
        scene_id: "{{ $.visualization_id }}"
        controls: ["rotate", "zoom", "slice"]
      dimensions:
        width: 1200
        height: 800
    next: "end"
```

### 6.2 **架构组件关系图**
```
+---------------------+     +---------------------+     +---------------------+
|   Application UI    |<--->|  Agentic Integration|<--->|   3D Graphics       |
|  (Qt/WinUI/SwiftUI) |     |  Layer              |     |  Service            |
|                     |     |  • /lib/ui/**       |     |  • Vulkan/DirectX   |
|  User Interaction   |     |  • /lib/graphics/** |     |  • GPU Rendering    |
+---------------------+     +----------+----------+     +----------+----------+
                                          ^                         ^
                                          |                         |
                                          v                         v
+---------------------+     +---------------------+     +---------------------+
|   AgenticCLI Core   |<----+  Security &          +---->|  OS & Hardware      |
|  • Workflows        |     |  Resource Manager   |     |  • GPU Drivers      |
|  • LLM Integration  |     |  • Permission Check |     |  • System Services  |
|  • Sandboxing       |     |  • Quota Enforcement|     |                     |
+---------------------+     +---------------------+     +---------------------+
```

## 七、开发与部署策略

### 7.1 **多仓库协作模式**
```
agentic-ecosystem/
├── agentic-cli/              # 核心引擎
├── agentic-ui-service/       # UI服务 (跨平台)
│   ├── qt-backend/          # Qt实现
│   ├── winui-backend/       # Windows实现  
│   └── swiftui-backend/     # macOS/iOS实现
├── agentic-graphics-service/ # 3D图形服务
│   ├── vulkan-backend/      # Vulkan实现
│   ├── directx-backend/     # DirectX实现
│   └── metal-backend/       # Metal实现
└── applications/             # 具体应用
    ├── scientific-visualizer/
    └── 3d-design-tool/
```

### 7.2 **版本兼容策略**
```cpp
// 语义化版本控制，确保兼容性
class ServiceVersionManager {
public:
    bool isCompatible(const ServiceVersion& service_ver, 
                     const CliVersion& cli_ver) {
        // 主版本必须匹配
        if (service_ver.major != cli_ver.major) {
            return false;
        }
        
        // 服务版本不能低于CLI要求的最低版本
        if (service_ver < cli_ver.min_required_service_version) {
            return false;
        }
        
        // 检查API兼容性
        return checkApiCompatibility(service_ver.api_signature, 
                                    cli_ver.required_api_signature);
    }
};

// DSL接口版本控制
### /lib/graphics/render_3d_scene@v2
# v2版本添加了光线追踪支持，但保持向后兼容
signature:
  version: "2.0.0"
  deprecated_since: "3.0.0"  # 未来可能弃用
  compatibility:
    v1: "/lib/graphics/render_3d_scene@v1"
  new_features:
    - raytracing
    - global_illumination
```

## 八、总结与建议

### 8.1 **架构决策矩阵**
| 需求类型 | 推荐架构 | 理由 |
|---------|----------|------|
| **标准UI界面** | 独立UI服务 + AgenticDSL接口 | 专业UI框架更成熟，性能更好 |
| **2D数据可视化** | Agentic Integration Layer + 专用可视化库 | 平衡灵活性与性能 |
| **3D图形应用** | 独立3D服务 + 标准化接口 | 3D渲染需要专业引擎和GPU优化 |
| **实时交互应用** | 混合架构：核心逻辑在CLI，渲染在专用服务 | 低延迟要求需要专业优化 |

### 8.2 **关键实施原则**
1. **不要重复造轮子**：使用成熟的UI/3D框架，AgenticCLI专注协调
2. **接口标准化**：通过AgenticDSL定义清晰、版本化的接口
3. **安全第一**：严格隔离，权限验证，资源限制
4. **性能优化**：零拷贝传输，异步执行，GPU资源管理
5. **渐进式演进**：从简单接口开始，逐步扩展复杂功能

### 8.3 **未来演进路径**
- **短期**：建立标准化的`/lib/ui/**`和`/lib/graphics/**`接口
- **中期**：实现跨平台的UI/3D服务参考实现
- **长期**：构建完整的可视化生态系统，支持智能UI生成

**最终结论**：可视化和3D应用不应直接建立在AgenticCLI之上，而应通过标准化接口与其协作。AgenticCLI作为智能协调层，连接专业UI/3D服务，实现"专业的事交给专业的框架，智能的事交给AgenticCLI"的架构理念。这种分层协作模式既能利用现有生态，又能发挥AgenticCLI的智能编排优势。
