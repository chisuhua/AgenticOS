# AgenticWeb 架构设计文档 v1.0  

> **核心愿景**：让LLM成为计算机主人，同时确保人类保持最终监督权  
> **文档目标**：定义Web作为LLM交互原语的标准化架构，实现安全、高效、可审计的人机协同


AgenticWeb是AIOS生态系统的Web交互核心组件，通过标准化能力接口，使LLM能够以受控、安全的方式与Web内容交互。

---

## 一、核心定位与架构全景

### 1.1 在Agentic-ecosystem中的定位
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Agentic-ecosystem                               │
│                                                                             │
│  ┌─────────────────────────────────────┐    ┌─────────────────────────────┐  │
│  │           上层应用层                │    │        生态治理层           │  │
│  │ • 企业工作流 • 个人助手 • 智能应用  │    │ • 能力认证 • 价值分配       │  │
│  └───────────────────┬─────────────────┘    └───────────────┬─────────────┘  │
│                      │                                      │              │
│  ┌───────────────────▼──────────────────────────────────────▼─────────────┐  │
│  │                  智能体运行时层 (Runtime)                             │  │
│  │ ┌───────────────────────────────────────────────────────────────────┐ │  │
│  │ │                    能力抽象层 (Capabilities)                      │ │  │
│  │ │                                                                   │ │  │
│  │ │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐   │ │  │
│  │ │  │  AgenticWeb  │  │  AgenticCLI  │  │   Agentic3D/AgenticVoice│   │ │  │
│  │ │  │ (本组件)     │◄─┼─►(/lib/os/**)│◄─┼─►(其他模态能力提供者)   │   │ │  │
│  │ │  └───────┬──────┘  └──────────────┘  └─────────────────────────┘   │ │  │
│  │ │          │                                                         │ │  │
│  │ │  ┌───────▼─────────────────────────────────────────────────────┐   │ │  │
│  │ │  │                      AIOS内核                               │   │ │  │
│  │ │  │ • 能力注册表 • 安全沙箱 • 资源调度器 • 上下文管理器         │   │ │  │
│  │ │  └─────────────────────────────────────────────────────────────┘   │ │  │
│  │ └───────────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**精准定位声明**：
- ✅ **核心角色**：Web交互能力提供者，非执行引擎
- ✅ **命名空间**：提供 `/lib/modal/web/**` 标准化原子能力（v2.0起更名为模态统一命名）
- ✅ **交互边界**：通过AIOS内核与生态其他组件交互
- ✅ **安全边界**：所有Web操作在强化沙箱中执行，权限严格受限
- ❌ **不负责**：DAG调度/LLM生成逻辑/非Web模态渲染
- ❌ **不暴露**：原始DOM API/浏览器内核细节/未沙箱化的JS执行

### 1.2 核心设计原则
| 原则 | 说明 | 实现机制 |
|------|------|----------|
| **模态统一** | Web是多模态生态的一部分 | 遵循USD-like统一场景描述标准 |
| **契约优先** | 所有能力接口明确定义 | 强制signature，完整JSON Schema |
| **沙箱强化** | 最小权限，防御纵深 | 五层沙箱架构，权限交集验证 |
| **可验证性** | 所有操作可追溯验证 | 完整Trace，DOM快照，预期输出比对 |
| **资源感知** | Web操作纳入全局预算 | 资源计量模型，动态降级策略 |
| **人机协同** | 关键操作保留人类监督 | 审批工作流，渐进式自动化 |
| **结构化接口**| 所有交互通过严格类型化的AgenticDSL接口 ||
| **渐进式自动化**| 从建议→辅助→自动化，逐步提升自动化级别 ||

---

## 二、核心架构设计

### 2.1 整体架构
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               AgenticWeb 架构                              │
│                                                                             │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────────────────┐  │
│  │ 能力提供层   │  │  安全控制层      │  │  浏览器内核集成层             │  │
│  │(标准库能力)  │  │(权限/预算/审计)  │  │(渲染/事件/网络)              │  │
│  └───────┬──────┘  └────────┬─────────┘  └───────────────┬───────────────┘  │
│          │                 │                            │                │
│  ┌───────▼─────────────────▼────────────────────────────▼───────────────┐  │
│  │                     Web能力执行上下文                               │  │
│  │ • 能力路由 • 参数验证 • 结果标准化 • 异常处理 • 资源计量             │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│          ▲                                  ▲                           │
│          │                                  │                           │
│  ┌───────┴─────────────────┐    ┌───────────┴───────────────────────────┐  │
│  │  AIOS内核接口           │    │  生态系统接口                        │  │
│  │ • 能力注册 • 权限验证   │    │ • 多模态同步 • 价值计量 • 事件总线    │  │
│  └─────────────────────────┘    └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                       AIOS 核心                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                   AgenticWeb v0                              │  │
│  │                                                                               │  │
│  │  ┌───────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                           人机协同层 (/lib/human/web/**)                 │  │  │
│  │  │ • 人类审批工作流 • 意图澄清 • 偏好学习 • 恢复协助                         │  │  │
│  │  └───────────────────────────────────┬───────────────────────────────────────┘  │  │
│  │                                      │                                          │  │
│  │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │  │
│  │  │                        交互语义层 (/lib/interaction/web/**)              │  │  │
│  │  │ • 意图驱动交互 • 跨模态协调 • 状态同步 • 事件桥接                         │  │  │
│  │  └───────────────────────────────────┬───────────────────────────────────────┘  │  │
│  │                                      │                                          │  │
│  │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │  │
│  │  │                           UI组件层 (/lib/modal/web/ui/**)                │  │  │
│  │  │ • 安全对话框 • 表单组件 • 通知系统 • 数据可视化                           │  │  │
│  │  └───────────────────────────────────┬───────────────────────────────────────┘  │  │
│  │                                      │                                          │  │
│  │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │  │
│  │  │                          DOM原语层 (/lib/modal/web/dom/**)               │  │  │
│  │  │ • 元素查询 • 安全操作 • 事件监听 • 布局计算                               │  │  │
│  │  └───────────────────────────────────┬───────────────────────────────────────┘  │  │
│  │                                      │                                          │  │
│  │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │  │
│  │  │                           沙箱层 (五层安全架构)                          │  │  │
│  │  │ • DOM隔离 • 执行隔离 • 资源计量 • 安全验证 • 人类监督                      │  │  │
│  │  └───────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                      │                                          │  │
│  └──────────────────────────────────────┼──────────────────────────────────────────┘  │
│                                         │                                             │
│  ┌──────────────────────────────────────▼─────────────────────────────────────────┐  │
│  │                             Web平台 (浏览器/DOM)                              │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 能力分层模型
| 层级 | 路径 | 职责 | 示例 |
|------|------|------|------|
| 0. 硬件抽象层 | `/lib/os/**` (AgenticCLI) | 原始设备访问 | `/lib/os/network/fetch` |
| 1. 模态基础层 | `/lib/modal/web/**` | Web原语抽象 | `/lib/modal/web/dom/element` |
| 2. DOM原语层 | | `/lib/modal/web/dom/query@v1`, `/lib/modal/web/dom/click@v1` |基础DOM安全操作|
| 3. 交互语义层 | `/lib/interaction/web/**` | 意图驱动交互 | `/lib/interaction/web/focus`, `/lib/interaction/web/content/present@v1`, `/lib/interaction/web/input/collect@v1` |
| 4. 应用组装层 | `/app/web/**` | 业务逻辑组合 | `/app/web/data_dashboard` |
| 5. 模态协同层 | `/lib/modal/cross/**` | 跨模态协作 | `/lib/modal/cross/web_3d_bridge` |
| 6. 人机协同层 | `/lib/human/web/approval_flow@v1`, `/lib/human/web/explanation_request@v1` | 人机交互高级语义| 
| 7. UI组件层 | | `/lib/modal/web/ui/dialog@v1`, `/lib/modal/web/ui/form@v1` |安全UI组件提供 |

> **架构铁律**：禁止在4-7层直接调用0层，所有跨层调用必须通过能力注册表验证完整委托链

### 2.3 核心组件设计
#### 2.3.1 能力注册中心
```cpp
// AgenticWeb能力注册示例
void register_web_capabilities(CapabilityRegistry& registry) {
  // DOM元素查询能力
  registry.register_capability("/lib/modal/web/dom/query@v1", {
    .description = "安全查询DOM元素内容",
    .signature = {
      .inputs = {
        {"selector", "string", "CSS选择器，必须符合安全策略"},
        {"max_elements", "integer", "最大返回元素数", 10}
      },
      .outputs = {
        {"elements", "array", "匹配的元素列表"},
        {"execution_time_ms", "number", "执行耗时"}
      }
    },
    .permissions = {"web_dom:read"},
    .resource_model = {
      .cpu_ms = "5 + 0.1 * element_count",
      .memory_mb = "1 + 0.01 * text_content_size_kb"
    },
    .executor = [](const CapabilityParams& params, 
                  const SecurityContext& ctx) -> CapabilityResult {
      return WebDOM::safe_query(params, ctx);
    },
    .modal_metadata = {
      .primary_input_modality = "visual",
      .primary_output_modality = "structured_data",
      .accessibility_level = "WCAG-AA"
    }
  });
  
  // UI对话框能力
  registry.register_capability("/lib/interaction/web/dialog@v1", {
    // ... 完整元数据
  });
}
```

#### 2.3.2 五层沙箱架构
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               Web沙箱架构                                  │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │  DOM隔离层   │  │  事件过滤层  │  │  资源限制层  │  │  网络代理层     │  │
│  │ • Shadow DOM │  │ • 事件白名单 │  │ • CPU/内存   │  │ • CORS策略      │  │
│  │ • 权限边界   │  │ • XSS防护    │  │ • 渲染预算   │  │ • 域名白名单    │  │
│  └───────┬──────┘  └───────┬──────┘  └───────┬──────┘  └────────┬────────┘  │
│          │                │                │                  │         │
│  ┌───────▼────────────────▼────────────────▼──────────────────▼───────┐  │
│  │                      能力策略引擎                                 │  │
│  │ • 权限交集验证 • 能力委托链检查 • 敏感数据过滤 • 审计日志生成       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│          ▲                                  ▲                           │
│          │                                  │                           │
│  ┌───────┴─────────────────┐    ┌───────────┴───────────────────────────┐  │
│  │  安全上下文             │    │  执行上下文                          │  │
│  │ • 用户身份 • 设备信息   │    │ • DAG状态 • 资源预算 • 调用链        │  │
│  └─────────────────────────┘    └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**沙箱策略示例**：
```json
{
  "sandbox_profile": {
    "dom_isolation": {
      "shadow_root_mode": "closed",
      "allowed_attributes": ["id", "class", "data-*"],
      "blocked_attributes": ["on*", "href", "src"]
    },
    "event_filtering": {
      "allowed_events": ["click", "input", "change"],
      "sensitive_event_audit": true,
      "user_gesture_required": ["clipboard", "fullscreen"]
    },
    "network_policy": {
      "allowed_domains": ["api.example.com", "cdn.example.com"],
      "response_sanitization": true,
      "max_request_size_kb": 1024
    }
  }
}
```
##### 层1: DOM隔离
- **技术选型**：Shadow DOM v2 + Trusted Types API
- **关键实现**：
```javascript
// 创建安全隔离上下文
const createSecureContext = () => {
  const secureRoot = document.createElement('div');
  document.body.appendChild(secureRoot);
  
  // 创建Trusted Types策略
  const ttPolicy = trustedTypes.createPolicy('agenticweb-safe', {
    createHTML: (string, context) => {
      // 严格HTML净化
      return sanitizeHTML(string, context);
    },
    createScriptURL: (url) => {
      // 严格URL验证
      if (!isSafeURL(url)) {
        logSecurityViolation(`Blocked unsafe script URL: ${url}`);
        return 'about:blank';
      }
      return url;
    }
  });

  // 创建Shadow Root
  const shadow = secureRoot.attachShadow({ 
    mode: 'closed',
    delegatesFocus: false
  });

  // 代理DOM API
  return new Proxy(shadow, {
    get(target, prop) {
      if (prop === 'querySelector' || prop === 'querySelectorAll') {
        return (selector) => {
          // 选择器验证
          if (!isValidSelector(selector)) {
            logSecurityViolation(`Blocked invalid selector: ${selector}`);
            return null;
          }
          return Reflect.apply(target[prop], target, [selector]);
        };
      }
      return Reflect.get(target, prop);
    }
  });
};
```

##### 层2: 执行上下文隔离
- **技术选型**：Web Worker + WebAssembly + CSP v3
- **关键实现**：
```http
Content-Security-Policy: 
  default-src 'none';
  script-src 'wasm-unsafe-eval' 'strict-dynamic' https://trusted.agenticweb.cdn;
  style-src 'self' 'unsafe-hashes' 'sha256-abc123...';
  sandbox allow-same-origin allow-scripts;
  require-trusted-types-for 'script';
  report-uri /csp-report-endpoint;
```

```javascript
// 安全执行上下文
class SecureExecutionContext {
  constructor() {
    this.worker = new Worker('/lib/security/execution_worker.js', {
      type: 'module',
      credentials: 'same-origin'
    });
    
    // 设置资源限制
    this.worker.postMessage({
      type: 'SET_RESOURCE_LIMITS',
      limits: {
        executionTimeMs: 5000,
        memoryMb: 100,
        domOperations: 1000
      }
    });
  }
  
  execute(codestring, context) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.worker.terminate();
        reject(new Error('Execution timeout exceeded'));
      }, 5000);
      
      this.worker.onmessage = (event) => {
        clearTimeout(timeout);
        if (event.data.error) {
          reject(event.data.error);
        } else {
          resolve(event.data.result);
        }
      };
      
      this.worker.postMessage({
        type: 'EXECUTE',
        code: codestring,
        context: this.sanitizeContext(context)
      });
    });
  }
  
  sanitizeContext(context) {
    // 深度净化上下文对象
    return JSON.parse(JSON.stringify(context), (key, value) => {
      if (typeof value === 'function') return '[FUNCTION]';
      if (value instanceof Node) return '[DOM_NODE]';
      return value;
    });
  }
}
```

##### 层3: 资源计量
- **技术选型**：Performance API + Resource Timing API
- **关键实现**：
```javascript
class ResourceMeter {
  constructor() {
    this.metrics = {
      cpuMs: 0,
      memoryMb: 0,
      networkBytes: 0,
      domOperations: 0,
      layoutForced: 0
    };
    this.start = performance.now();
    this.memoryStart = performance.memory?.usedJSHeapSize || 0;
  }
  
  countOperation(type, cost) {
    switch(type) {
      case 'dom_access':
        this.metrics.domOperations += 1;
        this.metrics.cpuMs += cost || 0.1;
        break;
      case 'layout_forced':
        this.metrics.layoutForced += 1;
        this.metrics.cpuMs += 10; // 布局强制代价高
        break;
      case 'network_request':
        this.metrics.networkBytes += cost || 1000;
        this.metrics.cpuMs += 5;
        break;
      default:
        this.metrics.cpuMs += cost || 1;
    }
  }
  
  getMetrics() {
    const elapsed = performance.now() - this.start;
    const memoryUsage = (performance.memory?.usedJSHeapSize || 0) - this.memoryStart;
    
    return {
      ...this.metrics,
      totalTimeMs: elapsed,
      memoryMb: memoryUsage / (1024 * 1024),
      timestamp: new Date().toISOString()
    };
  }
  
  enforceBudget(budget) {
    const metrics = this.getMetrics();
    const violations = [];
    
    if (metrics.cpuMs > budget.cpuMs) violations.push('cpu');
    if (metrics.memoryMb > budget.memoryMb) violations.push('memory');
    if (metrics.domOperations > budget.domOperations) violations.push('dom');
    
    if (violations.length > 0) {
      throw new Error(`Resource budget exceeded: ${violations.join(', ')}`);
    }
    
    return metrics;
  }
}
```


---

## 三、与其他生态模块的接口

### 3.1 与AgenticCLI (/lib/os/**) 的接口

#### 3.1.1 依赖接口（AgenticWeb → AgenticCLI）
| 能力路径 | 用途 | 权限映射 | 资源计量 |
|----------|------|----------|----------|
| `/lib/os/network/fetch@v1` | 网络请求 | `web_network:fetch` → `os_network:fetch` | 合并网络带宽预算 |
| `/lib/os/file/read@v1` | 读取本地文件 | `web_file:read` → `os_file:read` | 合并IO预算 |
| `/lib/os/time/get@v1` | 获取时间 | `web_time:get` → `os_time:get` | 无额外开销 |
| `/lib/os/process/spawn@v1` | 启动子进程 | 仅限特权Web Worker | 独立CPU预算 |

**接口契约**：
```agenticdsl
### AgenticDSL '/lib/modal/web/network/fetch@v1'
signature:
  inputs:
    - name: url
      type: string
      validation: "must_match_domain_whitelist"
    - name: method
      type: string
      enum: ["GET", "POST"]
    - name: body_schema
      type: object
      description: "请求体JSON Schema，用于LLM生成验证"
  outputs:
    - name: response
      type: object
      schema: {
        "type": "object",
        "properties": {
          "status": {"type": "integer"},
          "headers": {"type": "object"},
          "body": {"type": "string"}
        }
      }
  dependencies:
    - capability: "/lib/os/network/fetch@v1"
      permission_mapping: {
        "web_network:fetch": ["os_network:fetch", "os_network:headers_read"]
      }
      resource_aggregation: {
        "network_mb": "base + 0.1 * response_size_mb"
      }
```

#### 3.1.2 委托执行流程
```
1. AgenticWeb接收能力请求
2. 验证Web层权限（web_network:fetch）
3. 构建安全参数（过滤敏感头，限制域名）
4. 调用AgenticCLI能力（/lib/os/network/fetch）
5. 传递映射后权限（os_network:fetch + os_network:headers_read）
6. AgenticCLI执行并返回结果
7. AgenticWeb过滤敏感响应头
8. 返回标准化结果
```

#### 3.1.3 资源预算协同
```cpp
// 资源预算协同示例
ResourceBudget::register_consumer("/lib/modal/web/network/fetch", 
  [](const CapabilityParams& params, const ResourceContext& ctx) {
    // 从AgenticCLI获取基础资源模型
    auto base_budget = AgenticCLI::get_resource_model("/lib/os/network/fetch");
    
    // 添加Web层额外开销
    return ResourceEstimate{
      .network_mb = base_budget.network_mb + estimate_response_size(params["url"]),
      .cpu_ms = base_budget.cpu_ms + 2,  // DOM解析开销
      .security_level = "medium"  // 影响沙箱强度
    };
  });
```

### 3.2 与AIOS内核的接口

#### 3.2.1 能力注册接口
```cpp
// 向AIOS内核注册Web能力
AiosKernel::register_capability_provider("web", {
  .provider_metadata = {
    .version = "2.0",
    .compatibility = "agenticdsl_v3.9+",
    .required_apis = ["aios_kernel_v1.2"]
  },
  .init_function = [](const KernelContext& ctx) {
    // 初始化Web引擎
    WebEngine::initialize(ctx.config.get("web_engine"));
    
    // 注册所有Web能力
    register_web_capabilities(ctx.capability_registry);
    
    // 注册事件监听器
    ctx.event_bus.subscribe("aios.lifecycle.suspend", 
      [](const Event& e) { WebEngine::suspend(); });
  },
  .shutdown_function = WebEngine::shutdown,
  .health_check = WebEngine::health_check
});
```

#### 3.2.2 安全上下文共享
| 上下文字段 | 来源 | 用途 |
|------------|------|------|
| `security.user_identity` | AIOS内核 | 权限决策基础 |
| `security.device_profile` | AIOS内核 | 能力降级决策 |
| `budget.tokens_left` | AIOS内核 | LLM调用预算控制 |
| `state.shared_context` | AIOS内核 | 跨能力状态共享 |
| `modal.current_modality` | AIOS内核 | 自适应UI渲染 |

**上下文合并策略**：
```agenticdsl
### AgenticDSL '/lib/modal/web/context/merge@v1'
type: assign
assign:
  expr: "{{ merge_context($.web_local_state, $.aios_global_state, 'deep_merge') }}"
  path: "web_merged_context"
context_merge_policy:
  - path: "user.preferences.*"
    strategy: "last_write_wins"  # 用户偏好以最后设置为准
  - path: "system.settings.*"
    strategy: "error_on_conflict"  # 系统设置冲突必须报错
```

### 3.3 与多智能体协作框架的接口

#### 3.3.1 角色能力声明
```agenticdsl
### AgenticDSL '/__meta__/agent_role'
role_contract:
  role_id: "web_interaction_specialist"
  capabilities:
    - "/lib/modal/web/dom/query@v1"
    - "/lib/interaction/web/dialog@v1"
    - "/lib/interaction/web/form/validate@v1"
  trust_level: "verified"
  conflict_resolution:
    - when: "concurrent_dom_write"
      strategy: "timestamp_based"
      tiebreaker: "user_input_priority"
  contribution_metrics:
    - metric: "user_interaction_success_rate"
      weight: 0.6
    - metric: "dom_operation_efficiency"
      weight: 0.4
```

#### 3.3.2 事件总线集成
```cpp
// 事件总线订阅示例
EventBus::subscribe({
  .event_types = {"user.interaction.click", "agent.decision.made"},
  .filter = "source_modality == 'web'",
  .handler = [](const Event& e) {
    if (e.type == "user.interaction.click") {
      // 记录用户点击，用于训练
      TrainingData::record_interaction(e.payload);
      
      // 通知其他智能体
      EventBus::publish({
        .type = "web.ui.state_changed",
        .source = "agenticweb",
        .payload = {
          {"element_id", e.payload["element_id"]},
          {"interaction_type", "click"},
          {"timestamp", std::time(nullptr)}
        }
      });
    }
  }
});
```

### 3.4 与多模态能力提供者接口

#### 3.4.1 统一场景描述标准
```json
{
  "scene_description": {
    "version": "1.0",
    "nodes": [
      {
        "id": "main_chart",
        "type": "data_visualization",
        "modality": "web",
        "properties": {
          "chart_type": "bar",
          "data_source": "/data/sales_q3",
          "dimensions": {"width": 800, "height": 600}
        },
        "transform": {"position": [0, 0, 0]}
      },
      {
        "id": "3d_product_view",
        "type": "product_model",
        "modality": "3d",
        "properties": {
          "model_url": "models/product_v2.glb",
          "interaction_mode": "rotate_zoom"
        },
        "transform": {"position": [1000, 0, 0]}
      }
    ],
    "relations": [
      {
        "source": "main_chart",
        "target": "3d_product_view",
        "type": "data_drives_visualization",
        "properties": {
          "mapping": {
            "chart_selection": "product_filter"
          }
        }
      }
    ]
  }
}
```

#### 3.4.2 跨模态同步接口
```agenticdsl
### AgenticDSL '/lib/modal/cross/sync_state@v1'
signature:
  inputs:
    - name: source_modality
      type: string
      enum: ["web", "3d", "voice", "ar"]
    - name: target_modality
      type: string
      enum: ["web", "3d", "voice", "ar"]
    - name: state_path
      type: string
      description: "要同步的状态路径，如 'user.selection.item_id'"
    - name: transform_function
      type: string
      description: "状态转换函数，Inja模板"
  outputs:
    - name: sync_status
      type: string
      enum: ["success", "partial", "failed"]
    - name: conflicts_resolved
      type: integer

type: tool_call
tool: modal_state_sync
arguments:
  source: "{{ $.source_modality }}"
  target: "{{ $.target_modality }}"
  state: "{{ get_context_path($.state_path) }}"
  transform: "{{ $.transform_function }}"
permissions:
  - modal: state_sync
  - resource: "state_sync_bandwidth_mb:2"

next: "/self/validate_sync"
```

---

## 四、暴露给生态的接口

### 4.1 能力注册接口

#### 4.1.1 能力描述标准
**定位**：提供最小化、原子化的DOM安全操作能力
**关键能力**：
- `/lib/modal/web/dom/query@v1` - 安全元素查询
- `/lib/modal/web/dom/click@v1` - 安全点击操作
- `/lib/modal/web/dom/input@v1` - 安全输入操作
- `/lib/modal/web/dom/observe@v1` - 安全DOM变化监听

```yaml
# 能力描述YAML标准
capability_descriptor:
  path: "/lib/modal/web/dom/query@v1"
  semantic_tags: 
    - "dom_inspection"
    - "data_extraction"
    - "user_interface_analysis"
  signature:
    inputs:
      - name: selector
        type: string
        validation: "css_selector_syntax"
        examples: ["#main-content", ".product-list > li"]
      - name: include_attributes
        type: array
        items: {type: string}
        default: ["id", "class", "text"]
    outputs:
      - name: elements
        type: array
        schema: {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {"type": "string"},
              "text": {"type": "string"},
              "attributes": {"type": "object"}
            }
          }
        }
  quality_attributes:
    latency_p95_ms: 50
    accuracy: 0.99
    accessibility_compliance: "WCAG-AA"
  compatibility:
    browsers: ["chrome_115+", "firefox_110+", "safari_16+"]
    devices: ["desktop", "tablet", "mobile"]
type: tool_call
tool: safe_dom_query
arguments:
  selectors: "{{ $.selectors }}"
  context: "{{ $.context }}"
  limit: "{{ $.max_results }}"
  retry_config: "{{ $.retry_strategy }}"
permissions:
  - dom: read
  - layout: read
resource_allocation:
  cpu_ms: 10
  memory_mb: 5
audit_trail:
  query_signature: "sha256:{{ $.selectors | join(',') }}"

```

#### 4.1.2 能力发现协议
```agenticdsl
### AgenticDSL '/lib/modal/web/discover_capabilities@v1'
type: tool_call
tool: capability_discovery
arguments:
  query: {
    "semantic_tags": ["data_visualization", "interactive"],
    "input_semantics": {
      "data_type": "tabular",
      "dimensions": 2
    },
    "output_semantics": {
      "visualization_type": "chart"
    },
    "quality_requirements": {
      "latency_ms": "< 200",
      "accessibility": "WCAG-AA"
    }
  }
output_mapping:
  matching_capabilities: "web_visualization_capabilities"

next: "/app/use_case/select_best_capability"
```

### 4.2 事件订阅接口

#### 4.2.1 事件标准格式
```json
{
  "event": {
    "id": "evt_20251124_123456",
    "timestamp": "2025-11-24T12:34:56Z",
    "source": "agenticweb",
    "type": "web.dom.mutation",
    "modality": "web",
    "confidence": 0.95,
    "payload": {
      "element_id": "checkout-button",
      "mutation_type": "attribute_change",
      "attribute": "disabled",
      "old_value": "true",
      "new_value": "false"
    },
    "context": {
      "dag_id": "dag_20251124_abcdef",
      "agent_id": "shopping_assistant_v2",
      "user_session": "sess_123456"
    },
    "security": {
      "signature": "sha256:abcdef123456...",
      "permissions_used": ["web_dom:observe"]
    }
  }
}
```

#### 4.2.2 事件订阅API
```agenticdsl
### AgenticDSL '/lib/modal/web/event/subscribe@v1'
signature:
  inputs:
    - name: event_types
      type: array
      items: {type: string}
      description: "要订阅的事件类型，如 ['dom.mutation', 'user.click']"
    - name: filter_expression
      type: string
      description: "事件过滤表达式，Inja模板"
    - name: delivery_mode
      type: string
      enum: ["immediate", "batched", "buffered"]
      default: "immediate"
    - name: max_buffer_size
      type: integer
      default: 100
  outputs:
    - name: subscription_id
      type: string
    - name: active_filters
      type: array

type: tool_call
tool: event_subscription
arguments:
  types: "{{ $.event_types }}"
  filter: "{{ $.filter_expression }}"
  mode: "{{ $.delivery_mode }}"
  buffer_size: "{{ $.max_buffer_size }}"
permissions:
  - modal: event_subscribe
  - resource: "event_bandwidth_events_per_sec:10"

on_success:
  archive_to: "/state/event_subscriptions/{{ $.subscription_id }}"
```

### 4.3 状态同步接口

#### 4.3.1 双向状态同步协议
```agenticdsl
### AgenticDSL '/lib/modal/web/state/sync_bidirectional@v1'
signature:
  inputs:
    - name: local_state_path
      type: string
      description: "本地状态路径，如 'ui.form.checkout'"
    - name: remote_state_path
      type: string
      description: "远程状态路径，跨智能体/模态"
    - name: sync_strategy
      type: string
      enum: ["immediate", "debounced", "manual_trigger"]
      default: "debounced"
    - name: conflict_resolution
      type: string
      enum: ["local_wins", "remote_wins", "merge", "human_approval"]
      default: "merge"
  outputs:
    - name: sync_handle
      type: string
    - name: initial_sync_status
      type: string

type: tool_call
tool: state_synchronizer
arguments:
  local_path: "{{ $.local_state_path }}"
  remote_path: "{{ $.remote_state_path }}"
  strategy: "{{ $.sync_strategy }}"
  conflict_policy: "{{ $.conflict_resolution }}"
permissions:
  - modal: state_sync
  - security: "data_classification:public"  # 仅同步公开数据

next: "/self/monitor_sync"
```

#### 4.3.2 状态变更事件
```json
{
  "state_change_event": {
    "sync_handle": "sync_123456",
    "timestamp": "2025-11-24T12:35:01Z",
    "direction": "local_to_remote",
    "changed_paths": ["ui.form.checkout.items"],
    "conflict_detected": false,
    "resource_usage": {
      "bandwidth_kb": 2.5,
      "cpu_ms": 1.2
    },
    "trace_id": "trace_abcdef123456"
  }
}
```

### 4.4 UI组件层 (`/lib/modal/web/ui/**`)

**定位**：提供安全、标准化的UI组件原语，而非完整界面

```agenticdsl
### AgenticDSL '/lib/modal/web/ui/dialog@v1'
signature:
  inputs:
    - name: content
      type: object
      properties:
        title: {type: "string", required: true}
        body: {
          type: "object",
          properties: {
            type: {type: "string", enum: ["text", "table", "chart", "form"]},
            data: {type: "object"}
          },
          required: ["type", "data"]
        }
        actions: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: {type: "string"},
              label: {type: "string"},
              style: {type: "string", enum: ["primary", "secondary", "danger"]}
            },
            required: ["id", "label"]
          }
        }
      }
      required: ["title", "body", "actions"]
    - name: security_level
      type: string
      enum: ["standard", "sensitive", "critical"]
      default: "standard"
    - name: timeout_seconds
      type: integer
      default: 300
  
  outputs:
    - name: user_action
      type: object
      properties:
        action_id: {type: "string"},
        timestamp: {type: "string", format: "date-time"},
        context: {type: "object"}
    - name: interaction_metrics
      type: object
      properties:
        response_time_ms: {type: "integer"},
        hesitation_count: {type: "integer"}

type: tool_call
tool: safe_dialog_system
arguments:
  content: "{{ $.content }}"
  security_context: {
    level: "{{ $.security_level }}",
    audit_trail: true,
    require_confirmation: "{{ $.security_level == 'critical' }}"
  }
  timeout: "{{ $.timeout_seconds }}"
  accessibility_profile: "{{ $.user.accessibility_profile }}"
permissions:
  - ui: dialog
  - human: interaction
resource_allocation:
  cpu_ms: 50
  memory_mb: 20
security:
  content_sanitization: high
  user_verification_required: "{{ $.security_level == 'critical' }}"
audit_trail:
  dialog_type: "security_aware"
  user_verification_method: "implicit"
```

**关键能力**：
- `/lib/modal/web/ui/dialog@v1` - 安全对话框系统
- `/lib/modal/web/ui/form@v1` - 安全表单组件
- `/lib/modal/web/ui/notification@v1` - 通知系统
- `/lib/modal/web/ui/data_visualization@v1` - 安全数据可视化

### 4.5 交互语义层 (`/lib/interaction/web/**`)

**定位**：将LLM意图转换为具体的Web交互操作

```agenticdsl
### AgenticDSL '/lib/interaction/web/content/present@v1'
signature:
  inputs:
    - name: content_type
      type: string
      enum: ["text", "table", "chart", "image", "mixed"]
    - name: content_data
      type: object
      description: "结构化内容数据，非原始HTML"
    - name: presentation_mode
      type: string
      enum: ["inline", "modal", "sidebar", "full_page"]
    - name: interaction_allowed
      type: boolean
      default: true
    - name: accessibility_requirements
      type: object
      properties:
        compliance_level: {type: "string", enum: ["WCAG-AA", "WCAG-AAA"]}
        adaptation_needed: {type: "boolean"}
  
  outputs:
    - name: presentation_id
      type: string
    - name: user_engagement_metrics
      type: object
      properties:
        view_duration_ms: {type: "integer"},
        interactions_count: {type: "integer"},
        accessibility_adjustments_applied: {type: "integer"}

type: tool_call
tool: safe_content_presentation
arguments:
  content_type: "{{ $.content_type }}"
  structured_data: "{{ $.content_data }}"
  presentation_style: "{{ $.presentation_mode }}"
  allow_interaction: "{{ $.interaction_allowed }}"
  accessibility: "{{ $.accessibility_requirements }}"
permissions:
  - modal: content_presentation
  - security: "content_sanitization_level:high"
resource_allocation:
  cpu_ms: 75
  memory_mb: 30
security:
  content_verification: required
  sandbox_level: high
audit_trail:
  content_hash: "sha256:{{ $.content_data | hash }}"
  presentation_context: "user_facing"
```

**关键能力**：
- `/lib/interaction/web/content/present@v1` - 安全内容呈现
- `/lib/interaction/web/input/collect@v1` - 安全输入收集
- `/lib/interaction/web/navigation@v1` - 语义导航
- `/lib/interaction/web/state/sync@v1` - 状态同步

### 4.6 人机协同层 (`/lib/human/web/**`)

**定位**：专为人类与LLM协同场景设计的高级能力

```agenticdsl
### AgenticDSL '/lib/human/web/approval_flow@v1'
signature:
  inputs:
    - name: action_description
      type: string
      description: "需要审批的操作描述，结构化数据"
    - name: risk_assessment
      type: object
      properties:
        risk_level: {type: "string", enum: ["low", "medium", "high", "critical"]},
        potential_impact: {type: "string"},
        mitigation_options: {type: "array", items: {type: "string"}}
    - name: context_snapshot
      type: object
      description: "操作上下文快照，用于审批决策"
    - name: escalation_path
      type: array
      items: {type: "string"}
      description: "审批链，如 ['primary_user', 'supervisor']"
  
  outputs:
    - name: approval_result
      type: object
      properties:
        decision: {type: "string", enum: ["approved", "rejected", "deferred"]},
        approver_id: {type: "string"},
        timestamp: {type: "string", format: "date-time"},
        justification: {type: "string"},
        modified_parameters: {type: "object"}
    - name: process_metadata
      type: object
      properties:
        total_duration_ms: {type: "integer"},
        human_verification_method: {type: "string"},
        confidence_score: {type: "number"}

type: tool_call
tool: human_approval_workflow
arguments:
  action: "{{ $.action_description }}"
  risk: "{{ $.risk_assessment }}"
  context: "{{ $.context_snapshot }}"
  escalation_rules: {
    path: "{{ $.escalation_path }}",
    timeout_ms: {
      low: 300000,    # 5分钟
      medium: 180000, # 3分钟
      high: 60000,    # 1分钟
      critical: 30000 # 30秒
    }
  }
permissions:
  - human: approval
  - security: "identity_verification_required:high"
resource_allocation:
  cpu_ms: 100
  memory_mb: 40
security:
  identity_verification: required
  audit_level: comprehensive
audit_trail:
  approval_chain: "{{ $.escalation_path | join(' → ') }}"
  risk_context_preserved: true
```

**关键能力**：
- `/lib/human/web/approval_flow@v1` - 人类审批工作流
- `/lib/human/web/explanation_request@v1` - 意图澄清
- `/lib/human/web/preference_learning@v1` - 用户偏好学习
- `/lib/human/web/recovery_assistance@v1` - 恢复协助


---

## 五、安全与权限模型

### 5.1 权限体系设计
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Web权限层级                                      │
│                                                                             │
│  ┌──────────────────┐    ┌──────────────────┐    ┌────────────────────────┐  │
│  │  基础权限        │    │  交互权限        │    │  管理权限              │  │
│  │ (所有Web应用)    │    │ (用户交互)       │    │ (高级功能)            │  │
│  └────────┬─────────┘    └────────┬─────────┘    └───────────┬────────────┘  │
│           │                     │                           │             │
│  ┌────────▼─────────┐  ┌────────▼─────────┐  ┌──────────────▼────────────┐  │
│  │ web_dom:read     │  │ web_interaction: │  │ web_management:          │  │
│  │ web_time:get     │  │   dialog         │  │   capability_extension   │  │
│  │ web_network:     │  │ web_form:submit  │  │ web_security:            │  │
│  │   basic_fetch    │  │                  │  │   policy_override        │  │
│  └──────────────────┘  └──────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 权限验证流程
```
1. 能力请求到达
2. AIOS内核验证直接权限（web_dom:read）
3. 检查能力依赖链（是否有间接权限需求）
4. 验证权限交集（请求权限 ∩ 用户授权权限）
5. 检查沙箱策略覆盖范围
6. 验证敏感操作审批状态（如需要）
7. 执行能力
8. 记录权限使用审计
```

### 5.3 敏感操作审批工作流
```agenticdsl
### AgenticDSL '/lib/security/approval_workflow@v1'
type: switch
condition: "{{ is_sensitive_operation($.operation) }}"

cases:
  - condition: "true"
    path: "/self/request_approval"
  - condition: "false"
    path: "/self/execute_directly"

### AgenticDSL '/self/request_approval'
type: tool_call
tool: human_approval_request
arguments:
  operation: "{{ $.operation }}"
  risk_level: "{{ assess_risk_level($.operation) }}"
  justification: "{{ $.justification }}"
  timeout_seconds: 300
output_mapping:
  approval_status: "approval_result.status"
  approval_token: "approval_result.token"

next: 
  - condition: "{{ $.approval_status == 'approved' }}"
    path: "/self/execute_with_token"
  - condition: "{{ $.approval_status == 'rejected' }}"
    path: "/self/handle_rejection"
  - condition: "{{ $.approval_status == 'timeout' }}"
    path: "/self/apply_default_policy"
```

---

## 六、性能与资源管理

### 6.1 资源计量模型
| 资源类型 | 计量单位 | 计量方法 | 降级策略 |
|----------|----------|----------|----------|
| CPU时间 | ms/操作 | 硬件性能计数器 | 降低动画帧率，简化选择器 |
| 内存 | MB/操作 | 内存分配跟踪 | 减少DOM快照大小，限制元素数 |
| 网络 | KB/请求 | 代理层计量 | 压缩响应，降低图像质量 |
| LLM预算 | tokens | Token计数器 | 简化提示，缓存结果 |
| 渲染预算 | pixels×frames | 合成器跟踪 | 降低分辨率，减少动画 |

### 6.2 动态降级策略
```agenticdsl
### AgenticDSL '/lib/modal/web/performance/adapt@v1'
signature:
  inputs:
    - name: current_budget
      type: object
      description: "当前资源预算状态"
    - name: operation_complexity
      type: string
      enum: ["low", "medium", "high"]
    - name: user_priority
      type: string
      enum: ["background", "foreground", "critical"]
  outputs:
    - name: adapted_params
      type: object
    - name: quality_impact
      type: number

type: codelet_call
runtime: "wasm"
code: |
  function adapt(current_budget, complexity, priority) {
    let params = {...input_params};
    let quality = 1.0;
    
    // 根据CPU预算调整
    if (current_budget.cpu_ms < 10 && complexity === "high") {
      params.max_elements = Math.min(5, params.max_elements || 10);
      quality *= 0.8;
    }
    
    // 根据内存预算调整
    if (current_budget.memory_mb < 50) {
      params.include_text_content = false;
      quality *= 0.9;
    }
    
    // 用户优先级覆盖
    if (priority === "critical") {
      quality = Math.max(quality, 0.95); // 至少95%质量
    }
    
    return { adapted_params: params, quality_impact: quality };
  }
permissions:
  - resource: compute_adaptation
```

### 6.3 性能优化技术
- **预测性预加载**：基于DAG拓扑预测下一节点UI需求
- **差异更新**：仅更新DOM变更部分，减少重排重绘
- **WASM加速**：关键路径（如选择器匹配）使用WebAssembly
- **GPU卸载**：LLM生成内容的WebGL渲染
- **能力缓存**：高频调用结果缓存（带TTL和版本控制）

---

## 七、开发与调试支持

### 7.1 调试接口
```agenticdsl
### AgenticDSL '/lib/debug/web/dom_snapshot@v1'
signature:
  inputs:
    - name: element_selector
      type: string
      description: "要快照的元素选择器"
    - name: include_styles
      type: boolean
      default: false
    - name: max_depth
      type: integer
      default: 3
  outputs:
    - name: snapshot
      type: object
      description: "DOM树快照，JSON格式"

type: tool_call
tool: debug_dom_snapshot
arguments:
  selector: "{{ $.element_selector }}"
  styles: "{{ $.include_styles }}"
  depth: "{{ $.max_depth }}"
permissions:
  - debug: dom_inspection
  - modal: state_read

# 仅在dev模式可用
only_in_mode: "dev"
```

### 7.2 模拟器接口
```agenticdsl
### AgenticDSL '/lib/simulator/web/user_interaction@v1'
signature:
  inputs:
    - name: interaction_type
      type: string
      enum: ["click", "type", "scroll", "drag"]
    - name: target_selector
      type: string
    - name: interaction_data
      type: object
      description: "交互特定数据，如按键序列"
  outputs:
    - name: simulated_result
      type: object

type: tool_call
tool: simulate_user_interaction
arguments:
  type: "{{ $.interaction_type }}"
  target: "{{ $.target_selector }}"
  data: "{{ $.interaction_data }}"
permissions:
  - simulator: user_interaction
  - resource: "simulation_quota:100"

# 仅用于测试和训练
only_for: ["testing", "training"]
```

### 7.3 Trace标准格式
```json
{
  "web_trace": {
    "capability_id": "/lib/modal/web/dom/query@v1",
    "execution_id": "exec_20251124_abcdef",
    "timestamp": "2025-11-24T12:34:56Z",
    "inputs": {
      "selector": "#product-list",
      "max_elements": 10
    },
    "outputs": {
      "element_count": 8,
      "execution_time_ms": 24.5
    },
    "resource_usage": {
      "cpu_ms": 22.3,
      "memory_kb": 156,
      "dom_nodes_accessed": 120
    },
    "security_context": {
      "permissions_used": ["web_dom:read"],
      "sandbox_level": "standard"
    },
    "modal_context": {
      "device_type": "desktop",
      "browser": "chrome_119",
      "accessibility_mode": false
    },
    "aios_context": {
      "dag_id": "dag_20251124_123456",
      "node_id": "node_789",
      "budget_remaining": {
        "nodes": 15,
        "cpu_ms": 1200
      }
    },
    "debug_artifacts": {
      "dom_snapshot_id": "snap_20251124_123",
      "render_tree_hash": "sha256:abcdef..."
    }
  }
}
```

---

## 八. 生态集成

### 8.1 Web标准兼容性策略

#### 8.1.1 标准遵循原则
- **核心标准严格遵循**：HTML5, DOM Level 3, CSSOM, Web Components
- **新兴标准谨慎采用**：仅当W3C/WHATWG工作草案+2个主要浏览器支持
- **废弃标准隔离**：通过适配层支持旧API，禁止直接使用

#### 8.1.2 标准冲突解决
当AgenticWeb能力与Web标准冲突时：
1. **优先标准**：W3C/WHATWG标准始终优先
2. **能力降级**：当标准不支持时，能力应优雅降级
3. **标准贡献**：所有扩展必须通过W3C Community Group提交
4. **透明报告**：所有非标准行为必须在能力文档中明确标记

#### 8.1.3 浏览器兼容性保证
| 能力类别 | Chrome | Firefox | Safari | Edge | 移动Web |
|----------|--------|---------|--------|------|---------|
| 基础DOM操作 | 115+ | 110+ | 16+ | 115+ | 115+ |
| 安全对话框 | 118+ | 112+ | 16.4+ | 118+ | 118+ |
| 视觉定位 | 120+ | 115+ | 17+ | 120+ | 120+ |
| 离线缓存 | 115+ | 110+ | 16+ | 115+ | 115+ |

### 8.2 与前端框架集成

#### 8.2.1 框架中立原则
AgenticWeb必须保持框架中立，通过标准DOM API交互，而非框架特定API。

#### 8.2.2 框架集成架构
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           框架集成架构                                      │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  框架特定适配器 (由社区维护)                                          │  │
│  │ • React Hooks • Vue Composition API • Angular Services               │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                              │
│  ┌───────────────────────────▼───────────────────────────────────────────┐  │
│  │  框架抽象层 (/lib/ecosystem/framework/**)                            │  │
│  │ • 组件生命周期钩子 • 状态同步桥 • 事件转换器                          │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                              │
│  ┌───────────────────────────▼───────────────────────────────────────────┐  │
│  │  AgenticWeb核心能力 (/lib/modal/web/**)                             │  │
│  │ • 通过标准DOM API交互 • 无视框架内部实现                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 8.2.3 React集成示例
```jsx
// 社区维护的React集成包 @agenticweb/react
import { useAgenticWeb } from '@agenticweb/react';

function CheckoutButton() {
  const { executeCapability, loading, error } = useAgenticWeb(
    '/lib/interaction/web/button/click@v1'
  );
  
  // 自动处理框架生命周期
  useEffect(() => {
    return () => {
      // 组件卸载时清理AgenticWeb状态
      executeCapability('/lib/modal/web/state/cleanup@v1');
    };
  }, []);
  
  const handleCheckout = async () => {
    try {
      const result = await executeCapability({
        selector: '#checkout-button',
        waitForNavigation: true,
        accessibility_requirements: {
          compliance_level: "WCAG-AA",
          adaptation_needed: true
        }
      });
      
      if (result.navigationComplete) {
        // 状态自动同步到React组件
        setCheckoutStatus('completed');
      }
    } catch (err) {
      // 自动转换为框架友好的错误对象
      setError({ 
        message: err.message, 
        recoveryOptions: err.recoveryOptions,
        accessibilityRecommendations: err.accessibilityRecommendations
      });
    }
  };
  
  return (
    <button 
      onClick={handleCheckout}
      disabled={loading}
      aria-busy={loading}
      aria-label="Complete purchase"
    >
      {loading ? 'Processing...' : 'Checkout'}
    </button>
  );
}
```

### 8.3 开发者工具链集成

#### 8.3.1 浏览器开发者工具扩展
- **专用面板**：AgenticWeb能力监控、权限审查、资源计量
- **调试协议**：Chrome DevTools Protocol扩展点
- **可视化工具**：DOM选择器可视化、操作回放、安全边界可视化

#### 8.3.2 IDE集成架构
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IDE集成架构                                      │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  IDE插件 (VSCode/IntelliJ)                                           │  │
│  │ • 能力代码补全 • 类型推断 • 调试可视化 • 性能分析                    │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                              │
│  ┌───────────────────────────▼───────────────────────────────────────────┐  │
│  │  语言服务器协议 (LSP) 扩展                                           │  │
│  │ • 能力签名提供 • 错误检查 • 重构支持 • 文档生成                      │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                              │
│  ┌───────────────────────────▼───────────────────────────────────────────┐  │
│  │  AgenticDSL 语言服务                                                 │  │
│  │ • 语法验证 • 语义分析 • 跨文件引用 • 类型检查                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 8.3.3 模拟器与测试框架
```agenticdsl
### AgenticDSL '/lib/test/web/simulator@v1'
signature:
  inputs:
    - name: simulation_scenario
      type: object
      properties:
        page_url: {type: "string"}
        initial_dom_state: {type: "string"}  # HTML string
        network_conditions: {
          type: "object",
          properties: {
            latency_ms: {type: "integer", default: 100},
            bandwidth_kbps: {type: "integer", default: 10000},
            packet_loss_percent: {type: "number", default: 0}
          }
        }
        user_profile: {
          type: "object",
          properties: {
            viewport: {type: "object", default: {"width": 1200, "height": 800}},
            device_type: {type: "string", default: "desktop"},
            accessibility_needs: {type: "array", default: []}
          }
        }
    - name: test_capabilities
      type: array
      items: {type: "string"}
    - name: test_parameters
      type: object
      properties:
        iterations: {type: "integer", default: 1},
        stress_test: {type: "boolean", default: false}
  
  outputs:
    - name: test_report
      type: object
      properties:
        passed: {type: "boolean"},
        results: {type: "array"},
        performance_metrics: {type: "object"},
        accessibility_score: {type: "number"},
        security_violations: {type: "array"}

type: tool_call
tool: web_capability_simulator
arguments:
  scenario: "{{ $.simulation_scenario }}"
  capabilities_to_test: "{{ $.test_capabilities }}"
  validation_rules: {
    security_violations: "fail_on_any",
    performance_threshold: {
      cpu_ms: 100,
      memory_mb: 50,
      execution_time_ms: 2000
    },
    accessibility_level: "{{ $.simulation_scenario.user_profile.accessibility_needs.length > 0 ? 'WCAG-AA' : 'basic' }}"
  }
  test_config: "{{ $.test_parameters }}"
output_format: "comprehensive_report"
resource_allocation:
  cpu_ms: 5000
  memory_mb: 500
```


---

## 九、演进路线

### 9.1 短期路线（2025）
- **核心能力完善**：
  - 完整实现`/lib/modal/web/**`标准库（20+核心能力）
  - 与AgenticCLI深度集成，统一资源预算
  - 基础多模态同步能力
- **开发者体验**：
  - 浏览器开发者工具扩展
  - 本地模拟器支持
  - 调试Trace可视化
- **安全强化**：
  - 五层沙箱架构落地
  - 敏感操作审批工作流
  - 完整审计追踪

### 9.2 中期路线（2026）
- **性能优化**：
  - WASM加速关键路径
  - 预测性渲染引擎
  - 跨DAG能力缓存
- **多模态融合**：
  - 统一场景描述标准1.0
  - Web-3D无缝桥接
  - 语音-视觉协同交互
- **生态扩展**：
  - 能力市场接入
  - 第三方能力认证体系
  - 跨组织协作协议

### 9.3 长期愿景（2027+）
- **自主优化**：
  - 基于使用模式的能力自优化
  - 动态权限调整
  - 预测性资源分配
- **沉浸式Web**：
  - Web-AR/VR原生支持
  - 空间计算集成
  - 多用户共享场景
- **价值网络**：
  - 能力使用价值自动分配
  - 贡献证明与声誉系统
  - 去中心化治理参与

---

## 附录：接口规范参考

### A.1 能力注册IDL
```protobuf
message CapabilityDescriptor {
  string path = 1;  // "/lib/modal/web/dom/query@v1"
  string version = 2;
  string stability = 3;  // "stable", "experimental", "deprecated"
  
  CapabilitySignature signature = 4;
  repeated PermissionRequirement permissions = 5;
  ResourceModel resource_model = 6;
  
  ModalMetadata modal_metadata = 7;
  map<string, string> compatibility = 8;  // "browser:chrome_115+"
}

message CapabilitySignature {
  repeated ParameterDefinition inputs = 1;
  repeated ParameterDefinition outputs = 2;
  string expected_output_schema = 3;  // JSON Schema
}

message PermissionRequirement {
  string permission_id = 1;  // "web_dom:read"
  string required_level = 2;  // "basic", "advanced", "privileged"
  bool requires_approval = 3;
}
```

### A.2 事件总线协议
```protobuf
message ModalEvent {
  string id = 1;  // "evt_20251124_123456"
  google.protobuf.Timestamp timestamp = 2;
  string source = 3;  // "agenticweb"
  string type = 4;    // "web.dom.mutation"
  string modality = 5;  // "web"
  float confidence = 6;
  
  google.protobuf.Struct payload = 7;
  google.protobuf.Struct context = 8;
  
  SecurityMetadata security = 9;
}

message SecurityMetadata {
  string signature = 1;
  repeated string permissions_used = 2;
  string data_classification = 3;  // "public", "internal", "confidential"
}
```

---

> **专家组结语**：AgenticWeb不仅是浏览器自动化工具，而是AI-Native操作系统中Web模态的完整抽象。通过严格遵循模态统一原则、契约化接口设计、深度生态集成，我们构建了一个既安全可靠，又能释放LLM创造力的Web交互基础设施。每一个接口设计决策都围绕"让LLM成为计算机的主人"这一核心愿景，同时确保人类保持最终监督权和价值对齐。

**文档版本**：v2.0  
**最后修订**：2025年11月24日  
**批准机构**：Agentic-ecosystem联合架构委员会
