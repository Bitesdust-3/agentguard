(() => {
  "use strict";

  const storageKey = "agentguard.dashboard.language";
  const translations = {
    zh: {
      "nav.label": "仪表盘导航",
      "nav.overview": "总览",
      "nav.events": "安全事件",
      "nav.tools": "工具调用与审批",
      "nav.benchmark": "安全评测",
      "brand.controlPlane": "AI Agent 安全网关",
      "brand.policyWorkspace": "策略执行已启用",
      "console.title": "本地安全控制台",
      "runtime.provider": "Provider 模式",
      "runtime.version": "版本",
      "label.securityFlow": "安全链路",
      "label.auditStream": "审计流",
      "label.approvalQueue": "审批队列",
      "label.auditTimeline": "审计时间线",
      "label.toolRoutes": "工具策略路径",
      "label.toolRequest": "工具请求",
      "label.policyDecision": "策略决策",
      "label.executionState": "执行状态",
      "label.controlPerformance": "控制性能",
      "label.knownFailures": "已知薄弱项与失败",
      "label.requestID": "请求 ID",
      "label.securityTrace": "安全处理轨迹",
      "label.requestReceived": "请求已接收",
      "label.detection": "检测",
      "label.toolCall": "工具调用",
      "label.requestAttributes": "请求属性",
      "label.toolAuthorizationTrace": "工具授权轨迹",
      "label.toolRequested": "工具请求",
      "label.toolPolicy": "工具策略",
      "label.humanApproval": "人工审批",
      "language.label": "语言选择",
      "page.overview": "总览",
      "page.events": "安全事件",
      "page.tools": "工具调用与审批",
      "page.benchmark": "安全评测",
      "page.request": "请求详情",
      "page.tool": "工具详情",
      "health.checking": "正在检查服务",
      "health.online": "服务正常",
      "health.unavailable": "服务异常",
      "overview.totalChats": "Chat 请求总数",
      "overview.detections": "检测结果",
      "overview.secretPii": "密钥/凭据 Secret · PII",
      "overview.toolCalls": "工具调用",
      "overview.pendingApproval": "待审批",
      "overview.recentEvents": "最近安全事件",
      "overview.securityFlow": "安全处理链路",
      "overview.flowNote": "请求在进入 Provider 前后均经过策略控制",
      "overview.requests": "请求",
      "overview.signals": "当前安全信号",
      "overview.controlled": "受控",
      "overview.enforced": "已执行",
      "overview.policyActive": "策略已启用",
      "term.promptInjection": "提示词注入 Prompt Injection",
      "term.secret": "密钥/凭据 Secret",
      "term.pii": "敏感信息 PII",
      "common.viewAll": "查看全部",
      "common.all": "全部",
      "common.filter": "筛选",
      "common.clear": "清除",
      "common.details": "详情",
      "filter.eventType": "事件类型",
      "filter.eventPlaceholder": "例如 INPUT_POLICY",
      "filter.decision": "决策",
      "filter.detectionType": "检测类型",
      "table.time": "时间",
      "table.event": "事件",
      "table.detection": "检测结果",
      "table.detectionRule": "检测 / 规则",
      "table.decision": "决策",
      "table.risk": "风险",
      "table.record": "记录",
      "table.linkedRecord": "关联记录",
      "table.safeSummary": "安全摘要",
      "table.tool": "工具",
      "table.state": "状态",
      "table.approval": "审批",
      "table.attributes": "属性",
      "table.created": "创建时间",
      "table.completed": "完成时间",
      "table.actions": "操作",
      "tools.enforced": "由 Tool Policy 强制执行",
      "tools.routePass": "直接执行路径",
      "tools.routeApproval": "人工审批路径",
      "tools.routeBlock": "拒绝执行路径",
      "events.noDetection": "无检测命中",
      "attribute.external": "外部调用",
      "attribute.destructive": "破坏性",
      "attribute.sensitive": "敏感",
      "approval.approve": "批准",
      "approval.reject": "拒绝",
      "approval.requested": "申请时间",
      "approval.decided": "处理时间",
      "back.events": "返回安全事件",
      "back.tools": "返回工具调用与审批",
      "detail.model": "模型",
      "detail.finalDecision": "最终决策",
      "detail.score": "分数",
      "detail.confidence": "置信度",
      "detail.policyDecisions": "策略决策",
      "detail.processingTrace": "安全处理轨迹",
      "detail.requestReceived": "请求已接收",
      "detail.auditTimeline": "安全审计时间线",
      "detail.requestBlocked": "请求已被安全策略阻断",
      "detail.sensitiveContentRedacted": "敏感内容已按策略脱敏",
      "detail.toolExecutionDenied": "危险工具操作已被 Tool Policy 阻断",
      "detail.awaitingApproval": "敏感工具操作正在等待人工审批",
      "tool.call": "工具调用",
      "tool.arguments": "参数摘要",
      "tool.result": "执行结果",
      "benchmark.dataset": "数据集",
      "benchmark.samples": "样本数",
      "benchmark.accuracy": "准确率",
      "benchmark.precision": "精确率",
      "benchmark.recall": "召回率",
      "benchmark.fpr": "误报率 FPR",
      "benchmark.fnr": "漏报率 FNR",
      "benchmark.decisionAccuracy": "决策准确率",
      "benchmark.averageLatency": "平均额外延迟",
      "benchmark.averageLatencyShort": "平均额外延迟",
      "benchmark.p50": "P50 额外延迟",
      "benchmark.p95": "P95 额外延迟",
      "benchmark.reproducibility": "可复现性",
      "benchmark.run": "运行",
      "benchmark.datasetHash": "数据集哈希",
      "benchmark.configHash": "配置哈希",
      "benchmark.recentRuns": "最近评测运行",
      "benchmark.categoryMetrics": "分类指标",
      "benchmark.category": "类别",
      "benchmark.passed": "通过",
      "benchmark.failed": "失败",
      "benchmark.safeFailureSummary": "安全失败摘要",
      "benchmark.safeFailureNote": "这里不会显示输入文本、Prompt、Provider 响应或敏感信息原值。",
      "benchmark.honestNote": "评测控制台如实展示已知弱项与失败样本，不隐藏检测边界。",
      "benchmark.sample": "样本",
      "benchmark.expected": "预期",
      "benchmark.actual": "实际",
      "benchmark.rule": "规则",
      "benchmark.safeReason": "安全原因",
      "benchmark.lowerIsBetter": "越低越好",
      "empty.audit": "暂无安全审计事件。",
      "empty.events": "当前筛选条件下没有安全事件。",
      "empty.tools": "暂无工具调用记录。",
      "empty.approval": "该工具调用无需审批。",
      "empty.detections": "未发现安全检测结果。",
      "empty.decisions": "暂无策略决策记录。",
      "empty.failures": "没有失败样本。",
      "empty.benchmarkTitle": "暂无 Benchmark 运行记录",
      "empty.benchmarkBody": "请先运行 CLI Benchmark；此 Dashboard 只读取已持久化的结果。",
      "notice.approvalUpdated": "审批状态已更新，正在刷新当前页面。",
      "notice.approvalConflict": "该审批已处理，请刷新查看当前状态。",
      "notice.approvalFailed": "审批操作未完成，服务端状态未发生变化。"
    },
    en: {
      "nav.label": "Dashboard navigation",
      "nav.overview": "Overview",
      "nav.events": "Security Events",
      "nav.tools": "Tool & Approval",
      "nav.benchmark": "Benchmark",
      "brand.controlPlane": "AI Agent Security Gateway",
      "brand.policyWorkspace": "Policy enforcement active",
      "console.title": "LOCAL SECURITY CONSOLE",
      "runtime.provider": "Provider Mode",
      "runtime.version": "Version",
      "label.securityFlow": "Security Flow",
      "label.auditStream": "Audit Stream",
      "label.approvalQueue": "Approval Queue",
      "label.auditTimeline": "Audit Timeline",
      "label.toolRoutes": "Tool Policy Routes",
      "label.toolRequest": "Tool Request",
      "label.policyDecision": "Policy Decision",
      "label.executionState": "Execution State",
      "label.controlPerformance": "Control Performance",
      "label.knownFailures": "Known Weaknesses & Failures",
      "label.requestID": "Request ID",
      "label.securityTrace": "Security Process Trace",
      "label.requestReceived": "Request Received",
      "label.detection": "Detection",
      "label.toolCall": "Tool Call",
      "label.requestAttributes": "Request Attributes",
      "label.toolAuthorizationTrace": "Tool Authorization Trace",
      "label.toolRequested": "Tool Requested",
      "label.toolPolicy": "Tool Policy",
      "label.humanApproval": "Human Approval",
      "language.label": "Language selection",
      "page.overview": "Overview",
      "page.events": "Security Events",
      "page.tools": "Tool & Approval",
      "page.benchmark": "Benchmark",
      "page.request": "Request Detail",
      "page.tool": "Tool Detail",
      "health.checking": "Checking Service",
      "health.online": "Service Online",
      "health.unavailable": "Service Unavailable",
      "overview.totalChats": "Total Chat Requests",
      "overview.detections": "Detections",
      "overview.secretPii": "Secret · PII",
      "overview.toolCalls": "Tool Calls",
      "overview.pendingApproval": "Pending Approval",
      "overview.recentEvents": "Recent Security Events",
      "overview.securityFlow": "Security Processing Flow",
      "overview.flowNote": "Every request is policy-controlled before and after the Provider",
      "overview.requests": "Requests",
      "overview.signals": "Active Security Signals",
      "overview.controlled": "Controlled",
      "overview.enforced": "Enforced",
      "overview.policyActive": "Policy Active",
      "term.promptInjection": "Prompt Injection",
      "term.secret": "Secret",
      "term.pii": "PII",
      "common.viewAll": "View All",
      "common.all": "All",
      "common.filter": "Filter",
      "common.clear": "Clear",
      "common.details": "Details",
      "filter.eventType": "Event Type",
      "filter.eventPlaceholder": "e.g. INPUT_POLICY",
      "filter.decision": "Decision",
      "filter.detectionType": "Detection Type",
      "table.time": "Time",
      "table.event": "Event",
      "table.detection": "Detection",
      "table.detectionRule": "Detection / Rule",
      "table.decision": "Decision",
      "table.risk": "Risk",
      "table.record": "Record",
      "table.linkedRecord": "Linked Record",
      "table.safeSummary": "Safe Summary",
      "table.tool": "Tool",
      "table.state": "State",
      "table.approval": "Approval",
      "table.attributes": "Attributes",
      "table.created": "Created",
      "table.completed": "Completed",
      "table.actions": "Actions",
      "tools.enforced": "Enforced by Tool Policy",
      "tools.routePass": "Direct Execution Route",
      "tools.routeApproval": "Human Approval Route",
      "tools.routeBlock": "Execution Denied Route",
      "events.noDetection": "No Detection",
      "attribute.external": "External",
      "attribute.destructive": "Destructive",
      "attribute.sensitive": "Sensitive",
      "approval.approve": "Approve",
      "approval.reject": "Reject",
      "approval.requested": "Requested",
      "approval.decided": "Decided",
      "back.events": "Back to Security Events",
      "back.tools": "Back to Tool & Approval",
      "detail.model": "Model",
      "detail.finalDecision": "Final Decision",
      "detail.score": "Score",
      "detail.confidence": "Confidence",
      "detail.policyDecisions": "Policy Decisions",
      "detail.processingTrace": "Security Processing Trace",
      "detail.requestReceived": "Request Received",
      "detail.auditTimeline": "Audit Timeline",
      "detail.requestBlocked": "Request blocked by security policy",
      "detail.sensitiveContentRedacted": "Sensitive content redacted by policy",
      "detail.toolExecutionDenied": "Destructive tool action blocked by Tool Policy",
      "detail.awaitingApproval": "Sensitive tool action is awaiting human approval",
      "tool.call": "Tool Call",
      "tool.arguments": "Arguments Summary",
      "tool.result": "Execution Result",
      "benchmark.dataset": "Dataset",
      "benchmark.samples": "Samples",
      "benchmark.accuracy": "Accuracy",
      "benchmark.precision": "Precision",
      "benchmark.recall": "Recall",
      "benchmark.fpr": "False Positive Rate (FPR)",
      "benchmark.fnr": "False Negative Rate (FNR)",
      "benchmark.decisionAccuracy": "Decision Accuracy",
      "benchmark.averageLatency": "Average Added Latency",
      "benchmark.averageLatencyShort": "Avg Added Latency",
      "benchmark.p50": "P50 Added Latency",
      "benchmark.p95": "P95 Added Latency",
      "benchmark.reproducibility": "Reproducibility",
      "benchmark.run": "Run",
      "benchmark.datasetHash": "Dataset Hash",
      "benchmark.configHash": "Config Hash",
      "benchmark.recentRuns": "Recent Benchmark Runs",
      "benchmark.categoryMetrics": "Category Metrics",
      "benchmark.category": "Category",
      "benchmark.passed": "Passed",
      "benchmark.failed": "Failed",
      "benchmark.safeFailureSummary": "Safe Failure Summary",
      "benchmark.safeFailureNote": "Input text, prompts, provider responses, and raw sensitive values are never displayed here.",
      "benchmark.honestNote": "The evaluation console exposes known weaknesses and failed samples without hiding detection boundaries.",
      "benchmark.sample": "Sample",
      "benchmark.expected": "Expected",
      "benchmark.actual": "Actual",
      "benchmark.rule": "Rule",
      "benchmark.safeReason": "Safe Reason",
      "benchmark.lowerIsBetter": "Lower is better",
      "empty.audit": "No security audit events.",
      "empty.events": "No security events match the current filters.",
      "empty.tools": "No Tool Calls.",
      "empty.approval": "This Tool Call does not require approval.",
      "empty.detections": "No security detections found.",
      "empty.decisions": "No policy decisions recorded.",
      "empty.failures": "No failed samples.",
      "empty.benchmarkTitle": "No Benchmark Runs",
      "empty.benchmarkBody": "Run the CLI Benchmark first. This Dashboard only reads persisted results.",
      "notice.approvalUpdated": "Approval updated. Refreshing this page.",
      "notice.approvalConflict": "This approval has already been processed. Refresh to view its current state.",
      "notice.approvalFailed": "Approval was not completed. Server state was not changed."
    }
  };

  const detectionLabels = {
    zh: { PII: "敏感信息 PII", SECRET: "密钥/凭据 Secret", PROMPT_INJECTION: "提示词注入 Prompt Injection" },
    en: { PII: "PII", SECRET: "Secret", PROMPT_INJECTION: "Prompt Injection" }
  };
  const categoryLabels = {
    zh: { normal: "正常请求", pii: "敏感信息 PII", secret: "密钥/凭据 Secret", direct_prompt_injection: "直接提示词注入 Prompt Injection", indirect_prompt_injection: "间接提示词注入 Prompt Injection", tool_misuse: "工具滥用", approval_bypass: "审批绕过" },
    en: { normal: "Normal", pii: "PII", secret: "Secret", direct_prompt_injection: "Direct Prompt Injection", indirect_prompt_injection: "Indirect Prompt Injection", tool_misuse: "Tool Misuse", approval_bypass: "Approval Bypass" }
  };
  const providerLabels = {
    mock: "Mock Provider",
    openai_compatible: "OpenAI-Compatible",
    unknown: "—"
  };

  let language = readLanguage();

  function readLanguage() {
    try { return localStorage.getItem(storageKey) === "en" ? "en" : "zh"; } catch (_) { return "zh"; }
  }

  function message(key) {
    return translations[language][key] || translations.zh[key] || key;
  }

  function applyLanguage(root = document) {
    root.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = message(element.dataset.i18n); });
    root.querySelectorAll("[data-i18n-placeholder]").forEach((element) => { element.placeholder = message(element.dataset.i18nPlaceholder); });
    root.querySelectorAll("[data-i18n-aria-label]").forEach((element) => { element.setAttribute("aria-label", message(element.dataset.i18nAriaLabel)); });
    root.querySelectorAll("[data-i18n-count]").forEach((element) => {
      const count = element.dataset.i18nCount;
      element.textContent = language === "zh" ? `${count} 条结果` : `${count} results`;
    });
    root.querySelectorAll("[data-detection-label]").forEach((element) => {
      element.textContent = detectionLabels[language][element.dataset.detectionLabel] || element.dataset.detectionLabel;
    });
    root.querySelectorAll("[data-benchmark-category]").forEach((element) => {
      element.textContent = categoryLabels[language][element.dataset.benchmarkCategory] || element.dataset.benchmarkCategory;
    });
    root.querySelectorAll("[data-provider-mode]").forEach((element) => {
      element.textContent = providerLabels[element.dataset.providerMode] || element.dataset.providerMode;
    });
    document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-language]").forEach((button) => { button.setAttribute("aria-pressed", String(button.dataset.language === language)); });
    const titleKey = document.body.dataset.titleKey;
    if (titleKey) { document.title = `${message(titleKey)} · AgentGuard`; }
  }

  function formatBenchmarkRates(root = document) {
    root.querySelectorAll("[data-rate]").forEach((element) => {
      const value = Number.parseFloat(element.dataset.rate);
      element.textContent = Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : element.dataset.rate;
    });
  }

  function revealMetricBars(root = document) {
    window.requestAnimationFrame(() => {
      root.querySelectorAll(".metric-progress, .category-progress").forEach((element) => element.classList.add("is-visible"));
    });
  }

  function setLanguage(nextLanguage) {
    language = nextLanguage === "en" ? "en" : "zh";
    try { localStorage.setItem(storageKey, language); } catch (_) {}
    applyLanguage(document);
  }

  async function refreshHealth() {
    const health = document.getElementById("service-health");
    if (!health) { return; }
    const label = health.querySelector("[data-health-label]");
    try {
      const response = await fetch("/health", { headers: { Accept: "application/json" }, cache: "no-store" });
      const body = response.ok ? await response.json() : null;
      if (!body || body.status !== "ok") { throw new Error("health unavailable"); }
      health.className = "health-status online";
      label.dataset.i18n = "health.online";
    } catch (_) {
      health.className = "health-status unavailable";
      label.dataset.i18n = "health.unavailable";
    }
    label.textContent = message(label.dataset.i18n);
  }

  window.dashboardApprovalResult = (event) => {
    const notice = document.getElementById("dashboard-notice");
    if (event.detail.successful) {
      notice.textContent = message("notice.approvalUpdated");
      window.setTimeout(() => window.location.reload(), 250);
      return;
    }
    const status = event.detail.xhr ? event.detail.xhr.status : 0;
    notice.textContent = message(status === 409 ? "notice.approvalConflict" : "notice.approvalFailed");
  };

  document.querySelectorAll("[data-language]").forEach((button) => {
    button.addEventListener("click", () => setLanguage(button.dataset.language));
  });
  document.addEventListener("htmx:afterSwap", (event) => {
    applyLanguage(event.detail.target);
    formatBenchmarkRates(event.detail.target);
    revealMetricBars(event.detail.target);
  });
  applyLanguage(document);
  formatBenchmarkRates(document);
  revealMetricBars(document);
  refreshHealth();
})();
